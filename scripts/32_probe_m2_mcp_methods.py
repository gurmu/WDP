#!/usr/bin/env python3
"""
OD-8's second half: what HTTP methods does route M2 actually need?

THE AMBIGUITY THIS CLOSES
-------------------------
`iac/config/route-table.yaml` row M2 carries:

    methods: [POST]
    methods_unconfirmed: true
    methods_unconfirmed_because: >-
      §2.3.2 gives the method as "MCP", which is a protocol rather than
      an HTTP method. Streamable-HTTP MCP uses POST for calls and may
      use GET for the event stream. T-16 settles which methods the
      selector needs; a POST-only selector would silently drop the
      stream.

That is a real hazard and not a pedantic one. A Gravitee flow selector
restricted to POST, in front of a protocol that also uses GET to open
an SSE event stream, produces a route that passes a smoke test and
fails every long-running tool call -- and fails it by DROPPING the
stream, not by refusing it, so the caller sees a hang rather than an
error. The CONOPS cannot say `methods: [POST]` on a guess.

Two closes were acceptable: measure it, or record M2 NOT_RUN against
the named ambiguity. Guessing was not. This script measures it.

WHAT IT MEASURES, AND WHY EACH PROBE IS THERE
---------------------------------------------
1. Does an MCP surface exist on this tier at all? `/api/2.0/mcp/*`
   (route M3, the legacy path) 404s with ENDPOINT_NOT_FOUND -- already
   measured by T-16. M2 is a DIFFERENT path and must be probed
   separately. Treating M3's 404 as M2's answer would be the
   same-host-not-same-path error (B-40) one layer up.

2. The path SHAPE. The probe asks for a deliberately malformed service
   name and reads the shape back out of the server's own error, rather
   than assuming §2.3.2's `{mcp-name}` is right. It is not: the server
   requires `mcp-services/{catalog}.{schema}.{leaf}`, a three-part Unity
   Catalog name. A route table that describes this segment as an opaque
   slug is describing the wrong thing -- the segment carries a UC OBJECT
   IDENTITY, which means M2's authorization scope is per-UC-object, not
   per-service. That is a v1.6 correction and it came out of an error
   message, which is the cheapest place this repo has ever found one.

3. GET, on a WELL-FORMED name, twice: once with
   `text/event-stream` in Accept and once without. Both matter.
   A 405 returned only when SSE is absent from Accept would mean the
   stream exists and is content-negotiated; a 405 in both cases means
   there is no stream on this tier. The two-probe form is what makes
   the conclusion readable -- a single GET could not tell "no stream"
   from "stream, but I asked for it wrong."

4. POST on a well-formed name, as a positive control for 3. If POST
   also failed, a 405 on GET would say nothing about methods -- it
   would just mean the path was wrong, and the test would have
   "confirmed" POST-only by being broken. The control is what makes the
   405 attributable.

THE SHAPE OF THE ANSWER, STATED BEFORE THE RUN
----------------------------------------------
This probe can close the METHOD question without closing the
INVOCATION question, and those are different. The method question is
answered by which verbs the dispatcher accepts. Whether a tool call
actually succeeds depends on an MCP service being registered and
entitled, which on this tier it is not. So a 403 from a well-formed
POST is a PASS for this probe's purpose and must not be reported as a
failure of M2 -- it is the dispatcher authenticating, routing, and then
refusing on authorization, which is precisely the evidence that the
path and method are right.

Recording that distinction up front, because the tempting error is to
see 403 and write "M2 unreachable", which would retire a confirmed
finding as a blocker.

Usage:
    python3 scripts/32_probe_m2_mcp_methods.py
"""

import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))

from common import load_env  # noqa: E402

EVIDENCE = REPO / "evidence" / "m2-mcp-methods.json"
BASE = "/ai-gateway/mcp-services"
LEGACY = "/api/2.0/mcp/servers"

# A well-formed name in the shape the server itself requires. It does
# not need to EXIST -- a nonexistent-but-well-formed name still reaches
# the dispatcher, which is the thing being probed. A name that does not
# exist and a name the caller may not invoke both answer past the
# routing layer, and routing is the question.
WELL_FORMED = "awoz1227_demo.opensharing_test.test_dataset"
MALFORMED = "system"

INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                   "clientInfo": {"name": "awoz1227-m2-probe",
                                  "version": "1.0"}}}


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Do not follow redirects.

    A 307 followed silently would report the status of a DIFFERENT URL
    than the one asked about, and the whole question here is which URL
    and verb the dispatcher accepts. urllib follows redirects by
    default, so this has to be switched off explicitly -- a default
    that rewrites the subject of the measurement.
    """

    def redirect_request(self, *args, **kwargs):
        return None


def call(host, token, method, path, body=None, accept=None):
    headers = {"Authorization": f"Bearer {token}",
               "Content-Type": "application/json"}
    if accept:
        headers["Accept"] = accept
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(host + path, data=data, method=method,
                                 headers=headers)
    opener = urllib.request.build_opener(NoRedirect)
    out = {"method": method, "path": path,
           "accept": accept, "at": now()}
    try:
        with opener.open(req, timeout=30) as resp:
            raw = resp.read().decode()
            out["status"] = resp.status
            out["content_type"] = resp.headers.get("Content-Type")
            out["mcp_session_id_returned"] = bool(
                resp.headers.get("Mcp-Session-Id"))
            out["location"] = resp.headers.get("Location")
            out["body"] = raw[:600]
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode()
        out["status"] = exc.code
        out["content_type"] = exc.headers.get("Content-Type")
        out["location"] = exc.headers.get("Location")
        out["body"] = raw[:600]
    except Exception as exc:
        out["status"] = "ERR"
        out["error"] = str(exc)[:200]
    # Pull the JSON-RPC error out if there is one. An MCP server
    # answering with a JSON-RPC envelope is the signal that the request
    # REACHED an MCP dispatcher, which an HTTP status alone does not
    # say: this surface returns HTTP 200 carrying a JSON-RPC error, so
    # reading only the status would score a refusal as a success.
    body = out.get("body") or ""
    if body.strip().startswith("{"):
        try:
            parsed = json.loads(body)
            if parsed.get("jsonrpc"):
                out["jsonrpc"] = True
                err = parsed.get("error") or {}
                out["jsonrpc_error_code"] = err.get("code")
                out["jsonrpc_error_message"] = err.get("message")
                out["jsonrpc_result_present"] = "result" in parsed
            else:
                out["error_code"] = parsed.get("error_code")
        except Exception:
            pass
    return out


def main():
    load_env()
    host = os.environ.get("DATABRICKS_HOST", "").rstrip("/")
    token = os.environ.get("DATABRICKS_TOKEN", "")
    if not host or not token:
        sys.exit("DATABRICKS_HOST / DATABRICKS_TOKEN not set.")

    print("=" * 70)
    print("M2 / OD-8 second half: which methods does the MCP route need?")
    print("=" * 70)

    probes = {}

    print("\n[1] is there an MCP surface on this tier?")
    probes["legacy_m3_path"] = call(host, token, "GET", LEGACY)
    probes["m2_base_get"] = call(
        host, token, "GET", BASE,
        accept="application/json, text/event-stream")
    print(f"    legacy {LEGACY} -> "
          f"{probes['legacy_m3_path']['status']} "
          f"{probes['legacy_m3_path'].get('error_code')}")
    print(f"    M2 base {BASE} -> {probes['m2_base_get']['status']} "
          f"jsonrpc={probes['m2_base_get'].get('jsonrpc', False)} "
          f"code={probes['m2_base_get'].get('jsonrpc_error_code')}")

    print("\n[2] what path shape does the server require?")
    probes["malformed_name"] = call(
        host, token, "POST", f"{BASE}/{MALFORMED}", INIT,
        accept="application/json, text/event-stream")
    print(f"    POST {BASE}/{MALFORMED} -> "
          f"{probes['malformed_name']['status']}")
    print(f"    server says: "
          f"{probes['malformed_name'].get('jsonrpc_error_message')}")

    print("\n[3] GET on a well-formed name, with and without SSE in Accept")
    probes["well_formed_get_sse"] = call(
        host, token, "GET", f"{BASE}/{WELL_FORMED}",
        accept="application/json, text/event-stream")
    probes["well_formed_get_nosse"] = call(
        host, token, "GET", f"{BASE}/{WELL_FORMED}",
        accept="application/json")
    print(f"    GET +sse -> {probes['well_formed_get_sse']['status']} "
          f"({probes['well_formed_get_sse'].get('content_type')})")
    print(f"    GET -sse -> {probes['well_formed_get_nosse']['status']} "
          f"({probes['well_formed_get_nosse'].get('content_type')})")

    print("\n[4] POST on the same name -- the positive control")
    probes["well_formed_post"] = call(
        host, token, "POST", f"{BASE}/{WELL_FORMED}", INIT,
        accept="application/json, text/event-stream")
    print(f"    POST     -> {probes['well_formed_post']['status']} "
          f"jsonrpc={probes['well_formed_post'].get('jsonrpc', False)} "
          f"code={probes['well_formed_post'].get('jsonrpc_error_code')} "
          f"{probes['well_formed_post'].get('jsonrpc_error_message')}")

    # Also the base path with POST, which 307s. Recorded because a
    # reader who tries the base path first will see the 307 and may
    # conclude the route needs redirect handling -- it does not, it
    # needs a name.
    probes["m2_base_post"] = call(
        host, token, "POST", BASE, INIT,
        accept="application/json, text/event-stream")

    # --- what the probes establish ------------------------------------
    post = probes["well_formed_post"]
    get_sse = probes["well_formed_get_sse"]
    get_nosse = probes["well_formed_get_nosse"]

    # POST reached an MCP dispatcher if it came back in JSON-RPC. The
    # dispatcher refusing on AUTHORIZATION (-32007) still proves the
    # path and verb routed -- see the docstring.
    post_routed = bool(post.get("jsonrpc"))
    post_authz_refused = post.get("jsonrpc_error_code") == -32007
    get_refused_both = (get_sse.get("status") == 405
                        and get_nosse.get("status") == 405)
    get_content_negotiated = (get_sse.get("status") != 405
                              and get_nosse.get("status") == 405)

    if not post_routed:
        verdict = "CANNOT_SEE_POST_DID_NOT_REACH_AN_MCP_DISPATCHER"
    elif get_refused_both:
        verdict = "POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER"
    elif get_content_negotiated:
        verdict = "GET_STREAM_EXISTS_SELECTOR_MUST_INCLUDE_GET"
    else:
        verdict = "CANNOT_SEE_GET_BEHAVIOUR_AMBIGUOUS"

    confirmed = verdict == "POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER"

    ev = {
        "probe": "M2 MCP methods",
        "open_decision": "OD-8 (second half)",
        "route": "M2",
        "conops_ref": "§2.3.2 row M2",
        "at": now(),
        "closes": (
            "route-table.yaml M2 `methods_unconfirmed: true`. The method "
            "is POST, and a POST-only selector drops nothing, because "
            "this tier offers no GET event stream to drop."
            if confirmed else
            "Nothing yet; M2's methods_unconfirmed stays true."),
        "probes": probes,
        "verdict": verdict,
        "findings": {
            "mcp_surface_exists": {
                # Keyed on the NAMED probes, not on the base path.
                # The base path 307s, so a surface-existence check
                # written against it reports "no surface" on a tier that
                # plainly has one -- which is what the first draft of
                # this script did (B-19, corrected in place).
                "answer": bool(probes["malformed_name"].get("jsonrpc")
                               or probes["well_formed_post"].get("jsonrpc")),
                "evidence": (
                    f"POST {BASE}/<name> -> HTTP "
                    f"{probes['well_formed_post']['status']} and "
                    f"{probes['malformed_name']['status']}, both carrying "
                    "a JSON-RPC envelope. An MCP dispatcher answered. "
                    "Note the malformed-name probe returns HTTP 200 while "
                    "its JSON-RPC body is an ERROR -- reading the status "
                    "alone would score it a success, so any gateway "
                    "health check on this route that asserts on status "
                    "code will report a broken MCP service as healthy. "
                    "That is worth a line in v1.6 on its own."),
                "base_path_is_not_the_probe": (
                    f"GET {BASE} (no name, redirects NOT followed) -> "
                    f"{probes['m2_base_get']['status']}. An earlier "
                    "ad-hoc probe of this same URL reported 200 with a "
                    "JSON-RPC body, and the difference was urllib "
                    "following the 307 by default -- so the 200 belonged "
                    "to a DIFFERENT URL than the one named in the "
                    "result. Recorded because it is this repository's "
                    "recurring defect in miniature: the measurement was "
                    "real, the label was wrong, and nothing in the output "
                    "said so."),
                "contrast_with_m3": (
                    f"The legacy path {LEGACY} returns "
                    f"{probes['legacy_m3_path']['status']} "
                    f"{probes['legacy_m3_path'].get('error_code')} -- a "
                    "different path with a different answer. M3's 404 was "
                    "never evidence about M2."),
            },
            "path_shape_correction": {
                "conops_says": "/ai-gateway/mcp-services/{mcp-name}",
                "server_requires": probes["malformed_name"].get(
                    "jsonrpc_error_message"),
                "why_it_matters": (
                    "The segment is a three-part Unity Catalog name, not "
                    "an opaque service slug. So M2's authorization scope "
                    "is per-UC-OBJECT. Two consequences for v1.6: the "
                    "route table's description of this path is wrong and "
                    "should be corrected; and a gateway selector over "
                    "this path is selecting over UC object names, which "
                    "means the allow-list question for M2 is 'which "
                    "catalog.schema.leaf may be invoked', not 'which "
                    "service'. Those are different allow-lists with "
                    "different owners."),
                "base_path_307": (
                    f"POST {BASE} with no name -> "
                    f"{probes['m2_base_post']['status']}. A reader "
                    "probing the base path first sees a redirect and may "
                    "conclude the route needs redirect handling. It does "
                    "not; it needs a name."),
            },
            "methods": {
                "post": {
                    "status": post.get("status"),
                    "reached_dispatcher": post_routed,
                    "jsonrpc_error_code": post.get("jsonrpc_error_code"),
                    "jsonrpc_error_message": post.get(
                        "jsonrpc_error_message"),
                    "reading": (
                        "POST routes. The -32007 'Not authorized to "
                        "invoke MCP service' is the dispatcher refusing "
                        "on AUTHORIZATION after authenticating and "
                        "routing -- which is what confirms the path and "
                        "verb. It is NOT M2 being unreachable."
                        if post_authz_refused else
                        "POST reached a dispatcher; see the body."),
                },
                "get_with_sse_accept": {
                    "status": get_sse.get("status"),
                    "content_type": get_sse.get("content_type")},
                "get_without_sse_accept": {
                    "status": get_nosse.get("status"),
                    "content_type": get_nosse.get("content_type")},
                "conclusion": (
                    "POST only. GET returns 405 on a well-formed name "
                    "BOTH with and without text/event-stream in Accept, "
                    "so the 405 is not content negotiation -- there is no "
                    "GET event stream on this tier. route-table.yaml's "
                    "`methods: [POST]` is correct and "
                    "`methods_unconfirmed` can be cleared."
                    if get_refused_both else
                    "Not POST-only; see the GET probes."),
            },
        },
        "what_this_does_not_prove": {
            "invocation": (
                "No MCP tool was invoked. The dispatcher refused on "
                "authorization (-32007) because no MCP service is "
                "registered and entitled to this principal on this tier. "
                "So M2's END TO END behaviour -- a governed tool call "
                "through Gravitee to a Unity Gateway MCP service -- "
                "remains unexercised. What is settled is the route's "
                "method and path shape, which is what the selector needs "
                "and what OD-8's second half asked."),
            "the_stream_in_general": (
                "'No GET stream on this tier' is not 'no GET stream'. A "
                "workspace with a registered MCP service may well offer "
                "one, and the MCP streamable-HTTP spec permits it. So "
                "the selector for a PRODUCTION M2 should still be "
                "reviewed against the tier it will run on. What this run "
                "removes is the need to GUESS: the question now has a "
                "method, and the method is 'probe GET on a well-formed "
                "name twice'."),
            "tool_restriction": (
                "M2 carries `tool_restriction: read-only tools only`. "
                "Nothing here tests that. It cannot be tested without an "
                "invocable service, and it is not a method question."),
        },
    }
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(ev, indent=2))

    print()
    print(f"VERDICT: {verdict}")
    print(f"Wrote {EVIDENCE.relative_to(REPO)}")
    return 0 if confirmed else 1


if __name__ == "__main__":
    sys.exit(main())
