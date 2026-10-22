#!/usr/bin/env python3
"""T-15: a model call reaches the approved endpoint THROUGH the gateway,
with the gateway supplying the upstream identity.

E1 Task 1.9 part 2 | R12a | CONOPS 2.3.2 row M1, 3.2

WHAT R12 IS AND WHICH HALF THIS TEST CAN MEASURE
------------------------------------------------
CONOPS 3.2 says an external caller holds no Databricks credential: the
gateway holds one upstream identity per consumer -- a service principal
granted only the assets that consumer may call -- and forwards with its
OAuth token. R12 asks whether that is achievable. It is two questions:

  R12a  can the gateway inject an upstream credential at all?
  R12b  can it do so without holding a long-lived secret?

Only R12a is measurable here. The injected credential is a personal
access token: long-lived, bound to a human, carrying that human's full
entitlements. So a PASS on this test says the MECHANISM works. It says
nothing about 3.2's least-privilege property, which is the part a
reviewer will care about most. That gap is scripts/30's AI-3, and this
test is written to keep it visible rather than let a green verdict imply
it away.

THE SHAPE: FOUR PHASES. THE THIRD PROVES THE CLAIM, THE FOURTH BOUNDS IT
------------------------------------------------------------------------
  Phase 1  DIRECT to the serving endpoint with the real PAT.
           Expect 200. This is the control: it establishes that the
           model answers, that the request body shape is right, and
           that the credential works. Without it, a non-200 in any
           later phase is unattributable -- a broken model, a wrong
           body and a failed injection all look identical.

  Phase 2  THROUGH the gateway with NO Authorization header at all.
           Expect 200. The caller supplied no credential, so a 200 can
           only mean the gateway supplied one. This is R12a.

  Phase 3  THROUGH the gateway with a DELIBERATELY INVALID token.
           Expect 200, and a 401/403 here would be the interesting
           failure. Phase 2 alone cannot distinguish "the gateway
           injected a credential" from "the gateway added one and the
           upstream happened to accept the caller's". The injection
           policy is written as removeHeaders-then-addHeaders precisely
           so that a caller's garbage token is DISCARDED rather than
           forwarded alongside. If phase 3 fails while phase 2 passes,
           the policy is appending where it should replace, and every
           later reading of "injection works" would be crediting the
           gateway for the caller's own credential -- B-40's silent
           negative with the sign flipped.

  Phase 4  THROUGH the gateway with NO Authorization, to a DIFFERENT
           model's invocation path. Expect NOT 200.

           Phase 4 is the one that bounds the damage, and it is the
           most important measurement in this file. The gateway is
           holding a PAT with the operator's full workspace
           entitlements and handing it to anonymous callers. The ONLY
           thing standing between an unauthenticated stranger and that
           token's full reach is the flow selector: a literal path with
           pathOperator EQUALS, naming one approved model. If that
           selector is wider than intended -- a wildcard, a
           STARTS_WITH, a second flow -- then this route is not a model
           proxy, it is an open credential-vending machine for the
           whole workspace.

           route-table.yaml M1 states the intent as "One approved model
           service per route. Not a wildcard over /serving-endpoints."
           That is a sentence in a config file. Phase 4 is whether it
           is true of the running system.

WHY A NON-200 IN PHASE 4 IS NOT AUTOMATICALLY A PASS
----------------------------------------------------
A 404 in phase 4 could mean the selector correctly declined to inject
AND the unauthenticated request was refused upstream. It could equally
mean the second model name does not exist, in which case the phase
measured a typo. So phase 4 pairs its probe with a direct call to the
same alternative path using the real PAT: if that direct call answers,
the path is real and the refusal through the gateway is attributable to
the absence of injection. If the direct call 404s, phase 4 reports
CANNOT_SEE rather than claiming a scope boundary it did not observe.

WHAT THIS TEST DOES NOT PROVE
-----------------------------
Not R12b. Not 3.2's per-consumer least privilege (AI-3).
Not T-16: no MCP route is touched, and M3's deny is a separate test.
Not T-05: the class E rate limit is present on this flow but is NOT
exercised here, and note AI-1 -- because the route replaces the
Authorization header the limit keys on, every caller shares one bucket.
Not T-07: no header-hygiene claim is made about this route.
"""
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Report, load_env  # noqa: E402
# Imported, not restated. Today alone, restating a contract instead of
# importing it produced three separate defects (AI-6), so the transport,
# the attribution rule and the edge-base resolution all come from the
# module that already owns them.
from t01_gateway_read import (  # noqa: E402
    classify_responder,
    edge_base,
    scrub,
)

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ROOT / "gravitee" / "generated" / "api-m1-ai-gateway.json"
EVIDENCE = ROOT / "evidence" / "t15-model-route.json"

# The caller's deliberately-bad credential for phase 3.
#
# This was `dapi` followed by thirty-two zeroes -- shaped like a real
# Databricks PAT so it would be "well-formed enough to be sent". The
# secret-hygiene gate flagged it immediately, and the gate was right:
# a string indistinguishable in shape from a live credential is one
# careless edit away from being one, and the scanner cannot tell a
# plausible fake from the real thing. That is the whole reason it
# refuses shapes rather than values.
#
# Two things were wrong with the original reasoning. Nothing upstream
# requires the token to LOOK like a PAT -- phase 3 only needs the
# Authorization header to be present and invalid, and an unparseable
# value tests the strip more honestly than a plausible one. And the
# comment claimed the reader needed to see "at a glance" that it was
# never real, which is exactly what a PAT-shaped string prevents.
#
# So the value now uses the vocabulary the scanner already defines
# (DECLARED_PLACEHOLDER in scripts/check_secret_hygiene.py): it asserts
# in its own text that it is not a credential. Importing that rule
# rather than inventing a second exemption is B-39 -- two scanners with
# two exemption vocabularies and one string was the original defect.
INVALID_TOKEN = "caller-supplied-not-a-real-token"

PROMPT_BODY = {
    "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
    # scripts/08 used max_tokens=16 and got finish_reason "length" with a
    # reasoning-only block and no answer text. That is recorded in
    # route-table.yaml M1.prototype_observed as a caveat carrying into
    # the route build. 128 here so the response SHAPE is captured rather
    # than truncated -- this test reads whether a call succeeded, but the
    # shape is the thing the class E schema will have to validate, and
    # leaving it uncaptured a second time would be a choice.
    "max_tokens": 128,
}

# Filled by main() before finish() reads it. The edge base is DERIVED
# rather than declared (.env has no GRAVITEE_EDGE_BASE), and a derived
# value that does not say so in the evidence is a number nobody can
# re-check later.
EDGE_PROVENANCE = ["UNSET", None]


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def call(url, bearer, timeout=120):
    """POST the prompt. `bearer` of None means SEND NO HEADER.

    The distinction between an absent Authorization header and a header
    containing the string "None" is the whole of phase 2, so this helper
    does not reuse T-01's http(), which always sets the header. A helper
    that quietly sent "Bearer None" would turn phase 2 into a second
    copy of phase 3 and the test would still pass.
    """
    headers = {"Content-Type": "application/json"}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        r = requests.post(url, headers=headers, json=PROMPT_BODY,
                          timeout=timeout)
        return r.status_code, r.text, dict(r.headers), sorted(headers)
    except requests.RequestException as e:
        return 0, json.dumps({"error_code": "LOCAL_TRANSPORT",
                              "message": str(e)}), {}, sorted(headers)


def body_shape(raw):
    """Summarise the response without dumping a model completion into
    evidence. Records the fields the class E schema will need."""
    try:
        d = json.loads(raw)
    except Exception:  # noqa: BLE001
        return {"parsed": False, "first_200_chars": scrub(raw[:200])}
    if not isinstance(d, dict):
        return {"parsed": True, "type": type(d).__name__}
    out = {"parsed": True, "top_level_keys": sorted(d.keys())}
    choices = d.get("choices")
    if isinstance(choices, list) and choices:
        c0 = choices[0] if isinstance(choices[0], dict) else {}
        out["choice_keys"] = sorted(c0.keys())
        out["finish_reason"] = c0.get("finish_reason")
        msg = c0.get("message") if isinstance(c0.get("message"), dict) else {}
        content = msg.get("content")
        out["content_type"] = type(content).__name__
        if isinstance(content, list):
            out["content_block_types"] = [
                b.get("type") for b in content if isinstance(b, dict)]
            out["content_is_array_of_typed_blocks"] = True
            out["schema_note"] = (
                "route-table.yaml M1.prototype_observed flagged this: "
                "`content` is an array of typed blocks, not a string, so "
                "the class E request/response schema must validate the "
                "array form. Confirmed here.")
        elif isinstance(content, str):
            out["content_is_array_of_typed_blocks"] = False
            out["content_chars"] = len(content)
    # Capture the failure text whenever ANY of these keys is present,
    # not only when "error_code" is.
    #
    # Hardened 2026-10-21. The first run of this test recorded, for both
    # failing phases, exactly this:
    #
    #   {"parsed": true, "top_level_keys": ["http_status_code","message"]}
    #
    # The body was {"message":"Unable to apply headers transformation",
    # "http_status_code":500} -- the single sentence that identified the
    # failing policy. This function listed the KEY "message" and threw
    # away its VALUE, because the guard asked for "error_code" and
    # Gravitee's own errors use "http_status_code". The evidence file
    # recorded the shape of the diagnosis and not the diagnosis, and the
    # 500 had to be reproduced by hand to learn anything from it.
    #
    # An evidence file that proves a failure happened but cannot say
    # what failed is a silent negative wearing a timestamp.
    for k in ("error_code", "http_status_code", "message", "error",
              "error_description", "detail"):
        if k in d:
            out[k] = scrub(str(d.get(k))[:400])
    if "choices" not in d and not any(
            k in out for k in ("message", "error", "detail")):
        # Not a completion and nothing recognised as an error either:
        # keep a bounded verbatim prefix rather than only the key names.
        # Guarded on "choices" so a successful model response is never
        # transcribed into the evidence file.
        out["unrecognised_body_prefix"] = scrub(raw[:400])
    return out


def load_route():
    """Read the approved model and the paths OUT of the generated
    artifact, so this test cannot drift from what was imported.

    A test carrying its own copy of the model name would keep passing
    after the generator changed it, and would be testing a path nobody
    deployed."""
    if not GENERATED.exists():
        sys.exit(f"Missing {GENERATED}. Run "
                 "scripts/30_gen_gravitee_ai_route.py, then "
                 "scripts/05_import_gravitee_api.py --definition "
                 "gravitee/generated/api-m1-ai-gateway.json")
    doc = json.loads(GENERATED.read_text())
    api = doc["api"]
    gen = doc.get("_generated") or {}
    ctx = api["listeners"][0]["paths"][0]["path"]
    target = api["endpointGroups"][0]["endpoints"][0]["configuration"]["target"]
    m1 = next((f for f in api["flows"] if f["name"].startswith("M1")), None)
    if m1 is None:
        sys.exit("No M1 flow in the generated definition.")
    sel = m1["selectors"][0]
    return {
        "context_path": ctx,
        "target": target,
        "model_path": sel["path"],
        "path_operator": sel.get("pathOperator"),
        "methods": sel.get("methods"),
        "upstream_host": gen.get("upstream_host"),
        "known_incomplete": [i["id"] for i in doc.get("_known_incomplete", [])],
    }


def pick_alternative_model(route, host, token):
    """Find a REAL second serving endpoint to aim phase 4 at.

    Listed from the workspace rather than guessed. A guessed name that
    does not exist turns phase 4 into a measurement of the typo: the
    gateway would 404 for the wrong reason and the scope boundary would
    be scored as proven."""
    approved = route["model_path"].split("/")[2]
    try:
        r = requests.get(f"https://{host}/api/2.0/serving-endpoints",
                         headers={"Authorization": f"Bearer {token}"},
                         timeout=60)
    except requests.RequestException as e:
        return None, {"listed": False, "error": str(e)}
    if r.status_code != 200:
        return None, {"listed": False, "status": r.status_code}
    names = [e.get("name") for e in (r.json().get("endpoints") or [])
             if e.get("name")]
    others = [n for n in names if n != approved]
    return (others[0] if others else None), {
        "listed": True,
        "endpoint_count": len(names),
        "approved_model": approved,
        "alternative_chosen": others[0] if others else None,
        "why": ("Phase 4 needs a path that EXISTS upstream but is NOT the "
                "approved model, so a refusal through the gateway is "
                "attributable to the selector rather than to the path "
                "being absent."),
    }


def main():
    load_env()
    report = Report()
    route = load_route()
    host = (os.environ.get("DATABRICKS_HOST", "")
            .replace("https://", "").replace("http://", ""))
    token = os.environ.get("DATABRICKS_TOKEN", "")
    if not host or not token:
        sys.exit("DATABRICKS_HOST and DATABRICKS_TOKEN must be set.")

    # edge_base() returns (base, provenance, note) -- three values, not a
    # string. Unpacked rather than indexed so a future change to the
    # tuple fails loudly here instead of silently building a URL out of
    # the provenance label.
    edge, edge_provenance, edge_note = edge_base()
    EDGE_PROVENANCE[0], EDGE_PROVENANCE[1] = edge_provenance, edge_note
    if edge_note:
        print(f"[edge base] {edge_provenance}: {edge_note}\n")
    gw_url = f"{edge}{route['context_path']}{route['model_path']}"
    direct_url = f"https://{host}{route['model_path']}"

    print("=" * 70)
    print("T-15: model call through the gateway with injected identity")
    print("=" * 70)
    print(f"approved model path : {route['model_path']}")
    print(f"selector            : {route['path_operator']} "
          f"{route['methods']}")
    print(f"direct              : {direct_url}")
    print(f"through the gateway : {gw_url}")
    print()

    phases = {}

    # --- Phase 1: the control -----------------------------------------
    st, raw, hdr, sent = call(direct_url, token)
    phases["1_direct_control"] = {
        "url": direct_url, "status": st, "headers_sent": sent,
        "shape": body_shape(raw),
        "purpose": ("Establishes that the model answers, the body shape is "
                    "right and the credential works. Every later phase is "
                    "unattributable without this."),
    }
    print(f"phase 1  DIRECT, real PAT                  -> {st}")
    if st != 200:
        phases["1_direct_control"]["consequence"] = (
            "The control FAILED, so nothing downstream is attributable. A "
            "non-200 through the gateway in phases 2-4 would be read as "
            "injection failing when the model itself is not answering. "
            "This run reports CANNOT_SEE rather than a verdict on R12a.")
        verdict = "CANNOT_SEE_CONTROL_FAILED"
        report.record(
            "T-15", "Model call through the gateway with injected identity",
            "direct control 200, then 200 through the gateway with no "
            "caller credential",
            f"direct control returned {st} -- no control, no verdict",
            False, "evidence/t15-model-route.json")
        finish(report, route, phases, verdict, gw_url, direct_url)
        return 1

    # --- Phase 2: R12a ------------------------------------------------
    st2, raw2, hdr2, sent2 = call(gw_url, None)
    who2 = classify_responder(raw2, hdr2, status=st2)
    phases["2_gateway_no_credential"] = {
        "url": gw_url, "status": st2, "headers_sent": sent2,
        "authorization_header_sent": False,
        "responder": who2, "shape": body_shape(raw2),
        "purpose": ("The caller supplied NO credential. A 200 can only "
                    "mean the gateway supplied one. This is R12a."),
    }
    print(f"phase 2  GATEWAY, no Authorization header  -> {st2}")

    # --- Phase 3: replace, not append ---------------------------------
    st3, raw3, hdr3, sent3 = call(gw_url, INVALID_TOKEN)
    who3 = classify_responder(raw3, hdr3, status=st3)
    phases["3_gateway_invalid_caller_token"] = {
        "url": gw_url, "status": st3, "headers_sent": sent3,
        "caller_token": "deliberately invalid, never a real credential",
        "responder": who3, "shape": body_shape(raw3),
        "purpose": ("Distinguishes REPLACE from APPEND. If this refuses "
                    "while phase 2 succeeds, the policy is leaving the "
                    "caller's header in place and a later 200 would be "
                    "the caller's own credential doing the work -- B-40's "
                    "silent negative with the sign flipped."),
    }
    print(f"phase 3  GATEWAY, invalid caller token     -> {st3}")

    # --- Phase 4: the scope boundary ----------------------------------
    alt, listing = pick_alternative_model(route, host, token)
    p4 = {"endpoint_listing": listing,
          "purpose": ("The gateway holds a PAT with full workspace "
                      "entitlements and gives it to anonymous callers. "
                      "The flow selector is the only thing scoping that. "
                      "This phase is whether route-table.yaml's 'not a "
                      "wildcard over /serving-endpoints' is true of the "
                      "RUNNING system.")}
    if not alt:
        p4["verdict"] = "CANNOT_SEE_NO_ALTERNATIVE_ENDPOINT"
        p4["why"] = ("Could not list a second serving endpoint, so there "
                     "is no real non-approved path to aim at. Guessing a "
                     "name would measure the guess: a 404 from a "
                     "non-existent endpoint is indistinguishable from the "
                     "selector declining to inject, and would have been "
                     "scored as the scope boundary holding.")
        print("phase 4  SCOPE                             -> CANNOT_SEE "
              "(no alternative endpoint to aim at)")
    else:
        alt_path = f"/serving-endpoints/{alt}/invocations"
        alt_gw = f"{edge}{route['context_path']}{alt_path}"
        alt_direct = f"https://{host}{alt_path}"
        sa, ra, ha, _ = call(alt_gw, None)
        sd, rd, _hd, _ = call(alt_direct, token)
        whoa = classify_responder(ra, ha, status=sa)
        p4.update({
            "alternative_model": alt,
            "through_gateway_no_credential": {
                "url": alt_gw, "status": sa, "responder": whoa,
                "shape": body_shape(ra)},
            "direct_with_real_pat": {
                "url": alt_direct, "status": sd,
                "note": ("Proves the alternative path is REAL. Without "
                         "this, a refusal through the gateway could be a "
                         "non-existent endpoint rather than a scope "
                         "boundary.")},
        })
        print(f"phase 4  GATEWAY, other model, no auth     -> {sa}"
              f"   (same path direct with PAT -> {sd})")
        if sd != 200:
            p4["verdict"] = "CANNOT_SEE_ALTERNATIVE_PATH_UNPROVEN"
            p4["why"] = (
                f"The alternative path returned {sd} called DIRECTLY with "
                "a real credential, so it is not demonstrably reachable. "
                f"The {sa} through the gateway therefore cannot be "
                "attributed to the selector declining to inject.")
        elif sa == 200:
            p4["verdict"] = "SCOPE_BREACH_INJECTION_IS_NOT_LIMITED_TO_THE_APPROVED_MODEL"
            p4["severity"] = "HIGH"
            p4["why"] = (
                "An unauthenticated caller reached a model OTHER than the "
                "approved one through this route, which means the gateway "
                "injected its credential for a path the route table does "
                "not authorise. With a full-entitlement PAT behind it, "
                "this route is a credential-vending machine rather than a "
                "model proxy.")
        else:
            p4["verdict"] = "SCOPE_HELD_NO_INJECTION_OUTSIDE_THE_APPROVED_PATH"
            p4["why"] = (
                f"The alternative path answers 200 directly with a real "
                f"credential but returned {sa} through the gateway with "
                "none, so the gateway did not inject for it. The selector "
                "is doing the scoping the route table claims.")
    phases["4_scope_boundary"] = p4

    # --- The verdict ---------------------------------------------------
    scope = p4.get("verdict", "")
    if st2 == 200 and st3 == 200:
        if scope.startswith("SCOPE_BREACH"):
            verdict = "R12A_WORKS_BUT_THE_SCOPE_IS_BROKEN"
        elif scope.startswith("SCOPE_HELD"):
            verdict = "R12A_CONFIRMED_INJECTION_REPLACES_AND_IS_SCOPED"
        else:
            verdict = "R12A_CONFIRMED_SCOPE_UNOBSERVED"
    elif st2 == 200 and st3 != 200:
        verdict = "INJECTION_APPENDS_INSTEAD_OF_REPLACING"
    elif st2 != 200 and st3 == 200:
        verdict = "NOT_INJECTION_THE_CALLERS_TOKEN_IS_BEING_FORWARDED"
    elif who2.get("responder") == "EDGE_NO_ROUTE_MATCHED":
        verdict = "CANNOT_SEE_NO_EDGE_ROUTE_FOR_THE_MODEL_PATH"
    else:
        verdict = "INJECTION_NOT_DEMONSTRATED"

    passed = verdict == "R12A_CONFIRMED_INJECTION_REPLACES_AND_IS_SCOPED"
    report.record(
        "T-15", "Model call through the gateway with injected identity",
        "200 through the gateway with no caller credential and with an "
        "invalid one, and NOT 200 for a non-approved model path",
        verdict, passed, "evidence/t15-model-route.json")
    finish(report, route, phases, verdict, gw_url, direct_url)
    return 0 if passed else 1


def finish(report, route, phases, verdict, gw_url, direct_url):
    ev = {
        "test": "T-15",
        "epic_task": "E1 Task 1.9 part 2",
        "risk": "R12a",
        "at": now(),
        "route": route,
        "urls": {"gateway": gw_url, "direct": direct_url,
                 "edge_base_provenance": EDGE_PROVENANCE[0],
                 "edge_base_note": EDGE_PROVENANCE[1]},
        "phases": phases,
        "verdict": verdict,
        "what_a_pass_does_not_mean": {
            "r12b": ("Not measured. The gateway holds a long-lived secret "
                     "to do this. R12b asks whether it can avoid that, and "
                     "nothing here addresses it."),
            "conops_3_2": (
                "NOT demonstrated. 3.2 specifies a per-consumer service "
                "principal granted only that consumer's assets. This "
                "injects a personal access token: long-lived, bound to a "
                "human, carrying full entitlements. The mechanism is the "
                "same; the security property is absent. scripts/30 AI-3."),
            "t05": ("The class E rate limit is on this flow and is not "
                    "exercised. Note AI-1: the route REPLACES the "
                    "Authorization header the limit keys on, so every "
                    "caller shares one bucket -- the opposite of the "
                    "per-consumer limit 2.3 describes."),
            "t07": "No header-hygiene claim is made about this route.",
            "t16": "No MCP path is touched. M3's deny is a separate test.",
        },
        "carried_from_the_generator": route.get("known_incomplete"),
    }
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(ev, indent=2))
    report.write(ROOT / "evidence" / "t15-report.json")
    print()
    print(f"VERDICT: {verdict}")
    print(report.summary())
    print(f"Wrote {EVIDENCE.relative_to(ROOT)}")


if __name__ == "__main__":
    sys.exit(main())
