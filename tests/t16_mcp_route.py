#!/usr/bin/env python3
"""T-16 (negative half): legacy managed MCP is unreachable, and so is
everything else the route table does not name.

E1 Task 1.9 part 4 | AC1, AC2, AC5 | CONOPS 2.3.2 rows M3 and X, 3.1.2 | OD-8

REWRITTEN 2026-10-21 after its first run. The first version measured one
path and found that M3's deny did not fire; chasing that produced a much
larger finding, and this version measures both. The old docstring's
reasoning is kept below wherever it still holds, and marked where it does
not (B-19).

WHAT M3 IS AND WHY IT IS A DENY
-------------------------------
route-table.yaml M3 covers `/api/2.0/mcp/*` -- Databricks' LEGACY
managed MCP endpoints -- and sets `exposed: false` with
`enforcement: explicit_deny_flow`. The reason, carried into the
generated artifact because an auditor reads the deployed definition
rather than the YAML two directories away:

    Databricks documents that these bypass Unity AI Gateway grants,
    policies and guardrails, and their calls do not appear in the
    tracing tables. A route that is invisible to the audit path cannot
    satisfy AC5 on any consumer.

An OMITTED route and a REFUSED route are the same absence in a deployed
gateway. Only one of them is a decision. M3 exists so the deployed
definition says which.

WHAT THE FIRST RUN FOUND, AND WHY IT CHANGED THIS TEST'S SUBJECT
----------------------------------------------------------------
The first run returned DENY_DOES_NOT_FIRE_THE_EDGE_FORWARDED_THE_REQUEST.
M3's deny was `policy-request-validation` with an empty `rules` list and
a comment claiming that refused everything reaching the flow. It refused
nothing: the policy validates each rule in turn, so with no rules there
is nothing to fail. The flow loaded, passed the request, and the gateway
forwarded it. AI-4 predicted the failure and predicted the wrong
mechanism -- it did not need to fail to load.

Diagnosing that exposed the real defect, which was never about M3.
Gravitee matches a context path as a PREFIX and FORWARDS any path that
matches no flow selector. This API's endpoint target is the workspace
ROOT, because M1's protocol path starts there. So with a valid caller
token, before any fix:

    /ai-gateway-demo/api/2.0/serving-endpoints  -> 200
    /ai-gateway-demo/api/2.0/clusters/list      -> 200
    /ai-gateway-demo/api/2.0/token/list         -> 200

The route was an open reverse proxy to the whole Databricks workspace
REST API. Worse, it was reachable by a caller holding NO credential,
because this route strips the caller's Authorization and injects the
gateway's -- R12a's mechanism is what made the hole worth using. §2.3.2's
route table turned out to be a documentation allow-list that nothing
enforced (B-48, AI-7, AI-8).

So this test now has two subjects, and the second one is bigger:

  (a) Does M3's deny fire, and can the refusal be attributed to it?
  (b) Is every path the route table does not name refused?

TWO CORRECTIONS THE FIRST RUN OF THIS VERSION FORCED (B-19)
-----------------------------------------------------------
**The open proxy forwarded the CALLER's credential, not the gateway's.**
This docstring said unclaimed paths were "reachable by a caller holding
NO credential, because this route strips the caller's Authorization and
injects the gateway's". Measured, and wrong. The strip and inject
policies live inside M1's flow, whose selector is EQUALS on the single
model path, so an unclaimed path never reaches them. Anonymous callers
got 401 from Databricks; only callers presenting their own token got 200,
with their own entitlements. So this was a bypass of the route
restriction, not a privilege escalation -- nobody reached anything
through the edge they could not reach directly. It is still an AC1/AC2
defect, because §3.1.2 reads as though the edge constrains which paths a
consumer may use. And it is one selector edit from being an escalation:
widen M1's EQUALS to a prefix, or lift the injection into a common flow,
and the gateway's own credential starts reaching unclaimed paths.
Consequence for this test: the unclaimed paths are probed BOTH ways, and
the control in phase 3 needs the token-bearing probe to move.

**Array position is not evaluation order.** This test was built on
scripts/30's claim that the allow-list runs last because it is emitted
last. It is emitted last and it runs FIRST. Gravitee orders flows from
the most generic selector to the most specific, and `/` STARTS_WITH is
the most generic there is. Measured: with the array [M1, M3,
X-terminal-allow-list], the legacy MCP path is answered by the
allow-list; disable that one flow and change nothing else and the same
path returns M3's marker. So M3's mock works and is simply never
reached, and the CONOPS reason does not reach the caller (AI-9, accepted
-- the stated requirement is that the reason is in the ARTIFACT). The
consequence for this test is that M3 can only be observed with the
allow-list disabled, which is what phase 3 does.

WHY ATTRIBUTION NEEDS THREE STATES NOW, NOT TWO
-----------------------------------------------
B-40's rule still governs: a negative assertion needs a same-path
positive control. But the fix changed what that control has to be.

The old plan was "disable the deny, watch the same URL be forwarded".
That no longer works, and the reason is worth stating because it is the
cost of defence in depth. Two policies can now refuse the same path, so
the test separates them by VOICE rather than by status code. M3 is a
`mock` policy carrying a marker string read out of the generated
artifact; the allow-list is a `resource-filtering` policy with its own
wording. Three states:

  as shipped    both enabled        MCP path -> 403 from the ALLOW-LIST
                                    unclaimed paths -> 403, both ways
  control A     allow-list OFF      MCP path -> 403 WITH M3's marker
                                    unclaimed + token -> 2xx
  control B     both OFF            MCP path -> FORWARDED

Control A is one state doing two jobs, and that is not an economy -- it
is the same single variable answering both questions, which is stronger
than two separate edits. Removing the allow-list and nothing else makes
M3's marker appear (so M3 fires, and the as-shipped 403 was the
allow-list's) AND brings the unclaimed paths back (so the allow-list is
what was closing them, rather than the endpoint target's shape or
anything else).

Control B proves the path reaches the edge, matches the context path and
would be proxied, so none of the refusals above was a dead route, an
unmatched path or a plan problem. Neither control alone is enough: A
without B cannot rule out that the path was never routable, and B without
A cannot say which of the two controls answered.

NOTE on what control A does NOT show. With the allow-list off, M3's
marker appearing proves M3 fires, but nothing here proves M3 would be
reached if the allow-list were ever reordered rather than removed -- the
measurement says the generic selector wins, and that is a platform
behaviour this test observes rather than controls.

CONTROL B DELIBERATELY RE-OPENS A KNOWN HOLE
--------------------------------------------
For a few seconds, with both flows disabled, this test puts the gateway
back in the state described above -- unclaimed paths reaching the
workspace REST API as the gateway's injected identity. That is the only
honest way to demonstrate that the allow-list is what closes them,
rather than asserting it; a perimeter test that never observes the
perimeter absent is measuring its own expectations.

It is done because this is a local prototype gateway bound to localhost
on a Free Edition workspace, the window is a single sequence of probes,
and the restore is in a `finally` with the snapshot written to disk
BEFORE anything is touched. Pass `--no-reopen` to skip control B; the
run then reports CANNOT_SEE for that half rather than quietly claiming
the stronger result. The choice is recorded in the evidence either way.
It should not be done this way against anything shared.

  Phase 0  DIRECT with a real PAT. Does the subject exist upstream at
           all? Governs the scope of every verdict below.
  Phase 1  M3's path through the edge, twice: no credential AND a valid
           one. Both, because a deny that only refuses anonymous callers
           is not a deny -- the caller this control exists to stop is
           one who HAS a workspace token.
  Phase 2  The B-48 regression. Three workspace REST paths no flow
           claims, each measured at 200 before the fix, each probed
           anonymously AND with a valid token. None may answer 2xx by
           either route and each refusal must be a named edge policy.
  Phase 3  Control A. Allow-list disabled, M3 left in place. M3's marker
           must appear on the MCP path and the unclaimed paths must come
           back to life for a token-bearing caller.
  Phase 4  Control B. Both disabled. M3's path must be FORWARDED.
  Phase 5  Both restored. Without it, phases 1-4 show the route can be
           broken, not that the controls work and are reversible.
           T-03's lesson.

WHAT THIS TEST DOES NOT PROVE
-----------------------------
Not that the ESTATE is closed. The allow-list exists on this one API.
scripts/29's sharing and storage APIs still forward unmatched paths and
are confined only because their endpoint target carries a deep base
path, so a stray path appends and the upstream 404s -- confinement by
string concatenation, not a control. Nothing here tests them. B-48 stays
open until they carry an equivalent and a test asserts it.

Not authorisation. resource-filtering decides on the request PATH. It
says nothing about who the caller is, and this route's plan is KEY_LESS
(AI-1), so a 403 here must never be cited as an unentitled caller being
refused.

Not M2, and so not OD-8's other half. M2 is ungenerated (AI-5): §2.3.2
gives its method as "MCP", a protocol rather than an HTTP method, and a
POST-only selector would silently drop the streamable-HTTP event stream.

Not AC5's audit trail. Nothing here reads a tracing table.
Not T-15. No model path and no credential injection is touched -- but
T-15 MUST be re-run after this, because the allow-list is now in the
path of the model route it measures.
"""
import argparse
import copy
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Report, load_env  # noqa: E402
from t01_gateway_read import classify_responder, edge_base, scrub  # noqa: E402
# The management-plane helpers come from T-03, which already owns them.
# Restating a contract instead of importing it produced four separate
# defects earlier today (AI-6), and a divergent copy of the DEPLOY step
# would be the worst one to have: a test that edited the management
# plane and measured the previous deployment would pass while proving
# nothing.
from t03_ip_refusal import (  # noqa: E402
    DEPLOY_SETTLE_SECONDS,
    deploy,
    find_api,
    mgmt,
    put_api,
)

ROOT = Path(__file__).resolve().parent.parent
GENERATED = ROOT / "gravitee" / "generated" / "api-m1-ai-gateway.json"
EVIDENCE = ROOT / "evidence" / "t16-mcp-deny.json"
# TWO snapshots, and the split is not tidiness. Found 2026-10-21 by
# check_secret_hygiene, which failed with "Databricks personal access
# token found in evidence/t16-api-snapshot-before.json".
#
# The first version of this test wrote ONE snapshot, to evidence/. The
# live API carries the filled `databricks_upstream_token` property --
# scripts/05 PUTs the real credential onto the server, and find_api reads
# the server's body back -- so the restore source was a verbatim copy of
# a working credential, sitting in the directory this repo publishes as
# evidence. §3.6 says no credential is written to a committed artifact,
# and nothing in the test was aware it had just written one.
#
# Worth naming the shape: the snapshot exists so a crash cannot leave the
# perimeter disabled. It is a SAFETY mechanism, and it created a
# disclosure. The gate caught it because it scans the working tree rather
# than the index -- the file was untracked, so a git-only check would
# have reported clean, which is this repo's silent negative in its most
# ordinary clothes.
#
# So: the redacted copy is the evidence, and the full-fidelity copy goes
# to _secrets/, which is gitignored. Neither is the restore source during
# a run; that is the in-memory body, which never loses the value.
SNAPSHOT = ROOT / "evidence" / "t16-api-snapshot-before.json"
SNAPSHOT_FULL = ROOT / "_secrets" / "t16-api-snapshot-before.json"

# One concrete legacy path under M3's selector. scripts/08 probed this
# exact URL directly and recorded 404 ENDPOINT_NOT_FOUND.
LEGACY_MCP_PATH = "/api/2.0/mcp/servers"

M3_FLOW_PREFIX = "M3"

# Paths no flow selector claims. Every one of these returned 200 through
# the edge on 2026-10-21 before the terminal allow-list existed, which is
# why these three and not an arbitrary sample: the test asserts the
# specific exposures that were measured, so a regression reproduces the
# original finding rather than something adjacent to it.
#
# This list is illustrative, not exhaustive, and the distinction matters
# for how a pass is read. The Databricks REST API has hundreds of paths;
# three of them passing is not proof the other hundreds are closed. What
# makes the result general is the SHAPE of the control -- a whitelist
# refuses by default, so an unlisted path is refused whether or not this
# test thought to name it. These three are here to prove the whitelist is
# installed and effective, not to enumerate the surface.
UNCLAIMED_PATHS = [
    ("/api/2.0/token/list",
     "Personal access token metadata. The worst of the three: it "
     "enumerates credentials, and it answered 200 through the edge to a "
     "caller holding none of its own."),
    ("/api/2.0/clusters/list",
     "Compute inventory. Nothing in channel E-3 exposes compute; this "
     "path was reachable purely because no selector claimed it."),
    ("/api/2.0/serving-endpoints",
     "The model INDEX, as opposed to M1's single approved invocation "
     "path. route-table M1's exposure_scope says 'One approved model "
     "service per route. Not a wildcard over /serving-endpoints.' This "
     "path is how that scope was escaped without a wildcard."),
]


def now():
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def probe(url, bearer=None, timeout=45):
    """GET the URL. `bearer` of None means SEND NO HEADER.

    Not reusing T-01's http(): it always sets Authorization, and the
    difference between an absent header and a header reading
    "Bearer None" is half of phase 1."""
    headers = {}
    if bearer is not None:
        headers["Authorization"] = f"Bearer {bearer}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        return r.status_code, r.text, dict(r.headers)
    except requests.RequestException as e:
        return 0, json.dumps({"error_code": "LOCAL_TRANSPORT",
                              "message": str(e)}), {}


def observe(url, bearer, label, why, marker=None):
    """Probe and classify. `marker` is M3's attribution string.

    The marker is matched against the FULL body, before the truncation
    that scrub+slice applies for the evidence file. A 400-character
    window is enough today and would silently stop finding the marker the
    moment the mock body grew -- an attribution that fails by length is
    the kind of defect that reads as the control not working."""
    st, raw, hdr = probe(url, bearer)
    who = classify_responder(raw, hdr, status=st)
    out = {
        "label": label,
        "url": url,
        "authorization_header_sent": bearer is not None,
        "status": st,
        "responder": who,
        "body": scrub(raw[:400]),
        "why_probed": why,
    }
    if marker:
        out["m3_marker_present"] = marker in (raw or "")
        # The header copy is recorded separately rather than OR'd into one
        # flag: if the body marker is gone and the header's is not, the
        # response sanitizer is eating the body, which is a different
        # problem from the deny not firing.
        out["m3_marker_header"] = (hdr or {}).get("X-AWOZ-Refused-By")
    return out


def read_m3_marker(gen):
    """Read M3's attribution marker out of the generated artifact.

    Read, not restated. The marker is the entire basis on which this test
    distinguishes M3's refusal from the terminal allow-list's, and a copy
    of it here would be one generator edit away from a test that reports
    'M3 did not fire' on a working deny. B-39, which has cost four
    defects in this repo today.

    Absent marker is a hard stop, not a fallback: a test that silently
    stopped checking the marker would score the allow-list's refusal as
    M3's, which is the exact confusion it exists to prevent."""
    for flow in gen["api"].get("flows", []):
        if not flow.get("name", "").startswith(M3_FLOW_PREFIX):
            continue
        for step in flow.get("request", []):
            marker = (step.get("_rationale") or {}).get("attribution_marker")
            if marker:
                return marker
    sys.exit(
        "No attribution_marker on any M3 request step in "
        f"{GENERATED.name}. This test cannot tell M3's refusal from the "
        "terminal allow-list's without it, and guessing would mean "
        "crediting one control with another's work. Regenerate with "
        "scripts/30_gen_gravitee_ai_route.py.")


def find_allow_list_flows(body):
    """Name the allow-list flows by what they DO, not by what they are
    called.

    A name match would be one rename away from a control that disables
    nothing and reports success. Identified instead by carrying a
    resource-filtering step with a non-empty whitelist, which is the
    functional definition of the thing being toggled."""
    names = []
    for flow in body.get("flows", []):
        for step in flow.get("request", []):
            if step.get("policy") != "resource-filtering":
                continue
            if (step.get("configuration") or {}).get("whitelist"):
                names.append(flow.get("name"))
                break
    return names


def set_flows_enabled(body, names, enabled):
    """Toggle exactly the named flows. Returns (new_body, touched).

    Operates on a deep copy so the snapshot taken for the restore path
    cannot be mutated by accident -- a restore that writes back an
    already-modified object would leave the perimeter off and report
    success."""
    out = copy.deepcopy(body)
    touched = []
    for flow in out.get("flows", []):
        if flow.get("name") in names:
            flow["enabled"] = enabled
            touched.append(flow["name"])
    return out, touched


def write_snapshots(body):
    """Write the redacted snapshot to evidence/ and the full one to
    _secrets/. Returns the list of property keys that were redacted.

    The redacted copy keeps the property KEY and the name of the .env
    variable that refills it, because a restore source that silently
    drops a credential is its own trap: PUT it back and the route runs
    with an empty injected Authorization, which fails -- and fails
    looking exactly like the gateway being unable to inject at all, i.e.
    like R12a being impossible (B-44, and the same confusion scripts/05's
    property guard exists to prevent). The file says what it is missing
    and how to put it back."""
    redacted = copy.deepcopy(body)
    keys = []
    for prop in redacted.get("properties") or []:
        if prop.get("value"):
            keys.append(prop.get("key"))
            prop["value"] = ""
            prop["_redacted_by"] = "tests/t16_mcp_route.py"
            prop["_redacted_because"] = (
                "The live API carries the filled credential. Writing it "
                "to evidence/ would put a working Databricks PAT in a "
                "committed artifact (§3.6). check_secret_hygiene caught "
                "exactly this on 2026-10-21.")
            prop["_refill_with"] = (
                "python3 scripts/05_import_gravitee_api.py --definition "
                "gravitee/generated/api-m1-ai-gateway.json, which fills "
                "this property from DATABRICKS_TOKEN and CONFIRMS it "
                "landed on the server before reporting success.")
    SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT.write_text(json.dumps(redacted, indent=2))
    SNAPSHOT_FULL.parent.mkdir(parents=True, exist_ok=True)
    SNAPSHOT_FULL.write_text(json.dumps(body, indent=2))
    try:
        SNAPSHOT_FULL.chmod(0o600)
    except OSError:
        pass
    return keys


def attribute(obs):
    """Which control refused this, if any?

    Returns (ok, control, basis). `ok` means an edge policy refused, by
    positive identification. Deliberately narrow: classify_responder's
    `EDGE_POLICY_OR_PROXY_ERROR` is its CATCH-ALL -- B-46 is the record
    of that label being accepted as proof once already -- and a proxy
    failure wears it too, so it is never admitted here as the basis for
    a pass."""
    who = obs["responder"]
    st = obs["status"]
    if st == 0:
        return False, None, "no response: local transport error"
    if 200 <= st < 300:
        return False, None, (
            f"{st}. Not a refusal at all -- the request was served.")
    if who.get("vocabulary") == "UPSTREAM":
        return False, None, (
            f"{st} in the UPSTREAM's vocabulary, so this was forwarded "
            "and refused by Databricks, not by the edge. B-44: an edge "
            "refusal and an upstream refusal forwarded through the edge "
            "are the same status code with opposite remedies.")
    if who.get("responder") == "EDGE_NO_ROUTE_MATCHED":
        return False, None, "no route matched; nothing was evaluated"
    if who.get("responder") == "EDGE_IP_FILTERING_POLICY":
        return False, None, (
            "refused by the ip-filtering policy, which is a DIFFERENT "
            "control -- scoring it here would credit M3 with another "
            "policy's refusal")
    if obs.get("m3_marker_present"):
        return True, "M3_EXPLICIT_DENY", (
            f"{st} carrying M3's attribution marker in the body. The "
            "mock policy generated from route-table row M3 answered, so "
            "the refusal is the DECISION, with its CONOPS reason in the "
            "response the caller receives.")
    if who.get("responder") == "EDGE_RESOURCE_FILTERING_POLICY":
        return True, "TERMINAL_ALLOW_LIST", (
            f"{st} from Gravitee's resource-filtering policy, by name "
            "and in its own words. The path is not on the allow-list. "
            "This is the perimeter working; it carries no reason, so it "
            "is not M3's deny.")
    return False, None, (
        f"{st} round-tripped the edge but no named policy claims it "
        f"(responder={who.get('responder')}, "
        f"vocabulary={who.get('vocabulary')}). Recorded as "
        "unattributed rather than assigned to the nearest control: "
        "`EDGE_POLICY_OR_PROXY_ERROR` is a catch-all a proxy failure "
        "also wears, and B-46 exists because it was once accepted as "
        "proof.")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--no-reopen", action="store_true",
        help=("Skip control B, which briefly disables the terminal "
              "allow-list and so re-opens the workspace REST API through "
              "the edge. The run then reports CANNOT_SEE for that half "
              "rather than claiming the stronger result."))
    args = ap.parse_args()

    load_env()
    report = Report()
    host = (os.environ.get("DATABRICKS_HOST", "")
            .replace("https://", "").replace("http://", ""))
    token = os.environ.get("DATABRICKS_TOKEN", "")
    if not host or not token:
        sys.exit("DATABRICKS_HOST and DATABRICKS_TOKEN must be set.")

    if not GENERATED.exists():
        sys.exit(f"Missing {GENERATED}. Run scripts/30 then scripts/05.")
    gen = json.loads(GENERATED.read_text())
    ctx = gen["api"]["listeners"][0]["paths"][0]["path"]
    marker = read_m3_marker(gen)

    edge, edge_prov, edge_note = edge_base()
    if edge_note:
        print(f"[edge base] {edge_prov}: {edge_note}\n")

    gw_url = f"{edge}{ctx}{LEGACY_MCP_PATH}"
    direct_url = f"https://{host}{LEGACY_MCP_PATH}"

    print("=" * 70)
    print("T-16: legacy MCP denied, and unclaimed paths refused (B-48)")
    print("=" * 70)
    print(f"subject through the edge : {gw_url}")
    print(f"same path direct         : {direct_url}")
    print(f"M3 attribution marker    : {marker}  (read from the artifact)")
    print(f"unclaimed paths probed   : {len(UNCLAIMED_PATHS)}")
    print()

    session, base = mgmt()
    # find_api returns (id, FULL BODY) -- not (id, name). Using the body
    # it already fetched rather than issuing a second GET, because two
    # reads of a live object can disagree, and the one written to the
    # snapshot must be the one the restore puts back.
    api_id, before = find_api(session, base, ctx)
    if not api_id:
        sys.exit(f"No live API found at context path {ctx}. Import it "
                 "first with scripts/05.")
    api_name = before.get("name")
    allow_names = find_allow_list_flows(before)
    print(f"subject API: {api_name} ({api_id})")
    print(f"allow-list flows on the live API: {allow_names or 'NONE'}")
    if not allow_names:
        print("  WARNING: no resource-filtering whitelist is deployed. "
              "Phase 2 will measure the OPEN state.")
    print()

    # Written BEFORE anything is touched. A test that mutates a live
    # gateway and keeps the only copy of the original in memory has one
    # crash between the estate and a silently disabled perimeter.
    redacted_keys = write_snapshots(before)
    print(f"snapshot (redacted) -> {SNAPSHOT.relative_to(ROOT)}")
    print(f"snapshot (full)     -> {SNAPSHOT_FULL.relative_to(ROOT)}  "
          f"[gitignored]")
    if redacted_keys:
        print(f"  redacted {len(redacted_keys)} credential propert"
              f"{'y' if len(redacted_keys) == 1 else 'ies'} from the "
              f"evidence copy: {', '.join(redacted_keys)}")

    phases = {}
    restored = False
    try:
        # --- Phase 0: does the subject exist upstream? ----------------
        p0 = observe(direct_url, token, "direct_with_real_pat",
                     "Establishes whether the legacy MCP surface exists "
                     "on this workspace at all. Governs the scope of "
                     "everything below.")
        exists_upstream = p0["status"] == 200
        p0["subject_exists_upstream"] = exists_upstream
        p0["consequence"] = (
            "The subject ANSWERS directly, so the deny is closing a real, "
            "reachable exposure and a 403 at the edge is a security "
            "result."
            if exists_upstream else
            "The subject does NOT answer directly even with a full "
            "workspace credential, so there is no reachable legacy MCP "
            "surface on this workspace to expose. A 403 at the edge "
            "proves the POLICY FIRES but does not prove an exposure was "
            "closed, and a BROKEN deny would forward to a non-existent "
            "path and return a 404, which is also refusal-shaped. "
            "Attribution by responder is the only thing separating the "
            "two. NOTE: this caveat applies to M3's path only. Phase 2's "
            "unclaimed paths DO exist upstream and did answer 200 "
            "through the edge, so that half carries no such scoping.")
        phases["0_upstream_existence"] = p0
        print(f"phase 0  DIRECT, real PAT                  -> "
              f"{p0['status']}  "
              f"({'subject exists' if exists_upstream else 'subject ABSENT upstream'})")

        # --- Phase 1: M3's deny as deployed ---------------------------
        p1_anon = observe(gw_url, None, "edge_no_credential",
                          "The deny must not depend on the caller "
                          "lacking a credential.", marker)
        p1_auth = observe(gw_url, token, "edge_valid_credential",
                          "The caller this control exists to stop is one "
                          "who HOLDS a workspace token. A deny that only "
                          "refuses anonymous callers is not a deny.",
                          marker)
        for obs in (p1_anon, p1_auth):
            ok, ctrl, basis = attribute(obs)
            obs["attributed"] = {"ok": ok, "control": ctrl, "basis": basis}
        phases["1_deny_as_deployed"] = {"anonymous": p1_anon,
                                        "authenticated": p1_auth}
        for lbl, obs in (("no credential   ", p1_anon),
                         ("VALID credential", p1_auth)):
            print(f"phase 1  EDGE, {lbl}            -> {obs['status']}  "
                  f"[{obs['attributed']['control'] or 'UNATTRIBUTED'}]")

        # --- Phase 2: the B-48 regression -----------------------------
        # BOTH ways, and the first run of this test is why. It probed
        # anonymously only, on the strength of a docstring claim that the
        # route injects the gateway's credential on any path. It does
        # not: the injection lives inside M1's flow, selector EQUALS on
        # the model path, so an unclaimed path never reaches it and an
        # anonymous caller gets the upstream's 401. Probing anonymously
        # alone therefore could not reproduce the 200 this test exists to
        # prevent -- it would have passed on a wide-open gateway, because
        # the upstream was doing the refusing. The silent negative again:
        # a probe that cannot reach the thing it is checking looks
        # exactly like a probe that checked and found nothing.
        #
        # Anonymous is still worth recording, because the day it returns
        # 200 the injection has escaped M1's flow.
        p2_rows = []
        for path, why in UNCLAIMED_PATHS:
            for bearer, how in ((None, "anonymous"), (token, "with_token")):
                obs = observe(f"{edge}{ctx}{path}", bearer,
                              f"unclaimed{path}[{how}]", why, marker)
                ok, ctrl, basis = attribute(obs)
                obs["attributed"] = {"ok": ok, "control": ctrl,
                                     "basis": basis}
                obs["reached_upstream"] = 200 <= obs["status"] < 300
                obs["probe"] = how
                p2_rows.append(obs)
                flag = "REACHED UPSTREAM" if obs["reached_upstream"] else (
                    ctrl or "unattributed")
                print(f"phase 2  UNCLAIMED {path:26s} {how:10s} -> "
                      f"{obs['status']}  [{flag}]")
        any_reached = any(r["reached_upstream"] for r in p2_rows)
        all_refused_by_allow_list = bool(p2_rows) and all(
            r["attributed"]["control"] == "TERMINAL_ALLOW_LIST"
            for r in p2_rows)
        phases["2_unclaimed_paths_as_deployed"] = {
            "probes": p2_rows,
            "any_reached_upstream": any_reached,
            "all_refused_by_the_allow_list": all_refused_by_allow_list,
            "reading": (
                "AT LEAST ONE unclaimed path reached the Databricks "
                "workspace REST API through the edge. This is B-48 live: "
                "the route table is a documentation allow-list that "
                "nothing enforces, and the identity that reached the "
                "upstream is the gateway's injected credential, not the "
                "caller's."
                if any_reached else
                "Every unclaimed path was refused, and by the "
                "allow-list's own named voice rather than a catch-all. "
                "The perimeter is installed. Phase 4 is what shows it is "
                "the perimeter doing it."
                if all_refused_by_allow_list else
                "Nothing reached the upstream, but at least one refusal "
                "could not be attributed to the allow-list by name. A "
                "refusal this test cannot attribute is not evidence the "
                "allow-list is working -- it could be a proxy error, and "
                "a proxy error that happens to refuse is the shape B-46 "
                "exists to keep out of a verdict."),
        }

        # --- Phase 3: control A, allow-list off, M3 still on ----------
        # ONE variable, answering two questions. See the docstring: this
        # is the state in which M3 can be observed at all, because the
        # allow-list's generic selector is reached first whenever it is
        # enabled.
        if args.no_reopen:
            phases["3_control_a_allow_list_disabled"] = {
                "verdict": "CANNOT_SEE_CONTROL_A_DECLINED_BY_FLAG",
                "why": ("--no-reopen was passed, so the allow-list was "
                        "never disabled. This run therefore cannot show "
                        "that the allow-list is what closes the "
                        "unclaimed paths (as opposed to the endpoint "
                        "target's shape), and cannot observe M3's mock "
                        "at all, since the allow-list is reached first "
                        "while it is enabled. Recorded as unmeasured "
                        "rather than assumed."),
                "declined_by_operator": True}
            print("phase 3  CONTROL A                         -> CANNOT_SEE "
                  "(--no-reopen)")
            off_allow, found_allow = before, []
        elif not allow_names:
            phases["3_control_a_allow_list_disabled"] = {
                "verdict": "CANNOT_SEE_NO_ALLOW_LIST_TO_DISABLE",
                "why": ("No resource-filtering whitelist is deployed, so "
                        "there is nothing to disable. Phase 2 already "
                        "measured the open state directly.")}
            print("phase 3  CONTROL A                         -> CANNOT_SEE "
                  "(no allow-list deployed)")
            off_allow, found_allow = before, []
        else:
            off_allow, found_allow = set_flows_enabled(
                before, allow_names, False)
            st3, _ = put_api(session, base, api_id, off_allow)
            dep3 = deploy(session, base, api_id)
            time.sleep(DEPLOY_SETTLE_SECONDS)
            p3_mcp = observe(gw_url, None, "allow_list_off_mcp_path",
                             "The allow-list is the only thing standing "
                             "between a caller and M3's mock. With it "
                             "off, M3's marker must appear -- that is "
                             "what proves M3's deny is a working "
                             "backstop and not dead configuration.",
                             marker)
            ok3, ctrl3, basis3 = attribute(p3_mcp)
            p3_mcp["attributed"] = {"ok": ok3, "control": ctrl3,
                                    "basis": basis3}
            p3_rows = []
            for path, why in UNCLAIMED_PATHS:
                obs = observe(f"{edge}{ctx}{path}", token,
                              f"reopened{path}",
                              "With the allow-list off this must come "
                              "back to life for a token-bearing caller. "
                              "If it does not, the allow-list was not "
                              "what was closing it and phase 2 credited "
                              "the wrong control.", marker)
                obs["reached_upstream"] = 200 <= obs["status"] < 300
                p3_rows.append(obs)
            reopened = sum(1 for r in p3_rows if r["reached_upstream"])
            phases["3_control_a_allow_list_disabled"] = {
                "flows_disabled": found_allow,
                "put_status": st3, "deploy_status": dep3,
                "mcp_path": p3_mcp,
                "m3_marker_appeared": bool(p3_mcp.get("m3_marker_present")),
                "unclaimed_probes": p3_rows,
                "reopened_count": reopened,
                "of": len(p3_rows),
                "reading_m3": (
                    "M3's marker appeared the moment the allow-list was "
                    "removed, on the same URL with nothing else changed. "
                    "M3's mock policy fires, short-circuits, and carries "
                    "its CONOPS reason -- it is a working backstop that "
                    "the allow-list simply reaches first (AI-9)."
                    if p3_mcp.get("m3_marker_present") else
                    "M3's marker did NOT appear with the allow-list off. "
                    "Then M3's deny does not fire at all, and the legacy "
                    "MCP path is held only by the allow-list. The "
                    "perimeter may still be closed, but there is no "
                    "backstop and no decision in the response."),
                "reading_perimeter": (
                    f"{reopened}/{len(p3_rows)} unclaimed paths answered "
                    "2xx again with the allow-list off. The allow-list is "
                    "demonstrably the control closing them -- same paths, "
                    "same client, one variable."
                    if reopened else
                    "NO unclaimed path came back with the allow-list "
                    "off. Phase 2's refusals cannot then be credited to "
                    "the allow-list: something else is refusing these "
                    "paths, and the perimeter this test set out to "
                    "measure is unproven. B-40 -- a control that does "
                    "not move when the variable moves is not a "
                    "control."),
                "note_on_what_was_done": (
                    "This phase briefly restored the open-proxy state "
                    "described in the module docstring. It is the only "
                    "honest way to show the allow-list is load-bearing. "
                    "Phase 5 closes it; the snapshot on disk closes it "
                    "even if this process dies."),
            }
            print(f"phase 3  CONTROL A, allow-list off, MCP    -> "
                  f"{p3_mcp['status']}  [{ctrl3 or 'UNATTRIBUTED'}]  "
                  f"m3_marker={bool(p3_mcp.get('m3_marker_present'))}")
            print(f"phase 3  CONTROL A, unclaimed reopened     -> "
                  f"{reopened}/{len(p3_rows)}  (with a caller token)")

        # --- Phase 4: control B, both off -----------------------------
        m3_names = [f["name"] for f in before.get("flows", [])
                    if (f.get("name") or "").startswith(M3_FLOW_PREFIX)]
        if not m3_names:
            phases["4_control_b_both_disabled"] = {
                "verdict": "CANNOT_SEE_NO_M3_FLOW_TO_DISABLE",
                "why": (f"No flow whose name starts with '{M3_FLOW_PREFIX}' "
                        "exists on the live API, so the route cannot be "
                        "shown to be routable at all and phases 1-3's "
                        "refusals cannot be separated from a dead URL.")}
            print("phase 4  CONTROL B                         -> CANNOT_SEE "
                  "(no M3 flow on the live API)")
        elif args.no_reopen or not allow_names:
            phases["4_control_b_both_disabled"] = {
                "verdict": "CANNOT_SEE_CONTROL_B_REQUIRES_CONTROL_A",
                "why": ("Control B disables BOTH controls, so it cannot "
                        "run when control A was declined or when there "
                        "is no allow-list. Without it, nothing here "
                        "proves the MCP path is routable, so a refusal "
                        "and a dead URL are not separated.")}
            print("phase 4  CONTROL B                         -> CANNOT_SEE "
                  "(control A did not run)")
        else:
            both_off, touched = set_flows_enabled(off_allow, m3_names, False)
            st4, _ = put_api(session, base, api_id, both_off)
            dep4 = deploy(session, base, api_id)
            time.sleep(DEPLOY_SETTLE_SECONDS)
            p4_mcp = observe(gw_url, None, "both_disabled_mcp_path",
                             "With no edge control on this path, the "
                             "request must be FORWARDED. That is what "
                             "proves the path reaches the edge, matches "
                             "the context path and is routable -- so "
                             "phases 1-3's refusals were policies, not a "
                             "dead URL.", marker)
            fwd = (p4_mcp["responder"].get("round_trip_headers") or
                   p4_mcp["responder"].get("vocabulary") == "UPSTREAM")
            p4_mcp["request_was_forwarded"] = fwd
            phases["4_control_b_both_disabled"] = {
                "flows_disabled": found_allow + touched,
                "put_status": st4, "deploy_status": dep4,
                "mcp_path": p4_mcp,
                "request_was_forwarded": fwd,
                "reading": (
                    "Forwarded. The path reaches the edge, matches the "
                    "context path and would be proxied, so every refusal "
                    "above was a policy decision rather than a dead URL, "
                    "a wrong context path or a plan problem."
                    if fwd else
                    "NOT demonstrably forwarded. With both controls off "
                    "the edge still did not proxy this path, so the "
                    "refusals above cannot be attributed to either "
                    "control -- something else is refusing, and this "
                    "test must not claim M3 or the allow-list is "
                    "enforcing anything."),
            }
            print(f"phase 4  CONTROL B, both off, MCP path     -> "
                  f"{p4_mcp['status']}  forwarded={fwd}")

            # --- Phase 5: restore ------------------------------------
            st5, _ = put_api(session, base, api_id, before)
            dep5 = deploy(session, base, api_id)
            time.sleep(DEPLOY_SETTLE_SECONDS)
            restored = True
            p5_mcp = observe(gw_url, None, "restored_mcp_path",
                             "Reversibility for M3.", marker)
            ok5, ctrl5, basis5 = attribute(p5_mcp)
            p5_mcp["attributed"] = {"ok": ok5, "control": ctrl5,
                                    "basis": basis5}
            # WITH A TOKEN, for the same reason phase 2 and phase 3 use
            # one. An anonymous probe here returns the upstream's 401
            # whether the perimeter came back or not, so a restore check
            # built on it would report "perimeter_back" on a gateway left
            # wide open -- the silent negative, in the one place where
            # getting it wrong leaves a live open proxy behind.
            p5_rows = []
            for path, why in UNCLAIMED_PATHS:
                obs = observe(f"{edge}{ctx}{path}", token,
                              f"restored{path}",
                              "Reversibility for the perimeter, probed "
                              "with a caller token because that is the "
                              "probe phase 3 showed can tell open from "
                              "closed. Phases 2-4 without this show the "
                              "perimeter can be BROKEN, not that it works "
                              "and comes back.", marker)
                ok, ctrl, basis = attribute(obs)
                obs["attributed"] = {"ok": ok, "control": ctrl,
                                     "basis": basis}
                obs["reached_upstream"] = 200 <= obs["status"] < 300
                p5_rows.append(obs)
            still_open = [r["url"] for r in p5_rows if r["reached_upstream"]]
            # Not merely "did not reach the upstream" -- refused by the
            # allow-list BY NAME. B-46: a proxy error also fails to reach
            # the upstream.
            reclosed_by_name = [
                r["url"] for r in p5_rows
                if r["attributed"]["control"] == "TERMINAL_ALLOW_LIST"]
            phases["5_restored"] = {
                "put_status": st5, "deploy_status": dep5,
                "mcp_path": p5_mcp,
                "unclaimed_probes": p5_rows,
                "perimeter_back": (not still_open
                                   and len(reclosed_by_name) == len(p5_rows)),
                "still_open_after_restore": still_open,
                "reclosed_by_the_allow_list_by_name": reclosed_by_name,
                "probed_with": "caller_token",
            }
            print(f"phase 5  RESTORED, MCP path                -> "
                  f"{p5_mcp['status']}  [{ctrl5 or 'UNATTRIBUTED'}]")
            print(f"phase 5  RESTORED, unclaimed still open    -> "
                  f"{len(still_open)}")
            if still_open:
                print("  *** THE PERIMETER DID NOT COME BACK. The API is "
                      "live and open. Restore by hand from "
                      f"{SNAPSHOT_FULL.relative_to(ROOT)} -- the "
                      f"_secrets copy, not the redacted evidence one, "
                      f"which would put the credential property back "
                      f"empty. ***")
    finally:
        if not restored:
            print("\n[restore] the run did not reach phase 5 -- putting "
                  "the snapshot back so neither the deny nor the "
                  "allow-list is left disabled.")
            rs, rtext = put_api(session, base, api_id, before)
            rd = deploy(session, base, api_id)
            print(f"[restore] PUT {rs}  deploy {rd}  {rtext[:200]}")
            phases["emergency_restore"] = {"put_status": rs,
                                           "deploy_status": rd}

    # --- The verdict ---------------------------------------------------
    p1 = phases["1_deny_as_deployed"]
    p2 = phases["2_unclaimed_paths_as_deployed"]
    p3 = phases.get("3_control_a_allow_list_disabled", {})
    p4 = phases.get("4_control_b_both_disabled", {})
    p5 = phases.get("5_restored", {})

    # WHERE EACH OF THESE IS READ FROM, AND WHY NOT WHERE THE FIRST
    # VERSION READ THEM (B-19, retraction in place).
    #
    # `m3_fired` was read from PHASE 1 -- the as-deployed state -- on the
    # assumption that M3's flow, being emitted before the allow-list in
    # the flows array, would be evaluated first. Measured 2026-10-21:
    # Gravitee evaluates flows from the MOST GENERIC selector to the most
    # specific, so the allow-list's `/` STARTS_WITH flow runs FIRST
    # however late it appears in the array. Phase 1 therefore CANNOT see
    # M3, and a test that demanded M3's marker there was demanding
    # something the platform will not produce while the perimeter is on.
    # It is read from phase 3 instead -- the one state in which M3 is
    # reachable -- which is a weaker claim honestly made: M3 fires as a
    # BACKSTOP, not as the first responder (AI-9).
    #
    # `perimeter_control_ok` was read from phase 4 (both off). It belongs
    # in phase 3 (allow-list off, M3 still on), because that is the run
    # that moves exactly ONE variable. Phase 4 moves two and so cannot
    # attribute what changed to either.
    m3_fired = p3.get("m3_marker_appeared") is True
    m3_is_first_responder = all(
        p1[k]["attributed"]["control"] == "M3_EXPLICIT_DENY"
        for k in ("anonymous", "authenticated"))
    perimeter_closed = (p2["any_reached_upstream"] is False
                        and p2["all_refused_by_the_allow_list"])
    perimeter_control_ok = p3.get("reopened_count", 0) > 0
    routable = p4.get("request_was_forwarded") is True
    reversible = p5.get("perimeter_back") is True and \
        p5.get("mcp_path", {}).get("attributed", {}).get("ok") is True

    # Ordered by severity, not by which subject the test was named for.
    # The open proxy outranks M3: a legible deny on one path is worth
    # nothing while every other path is forwarded.
    if p2["any_reached_upstream"]:
        verdict = "OPEN_PROXY_UNCLAIMED_PATHS_REACH_THE_UPSTREAM"
    elif any(p1[k]["responder"].get("vocabulary") == "UPSTREAM"
             for k in ("anonymous", "authenticated")):
        verdict = "DENY_DOES_NOT_FIRE_THE_EDGE_FORWARDED_THE_REQUEST"
    elif not perimeter_closed:
        verdict = "CANNOT_SEE_REFUSALS_NOT_ATTRIBUTABLE_TO_THE_ALLOW_LIST"
    elif not perimeter_control_ok:
        verdict = "CANNOT_SEE_PERIMETER_CONTROL_NOT_RUN"
    elif not routable:
        verdict = "CANNOT_SEE_ROUTABILITY_NOT_SHOWN"
    elif not m3_fired:
        verdict = "PERIMETER_CLOSED_BUT_M3_IS_DEAD_CONFIGURATION"
    elif not reversible:
        verdict = "CONTROLS_FIRE_BUT_REVERSIBILITY_NOT_SHOWN"
    elif phases["0_upstream_existence"]["subject_exists_upstream"]:
        verdict = "PERIMETER_CLOSED_M3_IS_THE_BACKSTOP_EXPOSURE_WAS_REAL"
    else:
        verdict = "PERIMETER_CLOSED_M3_IS_THE_BACKSTOP_SUBJECT_ABSENT_UPSTREAM"

    passed = verdict in (
        "PERIMETER_CLOSED_M3_IS_THE_BACKSTOP_EXPOSURE_WAS_REAL",
        "PERIMETER_CLOSED_M3_IS_THE_BACKSTOP_SUBJECT_ABSENT_UPSTREAM")

    ev = {
        "test": "T-16",
        "epic_task": "E1 Task 1.9 part 4",
        "open_decision": "OD-8 (half)",
        "at": now(),
        "subject": {"routes": ["M3", "X (terminal allow-list)"],
                    "edge_url": gw_url, "direct_url": direct_url,
                    "api": {"id": api_id, "name": api_name},
                    "m3_attribution_marker": marker,
                    "allow_list_flows": allow_names,
                    "edge_base_provenance": edge_prov},
        "control_b_run": not args.no_reopen,
        "phases": phases,
        "verdict": verdict,
        "which_control_answers_first": {
            "measured": "TERMINAL_ALLOW_LIST",
            "m3_is": "a backstop, reachable only with the allow-list off",
            "why": (
                "Gravitee evaluates flows from the most GENERIC selector "
                "to the most specific. The allow-list's selector is `/` "
                "STARTS_WITH, the most generic there is, so it is "
                "evaluated FIRST however late it appears in the flows "
                "array. Proven both ways on 2026-10-21: with the "
                "allow-list enabled the MCP path answers in "
                "resource-filtering's words; disable that one flow and the "
                "same path returns M3's marker."),
            "consequence_accepted": (
                "AI-9. The caller receives the allow-list's reasonless "
                "403 rather than M3's CONOPS reason. The trade is "
                "deliberate: the reason-carrier fails OPEN and the "
                "enforcer fails CLOSED, so the enforcer is the one that "
                "must answer first."),
        },
        "findings": {
            "b48": (
                "Gravitee FORWARDS any path that matches no flow "
                "selector; it does not refuse it. With this API's target "
                "at the workspace root, that made the AI route an open "
                "reverse proxy to the whole Databricks REST API for any "
                "caller holding ANY workspace token, on paths the route "
                "table never exposed. Measured 2026-10-21. Fixed on this "
                "API by a terminal resource-filtering whitelist derived "
                "from the forwarding flows' own selectors. "
                "SEVERITY CORRECTED IN PLACE (B-19): the first write-up "
                "of this finding said the paths were reachable with NO "
                "credential, as the gateway's injected identity. "
                "Measured: anonymous gets the upstream's 401, because the "
                "strip-and-inject steps live inside M1's flow, whose "
                "selector is EQUALS on the single model path. So this was "
                "a bypass of the ROUTE RESTRICTION, with the caller's own "
                "entitlements -- not a privilege escalation. It was one "
                "selector edit away from being one."),
            "ai_4": (
                "CLOSED BY MEASUREMENT, and it was real. M3's deny was "
                "policy-request-validation with an empty `rules` list, "
                "which validates nothing and passes everything. The "
                "policy LOADED and forwarded -- AI-4 predicted the "
                "outcome and the wrong mechanism. Re-expressed as a "
                "`mock` policy whose fields were read from this "
                "installation's schema endpoint, with enforcement moved "
                "behind it to the allow-list so a future failure of the "
                "deny falls CLOSED."),
            "what_caught_it": (
                "Not a gate and not the policy. This test, because it "
                "required Gravitee's own vocabulary instead of accepting "
                "any 4xx. An assertion of `status in (401, 403)` would "
                "have passed on the upstream's forwarded 401 and the "
                "no-op deny would have shipped as working."),
        },
        "scope_of_this_result": (
            "M3's path does not answer upstream even to a full workspace "
            "credential, so the M3 half is evidence that the CONTROL "
            "WORKS, not that a reachable exposure was closed. The "
            "unclaimed-path half carries no such caveat: those paths DO "
            "exist, DID answer 200 through the edge, and are now refused."
            if not phases["0_upstream_existence"]["subject_exists_upstream"]
            else "Both halves closed reachable exposures at the "
                 "perimeter."),
        "what_this_does_not_prove": {
            "the_estate": (
                "The allow-list is on this ONE API. scripts/29's sharing "
                "and storage APIs still forward unmatched paths and are "
                "confined only by their endpoint target carrying a deep "
                "base path, so a stray path appends and the upstream "
                "404s -- confinement by string concatenation, not a "
                "control, and one target edit from being gone. Nothing "
                "here tests them. B-48 stays OPEN."),
            "authorisation": (
                "resource-filtering decides on the request PATH. It says "
                "nothing about who the caller is, and this route's plan "
                "is KEY_LESS (AI-1), so a 403 here is not an unentitled "
                "caller being refused."),
            "exhaustiveness": (
                f"{len(UNCLAIMED_PATHS)} paths were probed out of "
                "hundreds in the Databricks REST API. What makes the "
                "result general is the whitelist's default-deny SHAPE, "
                "not this sample."),
            "m2": ("Ungenerated (AI-5). §2.3.2 gives M2's method as "
                   "'MCP', a protocol not an HTTP method, and a POST-only "
                   "selector would silently drop the streamable-HTTP "
                   "event stream. OD-8's other half stays open."),
            "ac5_audit": "No tracing table was read.",
            "m3_as_first_responder": (
                "NOT shown, and cannot be while the perimeter is on: "
                f"m3_is_first_responder={m3_is_first_responder}. What is "
                "shown is that M3's mock fires, short-circuits and carries "
                "its reason when it is the control that is reached. A "
                "CONOPS claim that the caller is TOLD why the legacy MCP "
                "route is closed is therefore not supported by this run."),
            "step_conditions": (
                "AI-10. A step-level `condition` that does not evaluate "
                "true SILENTLY OMITS the policy -- PUT 200, deploy 202, no "
                "warning. Measured here by accident: a condition added to "
                "the allow-list step reopened /api/2.0/token/list to 200. "
                "Reverted and verified. No `condition` belongs on any step "
                "whose absence fails open."),
            "t15": (
                "No model path or credential injection was touched here "
                "-- but T-15 MUST be re-run, because the allow-list is "
                "now in the path of the model route T-15 measures."),
        },
    }
    EVIDENCE.write_text(json.dumps(ev, indent=2))

    report.record(
        "T-16", "Legacy managed MCP denied, and unclaimed paths refused",
        "No unclaimed workspace path reaching the upstream with a caller "
        "token, every refusal attributed to a NAMED policy; those paths "
        "alive again with the allow-list disabled and no other change; "
        "M3's marker appearing in that same state, proving the backstop "
        "is live rather than dead configuration; the path forwarded with "
        "both off, proving it was routable all along; and the perimeter "
        "demonstrably back, by name, after restore",
        verdict, passed, "evidence/t16-mcp-deny.json")
    report.write(ROOT / "evidence" / "t16-report.json")
    print()
    print(f"VERDICT: {verdict}")
    print(report.summary())
    print(f"Wrote {EVIDENCE.relative_to(ROOT)}")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
