#!/usr/bin/env python3
"""T-03: a valid token from an address not on the allow-list is refused.

E1 Task 1.6 | AC1, AC2 | CONOPS 2.3.2, 3.1

WHY THIS TEST HAD TO BE REBUILT
-------------------------------
docs/12 §12.2 records T-03 as "already passed once: 403 ip-filtering,
2026-10-17T15:40Z". That pass was against the API at context path
`/opensharing-demo/`, which was **deleted on 2026-10-21** -- it had
`flows: 0`, no perimeter policies at all, and an upstream pinned to a
credential that expired 2026-10-18 (docs/11, "The legacy API was not
inert"). An API with zero flows has no ip-filtering policy to produce a
403, so whatever refused that request on 2026-10-17, the recorded
attribution cannot be trusted. The prior pass is therefore treated as
UNVERIFIABLE rather than as a result, and this test starts over.

WHY THE SUBJECT IS psp7-demo AND NOT t02-iplist
-----------------------------------------------
t02-iplist is the recipient that *sounds* right: it is the one carrying
an APPLIED Databricks IP access list. It is the wrong subject, and the
reason matters.

B-40's rule is that a negative assertion needs a same-path POSITIVE
control. For t02-iplist that control is unreachable: its Databricks-side
IP access list deliberately excludes this operator's address, so the
upstream refuses us whatever the gateway does. A 403 there is
unattributable -- edge policy and upstream policy would both be
refusing, for different reasons, with the same status code (B-44).

psp7-demo reads 200 through this exact path (T-01, same run, same
credential). So the control exists, and the ONE variable this test
changes is the contents of the gateway's own allow-list.

THE SHAPE: THREE PHASES, AND THE THIRD IS THE ONE PEOPLE SKIP
-------------------------------------------------------------
  Phase 1  allow-list as generated (psp7-demo: ip-filtering disabled)
           -> expect 200.  The before-picture.
  Phase 2  allow-list rewritten to a single TEST-NET-3 address that
           cannot contain us -> expect 403 from Gravitee's own
           ip-filtering policy.
  Phase 3  allow-list restored -> expect 200 again.

Phase 3 is not ceremony. Without it, "we changed the config and the
route stopped answering" is indistinguishable from "we changed the
config and BROKE the route". Only the restoration shows the refusal was
caused by the policy and is reversible. A one-way test that ends on a
403 proves the route can fail, not that the control works.

THE SECOND MEASUREMENT: WHO IS REFUSING, AND WHAT IS STILL REACHABLE
--------------------------------------------------------------------
During the phase-2 window this test also reads the recipient's endpoint
DIRECTLY, bypassing the edge entirely. If that returns 200 while the
edge returns 403, then the edge allow-list refused the request and the
data stayed reachable by the same credential over the open internet.
That is not a defect in the gateway -- it is the correct behaviour of a
perimeter that is not the only door. But §2.3.2 reads as though the edge
allow-list is a control over ACCESS, and what it actually controls is
access THROUGH THE EDGE. The distinction is B-35's, and this is the
measurement that makes it concrete rather than argued.

WHAT THIS TEST DOES NOT PROVE
-----------------------------
Not T-02. The Databricks-side IP access list is a different mechanism at
a different layer with a different observable, and nothing here touches
it. The two allow-lists do not even see the same address: Databricks
sees this host's public NAT address, while Gravitee -- running in a
container beside the client -- sees a private address. Two controls
named the same thing, keyed on different observables, is worth stating
in v1.6 rather than discovering during an incident.

Not T-05 or T-07. No limiter is exercised and no header claim is made.
"""
import datetime
import json
import os
import sys
import time
from pathlib import Path

import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import Report, load_env  # noqa: E402
# Imported, not copied. B-39 was two scanners with two copies of one
# string; the same mistake with an attribution rule would be worse,
# because a divergent copy would silently disagree about who refused.
from t01_gateway_read import (  # noqa: E402
    FAMILY,
    classify_responder,
    edge_base,
    http,
    scrub,
)

ROOT = Path(__file__).resolve().parent.parent
SECRETS = ROOT / "_secrets"
EVIDENCE = ROOT / "evidence" / "t03-refusal.json"

SUBJECT = "psp7-demo"

# TEST-NET-3 (RFC 5737). Reserved for documentation, routable nowhere,
# so it cannot accidentally contain this operator's address -- the same
# reasoning recipients.yaml gives for the Databricks-side list. A
# "deny" expressed as an allow-list of one unreachable address is
# stronger than an empty list, because an empty list is ambiguous:
# some implementations read it as "allow nothing", others as "no list
# configured, allow everything". An absent control and a total block
# must never share a representation.
IMPOSSIBLE_CIDR = "203.0.113.9/32"

DEPLOY_SETTLE_SECONDS = 6


def now():
    return datetime.datetime.utcnow().isoformat() + "Z"


def mgmt():
    base_root = os.environ.get("GRAVITEE_MGMT_API_URL", "http://localhost:8083")
    s = requests.Session()
    s.auth = (os.environ.get("GRAVITEE_MGMT_USER", "admin"),
              os.environ.get("GRAVITEE_MGMT_PASSWORD", "admin"))
    base = (f"{base_root}/management/v2/organizations/DEFAULT"
            f"/environments/DEFAULT")
    return s, base


def find_api(session, base, edge_path):
    """Locate the live API by its context path, not by its name.

    By path because the path is what the gateway routes on and what this
    test reads. A name match would be one rename away from testing a
    different object than the one it reports on."""
    want = "/" + edge_path.strip("/")
    r = session.get(f"{base}/apis", params={"perPage": 200}, timeout=30)
    r.raise_for_status()
    for item in r.json().get("data", []):
        d = session.get(f"{base}/apis/{item['id']}", timeout=30)
        if d.status_code != 200:
            continue
        body = d.json()
        for lis in body.get("listeners", []):
            for p in lis.get("paths", []):
                if "/" + (p.get("path") or "").strip("/") == want:
                    return item["id"], body
    return None, None


def deploy(session, base, api_id):
    r = session.post(f"{base}/apis/{api_id}/deployments",
                     json={"deploymentLabel": f"t03 {now()}"}, timeout=30)
    return r.status_code


def put_api(session, base, api_id, body):
    r = session.put(f"{base}/apis/{api_id}", json=body, timeout=30)
    return r.status_code, (r.text or "")[:300]


def set_ip_filter(body, cidrs, enabled):
    """Rewrite every ip-filtering policy in the definition.

    Every one, not the first. The generated definition carries one per
    exposed route, and a test that armed the allow-list on /shares only
    would report a working control while nine sibling routes stayed
    open. That is the shape of a real incident, and a test that can
    produce it is worse than no test."""
    touched = []
    for flow in body.get("flows", []):
        for step in flow.get("request", []):
            if step.get("policy") != "ip-filtering":
                continue
            step["enabled"] = enabled
            cfg = step.setdefault("configuration", {})
            cfg["whitelistIps"] = list(cidrs)
            cfg["matchAllFromXForwardedFor"] = False
            touched.append(flow.get("name"))
    return touched


def read_edge(base, edge_path, bearer):
    st, raw, hdr = http(f"{base}{edge_path}/shares", bearer)
    return {
        "status": st,
        "responder": classify_responder(raw, hdr, status=st),
        "detail": scrub(raw)[:400],
    }


def read_direct(endpoint, bearer):
    st, raw, hdr = http(f"{endpoint}/shares", bearer)
    return {
        "status": st,
        "responder": classify_responder(raw, hdr, status=st),
        "detail": scrub(raw)[:300],
    }


def main():
    load_env()
    print("=" * 68)
    print("T-03: a valid token from an address not on the allow-list")
    print("E1 Task 1.6 | AC1, AC2 | CONOPS 2.3.2, 3.1")
    print("=" * 68)

    rep = Report()
    if not FAMILY.exists():
        sys.exit(f"Missing {FAMILY}. Run "
                 "scripts/29_gen_gravitee_route_family.py first.")
    family = json.loads(FAMILY.read_text())
    member = next((m for m in family["family"]
                   if m.get("slug") == SUBJECT or SUBJECT in m.get("recipient", "")),
                  None)
    if member is None:
        sys.exit(f"No route-family member matching '{SUBJECT}'. "
                 "Run scripts/29 then scripts/05 --all.")

    cred_path = SECRETS / f"credential-{member['recipient']}.json"
    if not cred_path.exists():
        sys.exit(f"Missing {cred_path}")
    cred = json.loads(cred_path.read_text())
    bearer = cred.get("bearerToken")
    endpoint = (cred.get("endpoint") or "").rstrip("/")

    base, base_source, base_note = edge_base()
    edge_path = member["edge_path"]
    print(f"\nsubject:     {member['recipient']}")
    print(f"edge path:   {edge_path}   (base {base}, {base_source})")
    print(f"allow-list:  will be set to {IMPOSSIBLE_CIDR} in phase 2")

    session, mbase = mgmt()
    api_id, original = find_api(session, mbase, edge_path)
    if api_id is None:
        sys.exit(f"No live API at context path {edge_path}. "
                 "Run scripts/05_import_gravitee_api.py --all first.")
    print(f"live api:    {api_id}")

    # Keep a byte-level copy BEFORE touching anything. Phase 3 restores
    # from this, and it is written to disk so a crash between phase 2 and
    # phase 3 leaves a recoverable definition rather than a route stuck
    # refusing everything.
    snapshot = json.loads(json.dumps(original))
    snap_path = ROOT / "evidence" / "t03-api-snapshot-before.json"
    snap_path.parent.mkdir(parents=True, exist_ok=True)
    snap_path.write_text(json.dumps(snapshot, indent=2))
    print(f"snapshot:    {snap_path.name} "
          f"(restore source for phase 3 and for a crash)")

    out = {
        "test_id": "T-03",
        "epic_task": "E1 Task 1.6",
        "acceptance_criteria": ["AC1", "AC2"],
        "conops": ["2.3.2", "3.1"],
        "run_at": now(),
        "subject_recipient": member["recipient"],
        "edge_path": edge_path,
        "edge_base": base,
        "edge_base_source": base_source,
        "edge_base_note": base_note,
        "live_api_id": api_id,
        "impossible_cidr": IMPOSSIBLE_CIDR,
        "prior_result_status": (
            "UNVERIFIABLE. docs/12 §12.2 records a 403 ip-filtering pass on "
            "2026-10-17 against the API at /opensharing-demo/, which had "
            "flows: 0 -- no ip-filtering policy existed on it to produce "
            "that 403. The API was deleted 2026-10-21. The attribution "
            "cannot be reconstructed, so the prior pass is superseded by "
            "this run rather than confirmed by it (B-19: labelled, not "
            "erased)."
        ),
    }

    restored = False
    try:
        # ---- phase 1: the before-picture --------------------------------
        print("\n--- phase 1: allow-list as generated (expect 200)")
        p1 = read_edge(base, edge_path, bearer)
        out["phase1_before"] = p1
        print(f"    edge -> {p1['status']}  ({p1['responder']['responder']})")
        if p1["status"] != 200:
            out["verdict"] = "CANNOT_SEE_NO_POSITIVE_CONTROL"
            out["why"] = (
                "The subject does not read 200 through the edge with the "
                "allow-list as generated, so a 403 after arming the list "
                "would not be attributable to the list. B-40: without a "
                "same-path positive control, a refusal and an absence are "
                "the same observation. Fix the read first."
            )
            rep.record("T-03", "a valid token from a non-allow-listed address "
                       "is refused at the edge",
                       "403 from the gateway's ip-filtering policy, with the "
                       "same path returning 200 before and after",
                       out["verdict"], False, "evidence/t03-refusal.json")
            rep.summary()
            EVIDENCE.write_text(json.dumps(out, indent=2))
            return 1

        # ---- phase 2: arm the allow-list --------------------------------
        print(f"\n--- phase 2: allow-list = [{IMPOSSIBLE_CIDR}] (expect 403)")
        armed = json.loads(json.dumps(original))
        touched = set_ip_filter(armed, [IMPOSSIBLE_CIDR], enabled=True)
        out["flows_armed"] = sorted(n for n in touched if n)
        out["flows_armed_note"] = (
            "Every ip-filtering policy in the definition was armed, not "
            "just the one on the path under test. See set_ip_filter()."
        )
        print(f"    arming {len(touched)} ip-filtering policies")
        st, body = put_api(session, mbase, api_id, armed)
        dep = deploy(session, mbase, api_id)
        out["phase2_put_status"] = st
        out["phase2_deploy_status"] = dep
        print(f"    PUT -> {st}   deploy -> {dep}")
        if st not in (200, 201, 204):
            out["verdict"] = "CANNOT_SEE_COULD_NOT_ARM_THE_POLICY"
            out["why"] = (
                "The management API refused the definition update, so the "
                "allow-list was never armed and nothing was tested. This is "
                "a harness failure, NOT a finding about the control -- "
                "recording it as a failed refusal would be the silent "
                "negative (§12.9)."
            )
            out["phase2_put_body"] = body
            raise RuntimeError("arm failed")
        time.sleep(DEPLOY_SETTLE_SECONDS)

        p2 = read_edge(base, edge_path, bearer)
        out["phase2_armed"] = p2
        print(f"    edge -> {p2['status']}  ({p2['responder']['responder']})")

        # The same credential, outside the edge, during the same window.
        p2d = read_direct(endpoint, bearer) if endpoint else {
            "status": None, "detail": "no endpoint in credential file"}
        out["phase2_direct_bypass"] = p2d
        out["phase2_direct_bypass_note"] = (
            "Read during the phase-2 window with the edge allow-list armed. "
            "This is NOT a control for the refusal -- it is a separate "
            "measurement of what the edge allow-list does and does not "
            "reach."
        )
        print(f"    direct (bypassing the edge) -> {p2d['status']}")

        # ---- phase 3: restore and re-read -------------------------------
        print("\n--- phase 3: allow-list restored (expect 200 again)")
        st3, body3 = put_api(session, mbase, api_id, snapshot)
        dep3 = deploy(session, mbase, api_id)
        restored = st3 in (200, 201, 204)
        out["phase3_put_status"] = st3
        out["phase3_deploy_status"] = dep3
        print(f"    PUT -> {st3}   deploy -> {dep3}")
        if not restored:
            out["phase3_put_body"] = body3
        time.sleep(DEPLOY_SETTLE_SECONDS)
        p3 = read_edge(base, edge_path, bearer)
        out["phase3_after"] = p3
        print(f"    edge -> {p3['status']}  ({p3['responder']['responder']})")

    finally:
        if not restored:
            print("\n    [RESTORE] phase 3 did not complete cleanly -- "
                  "restoring the snapshot")
            st_r, _ = put_api(session, mbase, api_id, snapshot)
            deploy(session, mbase, api_id)
            out["emergency_restore_status"] = st_r
            out["emergency_restore_note"] = (
                "The armed allow-list must never outlive the test. A route "
                "left refusing every address would make every later test "
                "fail for a reason none of them name."
            )
            print(f"    [RESTORE] PUT -> {st_r}")

    # ---- verdict --------------------------------------------------------
    p1 = out.get("phase1_before", {})
    p2 = out.get("phase2_armed", {})
    p3 = out.get("phase3_after", {})
    who = (p2.get("responder") or {}).get("responder")

    if p2.get("status") == 200:
        out["verdict"] = "ALLOW_LIST_NOT_ENFORCED"
        out["why"] = (
            "The read succeeded with the allow-list armed to an address "
            "this client cannot hold. Either the policy is not being "
            "applied to this flow, or it is matching on an observable "
            "other than the peer address (matchAllFromXForwardedFor is "
            "set False by this test precisely to remove that variable). "
            "This is a FINDING, not a harness problem: AC2 rests on this "
            "control."
        )
    elif p2.get("status") == 403 and who == "EDGE_IP_FILTERING_POLICY":
        # Tightened 2026-10-21. This branch previously also accepted
        # EDGE_POLICY_OR_PROXY_ERROR, which is the classifier's CATCH-ALL
        # -- a label a 200 also carries. The verdict's own text claimed
        # the refusal arrived "in the edge's own vocabulary" while the
        # condition had checked only that it was not recognisably
        # someone else's. It now requires the ip-filtering policy to
        # identify itself by name (B-46).
        if p3.get("status") == 200:
            out["verdict"] = "REFUSED_AT_THE_EDGE_AND_REVERSIBLE"
            out["why"] = (
                "200 before, 403 with the allow-list armed, 200 again after "
                "restoring it -- same path, same credential, same run, one "
                "variable. The refusing policy named ITSELF in the response "
                "body, so this is a positive attribution rather than the "
                "absence of a competing one (B-44, B-46). And the reversal "
                "rules out 'the config change broke the route', which a "
                "two-phase test could not have distinguished."
            )
        else:
            out["verdict"] = "REFUSED_BUT_NOT_SHOWN_REVERSIBLE"
            out["why"] = (
                "The armed allow-list produced a 403 at the edge, but the "
                "path did not return to 200 after restoring the definition. "
                "So the 403 is not yet attributable to the allow-list "
                "rather than to the act of rewriting the API. Re-run before "
                "reporting this as a working control."
            )
    elif p2.get("status") == 403:
        out["verdict"] = "REFUSED_BUT_BY_AN_UNATTRIBUTED_PARTY"
        out["why"] = (
            "A 403 arrived, but it does not carry the edge's own refusal "
            "vocabulary, so it may have been forwarded from upstream. An "
            "edge refusal and a forwarded upstream refusal are the same "
            "status code with opposite remedies (B-44), and this test may "
            "not claim the first when it observed only the second."
        )
    else:
        out["verdict"] = "UNEXPECTED_STATUS_WITH_THE_LIST_ARMED"
        out["why"] = (
            f"Expected 403 or 200 with the list armed; got "
            f"{p2.get('status')}. Recorded verbatim rather than mapped onto "
            "the nearest expected outcome."
        )

    # ---- what address is the allow-list actually matched against? -------
    # The refusal reports it, and this is the measurement that matters
    # most in the whole test -- more than the refusal it came attached to.
    seen_ip = (p2.get("responder") or {}).get("observed_client_ip")
    if seen_ip:
        out["observed_client_ip_at_the_edge"] = seen_ip
        vacuous = any(seen_ip.startswith(p) for p in ("172.", "10.", "192.168."))
        out["observed_client_ip_finding"] = {
            "address": seen_ip,
            "is_private": vacuous,
            "why_it_matters": (
                "This is the address Gravitee's ip-filtering policy "
                "compares against the allow-list. It is NOT the address "
                "Databricks sees: Databricks sees this host's public NAT "
                "address, while the gateway -- a container on the same "
                "host as the client -- sees a private one. Two controls "
                "both called 'the IP allow-list', keyed on addresses from "
                "different address spaces. 11.7 B-35 argued this; this is "
                "the measurement."
            ),
            "generator_consequence": (
                "scripts/29_gen_gravitee_route_family.py defines "
                "LOCAL_TEST_CIDR = 172.21.0.0/16 and ADDS it to the "
                "allow-list whenever a recipient's ip_access_list_mode is "
                "APPLIED. The observed client address falls inside that "
                "CIDR. So every allow-list the generator emits in APPLIED "
                "mode admits the whole Docker bridge network -- which is "
                "every client that can reach the gateway from this host. "
                "The control is vacuous in exactly the configuration that "
                "is supposed to enforce it."
            ) if vacuous else (
                "The observed address is public, so LOCAL_TEST_CIDR does "
                "not appear to be what admitted it. Worth confirming "
                "before relying on this."
            ),
            "near_miss": (
                "T-03 would have reported ALLOW_LIST_NOT_ENFORCED if it had "
                "used t02-iplist -- the recipient whose allow-list is "
                "APPLIED -- because that list contains LOCAL_TEST_CIDR and "
                "this client is inside it. The subject was chosen for a "
                "different reason (t02-iplist has no reachable 200 "
                "control), so the test passed by luck of subject "
                "selection, not by the control working everywhere."
            ) if vacuous else None,
            "severity": (
                "A test accommodation that silently disables the control "
                "under test, in a file whose whole purpose is to be the "
                "deployable source of truth for AC6 / T-12 'redeploy from "
                "code'. If promoted, the allow-list ships open."
            ) if vacuous else "low",
            "related": ["11.7 B-35", "11.7 B-47", "T-02", "AC2", "T-12"],
        }
        print(f"\n    observed client IP at the edge: {seen_ip}"
              + ("  <-- inside LOCAL_TEST_CIDR; see "
                 "observed_client_ip_finding" if vacuous else ""))

    # The bypass observation is reported separately and never folded into
    # the verdict: it is a fact about the architecture, not about whether
    # the policy works.
    p2d = out.get("phase2_direct_bypass", {})
    if p2d.get("status") == 200 and p2.get("status") == 403:
        out["edge_is_not_the_only_door"] = {
            "observed": "edge 403, direct 200, same credential, same window",
            "meaning": (
                "The edge allow-list controls access THROUGH THE EDGE. It "
                "does not control access to the share. The same bearer "
                "token read the same data over the open internet while the "
                "edge was refusing it."
            ),
            "not_a_defect_in": "Gravitee, which did exactly what it was told",
            "conops_consequence": (
                "§2.3.2 reads as though the edge allow-list is a control "
                "over access. AC2's acceptance text should say 'refused at "
                "the edge' rather than 'refused', and v1.6 should state "
                "which of the two allow-lists -- the gateway's or the "
                "Databricks-side one -- is the control of record for "
                "address-based refusal. Only the second can close the "
                "direct path, and 11.7 B-38 / D-8 show it gates its own "
                "enrolment."
            ),
            "related": ["11.7 B-35", "11.7 B-38", "10.7 D-8", "T-02"],
        }
        print("\n    note: direct read returned 200 while the edge refused "
              "-- recorded as edge_is_not_the_only_door, not as a failure")

    passed = out["verdict"] == "REFUSED_AT_THE_EDGE_AND_REVERSIBLE"
    rep.record(
        "T-03",
        "a valid token from a non-allow-listed address is refused at the edge",
        "403 from the gateway's own ip-filtering policy, with the same path "
        "returning 200 immediately before and immediately after -- the "
        "same-path positive control B-40 requires, in both directions",
        out["verdict"], passed, "evidence/t03-refusal.json")

    out["what_this_does_not_prove"] = [
        "T-02. The Databricks-side IP access list is a different control "
        "at a different layer and was not touched. The two allow-lists do "
        "not observe the same address: Databricks sees this host's public "
        "NAT address, the gateway sees a private one.",
        "That the allow-list protects the DATA. See "
        "edge_is_not_the_only_door when present.",
        "T-05 or T-07. No limiter was exercised and no header claim is made.",
    ]
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(out, indent=2))
    rep.write(ROOT / "evidence" / "t03-report.json")
    rep.summary()
    print("\n" + "=" * 68)
    print(f"T-03 VERDICT: {out['verdict']}")
    print("=" * 68)
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
