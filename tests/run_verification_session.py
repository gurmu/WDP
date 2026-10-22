#!/usr/bin/env python3
"""
Runs the CONOPS Section 6.3 "Client Verification Session" end to end and
writes a timestamped evidence log -- the same seven steps the real client
verification session will follow, just against your laptop stack instead
of the client's Databricks test environment.

    1. Publish a test dataset as a share (AC4)
    2. Register/approve a consumer, tied to a DSA reference (AC3, AC4)
    3. Issue the credential file, endpoint rewritten to the gateway (AC4)
    4. Read the data through the gateway, only entitled columns (AC1)
    5. Show the refusals: burst, malformed request, direct-to-Databricks,
       column outside grant (AC1, AC2)
    6. Trace one request across the gateway log and Databricks audit
       event (AC5)
    7. Revoke the consumer, show access fails; redeploy from code (AC3, AC6)

Prerequisite: scripts/00-05 have been run at least once (share, recipient,
credential file, Gravitee API imported and started).

Run with: python3 tests/run_verification_session.py
"""
import json
import sys
from pathlib import Path

import requests
import delta_sharing

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import ROOT, load_env, load_rewritten_credential, Report  # noqa: E402

import os


def step1_share_exists(report):
    load_env()
    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(host=os.environ["DATABRICKS_HOST"], token=os.environ["DATABRICKS_TOKEN"])
    # databricks-sdk 0.153.0 renamed SharesAPI.list to list_shares, and the
    # old name is GONE rather than deprecated -- so this step raised
    # AttributeError and killed the whole §6.3 runner at step 1, meaning
    # steps 2-7 reported NOTHING. A crash is not a failure: it produces no
    # verdict for the six steps that never ran. RecipientsAPI.list was NOT
    # renamed in the same release, which is why line 52 below still works
    # and this line did not. Resolved by name so the script runs on either.
    _list_shares = getattr(w.shares, "list_shares", None) or w.shares.list
    shares = {s.name for s in _list_shares()}
    ok = "awoz1227-psp7-demo-share" in shares
    report.record(
        "Step1/AC4", "Publish a test dataset as a share",
        "share exists in Unity Catalog", f"shares visible: {sorted(shares)}", ok,
    )


def step2_recipient_approved(report):
    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(host=os.environ["DATABRICKS_HOST"], token=os.environ["DATABRICKS_TOKEN"])
    recipients = {r.name for r in w.recipients.list()}
    ok = "psp7-demo-recipient" in recipients
    report.record(
        "Step2/AC3+AC4", "Register and approve a consumer, tied to a DSA reference",
        "recipient created & granted (DSA ref tracked in recipient comment/ticket)",
        f"recipients visible: {sorted(recipients)}", ok,
    )


# The live edge path is NOT /delta-sharing. It is
# /opensharing-demo/<recipient-slug>, generated per recipient by
# scripts/29 and recorded in gravitee/generated/route-family.json.
# /delta-sharing is RETIRED (route-table.yaml edge.sharing_listener.retires).
FAMILY = ROOT / "gravitee" / "generated" / "route-family.json"
RETIRED_PREFIXES = ("/delta-sharing",)


def live_edge_path(recipient):
    """The edge path this recipient actually reads through, from the
    generated route family rather than from a literal in this file.

    MEASURED 2026-10-22, and the reason this function exists: step 3 used
    to assert `rewritten_credential.endpoint == GRAVITEE_GATEWAY_EDGE_URL`
    and it PASSED -- while step 4, reading that same endpoint, got
    404 ENDPOINT_NOT_FOUND. Both sides of step 3's equality came from the
    same stale source (the env var and the rewriter both still say
    /delta-sharing), so the comparison was self-consistent and wrong. A
    control that shares an origin with its subject cannot contradict it;
    this is B-40 -- the control must be the same PATH as the subject --
    in a new place. The step that existed to catch endpoint drift
    certified it instead.
    """
    if not FAMILY.exists():
        return None, "CANNOT_SEE_NO_ROUTE_FAMILY (run scripts/29)"
    fam = json.loads(FAMILY.read_text())
    for m in fam.get("family", []):
        if m.get("recipient") == recipient:
            return m.get("edge_path"), None
    return None, f"CANNOT_SEE_RECIPIENT_NOT_IN_ROUTE_FAMILY ({recipient})"


def step3_credential_rewritten(report):
    try:
        cred = load_rewritten_credential()
    except SystemExit as e:
        report.record("Step3/AC4", "Issue the credential file, endpoint rewritten to the gateway",
                      "rewritten credential present", str(e), False)
        return
    endpoint = cred.get("endpoint") or ""
    base = os.environ.get("GRAVITEE_EDGE_BASE", "").rstrip("/")
    edge_path, why = live_edge_path("psp7-demo-recipient")
    if edge_path is None:
        report.record("Step3/AC4", "Issue the credential file, endpoint rewritten to the gateway",
                      "endpoint == the recipient's LIVE edge path", why, False)
        return
    want = f"{base}{edge_path}"
    stale = [p for p in RETIRED_PREFIXES if endpoint.endswith(p)]
    ok = endpoint == want
    actual = f"endpoint == {endpoint}"
    if stale:
        actual += (f"  verdict=ENDPOINT_IS_A_RETIRED_PATH{stale[0]!r}. The "
                   "rewriter and GRAVITEE_GATEWAY_EDGE_URL both still name "
                   "it, which is why comparing them to each other passed.")
    report.record(
        "Step3/AC4", "Issue the credential file, endpoint rewritten to the gateway",
        f"endpoint == {want}  (from route-family.json, not from a literal)",
        actual, ok,
    )


def step4_read_through_gateway(report):
    """Reads with the RAW credential plus the live edge path, not with the
    rewritten credential file, because the rewritten file currently carries
    the retired /delta-sharing endpoint (see step 3). Rewriting it here
    would hide step 3's finding behind step 4's pass."""
    import tempfile
    edge_path, why = live_edge_path("psp7-demo-recipient")
    if edge_path is None:
        report.record("Step4/AC1", "Read the data through the gateway, only entitled columns",
                      "rows returned, internal_notes withheld", why, False)
        return
    raw = ROOT / "_secrets" / "credential-psp7-demo-recipient.json"
    if not raw.exists():
        report.record("Step4/AC1", "Read the data through the gateway, only entitled columns",
                      "rows returned, internal_notes withheld",
                      f"CANNOT_SEE_NO_CREDENTIAL ({raw.name}); run scripts/27 --rotate-token",
                      False)
        return
    cred = json.loads(raw.read_text())
    base = os.environ.get("GRAVITEE_EDGE_BASE", "").rstrip("/")
    cred["endpoint"] = f"{base}{edge_path}"
    tmp = None
    try:
        with tempfile.NamedTemporaryFile("w", suffix=".share", delete=False) as fh:
            json.dump(cred, fh)
            tmp = fh.name
        os.chmod(tmp, 0o600)
        # The shared object is DISCOVERED, not named here. This line used
        # to read `...#awoz1227-psp7-demo-share.opensharing_test.test_dataset`
        # -- the BASE TABLE -- and E1's entitlement model makes every share
        # object a view, so the base table is deliberately absent from the
        # share. The platform's answer was RESOURCE_DOES_NOT_EXIST, which
        # reads exactly like a broken share and was in fact a correct
        # refusal of a name this repository's own design forbids.
        objs = delta_sharing.SharingClient(tmp).list_all_tables()
        if not objs:
            report.record("Step4/AC1", "Read the data through the gateway, only entitled columns",
                          "rows returned, internal_notes withheld",
                          f"CANNOT_SEE_NO_SHARED_OBJECTS via {edge_path}", False)
            return
        t = objs[0]
        table_url = f"{tmp}#{t.share}.{t.schema}.{t.name}"
        df = delta_sharing.load_as_pandas(table_url)
        withheld = "internal_notes" not in df.columns
        ok = withheld and len(df) > 0
        report.record(
            "Step4/AC1", "Read the data through the gateway, only entitled columns",
            "rows returned from the shared VIEW, internal_notes absent",
            f"{len(df)} rows from {t.schema}.{t.name} via {edge_path}, "
            f"columns={list(df.columns)}, internal_notes_withheld={withheld}", ok,
        )
    except Exception as e:
        report.record("Step4/AC1", "Read the data through the gateway, only entitled columns",
                      "successful read via gateway",
                      f"error via {edge_path}: {e}", False)
    finally:
        if tmp:
            try:
                os.unlink(tmp)   # a bearer token must not survive the run
            except OSError:
                pass


def step5_refusals(report):
    gateway = os.environ.get("GRAVITEE_GATEWAY_EDGE_URL", "")
    direct = f"https://{os.environ['DATABRICKS_HOST'].replace('https://','').replace('http://','')}/api/2.0/delta-sharing"

    # T-02: direct call to Databricks should be refused (network-level, not
    # gateway-level, since that's enforced by Databricks IP access lists /
    # network controls per Section 3.2, "Defense in depth").
    try:
        r = requests.get(direct, timeout=5)
        direct_refused = r.status_code in (401, 403, 404)
    except requests.exceptions.RequestException:
        direct_refused = True
    report.record("T-02/AC1", "Call straight to the Databricks sharing endpoint",
                   "refused", f"refused={direct_refused}", direct_refused)

    # T-06: malformed request body to the gateway's query route.
    #
    # `status >= 400` was NOT good enough and this row used to pass on the
    # wrong evidence. The URL it posts to is the retired /delta-sharing
    # path, so a 404 ENDPOINT_NOT_FOUND -- the route not existing -- scored
    # as "the edge rejected the malformed body". That is B-44: an edge
    # refusal and an upstream refusal forwarded through the edge are the
    # same status code with opposite remedies. A validation refusal is a
    # 400 from the edge; a 404 means nothing ever looked at the body.
    try:
        r = requests.post(gateway, data="{not valid json", timeout=5)
        st, body = r.status_code, (r.text or "")[:200]
        if st == 400:
            verdict, malformed_rejected = "REJECTED_AT_THE_EDGE_400", True
        elif st == 404 or "ENDPOINT_NOT_FOUND" in body:
            verdict, malformed_rejected = (
                "CANNOT_SEE_NO_ROUTE_AT_THIS_PATH -- the body was never "
                "validated because nothing answers here", False)
        elif st in (401, 403):
            verdict, malformed_rejected = (
                f"CANNOT_SEE_REFUSED_BEFORE_VALIDATION_{st} -- an auth "
                "refusal is not a body refusal", False)
        else:
            verdict, malformed_rejected = f"NOT_REJECTED_{st}", False
    except requests.exceptions.RequestException as e:
        st, verdict, malformed_rejected = "n/a", f"TRANSPORT_ERROR {e}", False
    report.record("T-06/AC2", "Malformed request body to a query route",
                  "a 400 FROM THE EDGE, not merely any status >= 400",
                  f"status={st}  verdict={verdict}", malformed_rejected)

    # T-05: burst above rate limit / spike arrest.
    try:
        statuses = [requests.get(gateway, timeout=5).status_code for _ in range(10)]
        throttled = 429 in statuses
    except requests.exceptions.RequestException:
        throttled = False
    report.record("T-05/AC2", "Burst above the rate limit and spike arrest",
                   "throttled (429) at some point", f"statuses={statuses if 'statuses' in dir() else 'n/a'}", throttled)


# Steps 6 and 7 are run by other programs. They used to be recorded here
# with passed=True and an actual of "see <that program>'s output" -- which
# is this repository's THIRD inversion written into a test: a report
# describing an intention as an outcome. Two of the nine rows in the §6.3
# evidence log were PASS rows that had measured nothing, and the log is
# what a client verification session would be shown. They now record
# NOT_RUN_HERE and do not count as passes. A row that cannot measure the
# thing it names must say so; see docs/12 §12.9 on the silent negative.
def step6_trace(report):
    report.record("Step6/AC5", "Trace one request across gateway log and Databricks audit event",
                  "correlation ID found in both logs",
                  "NOT_RUN_HERE -- run tests/test_t11_trace_correlation.py and "
                  "attach its evidence file. This row previously reported PASS "
                  "on the strength of a pointer to another program.", False,
                  evidence_ref="tests/test_t11_trace_correlation.py")


def step7_revoke_redeploy(report):
    report.record("Step7/AC3+AC6", "Revoke the consumer and redeploy config from code",
                  "revoked recipient fails; redeploy reproduces config",
                  "NOT_RUN_HERE -- run scripts/07_revoke_and_redeploy.py and "
                  "attach its evidence. Not run inline because it REVOKES a "
                  "live recipient that four other tests read through.", False,
                  evidence_ref="scripts/07_revoke_and_redeploy.py")


def main():
    load_env()
    report = Report()
    step1_share_exists(report)
    step2_recipient_approved(report)
    step3_credential_rewritten(report)
    step4_read_through_gateway(report)
    step5_refusals(report)
    step6_trace(report)
    step7_revoke_redeploy(report)

    out = ROOT / "_secrets" / "verification-session-evidence.json"
    report.write(out)
    all_passed = report.summary()
    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
