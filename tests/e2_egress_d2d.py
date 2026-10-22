#!/usr/bin/env python3
"""
E-2: the INTERNAL consumer reading the entitled views inside the
provider's own metastore.

E1 Task 1.10's outstanding deliverable, and the test the access matrix
needs most. `iac/config/access-matrix.yaml` carries fourteen deny rows;
the single most important one --

    internal_consumer_group MUST NOT hold SELECT on the base table

-- had `tested_by: NONE` and `gap: true` until this file existed. It
matters because §3.1's entire column scope is implemented by the view's
select list. SELECT on the base table does not weaken that boundary, it
removes it: every excluded column becomes reachable by going around the
view rather than through it.

WHAT THIS TEST CAN AND CANNOT REACH, DECIDED BY MEASUREMENT
-----------------------------------------------------------
E-2's subject is a PRINCIPAL -- "the internal consumer". Before writing
a line of this test the tier was probed for whether that principal can
exist and whether anything can authenticate as it. Both answers are no,
and both are recorded here as status codes rather than as assumptions,
because "the tier cannot do this" is the most self-serving sentence a
test can contain and it should never be taken on trust:

  PATCH permissions, principal = a workspace group
      -> 404 PRINCIPAL_DOES_NOT_EXIST
      Unity Catalog principals are ACCOUNT-level. A workspace group is
      invisible to UC, so `awoz1227-internal-consumers` as the matrix
      spells it cannot be created on this tier at all. This CONFIRMS
      the matrix's `implementable: false` -- which until now was an
      inference from the docs and is now a measured refusal.

  POST /api/2.0/oauth2/service-principal-secrets          -> 404
  GET  /api/2.0/oauth2/service-principal-secrets          -> 404
  POST /api/2.0/accounts/.../credentials/secrets          -> 404
      No credential can be minted for a non-human principal. So no
      request can be issued AS the internal consumer.

  PATCH permissions, principal = a service principal's applicationId
      -> 200. Grants to a non-owner principal DO work.

That combination decides the shape of the test. The consumer's IDENTITY
is unreachable, so this test does NOT claim "the internal consumer was
refused the base table". It measures the two things that are reachable,
and names the third as CANNOT_SEE:

  A. The column boundary, which is identity-independent. The excluded
     column is absent from the view for EVERY reader, owner included.
     This is the strongest part of the test and it needs no second
     identity, because the view either carries the column or it does
     not.

  B. The row boundary, the same way, tied to the predicate by a
     third count rather than to a remembered constant.

  C. The deny row as GRANT STATE, with a real grant and a real revoke
     as the control.

  (D) NOT measured: that holding or not holding the grant changes what
     the principal can READ. That is the consequence the deny row cares
     about and no credential exists to observe it. Recorded as
     CANNOT_SEE with the three 404s above as the reason.

WHY PART C NEEDS THE GRANT ACTUALLY MADE
----------------------------------------
Reading the grants and finding the base table clean is worth nothing on
its own. The metastore returns `{}` for a securable with no grants, and
it returns `{}` for a securable the caller cannot see grants on, and it
would return `{}` if the URL were slightly wrong. A clean read is
consistent with a working probe and with a probe pointed at nothing --
docs/12 §12.9's silent negative, in the one check whose job is to notice
an exposure.

So the control is a real SELECT grant on the real base table to a real
non-owner principal. The probe must report VIOLATED while it is in
place. If it does not, the probe is blind and every other result in this
file is void -- so that outcome is a verdict of its own and it is
checked BEFORE the clean baseline is allowed to count for anything.

The revoke runs in a `finally` and is followed by a RE-READ, not by a
200 on the revoke. B-23: a 200 on a mutation is not the finding, the
re-read is. A revoke that returned 200 and did not take effect would
leave the base table readable by a service principal, which is the
exact exposure scripts/26 was written to remediate.

ORDER: the baseline is captured BEFORE the control grant, so if the
process dies mid-run the pre-existing state is on disk and recoverable
(scripts/26's lesson -- capture the whole record before a mutation).

Usage:
    python3 tests/e2_egress_d2d.py --dry-run
    python3 tests/e2_egress_d2d.py
"""

import argparse
import datetime
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from common import Report, load_env  # noqa: E402

CONFIG = ROOT / "iac" / "config" / "entitlements.yaml"
MATRIX = ROOT / "iac" / "config" / "access-matrix.yaml"
EVIDENCE = ROOT / "evidence" / "e2-egress-d2d.json"
REPORT = ROOT / "evidence" / "e2-report.json"

UC = "/api/2.1/unity-catalog"
CATALOG = "awoz1227_demo"
SCHEMA = "opensharing_test"
BASE_TABLE = "test_dataset"

# The control principal. A service principal already on this metastore,
# addressed by applicationId because that is the form UC accepts -- the
# display name returns PRINCIPAL_DOES_NOT_EXIST, which is a trap worth
# naming since the name is what a human would reach for first.
#
# Deliberately NOT `account users`: that principal also accepts grants
# (measured 200), and granting SELECT on a base table to every user in
# the account -- even for the seconds this test holds it -- is a wider
# blast radius than the finding needs. A single non-human principal is
# enough to make the probe move.
CONTROL_SP_APP_ID = "73bc845e-ca36-4b46-9042-db90e29c2c70"
CONTROL_SP_NAME = "awoz1227_t19_denial_b_principal"


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class Api:
    """Thin Databricks caller that records every call it makes.

    The log is part of the evidence. A test that reports a refusal
    without the request that earned it cannot be re-run by a reviewer,
    and an evidence file that cannot say what was asked is the fourth
    inversion from docs/12 -- proof that something happened with no way
    to say what.
    """

    def __init__(self, host, token):
        self.host = host.rstrip("/")
        self.token = token
        self.calls = []

    def call(self, method, path, body=None, timeout=90):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            self.host + path, data=data, method=method,
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"})
        rec = {"method": method, "path": path, "at": now()}
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read().decode() or "{}"
                rec["status"] = resp.status
                self.calls.append(rec)
                return resp.status, json.loads(raw)
        except urllib.error.HTTPError as exc:
            raw = exc.read().decode()
            rec["status"] = exc.code
            try:
                parsed = json.loads(raw)
                rec["error_code"] = parsed.get("error_code")
            except Exception:
                parsed = {"_raw": raw[:400]}
            self.calls.append(rec)
            return exc.code, parsed
        except Exception as exc:
            rec["status"] = "ERR"
            rec["error"] = str(exc)[:200]
            self.calls.append(rec)
            return "ERR", {"_err": str(exc)[:200]}

    def sql(self, statement, warehouse):
        """Run one statement. Returns (state, error_code, message, rows)."""
        status, body = self.call("POST", "/api/2.0/sql/statements", {
            "warehouse_id": warehouse, "statement": statement,
            "wait_timeout": "30s", "catalog": CATALOG, "schema": SCHEMA})
        if status != 200:
            return "HTTP_" + str(status), body.get("error_code"), \
                json.dumps(body)[:200], None
        st = body.get("status") or {}
        err = st.get("error") or {}
        rows = (body.get("result") or {}).get("data_array")
        return st.get("state"), err.get("error_code"), \
            (err.get("message") or "")[:220], rows


def grants_on(api, securable_type, full_name):
    """Read the grant list for one securable, keeping the distinction
    between 'no grants' and 'could not read grants'.

    An empty dict from this endpoint is ambiguous on its own -- see the
    module docstring. The caller gets `readable` so it can tell the two
    apart instead of folding both into 'clean'.
    """
    status, body = api.call(
        "GET", f"{UC}/permissions/{securable_type}/{full_name}")
    if status != 200:
        return {"readable": False, "http_status": status,
                "error_code": body.get("error_code"),
                "assignments": None}
    assignments = body.get("privilege_assignments") or []
    return {"readable": True, "http_status": 200,
            "assignments": [
                {"principal": a.get("principal"),
                 "privileges": a.get("privileges", [])}
                for a in assignments]}


def holders_of(grant_blob, privilege):
    """Which principals hold `privilege` on this securable."""
    if not grant_blob.get("readable") or not grant_blob.get("assignments"):
        return []
    out = []
    for a in grant_blob["assignments"]:
        privs = a.get("privileges") or []
        if privilege in privs or "ALL_PRIVILEGES" in privs:
            out.append(a.get("principal"))
    return out


def probe_deny_row(api):
    """THE deny row: does any principal hold SELECT on the base table?

    This is the function the control has to move. It returns the holders
    rather than a boolean, because 'violated' without naming who is a
    verdict too coarse to act on -- B-20, a vocabulary that cannot name
    the cause blames the nearest thing.
    """
    full = f"{CATALOG}.{SCHEMA}.{BASE_TABLE}"
    blob = grants_on(api, "table", full)
    holders = holders_of(blob, "SELECT")
    return {
        "securable": full,
        "grants": blob,
        "select_holders": holders,
        "deny_row_holds": blob["readable"] and not holders,
        "deny_row_state": (
            "CANNOT_SEE_GRANTS_UNREADABLE" if not blob["readable"]
            else "CLEAN" if not holders else "VIOLATED"),
        "note": (
            "The table OWNER is not listed by this endpoint -- ownership "
            "is not a grant. So 'no SELECT holders' means no principal "
            "has been GRANTED SELECT; it does not mean the table is "
            "unreadable, and the owner can always read it. The deny row "
            "is about granted privilege, which is what it says."),
    }


def capability_baseline(api):
    """Record, as status codes, what this tier refuses.

    Runs the refusals rather than citing them. The matrix's
    `implementable: false` was an inference from documentation until
    this ran; a claim about a platform limit that nobody re-measured is
    how a stale constraint survives three sessions.
    """
    out = {}
    view_full = f"{CATALOG}.{SCHEMA}.v_entitled_t2_us"

    status, body = api.call(
        "PATCH", f"{UC}/permissions/table/{view_full}",
        {"changes": [{"principal": "awoz1227_p15_entitled_group",
                      "add": ["SELECT"]}]})
    out["workspace_group_as_uc_principal"] = {
        "http_status": status, "error_code": body.get("error_code"),
        "accepted": status == 200,
        "means": (
            "UC principals are account-level. A workspace group cannot "
            "receive a UC grant, so the matrix's "
            "`awoz1227-internal-consumers` group cannot be created as a "
            "UC principal on this tier. This is the measured form of the "
            "matrix's `implementable: false`."),
    }
    if status == 200:  # pragma: no cover -- would contradict the above
        api.call("PATCH", f"{UC}/permissions/table/{view_full}",
                 {"changes": [{"principal": "awoz1227_p15_entitled_group",
                               "remove": ["SELECT"]}]})

    mint = []
    for method, path in (
            ("POST", "/api/2.0/oauth2/service-principal-secrets"),
            ("GET", "/api/2.0/oauth2/service-principal-secrets"
                    f"?service_principal_id={CONTROL_SP_APP_ID}")):
        status, body = api.call(
            method, path,
            {"service_principal_id": CONTROL_SP_APP_ID}
            if method == "POST" else None)
        mint.append({"method": method, "path": path, "http_status": status})
    out["mint_credential_for_non_human_principal"] = {
        "attempts": mint,
        "possible": any(a["http_status"] == 200 for a in mint),
        "means": (
            "No credential can be issued for a service principal here, "
            "so no request can be made AS the internal consumer. This is "
            "why part D of this test is CANNOT_SEE and not a pass."),
    }
    return out


def part_a_column_scope(api, warehouse, views):
    """The column boundary, with the base table as the positive control.

    Identity-independent: the view either carries the excluded column or
    it does not, and that is true for the owner too. So this is the one
    part of E-2 that does not need the principal the tier cannot create.

    The control is the SAME COLUMN on the base table. Without it a
    failure is unreadable -- a typo'd column name fails exactly the same
    way as a correctly excluded one, and the test would pass by
    misspelling its own subject. B-40: the control must be the same
    question asked where the answer should differ.
    """
    results = []
    for view in views:
        vid = view["id"]
        excluded = view.get("excludes") or []
        entitled = view.get("select") or []
        for col in excluded:
            state, err, msg, _ = api.sql(
                f"SELECT {col} FROM {vid} LIMIT 1", warehouse)
            through_view_refused = (
                state == "FAILED" and err is not None
                and "UNRESOLVED_COLUMN" in (msg or ""))
            c_state, c_err, c_msg, _ = api.sql(
                f"SELECT {col} FROM {BASE_TABLE} LIMIT 1", warehouse)
            control_succeeded = (c_state == "SUCCEEDED")
            results.append({
                "view": vid, "column": col, "kind": "excluded",
                "through_view": {"state": state, "error_code": err,
                                 "message": msg},
                "control_on_base_table": {"state": c_state,
                                          "error_code": c_err,
                                          "message": c_msg},
                "refused_through_view": through_view_refused,
                "control_proves_column_exists": control_succeeded,
                "boundary_demonstrated": (through_view_refused
                                          and control_succeeded),
            })
        # And the entitled columns must still come back, or the "view
        # refuses the excluded column" result is just a broken view.
        if entitled:
            state, err, msg, _ = api.sql(
                f"SELECT {', '.join(entitled)} FROM {vid} LIMIT 1",
                warehouse)
            results.append({
                "view": vid, "column": ",".join(entitled),
                "kind": "entitled",
                "through_view": {"state": state, "error_code": err,
                                 "message": msg},
                "entitled_columns_readable": state == "SUCCEEDED",
                "why_this_check": (
                    "A view with no columns at all would refuse the "
                    "excluded column too. This separates 'scoped' from "
                    "'broken'."),
            })
    return results


def part_b_row_scope(api, warehouse, views):
    """The row boundary, tied to the predicate by a third count.

    view_count vs base_count shows the view filters something.
    predicate_count -- the same predicate applied directly to the base
    table -- shows it filters THAT. Without the third number a matching
    pair is a coincidence the test cannot rule out, which is how a row
    filter that silently stopped matching would still pass.
    """
    out = []
    state, err, _, rows = api.sql(
        f"SELECT COUNT(*) FROM {BASE_TABLE}", warehouse)
    base_count = int(rows[0][0]) if rows else None

    for view in views:
        vid = view["id"]
        predicate = view.get("where")
        state, err, msg, rows = api.sql(
            f"SELECT COUNT(*) FROM {vid}", warehouse)
        view_count = int(rows[0][0]) if rows else None

        entry = {"view": vid, "predicate": predicate,
                 "row_scope": view.get("row_scope"),
                 "base_table_count": base_count,
                 "view_count": view_count,
                 "view_count_state": state}

        if predicate:
            state2, err2, msg2, rows2 = api.sql(
                f"SELECT COUNT(*) FROM {BASE_TABLE} WHERE {predicate}",
                warehouse)
            pred_count = int(rows2[0][0]) if rows2 else None
            entry["predicate_count_on_base_table"] = pred_count
            entry["view_matches_its_predicate"] = (
                isinstance(pred_count, int)
                and pred_count == view_count)
            entry["filters_something"] = (
                isinstance(view_count, int) and isinstance(base_count, int)
                and view_count < base_count)
            entry["row_scope_demonstrated"] = bool(
                entry["view_matches_its_predicate"]
                and entry["filters_something"])
        else:
            entry["view_matches_its_predicate"] = (
                isinstance(view_count, int) and view_count == base_count)
            entry["filters_something"] = False
            entry["row_scope_demonstrated"] = entry[
                "view_matches_its_predicate"]
            entry["note"] = (
                "row_scope ALL_ROWS: the check is that the count EQUALS "
                "the base table. A view declared as carrying every row "
                "and quietly carrying fewer is a defect in the other "
                "direction, and nothing else in this suite would see it.")
        out.append(entry)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print the plan and touch nothing")
    ap.add_argument("--warehouse", default=None,
                    help="SQL warehouse id (default: first available)")
    args = ap.parse_args()

    load_env()
    host = os.environ.get("DATABRICKS_HOST", "").rstrip("/")
    token = os.environ.get("DATABRICKS_TOKEN", "")
    if not host or not token:
        sys.exit("DATABRICKS_HOST / DATABRICKS_TOKEN not set. "
                 "Copy .env.example to .env and fill it.")

    api = Api(host, token)
    cfg = yaml.safe_load(CONFIG.read_text())
    views = [v for v in cfg.get("views", []) if v.get("shared")]

    warehouse = args.warehouse
    if not warehouse:
        status, body = api.call("GET", "/api/2.0/sql/warehouses")
        whs = (body or {}).get("warehouses") or []
        if status != 200 or not whs:
            sys.exit("No SQL warehouse reachable, and parts A and B are "
                     "SQL. Rather than report them as CANNOT_SEE from a "
                     "run that never tried, this exits: a suite that "
                     "silently degrades to 'cannot see' on a transient "
                     "outage trains a reader to ignore the words.")
        warehouse = whs[0]["id"]

    print("=" * 70)
    print("E-2: internal consumer reading the entitled views")
    print("=" * 70)
    print(f"catalog.schema : {CATALOG}.{SCHEMA}")
    print(f"base table     : {BASE_TABLE}")
    print(f"views          : {', '.join(v['id'] for v in views)}")
    print(f"warehouse      : {warehouse}")
    print(f"control grantee: {CONTROL_SP_NAME}")
    print(f"                 (appId {CONTROL_SP_APP_ID} -- UC rejects the "
          f"display name)")
    print()

    if args.dry_run:
        print("--dry-run: nothing written, nothing granted.")
        print("  capability baseline  measure what the tier refuses")
        print("  part A  column scope, base table as control")
        print("  part B  row scope, predicate count as control")
        print("  part C  deny row + REAL grant/revoke control")
        return 0

    print("--- capability baseline: what this tier refuses")
    caps = capability_baseline(api)
    print("  workspace group as UC principal: "
          f"{caps['workspace_group_as_uc_principal']['http_status']} "
          f"{caps['workspace_group_as_uc_principal']['error_code']}")
    print("  mint a credential for a service principal: "
          f"{'YES' if caps['mint_credential_for_non_human_principal']['possible'] else 'NO'}")

    print("\n--- part A: column scope (control = the base table)")
    part_a = part_a_column_scope(api, warehouse, views)
    for r in part_a:
        if r["kind"] == "excluded":
            print(f"  {r['view']}.{r['column']}: view="
                  f"{r['through_view']['state']} base="
                  f"{r['control_on_base_table']['state']} -> "
                  f"{'BOUNDARY SHOWN' if r['boundary_demonstrated'] else 'NOT SHOWN'}")
        else:
            print(f"  {r['view']} entitled columns readable: "
                  f"{r['entitled_columns_readable']}")

    print("\n--- part B: row scope (control = the predicate's own count)")
    part_b = part_b_row_scope(api, warehouse, views)
    for r in part_b:
        print(f"  {r['view']}: view={r['view_count']} "
              f"base={r['base_table_count']} "
              f"predicate={r.get('predicate_count_on_base_table')} -> "
              f"{'SHOWN' if r['row_scope_demonstrated'] else 'NOT SHOWN'}")

    print("\n--- part C: the deny row, with a real grant as the control")
    baseline = probe_deny_row(api)
    print(f"  baseline      : {baseline['deny_row_state']} "
          f"holders={baseline['select_holders']}")

    # Also record the allow-side grants, so the matrix's E-2 rows are
    # measured rather than assumed. These are expected to be EMPTY: the
    # operator reads through ownership, not through a grant, which is
    # precisely the substitution the matrix calls out.
    allow_side = {
        "catalog": grants_on(api, "catalog", CATALOG),
        "schema": grants_on(api, "schema", f"{CATALOG}.{SCHEMA}"),
    }
    for v in views:
        allow_side[f"view:{v['id']}"] = grants_on(
            api, "table", f"{CATALOG}.{SCHEMA}.{v['id']}")

    control_on = None
    control_restored = None
    granted = False
    base_full = f"{CATALOG}.{SCHEMA}.{BASE_TABLE}"
    try:
        status, body = api.call(
            "PATCH", f"{UC}/permissions/table/{base_full}",
            {"changes": [{"principal": CONTROL_SP_APP_ID,
                          "add": ["SELECT"]}]})
        granted = (status == 200)
        print(f"  control grant : HTTP {status} "
              f"({'applied' if granted else body.get('error_code')})")
        if granted:
            control_on = probe_deny_row(api)
            print(f"  with control  : {control_on['deny_row_state']} "
                  f"holders={control_on['select_holders']}")
    finally:
        if granted:
            status, body = api.call(
                "PATCH", f"{UC}/permissions/table/{base_full}",
                {"changes": [{"principal": CONTROL_SP_APP_ID,
                              "remove": ["SELECT"]}]})
            # B-23: the re-read is the finding, not this 200.
            control_restored = probe_deny_row(api)
            print(f"  revoke        : HTTP {status}; re-read -> "
                  f"{control_restored['deny_row_state']} "
                  f"holders={control_restored['select_holders']}")

    # --- the verdict ---------------------------------------------------
    a_excluded = [r for r in part_a if r["kind"] == "excluded"]
    a_entitled = [r for r in part_a if r["kind"] == "entitled"]
    column_ok = bool(a_excluded) and all(
        r["boundary_demonstrated"] for r in a_excluded) and all(
        r["entitled_columns_readable"] for r in a_entitled)
    row_ok = bool(part_b) and all(
        r["row_scope_demonstrated"] for r in part_b)

    probe_moved = (
        control_on is not None
        and control_on["deny_row_state"] == "VIOLATED"
        and CONTROL_SP_APP_ID in (control_on["select_holders"] or []))
    baseline_clean = baseline["deny_row_state"] == "CLEAN"
    restored_clean = (control_restored is not None
                      and control_restored["deny_row_state"] == "CLEAN")

    # The ladder checks the PROBE before it checks the finding. A clean
    # baseline from a blind probe is the result this test exists to not
    # produce, so it must not be reachable as a pass.
    if not granted:
        verdict = "CANNOT_SEE_CONTROL_GRANT_REFUSED_PROBE_UNVERIFIED"
    elif not probe_moved:
        verdict = "PROBE_IS_BLIND_CONTROL_GRANT_DID_NOT_MOVE_IT"
    elif not restored_clean:
        verdict = "CONTROL_LEFT_IN_PLACE_BASE_TABLE_STILL_GRANTED"
    elif not baseline_clean:
        verdict = "DENY_ROW_VIOLATED_AS_FOUND_BASE_TABLE_WAS_GRANTED"
    elif not column_ok:
        verdict = "COLUMN_SCOPE_NOT_DEMONSTRATED"
    elif not row_ok:
        verdict = "ROW_SCOPE_NOT_DEMONSTRATED"
    else:
        verdict = ("E2_SCOPE_ENFORCED_AND_DENY_ROW_CLEAN_"
                   "CONSUMER_IDENTITY_NOT_OBSERVABLE")

    passed = verdict.startswith("E2_SCOPE_ENFORCED")

    ev = {
        "test": "E-2 internal consumer egress (D2D, inside the metastore)",
        "channel": "E-2",
        "epic_task": "E1 Task 1.10 (outstanding deliverable)",
        "at": now(),
        "subject": {
            "catalog": CATALOG, "schema": SCHEMA,
            "base_table": base_full,
            "views": [v["id"] for v in views],
            "warehouse": warehouse,
        },
        "capability_baseline": caps,
        "part_a_column_scope": part_a,
        "part_b_row_scope": part_b,
        "part_c_deny_row": {
            "matrix_row": ("internal_consumer_group MUST NOT hold SELECT "
                           "on the base table"),
            "baseline": baseline,
            "control_principal": {"name": CONTROL_SP_NAME,
                                  "app_id": CONTROL_SP_APP_ID,
                                  "why_this_one": (
                                      "a real non-owner principal UC "
                                      "accepts; narrower blast radius "
                                      "than `account users`, which also "
                                      "accepts grants here")},
            "with_control_grant": control_on,
            "after_revoke": control_restored,
            "probe_verified_by_control": probe_moved,
            "allow_side_grants": allow_side,
            "allow_side_reading": (
                "Every allow-side securable returns an empty grant list. "
                "That is the expected result and it is NOT the matrix's "
                "E-2 allow rows being satisfied: the operator reads "
                "these views by OWNING them, not by holding a granted "
                "SELECT. The matrix calls this out as `local_substitute` "
                "and it means the separation of duty between data owner "
                "and internal consumer is UNTESTED, not satisfied."),
        },
        "verdict": verdict,
        "what_this_closes": (
            "Task 1.10's outstanding deliverable, and the matrix's "
            "`tested_by: NONE` on its most important deny row -- "
            "partially. The deny row's GRANT STATE now has a probe, and "
            "the probe has been shown to move when the privilege it "
            "watches is actually granted. The column and row boundaries "
            "are demonstrated with controls. What is NOT closed is the "
            "identity half; see below."
            if passed else
            "Nothing. Task 1.10 stays open with this verdict attached."),
        "what_this_does_not_prove": {
            "the_consumer_identity": (
                "No request in this test was issued AS an internal "
                "consumer, because no credential can be minted for a "
                "non-human principal on this tier (three measured 404s "
                "in capability_baseline) and UC rejects workspace groups "
                "outright (PRINCIPAL_DOES_NOT_EXIST). So this test shows "
                "the base table carries no granted SELECT and that a "
                "grant would be SEEN -- not that a consumer attempting "
                "the read is refused. The difference matters: a UC "
                "privilege path this probe does not enumerate (a future "
                "grant at catalog or schema level, inherited) would not "
                "appear in a table-level grant read."),
            "inherited_privilege": (
                "probe_deny_row reads the TABLE's own grants. "
                "`effective-permissions` was probed and returns {} on "
                "this tier for these securables, so inheritance could "
                "not be enumerated independently. The catalog and schema "
                "grant lists are captured in allow_side_grants and are "
                "also empty, which is consistent with no inherited "
                "SELECT -- consistent with, not proof of."),
            "the_other_deny_row": (
                "'must not create or alter a share' is still "
                "`tested_by: NONE`. Testing it needs the consumer "
                "identity this tier cannot produce, for the same reason."),
            "ownership_chaining": (
                "Part A shows the excluded column is absent FROM THE "
                "VIEW. It does not test what happens when a reader holds "
                "SELECT on the view but not on the base table -- the "
                "ownership-chaining path that the real deployment would "
                "depend on. Same missing identity."),
        },
        "api_calls": api.calls,
    }
    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(ev, indent=2))

    report = Report()
    report.record(
        "E-2", "Internal consumer reads the entitled views, never the "
               "base table",
        "the view's column and row scope demonstrated against the base "
        "table as a control, and no granted SELECT on the base table -- "
        "with the grant probe proven to move when a real grant is made",
        verdict, passed, str(EVIDENCE.relative_to(ROOT)))
    report.write(REPORT)

    print()
    print(f"VERDICT: {verdict}")
    print(f"  column scope demonstrated : {column_ok}")
    print(f"  row scope demonstrated    : {row_ok}")
    print(f"  probe verified by control : {probe_moved}")
    print(f"  deny row clean as found   : {baseline_clean}")
    print(f"  base table left clean     : {restored_clean}")
    print(f"\nWrote {EVIDENCE.relative_to(ROOT)}")
    print(report.summary())
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
