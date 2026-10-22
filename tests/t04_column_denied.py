#!/usr/bin/env python3
"""T-04 rebuilt -- the column outside the grant. E1 Task 1.7, AC1 clause 1.3.

WHY THIS TEST IS BEING REBUILT RATHER THAN RUN
----------------------------------------------
docs/10 §10.7 D-2: T-04 as the CONOPS defines it proves nothing, because
the column it tested was INSIDE the grant. The share carried the base
table (§11.5), so a client asking for `internal_notes` was asking for a
column it had been granted, and whatever the test observed, it was not
"a column outside the grant is unreachable". Task 1.4 built the
replacement mechanism -- a view whose select list omits the column, in a
share that carries views only. This is the replacement test.

WHAT THE CONOPS CLAIMS
----------------------
AC1 clause 1.3: granular access via Unity Catalog, such that a consumer
reaches entitled data and nothing else. Task 1.7 names three assertions
and is emphatic about the order of their importance:

  "Assert on the ABSENCE OF THE COLUMN IN METADATA, not just on a failed
   query. A query can fail for a dozen uninteresting reasons; metadata
   absence is the thing AC1 clause 1.3 actually claims."

That instruction is §12.9 applied in advance. A failed query is the
cheapest possible evidence and the least attributable: an expired
credential, an IP allow-list denial, a missing grant, a typo'd column
and a genuine entitlement refusal all produce a failed query, and §11.7
B-38 has just shown how easily one is mistaken for another. Metadata
absence is different in kind. The column is not refused; it is NOT
THERE, in a schema the provider published and the recipient can read in
full. There is nothing to misconfigure and nothing to leak.

So this test has four assertions, graded separately, in descending order
of what they are worth:

  1. METADATA ABSENCE (the claim). `internal_notes` is absent from the
     shared table's published schema, and all six entitled columns are
     present. The second half matters as much as the first: a schema
     that is empty, or unparsable, or that omits everything, would also
     "not contain internal_notes".

  2. ROW SCOPE, MEASURED. The recipient's read yields 16 rows, not 50.
     Counted from the `numRecords` statistics the provider attaches to
     each file action, so no parquet is downloaded and no pre-signed URL
     is written anywhere (B-15). If the provider omits stats, this
     assertion returns CANNOT_SEE and says so, rather than inferring a
     count from the number of files.

  3. THE BASE TABLE IS NOT REACHABLE, ATTRIBUTABLY. A request for
     `test_dataset` at the share path must 404 -- but a 404 for "not in
     this share" and a 404 for "no such table anywhere" are the same
     code, so the sibling request for the view at the identical path
     shape is the positive control. A 404 on the base table beside a 200
     on the view, same credential, same share, same call shape, is
     attributable. A 404 on both is not, and grades CANNOT_SEE.
     Asserted across EVERY share the recipient can see, not just the one
     this test targets, because entitlements.yaml's own guard is written
     that way and a base table leaking through a second share would
     satisfy a single-share check.

  4. NAMING THE COLUMN IN A QUERY FAILS -- and this is the weakest of
     the four, deliberately recorded as such. The Delta Sharing query
     body's `predicateHints` are, by the protocol's own definition,
     HINTS: a server is permitted to ignore them. So a 200 here does not
     mean the column was accepted, and a 400 does not prove an access
     control exists. This assertion therefore grades into
     HINT_REJECTED / HINT_IGNORED_NOT_A_CONTROL / UNCLASSIFIED and is
     reported as colour around assertion 1 rather than as evidence for
     AC1. Writing it up as an entitlement refusal would be the §12.4
     error -- a verdict promoted past what was measured.

THE PROVIDER-SIDE NUMBERS AND WHERE THEY COME FROM
--------------------------------------------------
Assertion 2 compares against 50 and 16. Those are not constants invented
here: Task 1.4 counted them at apply time and
`evidence/entitlement-model.json` records `row_count: 50` for
`v_entitled_t2` and `row_count: 16` for `v_entitled_t2_us`. This test
reads them from that file rather than hard-coding them, and records the
file and the read value, because a constant in a test is re-asserted
rather than observed. If the file is missing or the numbers have moved,
the assertion degrades to "strictly fewer than the unscoped view and
more than zero" -- entitlement-model.json's own rule 5 wording -- and
says which of the two forms it used.

Note what that comparison is NOT. The 16 is a PROVIDER-side count of
the view; the count this test takes is a CONSUMER-side count through the
share. Agreement between them is the finding. Disagreement would be the
larger finding, and §11.7 B-32c is the open reason to expect it is
possible: a changed view definition propagating to a live share is
unmeasured.

OUTPUT
------
  evidence/t04-column-denied.json   the Report rows
  evidence/t04-report.json          the full observation record
"""
import argparse
import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))

from common import Report, load_env  # noqa: E402

CONFIG = ROOT / "iac" / "config" / "entitlements.yaml"
SECRETS = ROOT / "_secrets"
MODEL = ROOT / "evidence" / "entitlement-model.json"
EVIDENCE = ROOT / "evidence" / "t04-column-denied.json"
REPORT = ROOT / "evidence" / "t04-report.json"

RECIPIENT = "awoz1227-psp7-t2-us-recipient"
SHARE = "awoz1227-psp7-t2-us-share"
SCHEMA = "opensharing_test"
VIEW = "v_entitled_t2_us"
BASE_TABLE = "test_dataset"
EXCLUDED_COLUMN = "internal_notes"
ENTITLED_COLUMNS = ["record_id", "agency_name", "use_case", "region",
                    "record_date", "metric_value"]
UNSCOPED_VIEW = "v_entitled_t2"


def load_test_module(filename, modname):
    path = ROOT / "tests" / filename
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T02 = load_test_module("t02_ip_access_list.py", "t04_t02")
sharing_get = T02.sharing_get
scrub = T02.scrub
now = T02.now


# =====================================================================
# Assertion 1 -- metadata absence
# =====================================================================

def parse_schema_fields(raw):
    """Pull the column names out of a Delta Sharing metadata response.

    The response is NDJSON. The `metaData` line carries `schemaString`,
    which is itself a JSON document as a STRING -- so there are two
    parses, and a failure at either one has to be distinguishable from
    "the schema has no such column". That distinction is the whole point:
    an unparsable schema and a schema without `internal_notes` both make
    a naive `"internal_notes" not in text` check return True, and the
    naive check would be the silent negative in its purest form.
    """
    out = {"ndjson_lines": 0, "metadata_lines": 0, "fields": None,
           "parse": "NOT_ATTEMPTED"}
    lines = [ln for ln in (raw or "").splitlines() if ln.strip()]
    out["ndjson_lines"] = len(lines)
    blobs = []
    for ln in lines:
        try:
            obj = json.loads(ln)
        except Exception:  # noqa: BLE001
            continue
        meta = obj.get("metaData") or (obj.get("metadata") if isinstance(
            obj.get("metadata"), dict) else None)
        if isinstance(meta, dict):
            blobs.append(meta)
    out["metadata_lines"] = len(blobs)
    if not blobs:
        out["parse"] = "NO_METADATA_LINE"
        return out
    schema_string = None
    for meta in blobs:
        # Delta Sharing nests this differently across versions, so look
        # in both shapes rather than assuming one.
        schema_string = (meta.get("schemaString")
                         or ((meta.get("deltaMetadata") or {})
                             .get("schemaString")))
        if schema_string:
            break
    if not schema_string:
        out["parse"] = "METADATA_LINE_WITHOUT_SCHEMASTRING"
        return out
    try:
        schema = json.loads(schema_string)
    except Exception as exc:  # noqa: BLE001
        out["parse"] = "SCHEMASTRING_UNPARSABLE"
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    fields = schema.get("fields")
    if not isinstance(fields, list):
        out["parse"] = "SCHEMA_WITHOUT_FIELDS_LIST"
        return out
    out["fields"] = [f.get("name") for f in fields if isinstance(f, dict)]
    out["parse"] = "PARSED"
    return out


def assertion_1_metadata(endpoint, bearer, share, schema, table):
    res = {"assertion": "1 -- the excluded column is absent from the "
                        "published schema", "run_at": now(),
           "path": f"/shares/{share}/schemas/{schema}/tables/{table}/metadata"}
    status, raw = sharing_get(endpoint, bearer, res["path"])
    res["http_status"] = status
    parsed = parse_schema_fields(raw)
    res["schema_parse"] = parsed
    res["response_excerpt"] = scrub(raw or "")[:600]

    if status != 200:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            f"the metadata call returned HTTP {status}, so the schema was "
            f"never read. A column cannot be shown absent from a document "
            f"that was not retrieved.")
        return res
    if parsed["parse"] != "PARSED":
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            f"the metadata was retrieved but the schema could not be "
            f"parsed ({parsed['parse']}). An unparsable schema contains no "
            f"columns at all, which would satisfy a naive absence check "
            f"for the wrong reason -- §12.9.")
        return res

    fields = parsed["fields"] or []
    res["columns_published"] = fields
    res["excluded_column_present"] = EXCLUDED_COLUMN in fields
    missing_entitled = [c for c in ENTITLED_COLUMNS if c not in fields]
    res["entitled_columns_missing"] = missing_entitled

    if EXCLUDED_COLUMN in fields:
        res["verdict"] = "EXCLUDED_COLUMN_IS_PUBLISHED"
        res["conops_implication"] = (
            "AC1 clause 1.3 is falsified for this share. The column the "
            "entitlement model withholds is in the schema the recipient "
            "can read. This outranks every other result in this file.")
    elif missing_entitled:
        res["verdict"] = "ABSENT_BUT_SO_ARE_ENTITLED_COLUMNS"
        res["cannot_see_because"] = (
            f"{EXCLUDED_COLUMN} is absent, but so are the entitled columns "
            f"{missing_entitled}. A schema that omits almost everything "
            f"satisfies the absence check without demonstrating selective "
            f"withholding, which is what clause 1.3 claims.")
    else:
        res["verdict"] = "EXCLUDED_COLUMN_ABSENT_ENTITLED_COLUMNS_PRESENT"
        res["why_this_is_the_strong_form"] = (
            "The column is not refused, it is not present -- in a schema "
            "the recipient read in full, alongside all six columns that "
            "ARE entitled. Withholding by absence has nothing to "
            "misconfigure and no denial path to get wrong.")
    return res


# =====================================================================
# Assertion 2 -- row scope, counted from file statistics
# =====================================================================

def provider_side_counts():
    """Read Task 1.4's apply-time counts rather than hard-coding them."""
    out = {"source": str(MODEL.relative_to(ROOT)), "available": False}
    try:
        doc = json.loads(MODEL.read_text())
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
        return out
    found = {}

    def walk(node):
        if isinstance(node, dict):
            for key, val in node.items():
                if key in (VIEW, UNSCOPED_VIEW) and isinstance(val, dict):
                    if isinstance(val.get("row_count"), int):
                        found[key] = val["row_count"]
                walk(val)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(doc)
    out["counts"] = found
    out["available"] = VIEW in found
    return out


def count_rows_from_query(endpoint, bearer, share, schema, table):
    """Sum numRecords across file actions. No URL is ever retained.

    The query response carries one `file` action per parquet file, each
    with a `stats` blob. Summing `numRecords` gives the row count
    without fetching a byte of data, which is what keeps the pre-signed
    URLs out of this process entirely (B-15). The alternative -- count
    the file ACTIONS -- would be a different number wearing the same
    name, so when stats are absent this returns CANNOT_SEE instead of
    quietly substituting the file count.
    """
    res = {"path": f"/shares/{share}/schemas/{schema}/tables/{table}/query",
           "body": {"limitHint": 1000}}
    status, raw = sharing_get(endpoint, bearer, res["path"], method="POST",
                              body=res["body"], timeout=90)
    res["http_status"] = status
    if status != 200:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = f"query returned HTTP {status}"
        res["response_excerpt"] = scrub(raw or "")[:400]
        return res

    files, with_stats, total, stats_missing = 0, 0, 0, 0
    for ln in (raw or "").splitlines():
        if not ln.strip():
            continue
        try:
            obj = json.loads(ln)
        except Exception:  # noqa: BLE001
            continue
        fa = obj.get("file")
        if not isinstance(fa, dict):
            continue
        files += 1
        stats = fa.get("stats")
        if isinstance(stats, str):
            try:
                stats = json.loads(stats)
            except Exception:  # noqa: BLE001
                stats = None
        if isinstance(stats, dict) and isinstance(stats.get("numRecords"), int):
            with_stats += 1
            total += stats["numRecords"]
        else:
            stats_missing += 1

    res["file_actions"] = files
    res["file_actions_with_numrecords"] = with_stats
    res["file_actions_without_numrecords"] = stats_missing
    res["rows_counted"] = total if with_stats else None
    # Deliberately NOT written: the `url` field of any file action, and
    # the raw response. A pre-signed URL in an evidence file is a
    # credential in an evidence file.
    res["response_withheld_because"] = (
        "the query response contains pre-signed object-store URLs; only "
        "derived counts are recorded -- §11.7 B-15")

    if not files:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            "the query returned 200 with no file actions. Zero rows and "
            "an unserved table are the same observation here.")
    elif stats_missing:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            f"{stats_missing} of {files} file actions carry no numRecords "
            f"statistic, so the total is a floor rather than a count. "
            f"Substituting the file count would be a different number "
            f"under the same name.")
    else:
        res["verdict"] = "ROWS_COUNTED"
    return res


def assertion_2_row_scope(endpoint, bearer, share, schema, table):
    res = {"assertion": "2 -- row scope is observable from the consumer side",
           "run_at": now()}
    counted = count_rows_from_query(endpoint, bearer, share, schema, table)
    res["consumer_side"] = counted
    prov = provider_side_counts()
    res["provider_side"] = prov

    if counted["verdict"] != "ROWS_COUNTED":
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = counted.get("cannot_see_because")
        return res

    rows = counted["rows_counted"]
    res["rows_observed"] = rows
    expected = (prov.get("counts") or {}).get(VIEW)
    unscoped = (prov.get("counts") or {}).get(UNSCOPED_VIEW)
    res["comparison_form"] = None

    if isinstance(expected, int):
        res["comparison_form"] = "EXACT_AGAINST_APPLY_TIME_COUNT"
        res["expected"] = expected
        if rows == expected:
            res["verdict"] = "ROW_SCOPE_AGREES_WITH_PROVIDER_SIDE"
        else:
            res["verdict"] = "ROW_SCOPE_DISAGREES_WITH_PROVIDER_SIDE"
            res["conops_implication"] = (
                f"The provider measured {expected} rows in {VIEW} at apply "
                f"time and the recipient reads {rows} through the share. "
                f"That gap is the §11.7 B-32c question made concrete: "
                f"propagation from a view definition to a live share is "
                f"unmeasured, and this is a measurement of it.")
    elif isinstance(unscoped, int):
        res["comparison_form"] = "WEAK_STRICTLY_FEWER_AND_NONZERO"
        res["unscoped_count"] = unscoped
        res["verdict"] = ("ROW_SCOPE_IN_EFFECT_WEAK_FORM"
                          if 0 < rows < unscoped
                          else "ROW_SCOPE_NOT_DEMONSTRATED")
        res["weak_form_because"] = (
            f"{MODEL.name} records no row_count for {VIEW}, so the "
            f"assertion falls back to entitlement-model.json rule 5's own "
            f"wording: strictly fewer than the unscoped view and more than "
            f"zero. An empty view would also satisfy 'fewer'.")
    else:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            f"no provider-side count is available from {MODEL.name}, so "
            f"{rows} rows is a number with nothing to compare against. "
            f"A constant written into this test would be re-asserted, "
            f"not observed.")
    return res


# =====================================================================
# Assertion 3 -- the base table is not reachable, attributably
# =====================================================================

def assertion_3_base_table(endpoint, bearer, schema):
    res = {"assertion": "3 -- the base table is not reachable through any "
                        "share the recipient can see", "run_at": now()}

    st, raw = sharing_get(endpoint, bearer, "/shares")
    res["shares_http_status"] = st
    if st != 200:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = (
            f"/shares returned HTTP {st}, so the set of shares to check "
            f"across is unknown. Checking only the share named in this "
            f"file would satisfy the assertion while leaving a second "
            f"share unexamined.")
        return res
    try:
        shares = [s.get("name") for s in (json.loads(raw).get("items") or [])]
    except Exception as exc:  # noqa: BLE001
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = f"/shares unparsable: {exc}"
        return res
    res["shares_visible"] = shares

    per_share = []
    for share in shares:
        row = {"share": share}
        # The positive control and the subject, at the identical path
        # shape, in the same second, with the same credential. Without
        # the control, a 404 on the base table is just a 404.
        base_path = f"/shares/{share}/schemas/{schema}/tables/{BASE_TABLE}/metadata"
        b_st, b_raw = sharing_get(endpoint, bearer, base_path)
        row["base_table_status"] = b_st
        row["base_table_excerpt"] = scrub(b_raw or "")[:240]

        t_st, t_raw = sharing_get(
            endpoint, bearer, f"/shares/{share}/schemas/{schema}/tables")
        row["table_list_status"] = t_st
        names = []
        if t_st == 200:
            try:
                names = [t.get("name")
                         for t in (json.loads(t_raw).get("items") or [])]
            except Exception:  # noqa: BLE001
                names = []
        row["tables_listed"] = names
        row["base_table_in_listing"] = BASE_TABLE in names

        control = None
        if names:
            control_path = (f"/shares/{share}/schemas/{schema}/tables/"
                            f"{names[0]}/metadata")
            c_st, _ = sharing_get(endpoint, bearer, control_path)
            control = {"table": names[0], "status": c_st}
        row["positive_control"] = control

        if row["base_table_in_listing"] or (200 <= b_st < 300):
            row["verdict"] = "BASE_TABLE_REACHABLE"
        elif not control or control["status"] != 200:
            row["verdict"] = "CANNOT_SEE_NO_POSITIVE_CONTROL"
            row["cannot_see_because"] = (
                "no sibling object in this share answered 200, so a 404 on "
                "the base table is indistinguishable from a share whose "
                "objects are all unreachable.")
        else:
            row["verdict"] = "BASE_TABLE_ABSENT_SIBLING_READABLE"
        per_share.append(row)

    res["per_share"] = per_share
    verdicts = {r["verdict"] for r in per_share}
    if not per_share:
        res["verdict"] = "CANNOT_SEE"
        res["cannot_see_because"] = "the recipient can see no shares at all"
    elif "BASE_TABLE_REACHABLE" in verdicts:
        res["verdict"] = "BASE_TABLE_REACHABLE_IN_AT_LEAST_ONE_SHARE"
        res["conops_implication"] = (
            "§11.5's finding is not fully remediated. The base table is "
            "reachable through a share, which makes every column-scope "
            "claim in AC1 clause 1.3 void for that share.")
    elif verdicts <= {"BASE_TABLE_ABSENT_SIBLING_READABLE"}:
        res["verdict"] = "BASE_TABLE_ABSENT_FROM_EVERY_VISIBLE_SHARE"
    else:
        res["verdict"] = "PARTIAL_SOME_SHARES_LACK_A_POSITIVE_CONTROL"
    return res


# =====================================================================
# Assertion 4 -- naming the column in a query (the weak one)
# =====================================================================

def assertion_4_named_column(endpoint, bearer, share, schema, table):
    res = {"assertion": "4 -- naming the excluded column in a query "
                        "(WEAK -- predicateHints are advisory)",
           "run_at": now(),
           "weak_because": (
               "The Delta Sharing protocol defines predicateHints as hints: "
               "a server MAY ignore them. So a 200 does not mean the column "
               "was accepted and a 400 does not prove an access control. "
               "This is colour around assertion 1, not evidence for AC1.")}
    body = {"limitHint": 10,
            "predicateHints": [f"{EXCLUDED_COLUMN} IS NOT NULL"]}
    path = f"/shares/{share}/schemas/{schema}/tables/{table}/query"
    status, raw = sharing_get(endpoint, bearer, path, method="POST",
                              body=body, timeout=90)
    res["http_status"] = status
    res["sent_predicate"] = body["predicateHints"]
    # Only the error text, if any -- a 200 body carries pre-signed URLs.
    res["response_excerpt"] = (scrub(raw or "")[:400] if status != 200
                               else "<withheld: 200 body carries pre-signed URLs>")
    if 200 <= status < 300:
        res["verdict"] = "HINT_IGNORED_NOT_A_CONTROL"
        res["reading"] = (
            "The server accepted a request naming a column that is not in "
            "the schema. That is permitted protocol behaviour for a hint "
            "and says nothing about entitlement. The column's absence from "
            "the schema (assertion 1) is the finding; this is not.")
    elif status in (400, 422):
        res["verdict"] = "HINT_REJECTED"
        res["reading"] = (
            "The server rejected the request. Recorded, but still not "
            "promoted to entitlement evidence: a rejection for an unknown "
            "column name and a rejection for an unentitled column are the "
            "same response here.")
    elif status in (401, 403):
        res["verdict"] = "REFUSED_BY_AUTHZ"
    elif status == 0:
        res["verdict"] = "CANNOT_SEE_LOCAL_NETWORK_ERROR"
    else:
        res["verdict"] = f"UNCLASSIFIED_HTTP_{status}"
    return res


# =====================================================================
# main
# =====================================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipient", default=RECIPIENT)
    ap.add_argument("--share", default=SHARE)
    ap.add_argument("--schema", default=SCHEMA)
    ap.add_argument("--table", default=VIEW)
    args = ap.parse_args()

    print("T-04 rebuilt -- the column outside the grant")
    print("=" * 68)
    load_env()

    cred_path = SECRETS / f"credential-{args.recipient}.json"
    if not cred_path.exists():
        sys.exit(
            f"Missing {cred_path.relative_to(ROOT)}.\n"
            f"T-04 reads AS THE RECIPIENT. Run:\n"
            f"  python3 scripts/28_activate_credential.py --recipient "
            f"{args.recipient} --activate --also-rewrite")
    cred = json.loads(cred_path.read_text())
    endpoint, bearer = cred.get("endpoint"), cred.get("bearerToken")
    if not endpoint or not bearer:
        sys.exit(f"{cred_path.relative_to(ROOT)} is not a usable profile.")

    print(f"recipient: {args.recipient}")
    print(f"share:     {args.share}")
    print(f"object:    {args.schema}.{args.table}")
    print(f"withheld:  {EXCLUDED_COLUMN}")
    print(f"expires:   {cred.get('expirationTime')}")

    out = {"test": "T-04 (rebuilt)", "epic": "E1", "task": "1.7",
           "ac": "AC1 clause 1.3", "run_at": now(),
           "closes": ["D-2", "EKI-1", "RKI-1"],
           "recipient": args.recipient, "share": args.share,
           "object": f"{args.schema}.{args.table}",
           "excluded_column": EXCLUDED_COLUMN,
           "credential_expires": cred.get("expirationTime"),
           "assertions": {}}
    rep = Report()

    print("\nASSERTION 1 -- the excluded column is absent from the schema")
    a1 = assertion_1_metadata(endpoint, bearer, args.share, args.schema,
                              args.table)
    out["assertions"]["1_metadata_absence"] = a1
    print(f"  http {a1['http_status']}  parse "
          f"{a1['schema_parse']['parse']}  columns "
          f"{a1.get('columns_published')}")
    print(f"  verdict: {a1['verdict']}")

    print("\nASSERTION 2 -- row scope, counted from file statistics")
    a2 = assertion_2_row_scope(endpoint, bearer, args.share, args.schema,
                               args.table)
    out["assertions"]["2_row_scope"] = a2
    cs = a2.get("consumer_side") or {}
    print(f"  files {cs.get('file_actions')}  rows "
          f"{cs.get('rows_counted')}  expected {a2.get('expected')}  "
          f"form {a2.get('comparison_form')}")
    print(f"  verdict: {a2['verdict']}")

    print("\nASSERTION 3 -- the base table is not reachable in any share")
    a3 = assertion_3_base_table(endpoint, bearer, args.schema)
    out["assertions"]["3_base_table"] = a3
    for row in a3.get("per_share", []):
        print(f"    {row['share']:34s} base={row['base_table_status']:>4}  "
              f"control={(row.get('positive_control') or {}).get('status')}  "
              f"{row['verdict']}")
    print(f"  verdict: {a3['verdict']}")

    print("\nASSERTION 4 -- naming the column in a query (weak)")
    a4 = assertion_4_named_column(endpoint, bearer, args.share, args.schema,
                                  args.table)
    out["assertions"]["4_named_column"] = a4
    print(f"  http {a4['http_status']}  verdict: {a4['verdict']}")

    # ---- grading ----
    rep.record(
        "T-04.1",
        f"{EXCLUDED_COLUMN} is absent from the shared object's published schema",
        "the column is absent AND all six entitled columns are present",
        a1["verdict"],
        a1["verdict"] == "EXCLUDED_COLUMN_ABSENT_ENTITLED_COLUMNS_PRESENT",
        "evidence/t04-report.json")
    rep.record(
        "T-04.2", "Row scope is observable from the consumer side",
        "the recipient's row count agrees with the provider's apply-time "
        "count for the scoped view",
        a2["verdict"],
        a2["verdict"] in ("ROW_SCOPE_AGREES_WITH_PROVIDER_SIDE",
                          "ROW_SCOPE_IN_EFFECT_WEAK_FORM"),
        "evidence/t04-report.json")
    rep.record(
        "T-04.3", f"{BASE_TABLE} is not reachable through any visible share",
        "absent from every share, with a readable sibling object in each as "
        "the positive control",
        a3["verdict"],
        a3["verdict"] == "BASE_TABLE_ABSENT_FROM_EVERY_VISIBLE_SHARE",
        "evidence/t04-report.json")
    rep.record(
        "T-04.4", "Naming the excluded column in a query (recorded, not graded)",
        "recorded for completeness; predicateHints are advisory so no "
        "outcome here is evidence for AC1",
        a4["verdict"], True, "evidence/t04-report.json")

    strong = a1["verdict"] == "EXCLUDED_COLUMN_ABSENT_ENTITLED_COLUMNS_PRESENT"
    base_ok = a3["verdict"] == "BASE_TABLE_ABSENT_FROM_EVERY_VISIBLE_SHARE"
    rows_ok = a2["verdict"] in ("ROW_SCOPE_AGREES_WITH_PROVIDER_SIDE",
                                "ROW_SCOPE_IN_EFFECT_WEAK_FORM")
    if a1["verdict"] == "EXCLUDED_COLUMN_IS_PUBLISHED" or \
            a3["verdict"] == "BASE_TABLE_REACHABLE_IN_AT_LEAST_ONE_SHARE":
        out["verdict"] = "AC1_CLAUSE_1_3_FALSIFIED"
    elif strong and base_ok and rows_ok:
        out["verdict"] = "COLUMN_AND_ROW_SCOPE_PROVEN_FROM_THE_CONSUMER_SIDE"
        out["closes_d2"] = (
            "D-2 is closed: T-04 now tests a column that is genuinely "
            "outside the grant, asserts on metadata absence rather than on "
            "a failed query, and carries a positive control for every "
            "negative it reports.")
    elif strong and base_ok:
        out["verdict"] = "COLUMN_SCOPE_PROVEN_ROW_SCOPE_NOT_MEASURED"
    else:
        out["verdict"] = "CANNOT_SEE"

    rep.write(EVIDENCE)
    REPORT.write_text(json.dumps(out, indent=2, default=str))
    print("\n" + "=" * 68)
    print(f"T-04 VERDICT: {out['verdict']}")
    print(f"\nWrote {REPORT.relative_to(ROOT)}")
    return 0 if strong and base_ok else 1


if __name__ == "__main__":
    sys.exit(main())
