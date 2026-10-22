#!/usr/bin/env python3
"""
E1 Task 1.10 -- the provider-side substrate on GLOVASHU, for T-19.

Probe 15 now reports the ingress provider chain blocked on exactly one
thing: there is no table on glovashu to put in the share. create_share,
create_recipient_for_primary and grant_share_to_recipient are all
PERMITTED; add_table_to_share is NOT_ATTEMPTED for want of a subject.
This script creates that subject.

Three design constraints, none of them cosmetic.

1. NOT `workspace`.
   .env currently names GLOVASHU_CATALOG=workspace. That is one of the
   names .env.example explicitly forbids, and it is the name that
   produced the false SAME_METASTORE reading in docs/12 section 12.9:
   `workspace` exists in BOTH workspaces, so a fully-qualified name
   built from it resolves on either side and tells you nothing about
   which side answered. This script refuses to run against any catalog
   name that is not unique to glovashu, and refuses to run against the
   primary's catalog name as well. The prohibition moves out of a
   comment in a template and into executable code.

2. The rows must be ATTRIBUTABLE to glovashu.
   The primary already holds a synthetic table from script 01 with the
   same shape. If glovashu's table carried the same 50 rows of the same
   generated content, then a successful read during T-19 would prove
   that SOME table was read -- not that the INGRESS direction worked.
   A test whose pass is indistinguishable from the pass of the thing it
   is not testing is the section 12.9 shape with a green tick on it. So
   every row here carries an origin_metastore column stamped with
   glovashu's metastore id, the row count is deliberately different
   from script 01's, and T-19 asserts on both. The read then cannot
   succeed by accidentally hitting the local copy.

3. Verified by reading back, not by the statement state.
   A SUCCEEDED state on an INSERT says the statement ran. It does not
   say the rows are there, visible to this principal, or stamped the way
   we intended. The script SELECTs the count and the distinct origin
   back out and compares them to what it asked for, and writes both the
   intent and the observation to evidence.

Writes evidence/glovashu-provider-dataset.json

Usage:
    python3 scripts/17_create_glovashu_provider_dataset.py            # plan
    python3 scripts/17_create_glovashu_provider_dataset.py --apply
"""
import argparse
import datetime
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "evidence" / "glovashu-provider-dataset.json"

# Names that exist by default in a Databricks workspace, or that are
# reserved. A catalog whose name is shared by both metastores cannot
# distinguish them, which is the whole point of the glovashu side.
FORBIDDEN_CATALOGS = {"workspace", "main", "hive_metastore", "samples",
                      "system", "default", "dbdemos"}

# Deliberately NOT 50. Script 01 loads 50 rows into the primary.
ROW_COUNT = 37

SUGGESTED_CATALOG = "awoz1227_glovashu"
SUGGESTED_SCHEMA = "opensharing_provider"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit("No .env found.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A blank value is an ABSENCE, not a value (B-10b).
        if not v.strip():
            continue
        os.environ.setdefault(k.strip(), v.strip())


def refuse(reason, remedy):
    print()
    print("REFUSING TO RUN")
    print("=" * 68)
    print(reason)
    print()
    print(remedy)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps({
        "script": "17_create_glovashu_provider_dataset",
        "run_at": now(),
        "verdict": "REFUSED_BY_PRECONDITION",
        "reason": reason,
        "remedy": remedy,
        "means": ("Nothing was created. A precondition that is checked "
                  "only in a template comment is not checked at all, so "
                  "this one is enforced here."),
    }, indent=2))
    print(f"\nWrote {OUT.relative_to(REPO)}")
    sys.exit(2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="actually create the catalog, schema and table")
    args = ap.parse_args()

    load_env()

    for var in ("GLOVASHU_HOST", "GLOVASHU_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")

    host = os.environ["GLOVASHU_HOST"].strip().rstrip("/")
    token = os.environ["GLOVASHU_TOKEN"].strip()
    catalog = os.environ.get("GLOVASHU_CATALOG", "").strip()
    schema = os.environ.get("UC_SCHEMA_GLOVASHU", "").strip()
    # Resolved by the same rule probe 15 uses, in the same order.
    table = (os.environ.get("GLOVASHU_TABLE", "").strip()
             or os.environ.get("UC_TABLE", "").strip()
             or "test_dataset")
    primary_catalog = os.environ.get("UC_METASTORE_CATALOG", "").strip()

    # ---- preconditions, before any API call ----
    if not catalog:
        refuse("GLOVASHU_CATALOG is unset or blank in .env.",
               f"Set:  GLOVASHU_CATALOG={SUGGESTED_CATALOG}")
    if catalog.lower() in FORBIDDEN_CATALOGS:
        refuse(
            f"GLOVASHU_CATALOG={catalog!r} is a default or reserved catalog "
            f"name that exists in BOTH workspaces.\n"
            f"A fully-qualified name built from it resolves on either side, "
            f"so a read cannot be attributed to glovashu. This is the name "
            f"that produced the false SAME_METASTORE reading in docs/12 "
            f"section 12.9.",
            f"Edit .env:  GLOVASHU_CATALOG={SUGGESTED_CATALOG}\n"
            f"            UC_SCHEMA_GLOVASHU={SUGGESTED_SCHEMA}\n"
            f"then re-run this script.")
    if primary_catalog and catalog.lower() == primary_catalog.lower():
        refuse(
            f"GLOVASHU_CATALOG and UC_METASTORE_CATALOG are both "
            f"{catalog!r}.\nThe two sides would be indistinguishable by "
            f"name, which defeats T-19's ingress claim.",
            f"Edit .env:  GLOVASHU_CATALOG={SUGGESTED_CATALOG}")
    if not schema:
        refuse("UC_SCHEMA_GLOVASHU is unset or blank in .env.",
               f"Set:  UC_SCHEMA_GLOVASHU={SUGGESTED_SCHEMA}")

    full = f"{catalog}.{schema}.{table}"

    res = {
        "script": "17_create_glovashu_provider_dataset",
        "task": "E1 Task 1.10 -> T-19 provider substrate",
        "run_at": now(),
        "mode": "apply" if args.apply else "plan",
        "side": "glovashu (PROVIDER for the ingress direction)",
        "host": host,
        "target": {"catalog": catalog, "schema": schema, "table": table,
                   "full_name": full},
        "preconditions": {
            "verdict": "PASSED",
            "catalog_not_default_or_reserved": True,
            "catalog_differs_from_primary": (
                primary_catalog.lower() != catalog.lower()
                if primary_catalog else "primary catalog not set in .env"),
            "means": ("The catalog name is unique to glovashu, so a "
                      "fully-qualified read that succeeds could only have "
                      "been answered by glovashu."),
        },
    }

    print("Glovashu provider-side dataset")
    print("=" * 68)
    print(f"  target : {full}")
    print(f"  rows   : {ROW_COUNT}  (script 01 loads 50 on the primary, "
          f"on purpose)")
    print(f"  stamp  : origin_metastore = glovashu's metastore id")
    print()

    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(host=host, token=token)

    # Metastore id is the stamp. Read it rather than taking it from .env,
    # so the stamp cannot disagree with the metastore that holds the row.
    meta = w.metastores.summary()
    metastore_id = meta.metastore_id
    res["origin_metastore_id"] = metastore_id
    res["origin_metastore_id_source"] = "GET /metastore_summary on glovashu"
    print(f"  origin : {metastore_id}")

    warehouses = list(w.warehouses.list())
    if not warehouses:
        res["verdict"] = "BLOCKED_NO_WAREHOUSE"
        OUT.write_text(json.dumps(res, indent=2))
        sys.exit("No SQL warehouse on glovashu.")
    wh = warehouses[0]
    res["warehouse"] = {"name": wh.name, "id": wh.id, "state": str(wh.state)}
    print(f"  compute: {wh.name} ({wh.state}) -- serverless auto-starts")
    print()

    statements = [
        ("create_catalog", f"CREATE CATALOG IF NOT EXISTS {catalog}"),
        ("create_schema", f"CREATE SCHEMA IF NOT EXISTS {catalog}.{schema}"),
        ("create_table", f"""
            CREATE OR REPLACE TABLE {full} (
                record_id        BIGINT,
                agency_name      STRING,
                use_case         STRING,
                region           STRING,
                record_date      DATE,
                metric_value     DOUBLE,
                origin_metastore STRING,
                internal_notes   STRING
            )
         """),
        ("insert_rows", f"""
            INSERT INTO {full}
            SELECT
                id,
                element_at(array('Agency Delta','Agency Echo',
                                 'Agency Foxtrot'), CAST((id % 3) + 1 AS INT)),
                'CONOPS 2.4.1 D2D ingress demo',
                element_at(array('eu-west','eu-north','eu-south'),
                           CAST((id % 3) + 1 AS INT)),
                date_add(current_date(), CAST(-id AS INT)),
                round(rand() * 1000, 2),
                '{metastore_id}',
                'synthetic internal note, not for external sharing'
            FROM range(1, {ROW_COUNT + 1}) AS t(id)
         """),
    ]

    if not args.apply:
        res["verdict"] = "PLANNED"
        res["statements"] = [{"name": n, "sql": " ".join(s.split())}
                             for n, s in statements]
        print("Plan only. Statements that WOULD run:")
        for n, s in statements:
            print(f"  [{n}] {' '.join(s.split())[:110]}")
        print()
        print("To create it:")
        print("    python3 scripts/17_create_glovashu_provider_dataset.py "
              "--apply")
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(res, indent=2))
        print(f"\nWrote {OUT.relative_to(REPO)}")
        return 0

    res["statements"] = []
    for name, sql in statements:
        flat = " ".join(sql.split())
        resp = w.statement_execution.execute_statement(
            warehouse_id=wh.id, statement=sql, wait_timeout="30s")
        state = str(resp.status.state)
        entry = {"name": name, "sql": flat[:400], "state": state}
        if "FAILED" in state:
            entry["error"] = str(resp.status.error)[:500]
            res["statements"].append(entry)
            res["verdict"] = "FAILED"
            OUT.parent.mkdir(parents=True, exist_ok=True)
            OUT.write_text(json.dumps(res, indent=2))
            print(f"  [FAIL] {name}: {resp.status.error}")
            print(f"\nWrote {OUT.relative_to(REPO)}")
            return 1
        res["statements"].append(entry)
        print(f"  [ok ] {name}: {state}")

    # ---- verify by reading back, not by trusting the INSERT ----
    print()
    print("Verifying by read-back")
    check_sql = (f"SELECT count(*) AS n, "
                 f"count(DISTINCT origin_metastore) AS n_origins, "
                 f"min(origin_metastore) AS origin FROM {full}")
    resp = w.statement_execution.execute_statement(
        warehouse_id=wh.id, statement=check_sql, wait_timeout="30s")
    rows = (resp.result.data_array if resp.result else None) or []
    observed = rows[0] if rows else []
    n = int(observed[0]) if len(observed) > 0 else None
    n_origins = int(observed[1]) if len(observed) > 1 else None
    origin = observed[2] if len(observed) > 2 else None

    res["verification"] = {
        "query": check_sql,
        "intended": {"rows": ROW_COUNT, "distinct_origins": 1,
                     "origin": metastore_id},
        "observed": {"rows": n, "distinct_origins": n_origins,
                     "origin": origin},
        "row_count_matches": n == ROW_COUNT,
        "stamp_matches": origin == metastore_id and n_origins == 1,
        "distinct_from_primary_row_count": n != 50,
        "means": ("A SUCCEEDED INSERT says the statement ran. These three "
                  "say the rows exist, carry one origin, and that the "
                  "origin is the metastore we read the id from -- so a "
                  "T-19 read that returns these rows can only have been "
                  "answered by glovashu."),
    }
    v = res["verification"]
    ok = v["row_count_matches"] and v["stamp_matches"] and \
        v["distinct_from_primary_row_count"]
    res["verdict"] = "CREATED_AND_VERIFIED" if ok else "CREATED_UNVERIFIED"
    print(f"  rows            : {n} (wanted {ROW_COUNT}) "
          f"-> {'ok' if v['row_count_matches'] else 'MISMATCH'}")
    print(f"  distinct origins: {n_origins} (wanted 1)")
    print(f"  origin stamp    : {origin}")
    print(f"  -> {'ok' if v['stamp_matches'] else 'MISMATCH'}")
    print(f"\n  verdict: {res['verdict']}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2))
    print(f"\nWrote {OUT.relative_to(REPO)}")
    if ok:
        print()
        print(f"Set this in .env so probe 15 and T-19 look in the right "
              f"place:")
        print(f"    GLOVASHU_TABLE={table}")
        print("Then: python3 scripts/15_probe_d2d_prereqs.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
