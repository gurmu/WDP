#!/usr/bin/env python3
"""
CONOPS test-data rule (Section 1.2): "tests use a non-sensitive test
dataset. Records and evidence hold names and metadata only, never tokens
or client data." This script generates a purely synthetic dataset and
loads it into a Unity Catalog table, so nothing real ever touches the
demo.

Creates: <UC_METASTORE_CATALOG>.<UC_SCHEMA>.<UC_TABLE>
with a couple of extra columns so later tests (T-04, "request a column
outside the grant") have something to withhold.
"""
import os
import sys
from pathlib import Path

def load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A blank value is an ABSENCE, not a value -- see docs/11
        # B-10b, where a placeholder `AWS_PROFILE=` in .env reached
        # botocore as a request for a profile named "".
        if not v.strip():
            continue
        os.environ.setdefault(k, v)

def main():
    load_env()
    from databricks.sdk import WorkspaceClient
    from databricks.sdk.service import sql as dbsql

    host = os.environ["DATABRICKS_HOST"]
    token = os.environ["DATABRICKS_TOKEN"]
    catalog = os.environ.get("UC_METASTORE_CATALOG", "awoz1227_demo")
    schema = os.environ.get("UC_SCHEMA", "opensharing_test")
    table = os.environ.get("UC_TABLE", "test_dataset")

    w = WorkspaceClient(host=host, token=token)

    warehouses = list(w.warehouses.list())
    if not warehouses:
        sys.exit(
            "No SQL warehouse found. Create a small Serverless SQL "
            "warehouse in the workspace UI first (Free Edition includes "
            "one by default)."
        )
    warehouse_id = warehouses[0].id
    print(f"Using SQL warehouse: {warehouses[0].name} ({warehouse_id})")

    statements = [
        f"CREATE CATALOG IF NOT EXISTS {catalog}",
        f"CREATE SCHEMA IF NOT EXISTS {catalog}.{schema}",
        f"""
        CREATE OR REPLACE TABLE {catalog}.{schema}.{table} (
            record_id        BIGINT,
            agency_name       STRING,
            use_case          STRING,
            region            STRING,
            record_date       DATE,
            metric_value      DOUBLE,
            internal_notes    STRING   -- intentionally NOT entitled to recipients (T-04)
        )
        """,
        f"""
        INSERT INTO {catalog}.{schema}.{table}
        SELECT
            id,
            element_at(array('Agency Alpha','Agency Bravo','Agency Charlie'), CAST((id % 3) + 1 AS INT)),
            'CDAO PSP7 egress demo',
            element_at(array('us-east','us-west','us-central'), CAST((id % 3) + 1 AS INT)),
            date_add(current_date(), CAST(-id AS INT)),
            round(rand() * 1000, 2),
            'synthetic internal note, not for external sharing'
        FROM range(1, 51) AS t(id)
        """,
    ]

    for stmt in statements:
        print(f"Executing:\n{stmt}\n")
        resp = w.statement_execution.execute_statement(
            warehouse_id=warehouse_id,
            statement=stmt,
            wait_timeout="30s",
        )
        print(f"  -> state: {resp.status.state}")
        if str(resp.status.state) == "StatementState.FAILED":
            sys.exit(f"  -> ERROR: {resp.status.error}")

    print(f"\nDone. Synthetic table ready at {catalog}.{schema}.{table}")
    print("Next: python3 02_create_share.py")

if __name__ == "__main__":
    main()
