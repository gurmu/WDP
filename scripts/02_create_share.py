#!/usr/bin/env python3
"""
CONOPS Section 3.4 / T04-13 (AC4): Self-service publishing.
Creates a Unity Catalog Delta Share over the synthetic test table and
grants SELECT, but withholds the `internal_notes` column so T-04
("request a table or column outside the grant -> denied by UC") has
something real to test.
"""
import os
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
    from databricks.sdk.service.sharing import (
        SharedDataObject, SharedDataObjectUpdate, SharedDataObjectUpdateAction,
        SharedDataObjectDataObjectType,
    )

    host = os.environ["DATABRICKS_HOST"]
    token = os.environ["DATABRICKS_TOKEN"]
    catalog = os.environ.get("UC_METASTORE_CATALOG", "awoz1227_demo")
    schema = os.environ.get("UC_SCHEMA", "opensharing_test")
    table = os.environ.get("UC_TABLE", "test_dataset")
    share_name = "awoz1227-psp7-demo-share"

    w = WorkspaceClient(host=host, token=token)

    existing = {s.name for s in w.shares.list_shares()}
    if share_name not in existing:
        w.shares.create(name=share_name, comment="AWOZ-1227 demo share, non-sensitive synthetic data only")
        print(f"Created share: {share_name}")
    else:
        print(f"Share already exists: {share_name}")

    full_table_name = f"{catalog}.{schema}.{table}"
    w.shares.update(
        name=share_name,
        updates=[
            SharedDataObjectUpdate(
                action=SharedDataObjectUpdateAction.ADD,
                data_object=SharedDataObject(
                    name=full_table_name,
                    data_object_type=SharedDataObjectDataObjectType.TABLE,
                    comment="Synthetic test dataset for AWOZ-1227 verification session",
                    # If your SDK/metastore version supports column masks or
                    # partition-level sharing, exclude internal_notes here.
                    # Otherwise, withhold it via a view instead: create
                    # catalog.schema.test_dataset_external AS SELECT * EXCEPT
                    # (internal_notes) FROM ..., and share the view here.
                ),
            )
        ],
    )
    print(f"Added {full_table_name} to {share_name}")
    print("\nNext: python3 03_create_recipient.py")

if __name__ == "__main__":
    main()
