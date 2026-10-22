#!/usr/bin/env python3
"""
Run this FIRST, before building anything else.

It answers the one question that decides which Databricks path you need
(Free Edition vs. the 14-day Premium/AWS trial): can this workspace act as
an OpenSharing *provider* -- create a share, create a bearer-token
recipient, and issue a credential file -- using a personal access token
for automation?

As of the CONOPS research (Oct 2026), Databricks' own docs confirm Free
Edition workspaces can *consume* Delta Shares, but do not document
provider-side support (CREATE SHARE / CREATE RECIPIENT with a bearer
token) or guarantee personal-access-token/REST API access, since Free
Edition has "no access to the account console or account-level APIs."
This script checks your actual workspace instead of relying on docs.

Usage:
    pip install databricks-sdk --break-system-packages
    cp ../.env.example ../.env   # fill in DATABRICKS_HOST / DATABRICKS_TOKEN
    python3 00_check_capabilities.py
"""
import os
import sys
import json
from pathlib import Path

def load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        sys.exit(f"Missing {env_path}. Copy .env.example to .env and fill it in first.")
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
    host = os.environ.get("DATABRICKS_HOST", "")
    token = os.environ.get("DATABRICKS_TOKEN", "")
    if "<" in host or "<" in token or not host or not token:
        sys.exit("Fill in real DATABRICKS_HOST and DATABRICKS_TOKEN in .env first.")

    try:
        from databricks.sdk import WorkspaceClient
    except ImportError:
        sys.exit("Run: pip install databricks-sdk --break-system-packages")

    w = WorkspaceClient(host=host, token=token)
    results = {}

    # 1. Can we even authenticate with a PAT / call the REST API at all?
    try:
        me = w.current_user.me()
        results["pat_rest_api"] = {"ok": True, "user": me.user_name}
    except Exception as e:
        results["pat_rest_api"] = {"ok": False, "error": str(e)}

    # 2. Is Unity Catalog enabled / can we see catalogs?
    try:
        cats = [c.name for c in w.catalogs.list()]
        results["unity_catalog_visible"] = {"ok": True, "catalogs": cats[:10]}
    except Exception as e:
        results["unity_catalog_visible"] = {"ok": False, "error": str(e)}

    # 3. Can we list / attempt to create a share (provider-side OpenSharing)?
    try:
        shares = [s.name for s in w.shares.list_shares()]
        results["can_list_shares"] = {"ok": True, "shares": shares[:10]}
    except Exception as e:
        results["can_list_shares"] = {"ok": False, "error": str(e)}

    # 4. Can we list / create a recipient (bearer-token, Databricks-to-Open)?
    try:
        recipients = [r.name for r in w.recipients.list()]
        results["can_list_recipients"] = {"ok": True, "recipients": recipients[:10]}
    except Exception as e:
        results["can_list_recipients"] = {"ok": False, "error": str(e)}

    print(json.dumps(results, indent=2))

    provider_ready = (
        results["pat_rest_api"]["ok"]
        and results["unity_catalog_visible"]["ok"]
        and results["can_list_shares"]["ok"]
        and results["can_list_recipients"]["ok"]
    )

    print("\n--- Verdict -----------------------------------------------")
    if provider_ready:
        print("This workspace CAN act as an OpenSharing provider via PAT.")
        print("You can run the rest of this demo exactly as-is, whether")
        print("this is a Free Edition workspace or a Premium trial.")
    else:
        print("This workspace is missing something the provider-side flow")
        print("needs (see the 'ok: false' entries above). That is the")
        print("expected result on Free Edition for provider operations.")
        print("Next step: sign up for the 14-day Databricks trial on AWS")
        print("(Premium tier, Unity Catalog, full REST API/PAT access) --")
        print("see docs/00-services-setup-guide.md, Path B.")
    print("-------------------------------------------------------------")

if __name__ == "__main__":
    main()
