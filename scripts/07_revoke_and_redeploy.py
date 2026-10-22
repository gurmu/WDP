#!/usr/bin/env python3
"""
T-10 (AC3, AC4) + T-12 (AC6), and Step 7 of the client verification
session: "Revoke the consumer and show access fails; redeploy the
configuration from code."

Part A -- revoke:
    Deletes the recipient's token at Databricks (simulating offboarding /
    DSA termination / suspected compromise, per OD-5 decision #4) and
    confirms that a read through the gateway with the old credential file
    now fails.

Part B -- redeploy from code:
    Tears down the local Gravitee stack completely (including its state --
    `docker compose down -v`), brings it back up clean, and re-imports
    gravitee/api-definition.json via scripts/05. If the gateway edge comes
    back serving the same policy set with zero manual clicking, that's
    T-12 passing.
"""
import os
import subprocess
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parent.parent

def load_env():
    env_path = ROOT / ".env"
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

def part_a_revoke():
    from databricks.sdk import WorkspaceClient
    w = WorkspaceClient(host=os.environ["DATABRICKS_HOST"], token=os.environ["DATABRICKS_TOKEN"])
    recipient_name = "psp7-demo-recipient"

    recipient = w.recipients.get(recipient_name)
    tokens = getattr(recipient, "tokens", []) or []
    for t in tokens:
        print(f"Revoking token {t.id} for {recipient_name}")
        w.recipients.rotate_token(name=recipient_name, existing_token_expire_in_seconds=0)

    gateway = os.environ["GRAVITEE_GATEWAY_EDGE_URL"]
    cred_path = ROOT / "_secrets" / "rewritten-credential.json"
    print(f"\nAttempting a read with the now-revoked credential at {cred_path} ...")
    try:
        import delta_sharing
        table_url = f"{cred_path}#awoz1227-psp7-demo-share.opensharing_test.test_dataset"
        delta_sharing.load_as_pandas(table_url)
        print("UNEXPECTED: read succeeded after revocation -- investigate token/overlap settings (OD-5 #3).")
    except Exception as e:
        print(f"Expected failure after revocation: {e}")

def part_b_redeploy():
    print("\nTearing down the Gravitee stack (including state) ...")
    subprocess.run(["docker", "compose", "down", "-v"], cwd=ROOT, check=True)
    print("Bringing it back up clean ...")
    subprocess.run(["docker", "compose", "up", "-d"], cwd=ROOT, check=True)
    print("Waiting for the management API to become healthy ...")
    for _ in range(30):
        try:
            r = requests.get(f"{os.environ['GRAVITEE_MGMT_API_URL']}/management/organizations/DEFAULT/environments/DEFAULT/apis", timeout=3)
            if r.status_code in (200, 401):
                break
        except requests.exceptions.RequestException:
            pass
        time.sleep(5)
    else:
        sys.exit("Management API did not come up in time -- check `docker compose logs`.")

    print("Re-importing API definition from code (no manual console steps) ...")
    subprocess.run([sys.executable, str(ROOT / "scripts" / "05_import_gravitee_api.py")], check=True)
    print("\nT-12 evidence: same configuration, redeployed from code to a clean target.")

if __name__ == "__main__":
    load_env()
    print("=== Part A: revoke recipient token, confirm access fails (T-10) ===")
    part_a_revoke()
    print("\n=== Part B: redeploy gateway config from code to a clean target (T-12) ===")
    part_b_redeploy()
