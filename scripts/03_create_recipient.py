#!/usr/bin/env python3
"""
CONOPS Section 3.2 / 3.2.1 (OD-5) and Section 3.4.1 (OD-4), step 2-3:
creates a bearer-token recipient (Databricks-to-Open) for one simulated
consuming agency, grants it the demo share, retrieves the one-time
activation link, and downloads the Delta Sharing credential file.

This mirrors "a provisioning process, not the consumer, retrieves the
activation link... and downloads the credential file once" (Section
3.4.1, step 3) -- here, this script IS that provisioning process.

Token lifetime: this demo sets a short lifetime (OD-5 decision #2 is a
policy call for Data Governance in the real program; for a laptop demo
we default to 1 day so you aren't holding a long-lived token around).

Output: writes the raw credential file to ./_secrets/raw-credential.json
(gitignored). Do NOT commit, paste into chat, or upload this file.
"""
import os
import json
import datetime
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
        AuthenticationType, PermissionsChange, Privilege,
    )

    host = os.environ["DATABRICKS_HOST"]
    token = os.environ["DATABRICKS_TOKEN"]
    share_name = "awoz1227-psp7-demo-share"
    recipient_name = "psp7-demo-recipient"

    w = WorkspaceClient(host=host, token=token)

    expire_at_ms = int(
        (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)).timestamp() * 1000
    )

    existing = {r.name for r in w.recipients.list()}
    if recipient_name not in existing:
        recipient = w.recipients.create(
            name=recipient_name,
            authentication_type=AuthenticationType.TOKEN,
            comment="AWOZ-1227 demo recipient, simulated CDAO PSP7 consumer",
            expiration_time=expire_at_ms,
        )
        print(f"Created recipient: {recipient_name}")
    else:
        recipient = w.recipients.get(recipient_name)
        print(f"Recipient already exists: {recipient_name}")

    # Grant SELECT on the share to this recipient.
    w.shares.update_permissions(
        name=share_name,
        changes=[
            PermissionsChange(
                principal=recipient_name,
                add=[Privilege.SELECT],
            )
        ],
    )
    print(f"Granted SELECT on {share_name} to {recipient_name}")

    # Fetch the activation URL and token info. NOTE: recipient.as_dict()
    # contains the one-time activation_url, which is a bearer-equivalent
    # secret (whoever holds it can download the credential file once).
    # It is deliberately written ONLY to the gitignored secrets file below
    # and never printed to stdout, so it can't end up captured in a
    # terminal scrollback, screen share, or any tool/automation log.
    recipient = w.recipients.get(recipient_name)

    secrets_dir = Path(__file__).resolve().parent.parent / "_secrets"
    secrets_dir.mkdir(exist_ok=True)
    out_path = secrets_dir / "recipient-info.json"
    out_path.write_text(json.dumps(recipient.as_dict(), indent=2, default=str))
    try:
        out_path.chmod(0o600)
    except OSError:
        pass

    # Only print non-sensitive metadata to the console/logs.
    tokens = recipient.as_dict().get("tokens", [])
    token_summary = [
        {"activation_used": not bool(t.get("activation_url")), "expiration_time": t.get("expiration_time")}
        for t in tokens
    ]
    print("\nRecipient created/updated (non-sensitive summary):")
    print(json.dumps({"name": recipient_name, "tokens": token_summary}, indent=2, default=str))

    print(
        f"\nFull recipient info (including the one-time activation URL) was "
        f"written directly to {out_path} (gitignored, file permissions set "
        "to owner-only).\n"
        "Open that file YOURSELF in your own editor/terminal (not through "
        "me) to get the activation link, since it's a one-time-use secret. "
        "Then: open the link in your browser, download the credential file "
        "ONCE, and save it to _secrets/raw-credential.json -- the link "
        "self-destructs after one use, per Databricks' platform behavior "
        "(Section 3.2.1).\n"
        "Next: python3 04_rewrite_credential.py"
    )

if __name__ == "__main__":
    main()
