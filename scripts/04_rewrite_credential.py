#!/usr/bin/env python3
"""
CONOPS Section 3.4.1 (OD-4), step 4: "The provisioning process replaces
the endpoint in the file with the gateway edge URL. The bearer token is
unchanged." This is the core trick that makes the whole perimeter work:
without this step, any reference client would read the raw credential
file and call Databricks directly, bypassing Gravitee entirely.

MERGED 2026-10-18 (E1 Task 1.1). Two versions of this script existed: the
tracked one here, which was .env-driven but rewrote only `endpoint`, and
an untracked copy in _secrets/ which handled `icebergEndpoint` as well.
The untracked copy was the more correct of the two on the axis that
matters, so this is a merge rather than a deletion -- deleting it would
have thrown away the only correct handling of the iceberg field.

WHY THAT MATTERS. A live credential file in this repo was found with
`endpoint` rewritten to the gateway but `icebergEndpoint` still pointing
at the raw Databricks host. That is a complete bypass of the perimeter
OD-4 exists to create: a client that prefers the iceberg endpoint never
touches Gravitee. The CONOPS says "replaces the endpoint" (singular),
which is how both the document and the original script got it wrong.
v1.6 correction item 3 fixes the wording.

The defence here is not "also rewrite icebergEndpoint" -- that just
patches today's known field. It is the leak guard below: after rewriting,
every string in the file is scanned for the original provider host, and
the script REFUSES TO WRITE if any survives. A future credential format
that adds a third endpoint field will fail loudly instead of silently
shipping a bypass.

Input:  _secrets/raw-credential.json   (downloaded once from the
        activation link in script 03's output -- never commit this)
Output: _secrets/rewritten-credential.json  (all endpoints swapped to the
        Gravitee edge URL; this is what reference clients use)
"""
import json
import os
import re
import stat
from pathlib import Path
from urllib.parse import urlparse

# Fields known to carry an endpoint today. The leak guard is what
# protects us from the ones we do not know about yet.
ENDPOINT_FIELDS = ("endpoint", "icebergEndpoint")


def load_env():
    env_path = Path(__file__).resolve().parent.parent / ".env"
    if not env_path.exists():
        raise SystemExit(f"Missing {env_path}. Copy .env.example to .env and fill it in first.")
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


def walk_strings(obj, path="$"):
    """Yield (json_path, value) for every string in a nested structure."""
    if isinstance(obj, str):
        yield path, obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from walk_strings(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from walk_strings(v, f"{path}[{i}]")


def main():
    load_env()
    secrets_dir = Path(__file__).resolve().parent.parent / "_secrets"
    raw_path = secrets_dir / "raw-credential.json"
    if not raw_path.exists():
        raise SystemExit(
            f"Missing {raw_path}. Download the credential file from the "
            "one-time activation link (see script 03's output) and save it "
            "there first."
        )

    cred = json.loads(raw_path.read_text())
    original_endpoint = cred.get("endpoint")
    if not original_endpoint:
        raise SystemExit(
            "Credential file has no 'endpoint' field -- is this a valid Delta Sharing profile file?"
        )

    # The host we must eradicate from the output, derived from the file
    # itself rather than hardcoded, so this works for any provider.
    provider_host = urlparse(original_endpoint).hostname
    if not provider_host:
        raise SystemExit(f"Could not parse a hostname out of endpoint: {original_endpoint!r}")

    gateway_edge_url = os.environ.get("GRAVITEE_GATEWAY_EDGE_URL")
    if not gateway_edge_url:
        raise SystemExit("GRAVITEE_GATEWAY_EDGE_URL is not set in .env")
    base = gateway_edge_url.rstrip("/")

    # Iceberg gets its own suffix; override in .env if the route differs.
    iceberg_url = os.environ.get("GRAVITEE_GATEWAY_ICEBERG_URL", f"{base}/iceberg")

    rewritten = {}
    for field in ENDPOINT_FIELDS:
        if field in cred:
            rewritten[field] = (cred[field], iceberg_url if field == "icebergEndpoint" else base)
            cred[field] = rewritten[field][1]
    # bearerToken is left untouched, per CONOPS: "The bearer token is unchanged."

    # --- Leak guard: nothing may still point at the provider -------------
    leaks = [
        (p, v) for p, v in walk_strings(cred)
        if re.search(re.escape(provider_host), v, re.IGNORECASE)
    ]
    if leaks:
        print("REFUSING TO WRITE -- the rewritten credential still references the provider host.")
        print(f"Provider host: {provider_host}\n")
        for p, v in leaks:
            print(f"  {p} = {v}")
        raise SystemExit(
            "\nThis is the OD-4 bypass condition: a client reading one of the fields "
            "above would reach Databricks directly and never traverse Gravitee.\n"
            "Add the offending field to ENDPOINT_FIELDS at the top of this script, "
            "then re-run. Do not work around this check."
        )

    out_path = secrets_dir / "rewritten-credential.json"
    out_path.write_text(json.dumps(cred, indent=2))
    out_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600 regardless of umask

    for field, (was, now) in rewritten.items():
        print(f"{field}:\n    was: {was}\n    now: {now}")
    print(f"\nLeak guard: clean -- no reference to {provider_host} survives.")
    print(f"Wrote: {out_path} (mode 0600)")
    print(
        "\nThis file is what gets 'delivered to the consumer through the "
        "authenticated portal' in a real deployment (Section 3.4.1, step 5). "
        "For the demo, it's what tests/ point reference clients at.\n"
        "To confirm T-09 (reference client reads via rewritten file), run:\n"
        "  python3 tests/test_t09_reference_client_read.py"
    )


if __name__ == "__main__":
    main()
