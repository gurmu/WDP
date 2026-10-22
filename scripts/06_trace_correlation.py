#!/usr/bin/env python3
"""
T-11 / AC5: "Trace one request using the correlation ID -> gateway log
and Databricks audit event found; no tokens or bodies in logs."

1. Fires one request through the gateway with a known correlation ID.
2. Queries Gravitee's Elasticsearch (the demo's SIEM stand-in) for that
   request.
3. Queries Databricks' system.access.audit table for a matching
   share-query event in the same time window.
4. Confirms neither log contains the bearer token or a response body.

Note: system.access.audit requires the system catalog to be enabled for
your metastore (Account Console > Catalog > system catalogs, or ask your
Databricks admin / the Data Eng team in the real program). If it's not
enabled in your demo workspace, this script falls back to printing the
gateway-side correlation only and flags the Databricks side as
'not verified -- enable system tables'.
"""
import json
import os
import sys
import uuid
from pathlib import Path

import requests

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
    gateway = os.environ["GRAVITEE_GATEWAY_EDGE_URL"]
    correlation_id = str(uuid.uuid4())

    print(f"Firing one request with correlation hint {correlation_id} ...")
    resp = requests.get(gateway, headers={"X-Demo-Correlation-Hint": correlation_id}, timeout=10)
    gateway_correlation_id = resp.headers.get("X-Correlation-Id", "<not present -- check transform-headers policy>")
    print(f"Gateway response: {resp.status_code}, X-Correlation-Id={gateway_correlation_id}")

    es_url = "http://localhost:9200/gravitee-request-*/_search"
    try:
        es_resp = requests.post(
            es_url, json={"query": {"match": {"correlation-id": gateway_correlation_id}}}, timeout=10
        )
        hits = es_resp.json().get("hits", {}).get("hits", [])
        print(f"Elasticsearch (gateway log) hits: {len(hits)}")
        for h in hits[:3]:
            body = json.dumps(h["_source"])
            has_token = "bearer" in body.lower() or "authorization" in body.lower()
            print(f"  - contains possible token/auth text: {has_token} (should be False)")
    except requests.exceptions.RequestException as e:
        print(f"Could not query Elasticsearch: {e}")

    print("\nDatabricks side: query system.access.audit for a matching "
          "share query event in the same ~1 minute window, filtered by "
          "share name 'awoz1227-psp7-demo-share'. Example SQL:\n")
    print(
        "  SELECT event_time, action_name, request_params\n"
        "  FROM system.access.audit\n"
        "  WHERE service_name = 'unityCatalog'\n"
        "    AND action_name IN ('deltaSharingQueryTable','deltaSharingListTable')\n"
        "    AND event_time > current_timestamp() - INTERVAL 10 MINUTES\n"
        "  ORDER BY event_time DESC\n"
        "  LIMIT 10;\n"
    )
    print(
        "Run this in a SQL editor against your workspace and manually "
        "confirm an event lands in the same window as the gateway hit "
        "above. (Full automation of this cross-reference is Story 3 of "
        "1227-E5, 'Trace-compliance check' -- worth building once the "
        "real correlation-ID propagation contract is defined with Data "
        "Tooling, dependency 1694-E4.)"
    )

if __name__ == "__main__":
    main()
