#!/usr/bin/env python3
"""
Epic 1, Task 1.9 -- probe the Unity AI Gateway surface, then settle the
one thing console inspection cannot settle: whether inference actually
runs on this tier.

Context (2026-10-18). Console inspection confirmed Unity Gateway is live
on this workspace at /ml/ai-gateway, with thirteen governed models in
system.ai and tabs for Models, Providers, MCPs, Skills and Agents. That
retired the old assumption -- carried in R11 and in Task 1.9's original
text -- that Free Edition would not have an AI gateway at all.

What the console could NOT tell us is whether a call succeeds. Every
model showed 0 tokens over a rolling 7-day window, meaning nothing in
this workspace has ever been invoked. A Free Edition workspace can
plausibly list a governed model and still refuse inference on quota
grounds. That distinction matters for the ARB package:

    "available, invocation refused on quota"  -> a real, bounded finding
    "not available on this tier"              -> what we used to assume
    "works"                                   -> T-15 becomes BUILD

This script reports which of the three is true, and never guesses.

It is read-only apart from the single inference call in step 3, which is
deliberately tiny (max_tokens=16) so it cannot consume a meaningful
quota.

Usage:
    pip install databricks-sdk --break-system-packages
    python3 08_probe_ai_gateway.py

Writes: evidence/capability-baseline-ai.json
"""
import os
import sys
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Small models first. If a quota exists, these are likeliest to clear it,
# and a 20B answering "ok" proves the path just as well as a 120B.
CANDIDATE_MODELS = [
    "databricks-gpt-oss-20b",
    "databricks-gemma-3-12b",
    "databricks-meta-llama-3-1-8b-instruct",
    "databricks-gpt-oss-120b",
]


def load_env():
    env_path = REPO / ".env"
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


def call(host, token, path, method="GET", body=None, timeout=60):
    """Minimal REST helper. Returns (status, parsed_or_text)."""
    url = host.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def main():
    load_env()
    host = os.environ.get("DATABRICKS_HOST", "")
    token = os.environ.get("DATABRICKS_TOKEN", "")
    if "<" in host or "<" in token or not host or not token:
        sys.exit("Fill in real DATABRICKS_HOST and DATABRICKS_TOKEN in .env first.")

    results = {
        "probe": "unity-ai-gateway",
        "task": "E1 Task 1.9",
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "host": host,
        "console_observation_2026_10_18": {
            "gateway_page": "/ml/ai-gateway",
            "tabs": ["Models", "Providers", "MCPs", "Skills", "Agents"],
            "governed_models_seen": 13,
            "location_of_most": "system.ai",
            "tokens_7d_all_models": 0,
            "note": "surface confirmed by eye; this script confirms behaviour",
        },
        "steps": {},
    }

    # --- 1. Can we list serving endpoints at all? -------------------------
    # This is the API-level mirror of what the console showed. If the
    # console shows models but this 403s, that is itself a finding: the
    # route is governable by UI but not automatable, which would break
    # the IaC story for AC6 on the AI routes specifically.
    status, payload = call(host, token, "/api/2.0/serving-endpoints")
    endpoints = []
    if status == 200 and isinstance(payload, dict):
        endpoints = [e.get("name") for e in payload.get("endpoints", []) if e.get("name")]
    results["steps"]["list_serving_endpoints"] = {
        "status": status,
        "count": len(endpoints),
        "sample": endpoints[:15],
        "verdict": (
            "OK -- surface is automatable" if status == 200
            else "Listing refused; UI-only governance would be an AC6/IaC finding"
        ),
    }

    # --- 2. Is there an MCP surface reachable by API? --------------------
    # The console has an MCPs tab. T-16's open half is whether a *callable*
    # server exists or can be created on this tier. We only look.
    mcp_probe = {}
    for p in ("/api/2.0/mcp/servers", "/api/2.1/unity-catalog/mcp-servers"):
        s, b = call(host, token, p, timeout=20)
        mcp_probe[p] = {"status": s, "body": str(b)[:300]}
    results["steps"]["mcp_surface"] = {
        "probes": mcp_probe,
        "note": (
            "A 404/405 here does not mean 'no MCP' -- the console tab may be "
            "backed by a different path. Record what the MCPs tab shows by eye "
            "alongside this. Note also that /api/2.0/mcp/* is the LEGACY route "
            "that route M3 must prove unreachable from the Gravitee edge; "
            "reaching it directly with a workspace token is expected and is "
            "not a failure of M3."
        ),
    }

    # --- 3. THE question: does inference actually run? -------------------
    invocation = {"attempted": [], "conclusion": None}
    for model in CANDIDATE_MODELS:
        s, b = call(
            host, token,
            f"/serving-endpoints/{model}/invocations",
            method="POST",
            body={
                "messages": [{"role": "user", "content": "Reply with the single word: ok"}],
                "max_tokens": 16,
            },
            timeout=120,
        )
        snippet = str(b)[:400]
        invocation["attempted"].append({"model": model, "status": s, "body": snippet})
        if s == 200:
            invocation["conclusion"] = {
                "verdict": "WORKS",
                "model": model,
                "means": "T-15 availability is settled. Build the Gravitee M1 route (Task 1.9 part 2).",
            }
            break
        if s in (402, 429):
            invocation["conclusion"] = {
                "verdict": "QUOTA_REFUSED",
                "model": model,
                "status": s,
                "means": (
                    "Available but refused on quota/rate -- NOT an availability gap. "
                    "Record under A8 with this distinction stated explicitly; "
                    "do not write it up as 'tier does not support model serving'."
                ),
            }
            break
        if s in (401, 403):
            invocation["conclusion"] = {
                "verdict": "PERMISSION_REFUSED",
                "model": model,
                "status": s,
                "means": (
                    "Token lacks CAN_QUERY on the endpoint. This is a GRANT problem, "
                    "not a tier problem -- and it is good news for the CONOPS, because "
                    "it demonstrates Unity Catalog governing model access the same way "
                    "it governs tables (feeds the Sec 3.1 access matrix)."
                ),
            }
            break
    if invocation["conclusion"] is None:
        invocation["conclusion"] = {
            "verdict": "INCONCLUSIVE",
            "means": "No candidate returned a classifiable status. Inspect bodies above before concluding anything.",
        }
    results["steps"]["invocation"] = invocation

    # --- 4. Opportunistic: is usage queryable? ---------------------------
    # The console tracks tokens per model over 7 days. If that accounting
    # is reachable, T-11 gets a second join key to try on the AI routes.
    # Fifteen minutes, then drop it. Rows or nothing -- never infer.
    results["steps"]["usage_accounting_lead"] = {
        "status": "manual",
        "try_in_sql": [
            "SHOW TABLES IN system.serving",
            "SELECT * FROM system.serving.endpoint_usage LIMIT 5",
            "SHOW SCHEMAS IN system",
        ],
        "why": (
            "Not a solution to 1694-E4's correlation-ID contract. But if any of "
            "these return rows, the AI routes have a usage record the Delta "
            "Sharing routes lack, and Epic 5 gains a second join key to test. "
            "Report rows or report nothing."
        ),
    }

    out = REPO / "evidence" / "capability-baseline-ai.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))

    print(json.dumps(results["steps"]["invocation"]["conclusion"], indent=2))
    print(f"\nFull probe written to {out}")
    print(
        "\nReminder: this settles AVAILABILITY and INVOCATION only.\n"
        "It says nothing about GovCloud/IL5 -- that is R11's surviving half\n"
        "and ask 9a, and no commercial-region workspace can answer it."
    )


if __name__ == "__main__":
    main()
