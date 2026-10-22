#!/usr/bin/env python3
"""
E1 Task 1.2 -- the two probes that gate T-19 and the proposed E-2 test.

Databricks-to-Databricks sharing is **metastore-to-metastore**, not
catalog-to-catalog. A recipient is identified by a sharing identifier of
the form `cloud:region:uuid`, where the uuid is the *metastore* id. If
both workspaces resolve to the same metastore, D2D between them is
refused by construction -- a recipient cannot carry the provider's own
sharing identifier -- and no amount of configuration fixes it.

This is the single assumption the whole D2D half of the topology rests
on, and it has not been tested. A second Unity *Catalog* is not a second
*metastore*: on Free Edition a metastore is provisioned per account per
region, so `glovashu` may well live under the same metastore
(48cda780-1dc7-459d-bee0-77abde9af938) as the primary workspace. If it
does, T-19 and the E-2 proposal both fail here and must be recorded as
NOT_RUN with the reason -- not simulated.

Probe 1: does glovashu resolve to a DIFFERENT metastore id?
Probe 2: does this tier permit a recipient with
         authentication_type = DATABRICKS at all?

Probe 2 runs only if probe 1 passes, because a DATABRICKS recipient
needs the far-side sharing identifier to be meaningful.

Usage:
    python3 scripts/09_probe_metastore_identity.py

Two modes, chosen automatically:

  * GLOVASHU_HOST + GLOVASHU_TOKEN set in .env -> ask both workspaces
    which metastore they are attached to and compare.
  * Not set -> ask whether GLOVASHU_CATALOG is a catalog under the
    primary metastore. If it is, probe 1 is answered in the negative
    conclusively, with no second credential needed.

The second mode is not a weaker version of the first. A catalog has no
sharing identifier, so finding glovashu among the primary's catalogs is
positive evidence that there is no far side for D2D -- not a failure to
measure.

Writes: evidence/capability-baseline-d2d.json
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


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


def metastore_summary(host, token, label):
    """Ask a workspace which metastore it is attached to."""
    status, payload = call(host, token, "/api/2.1/unity-catalog/metastore_summary")
    out = {"label": label, "host": host, "status": status}
    if status == 200 and isinstance(payload, dict):
        out["metastore_id"] = payload.get("metastore_id")
        out["name"] = payload.get("name")
        out["region"] = payload.get("region")
        out["cloud"] = payload.get("cloud")
        gsi = payload.get("global_metastore_id")
        out["global_metastore_id"] = gsi
        out["sharing_identifier"] = gsi  # this is the cloud:region:uuid form
    else:
        out["error"] = str(payload)[:400]
    return out


# Catalog names that exist in every Databricks workspace and therefore
# cannot be used to tell one workspace from another.
AMBIGUOUS_CATALOG_NAMES = {"workspace", "default", "samples", "system", "main", "hive_metastore"}


def catalog_check(host, token, catalog):
    """Is `catalog` a catalog under THIS workspace's metastore?

    Used when there is no second workspace to probe. If glovashu is a
    catalog here, that settles probe 1 without any second credential:
    a catalog is not a metastore, so there is no second sharing
    identifier and D2D has no far side.
    """
    status, payload = call(host, token, "/api/2.1/unity-catalog/catalogs")
    out = {"status": status, "looked_for": catalog}
    if status == 200 and isinstance(payload, dict):
        cats = payload.get("catalogs") or []
        out["catalogs_visible"] = [c.get("name") for c in cats]
        match = next((c for c in cats if c.get("name") == catalog), None)
        out["found"] = match is not None
        if match:
            out["metastore_id_of_catalog"] = match.get("metastore_id")
            out["catalog_type"] = match.get("catalog_type")
            out["owner"] = match.get("owner")
    else:
        out["error"] = str(payload)[:400]
    return out


def main():
    load_env()
    primary_host = os.environ.get("DATABRICKS_HOST", "")
    primary_token = os.environ.get("DATABRICKS_TOKEN", "")
    glov_host = os.environ.get("GLOVASHU_HOST", "")
    glov_token = os.environ.get("GLOVASHU_TOKEN", "")
    glov_catalog = os.environ.get("GLOVASHU_CATALOG", "workspace")

    for name, val in [
        ("DATABRICKS_HOST", primary_host), ("DATABRICKS_TOKEN", primary_token),
    ]:
        if not val or "<" in val:
            sys.exit(f"Set a real {name} in .env first (see .env.example).")

    # Two modes. If there is no second workspace credential, we do not
    # stop -- we answer probe 1 the other way, by asking whether
    # glovashu is merely a catalog under the primary metastore. That is
    # a conclusive NO for D2D, and it is a recorded finding rather than
    # a blocked task.
    second_workspace = bool(
        glov_host and glov_token and "<" not in glov_host and "<" not in glov_token
    )

    results = {
        "probe": "d2d-metastore-identity",
        "task": "E1 Task 1.2",
        "run_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "gates": ["T-19 (D2D ingress)", "E-2 proposed test (D2D egress)"],
        "probes": {},
    }

    # --- Probe 1: are these two DIFFERENT metastores? --------------------
    primary = metastore_summary(primary_host, primary_token, "primary")
    results["mode"] = "two_workspace" if second_workspace else "single_workspace"

    if not second_workspace:
        cat = catalog_check(primary_host, primary_token, glov_catalog)
        results["probes"]["metastore_identity"] = {
            "primary": primary,
            "glovashu": {
                "label": "glovashu",
                "probed_as": "catalog under the primary metastore",
                "why": (
                    "No GLOVASHU_HOST/GLOVASHU_TOKEN in .env, so there is no "
                    "second workspace to ask. Asking instead whether glovashu "
                    "is a catalog here -- which answers probe 1 conclusively "
                    "in the negative if it is."
                ),
                "catalog_check": cat,
            },
        }
        # A generic catalog name cannot distinguish two workspaces.
        # EVERY Databricks workspace ships `workspace`, `default`,
        # `samples` and `system`, so finding one of those in the primary
        # tells us nothing about the second account -- it finds the
        # primary's OWN catalog and mislabels it as the far side. This
        # produced a false SAME_METASTORE on 2026-10-18 with
        # GLOVASHU_CATALOG=workspace. Refuse rather than conclude.
        if glov_catalog.lower() in AMBIGUOUS_CATALOG_NAMES:
            verdict = {
                "verdict": "INVALID_PROBE",
                "means": (
                    f"GLOVASHU_CATALOG='{glov_catalog}' is a name every "
                    f"Databricks workspace has, so matching it against the "
                    f"primary's catalog list cannot tell the two accounts "
                    f"apart. Any verdict from this comparison would be an "
                    f"artefact of the name, not a finding about metastores.\n"
                    f"FIX: either set GLOVASHU_HOST + GLOVASHU_TOKEN in .env "
                    f"(the real two-workspace comparison, which needs no "
                    f"catalog name at all), or set GLOVASHU_CATALOG to a "
                    f"catalog that exists ONLY in the second workspace."
                ),
                "ambiguous_names": sorted(AMBIGUOUS_CATALOG_NAMES),
                "catalogs_visible_in_primary": cat.get("catalogs_visible"),
            }
        elif cat.get("found"):
            verdict = {
                "verdict": "SAME_METASTORE",
                "metastore_id": cat.get("metastore_id_of_catalog") or primary.get("metastore_id"),
                "evidence": "glovashu is a CATALOG under the primary metastore",
                "means": (
                    "glovashu is a second catalog, not a second metastore. D2D "
                    "needs two metastores: the recipient is identified by a "
                    "sharing identifier cloud:region:uuid where the uuid IS the "
                    "metastore id, so a catalog has no sharing identifier of its "
                    "own and there is no far side to name.\n"
                    "CONSEQUENCE: T-19 and the E-2 proposal are NOT_RUN, with "
                    "'only one metastore available on this tier' as the stated "
                    "reason. Record it; do not simulate it. The D2O half (OSS "
                    "provider) is unaffected and still carries T-20 and T-23."
                ),
            }
        else:
            verdict = {
                "verdict": "INCONCLUSIVE",
                "means": (
                    f"No second workspace credential, and no catalog named "
                    f"'{glov_catalog}' is visible here either. Either the name "
                    f"is wrong or glovashu really is a separate workspace -- in "
                    f"which case set GLOVASHU_HOST/GLOVASHU_TOKEN and re-run. "
                    f"Do NOT record a verdict from this run."
                ),
                "catalogs_visible": cat.get("catalogs_visible"),
            }
        results["probes"]["metastore_identity"]["conclusion"] = verdict
        results["probes"]["databricks_auth_recipient"] = {
            "status": "skipped",
            "why": "Probe 1 did not establish two distinct metastores.",
        }
        out = REPO / "evidence" / "capability-baseline-d2d.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2))
        print(json.dumps(verdict, indent=2))
        print(f"\nFull probe written to {out}")
        return

    glov = metastore_summary(glov_host, glov_token, "glovashu")
    results["probes"]["metastore_identity"] = {"primary": primary, "glovashu": glov}

    pid, gid = primary.get("metastore_id"), glov.get("metastore_id")
    if not pid or not gid:
        verdict = {
            "verdict": "INCONCLUSIVE",
            "means": (
                "One or both workspaces did not return a metastore summary. "
                "Check the token scopes before concluding anything. Do NOT "
                "assume distinctness."
            ),
        }
    elif pid == gid:
        verdict = {
            "verdict": "SAME_METASTORE",
            "metastore_id": pid,
            "means": (
                "glovashu is a second CATALOG under the same metastore, not a "
                "second metastore. D2D between these two workspaces is refused "
                "by construction -- a recipient cannot carry the provider's own "
                "sharing identifier.\n"
                "CONSEQUENCE: T-19 and the E-2 proposal are NOT_RUN with this "
                "as the stated reason. Record it; do not simulate it. The D2O "
                "half of the topology (OSS provider) is unaffected and still "
                "carries T-20 and T-23."
            ),
        }
    else:
        verdict = {
            "verdict": "DISTINCT_METASTORES",
            "primary": pid,
            "glovashu": gid,
            "means": (
                "D2D is structurally possible between these two workspaces. "
                "Proceed to probe 2, then to the full T-19 sequence and the "
                "E-2 egress proposal."
            ),
        }
    results["probes"]["metastore_identity"]["conclusion"] = verdict

    # --- Probe 2: will this tier accept a DATABRICKS-auth recipient? -----
    if verdict["verdict"] != "DISTINCT_METASTORES":
        results["probes"]["databricks_auth_recipient"] = {
            "status": "skipped",
            "why": "Probe 1 did not establish two distinct metastores.",
        }
    else:
        sharing_id = glov.get("sharing_identifier") or glov.get("global_metastore_id")
        name = "awoz1227_probe_d2d_recipient"
        status, payload = call(
            primary_host, primary_token,
            "/api/2.1/unity-catalog/recipients",
            method="POST",
            body={
                "name": name,
                "authentication_type": "DATABRICKS",
                "data_recipient_global_metastore_id": sharing_id,
                "comment": "E1 Task 1.2 capability probe -- safe to delete",
            },
        )
        probe2 = {"attempt_status": status, "sharing_identifier_used": sharing_id,
                  "body": str(payload)[:500]}
        if status in (200, 201):
            probe2["verdict"] = "PERMITTED"
            probe2["means"] = "Tier accepts DATABRICKS-auth recipients. T-19 is BUILD."
            d, _ = call(primary_host, primary_token,
                        f"/api/2.1/unity-catalog/recipients/{name}", method="DELETE")
            probe2["cleanup_status"] = d
        else:
            probe2["verdict"] = "REFUSED_OR_ERROR"
            probe2["means"] = (
                "Read the error body before concluding. A quota/permission error "
                "is a different finding from 'this tier does not support D2D "
                "recipients', exactly as with the AI Gateway probe. State which."
            )
        results["probes"]["databricks_auth_recipient"] = probe2

    out = REPO / "evidence" / "capability-baseline-d2d.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))

    print(json.dumps(verdict, indent=2))
    if "databricks_auth_recipient" in results["probes"]:
        print("\nProbe 2:", json.dumps(
            results["probes"]["databricks_auth_recipient"].get("verdict", "skipped"), indent=2))
    print(f"\nFull probe written to {out}")


if __name__ == "__main__":
    main()
