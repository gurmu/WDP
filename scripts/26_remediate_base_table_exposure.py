#!/usr/bin/env python3
"""
E1 Task 1.4 follow-on: find every share carrying a base table, measure
whether it is REACHABLE, then remove the exposure.

WHY THIS SCRIPT EXISTS AT ALL
-----------------------------
scripts/24's rule 1 enumerates every share on the metastore rather than
only the two the entitlement config owns. On its first run both owned
shares came back MATCHES_CONFIG and the verdict was still
ENTITLEMENT_MODEL_DIVERGES, because `awoz1227_p18_primary_share` -- a
probe artifact from scripts/18, kept deliberately so scripts/19 could
reuse it -- still carried `awoz1227_demo.opensharing_test.test_dataset`.

A check scoped to the shares in entitlements.yaml would have reported a
clean pass. That is §11.5 repeating itself one layer out: the defect was
never in the share somebody was looking at.

MEMBERSHIP IS NOT REACHABILITY
------------------------------
"The base table is in a share" and "a recipient can read the base
table" are different claims, and collapsing them fails in both
directions:

  - Reported as a breach when the share has no recipient, and the real
    finding (a loaded share waiting for its first grant) gets lost in
    an argument about whether anything was actually exposed.
  - Reported as fine when the share HAS an activated recipient, which
    is the one case that is not fine at all.

So this script reads the share's `permissions` and each granted
recipient's activation state BEFORE it changes anything, and the
classification it writes is the finding. The removal is the easy part.

ORDER MATTERS. Evidence first, mutation second. A REMOVE issued before
the permissions read would destroy the only record of whether the
exposure was reachable, and the question would then be unanswerable --
which is how an incident review ends up guessing.

A LOSS THIS SCRIPT CANNOT RECOVER, STATED PLAINLY
-------------------------------------------------
scripts/24 recorded `objects_before` as a list of NAMES when it removed
the base table from `awoz1227-psp7-demo-share`. The sharing API returns
`added_at` and `added_by` on each object, and those were not captured,
so the exposure WINDOW for that share cannot be reconstructed -- only
that it existed before the run and not after. This script captures the
full object records, so the window is measurable for anything it finds.
The lesson generalises: capture the whole record before a REMOVE, not
the field the next assertion happens to need.

Usage:
    python3 scripts/26_remediate_base_table_exposure.py
    python3 scripts/26_remediate_base_table_exposure.py --remove
"""

import argparse
import datetime
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "iac" / "config" / "entitlements.yaml"
EVIDENCE = REPO / "evidence" / "base-table-exposure.json"
UC = "/api/2.1/unity-catalog"


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "s26_probe14")
P19 = load_probe("19_probe_token_path_same_pair.py", "s26_probe19")
call, redact, err_bits = P14.call, P14.redact, P14.err_bits
load_env = P19.load_env


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def ms_to_iso(ms):
    if not ms:
        return None
    try:
        return (datetime.datetime.fromtimestamp(int(ms) / 1000,
                                                datetime.timezone.utc)
                .isoformat().replace("+00:00", "Z"))
    except (TypeError, ValueError, OSError):
        return None


def age_seconds(ms):
    if not ms:
        return None
    try:
        return round(datetime.datetime.now(datetime.timezone.utc).timestamp()
                     - int(ms) / 1000, 1)
    except (TypeError, ValueError):
        return None


def recipient_state(host, token, name):
    """What a grant to this recipient actually buys the holder.

    Three things are distinguished, because they are three different
    exposures: the recipient exists, the recipient has been activated,
    and the recipient's token has not expired. A grant to a recipient
    whose activation link was never opened is not a read; a grant to an
    activated one with a live token is."""
    st, pl = call(host, token, f"{UC}/recipients/{name}")
    if st != 200:
        return {"recipient": name, "http_status": st,
                "verdict": "CANNOT_SEE",
                "means": "The recipient could not be read, so what the grant "
                         "buys is unknown -- not nothing."}
    tokens = pl.get("tokens") or []
    live, expired, unactivated = [], [], []
    for t in tokens:
        exp = t.get("expiration_time")
        rec = {"id": t.get("id"),
               "created_at": ms_to_iso(t.get("created_at")),
               "expiration_time": ms_to_iso(exp),
               "expired": bool(exp) and age_seconds(exp) is not None
                          and age_seconds(exp) > 0}
        if t.get("activation_url"):
            rec["activation_pending"] = True
            unactivated.append(rec)
        elif rec["expired"]:
            expired.append(rec)
        else:
            live.append(rec)
    activated = pl.get("activated")
    if activated is None:
        activated = bool(tokens) and not unactivated
    verdict = ("ACTIVATED_WITH_LIVE_TOKEN" if live
               else "ACTIVATION_PENDING" if unactivated
               else "TOKEN_EXPIRED" if expired
               else "NO_TOKEN")
    return {
        "recipient": name,
        "authentication_type": pl.get("authentication_type"),
        "activated": activated,
        "owner": pl.get("owner"),
        "ip_access_list": bool((pl.get("ip_access_list") or {})
                               .get("allowed_ip_addresses")),
        "tokens_live": live,
        "tokens_activation_pending": unactivated,
        "tokens_expired": expired,
        "verdict": verdict,
        "means": {
            "ACTIVATED_WITH_LIVE_TOKEN":
                "A credential exists in somebody's hands right now. A grant "
                "to this recipient is a read, not a risk of one.",
            "ACTIVATION_PENDING":
                "The activation link has not been exchanged for a "
                "credential. The exposure is one click away and was never "
                "taken -- which is a materially different finding from a "
                "read, and from nothing.",
            "TOKEN_EXPIRED":
                "A credential existed and no longer works. Whether it was "
                "used while live is an audit-log question, not a "
                "configuration one.",
            "NO_TOKEN":
                "The recipient has no token at all, so the grant buys "
                "nothing today.",
            "CANNOT_SEE": "unknown",
        }[verdict],
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--remove", action="store_true",
                    help="remove base-table objects from shares that are "
                         "not managed by entitlements.yaml")
    args = ap.parse_args()

    try:
        import yaml
    except ImportError:
        sys.exit("pyyaml is required: pip install -r requirements.txt")
    cfg = yaml.safe_load(CONFIG.read_text())

    load_env()
    host = os.environ.get("DATABRICKS_HOST", "").strip().rstrip("/")
    token = os.environ.get("DATABRICKS_TOKEN", "").strip()
    if not host or not token:
        sys.exit("DATABRICKS_HOST and DATABRICKS_TOKEN must be set in .env")
    catalog = os.environ.get("UC_METASTORE_CATALOG", cfg["catalog"])
    schema = os.environ.get("UC_SCHEMA", cfg["schema"])
    bases = [f"{catalog}.{schema}.{t['name']}"
             for t in (cfg.get("base_tables") or [])]
    managed = {s["name"] for s in (cfg.get("shares") or [])}

    res = {
        "script": "26_remediate_base_table_exposure",
        "run_at": now(),
        "mode": "REMOVE" if args.remove else "REPORT_ONLY",
        "base_tables": bases,
        "shares_managed_by_config": sorted(managed),
        "found_by": "scripts/24 rule 1, which enumerates EVERY share rather "
                    "than only the ones entitlements.yaml declares",
    }

    print("=" * 70)
    print("Base-table exposure: inventory, reachability, remediation")
    print("=" * 70)
    print(f"  base tables: {bases}")
    print(f"  mode:        {res['mode']}")

    st, pl = call(host, token, f"{UC}/shares")
    if st != 200:
        res["verdict"] = "CANNOT_SEE"
        res["http_status"] = st
        res["means"] = ("The share list could not be read. Nothing is "
                        "reported as clean on the strength of a failed "
                        "look (§12.9).")
        EVIDENCE.write_text(json.dumps(res, indent=2))
        print(f"\n  CANNOT_SEE: share list returned {st}")
        return 1
    share_names = [s.get("name") for s in (pl.get("shares") or [])]
    res["shares_examined"] = share_names
    print(f"\n-- inventory: {len(share_names)} share(s) ------------------")

    findings, inventory = [], {}
    for name in share_names:
        st, pl = call(host, token,
                      f"{UC}/shares/{name}?include_shared_data=true")
        if st != 200:
            inventory[name] = {"verdict": "CANNOT_SEE", "http_status": st}
            print(f"  {name}: CANNOT_SEE ({st})")
            continue
        # The FULL object records, not just the names -- see the module
        # docstring on the window scripts/24 cannot reconstruct.
        objs = [{"name": o.get("name"),
                 "data_object_type": o.get("data_object_type"),
                 "added_at": ms_to_iso(o.get("added_at")),
                 "added_by": o.get("added_by"),
                 "age_seconds": age_seconds(o.get("added_at")),
                 "status": o.get("status")}
                for o in (pl.get("objects") or [])]
        hits = [o for o in objs if o["name"] in bases]
        inventory[name] = {
            "managed_by_config": name in managed,
            "objects": objs,
            "carries_base_table": bool(hits),
            "owner": pl.get("owner"),
            "created_at": ms_to_iso(pl.get("created_at")),
        }
        flag = ("  <-- BASE TABLE" if hits else "")
        print(f"  {name}: {len(objs)} object(s)"
              f"{' [config-managed]' if name in managed else ''}{flag}")
        if not hits:
            continue

        # Reachability, read BEFORE anything is changed.
        st, perms = call(host, token, f"{UC}/shares/{name}/permissions")
        if st != 200:
            grants, grant_verdict = None, "CANNOT_SEE"
        else:
            grants = [{"principal": a.get("principal"),
                       "privileges": a.get("privileges")}
                      for a in (perms.get("privilege_assignments") or [])]
            grant_verdict = "GRANTED" if grants else "NO_GRANTS"
        recipients = []
        for g in (grants or []):
            recipients.append(recipient_state(host, token, g["principal"]))

        live = [r for r in recipients
                if r["verdict"] == "ACTIVATED_WITH_LIVE_TOKEN"]
        pending = [r for r in recipients
                   if r["verdict"] == "ACTIVATION_PENDING"]
        reach = ("REACHABLE_NOW" if live
                 else "REACHABLE_ON_ACTIVATION" if pending
                 else "CANNOT_SEE" if grant_verdict == "CANNOT_SEE"
                 else "DORMANT_NO_LIVE_CREDENTIAL" if grants
                 else "DORMANT_NO_GRANT")
        f = {
            "share": name,
            "managed_by_config": name in managed,
            "base_table_objects": hits,
            "exposure_window": {
                "added_at": hits[0]["added_at"],
                "seconds_in_share_at_this_read": hits[0]["age_seconds"],
                "means": "Measured from the sharing API's own added_at, so "
                         "it is the platform's record rather than this "
                         "repo's. An unknown added_at leaves the window "
                         "unmeasured, not zero.",
            },
            "grants": grants,
            "grant_verdict": grant_verdict,
            "recipients": recipients,
            "reachability": reach,
            "means": {
                "REACHABLE_NOW":
                    "A recipient holds a live credential and the share "
                    "grants it SELECT. The withheld column was readable, "
                    "and this is an exposure that happened rather than one "
                    "that could have.",
                "REACHABLE_ON_ACTIVATION":
                    "A recipient is granted but its activation link was "
                    "never exchanged for a credential. Nobody could read "
                    "the base table, and anybody holding that link could "
                    "have. Reported as neither a breach nor a pass.",
                "DORMANT_NO_LIVE_CREDENTIAL":
                    "Granted recipients exist but none holds a working "
                    "credential, so the exposure had no reader. It would "
                    "have acquired one the moment a token was issued.",
                "DORMANT_NO_GRANT":
                    "The share has no recipient at all. Nothing could read "
                    "it. This is a loaded share, not an incident -- and the "
                    "distinction is the point: a check that called this a "
                    "breach would be dismissed, and one that called it "
                    "clean would leave it in place.",
                "CANNOT_SEE":
                    "Grants could not be read, so reachability is unknown.",
            }[reach],
        }
        findings.append(f)
        print(f"      reachability: {reach}")
        for r in recipients:
            print(f"      recipient {r['recipient']}: {r['verdict']}")

    res["inventory"] = inventory
    res["findings"] = findings

    # ---- remediation ------------------------------------------------
    actions = []
    for f in findings:
        name = f["share"]
        if f["managed_by_config"]:
            actions.append({
                "share": name, "action": "REFUSED",
                "because": "This share is declared in entitlements.yaml and "
                           "is owned by scripts/24. Two writers of one "
                           "share's object list is the hazard that cost "
                           "outbound-allow-list.yaml a contribution; fix it "
                           "in the config and re-run scripts/24.",
            })
            continue
        updates = [{"action": "REMOVE", "data_object": {"name": o["name"]}}
                   for o in f["base_table_objects"]]
        if not args.remove:
            actions.append({"share": name, "action": "WOULD_REMOVE",
                            "updates": updates,
                            "note": "re-run with --remove"})
            continue
        st, pl = call(host, token, f"{UC}/shares/{name}", "PATCH",
                      {"updates": updates})
        code, msg = err_bits(pl)
        act = {"share": name, "action": "REMOVE", "http_status": st,
               "error_code": code or None,
               "error": None if st == 200 else redact(msg)[:400]}
        # B-23: the re-read is the finding.
        st2, pl2 = call(host, token,
                        f"{UC}/shares/{name}?include_shared_data=true")
        after = ([o.get("name") for o in (pl2.get("objects") or [])]
                 if st2 == 200 else None)
        act["objects_after"] = after
        act["verdict"] = ("REMOVED" if after is not None
                          and not (set(after) & set(bases))
                          else "STILL_PRESENT" if after is not None
                          else "CANNOT_SEE")
        if after == []:
            act["share_now_empty"] = (
                "The share remains and is empty. It is left in place "
                "deliberately: scripts/19 reuses probe 18's shares by name, "
                "and deleting one here would make that probe fail with a "
                "missing-share error that reads like a permissions "
                "problem. An empty share grants nothing.")
        actions.append(act)
        print(f"  {name}: {act['verdict']}")
    res["actions"] = actions

    exposed = [f for f in findings if f["reachability"] == "REACHABLE_NOW"]
    unresolved = [a for a in actions
                  if a.get("action") in ("WOULD_REMOVE",)
                  or a.get("verdict") in ("STILL_PRESENT", "CANNOT_SEE")]
    if not findings:
        res["verdict"] = "NO_BASE_TABLE_IN_ANY_SHARE"
    elif unresolved:
        res["verdict"] = ("EXPOSURE_FOUND_NOT_REMEDIATED" if not args.remove
                          else "EXPOSURE_FOUND_REMEDIATION_INCOMPLETE")
    else:
        res["verdict"] = "EXPOSURE_FOUND_AND_REMEDIATED"
    res["reachability_summary"] = {
        "reachable_now": [f["share"] for f in exposed],
        "reachable_on_activation": [f["share"] for f in findings
                                    if f["reachability"]
                                    == "REACHABLE_ON_ACTIVATION"],
        "dormant": [f["share"] for f in findings
                    if f["reachability"].startswith("DORMANT")],
    }
    res["conops_note"] = (
        "§3.1's share-isolation rule is written as a rule about how shares "
        "are created. This finding is about a share nobody created on "
        "purpose: a probe's artifact, kept so a later probe could reuse it, "
        "carrying the base table for as long as it sat there. The control "
        "that catches it is not a naming convention, it is a periodic "
        "metastore-wide assertion that no base table appears in any share "
        "-- which is what scripts/24 rule 1 is, and what v1.6 should "
        "require as a standing check rather than a publish-time one.")

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(json.dumps(res, indent=2))
    print(f"\n  VERDICT: {res['verdict']}")
    print(f"  Wrote {EVIDENCE.relative_to(REPO)}")
    if res["verdict"] == "EXPOSURE_FOUND_AND_REMEDIATED":
        print("\nNext: python3 scripts/24_build_entitlement_model.py "
              "(re-verify; rule 1 should now report BASE_TABLE_IN_NO_SHARE)")
    return 0 if res["verdict"] in ("NO_BASE_TABLE_IN_ANY_SHARE",
                                   "EXPOSURE_FOUND_AND_REMEDIATED") else 1


if __name__ == "__main__":
    sys.exit(main())
