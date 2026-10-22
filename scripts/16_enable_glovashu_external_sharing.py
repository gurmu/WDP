#!/usr/bin/env python3
"""Diagnose, then (optionally) flip, External Delta Sharing on glovashu.

Probe 15 hit this on the ingress direction:

    403 PERMISSION_DENIED
    External Delta Sharing is not enabled on the metastore.
    Please contact the metastore admin to enable External Delta Sharing.

That is a METASTORE SETTING, not a tier ceiling, and the repository
already holds the one-variable control that proves it: a DATABRICKS-auth
recipient was created HTTP 200 on the PRIMARY metastore, same tier
(Free Edition), same region (aws:us-east-2), same API. Only the target
metastore differs. So the capability is sold at this tier and glovashu
simply has the switch off.

The setting is `delta_sharing_scope` on the metastore object:

    INTERNAL                -- share only inside this metastore
    INTERNAL_AND_EXTERNAL   -- share outside it, which is what D2D needs

READ BEFORE WRITE, ON PURPOSE
-----------------------------
This script reads the scope on BOTH metastores and prints them side by
side before it changes anything. Two reasons.

First, the diagnosis has to be visible. "We enabled a setting and it
started working" is a weaker artefact than "the setting differed between
two metastores on the same tier, here are both values, we changed one
and only one". The second is a controlled change; the first is a story.

Second, if glovashu already reads INTERNAL_AND_EXTERNAL then the refusal
means something else entirely and flipping a switch that is already on
would send us down the wrong path while appearing to act. The script
stops in that case rather than issuing a no-op PATCH and reporting
success -- a no-op that reports success is the 12.9 shape.

WHY THE API AND NOT THE UI
--------------------------
The same change can be made in the account console. Doing it by API
costs nothing extra and buys two things: AC6 / T-12 asks for the
environment to be redeployable from code, and a UI click leaves no
artefact for that. And it records the BEFORE value, which the UI does
not.

If the PATCH is refused -- plausibly, since metastore updates usually
require ACCOUNT admin rather than workspace admin, and .env holds
workspace tokens -- the script says so precisely and prints the console
path as the fallback. A refusal here is not a dead end for T-19; it is a
different route to the same prerequisite.

USAGE
    python3 scripts/16_enable_glovashu_external_sharing.py           # read only
    python3 scripts/16_enable_glovashu_external_sharing.py --apply   # then PATCH
"""

import argparse
import datetime
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "evidence" / "glovashu-external-sharing-scope.json"

WANTED = "INTERNAL_AND_EXTERNAL"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def write_evidence(res):
    """Write OUT, carrying forward every prior attempt.

    B-19. The first --apply run was REFUSED 400 with 'delta_sharing_
    recipient_token_lifetime_in_seconds must be set' -- which is the most
    transferable finding this script produced, because it proves the
    platform will not let you enable external sharing without choosing a
    credential expiry. The second run succeeded and overwrote it. An
    evidence writer that destroys the refusal its own fix was derived from
    leaves a record showing only a clean 200, i.e. it reports 'enabling
    this is one easy call' -- the opposite of what happened. That is the
    12.9 shape applied to our own audit trail, so attempts accumulate
    rather than replace.
    """
    history = []
    if OUT.exists():
        try:
            prior = json.loads(OUT.read_text())
        except (json.JSONDecodeError, OSError):
            prior = None
        if isinstance(prior, dict):
            history = list(prior.get("prior_attempts") or [])
            if prior.get("apply") is not None:
                history.append({
                    "run_at": prior.get("run_at"),
                    "mode": prior.get("mode"),
                    "apply": prior.get("apply"),
                    "verified": prior.get("verified"),
                })
    if history:
        res["prior_attempts"] = history
        res["prior_attempts_note"] = (
            "Earlier runs of this script, newest last. Kept because the "
            "refusals are evidence (B-19); a file showing only the "
            "successful call would misrepresent what enabling this took.")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(res, indent=2))


def probe14():
    path = REPO / "scripts" / "14_probe_d2o_provider_import.py"
    if not path.exists():
        sys.exit(f"Missing {path}; this script reuses its HTTP helper.")
    spec = importlib.util.spec_from_file_location("probe14", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit("No .env found.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def read_scope(call, label, host, token):
    """Read the metastore's id and delta_sharing_scope.

    metastore_summary needs no running compute, which matters on Free
    Edition and keeps this replayable for T-12.
    """
    status, payload = call(host, token,
                           "/api/2.1/unity-catalog/metastore_summary")
    out = {"label": label, "host": host, "status": status}
    if status != 200:
        out["error"] = str(payload)[:300]
        out["scope"] = None
        return out
    out["metastore_id"] = payload.get("metastore_id")
    out["name"] = payload.get("name")
    out["region"] = payload.get("region")
    out["global_metastore_id"] = payload.get("global_metastore_id")
    # The field is absent on some API versions rather than null. Absent
    # and INTERNAL are different observations and must not be merged:
    # one means "off", the other means "this API did not tell us".
    if "delta_sharing_scope" in payload:
        out["scope"] = payload.get("delta_sharing_scope")
        out["scope_observed"] = True
    else:
        out["scope"] = None
        out["scope_observed"] = False
        out["scope_note"] = ("metastore_summary did not return "
                             "delta_sharing_scope. Absent is NOT the same as "
                             "INTERNAL -- it means this endpoint did not "
                             "report it. The full metastores endpoint is "
                             "tried next.")
    out["recipient_token_lifetime"] = payload.get(
        "delta_sharing_recipient_token_lifetime_in_seconds")
    return out


def read_scope_full(call, label, host, token, metastore_id):
    """Fall back to the full metastore object if the summary omits scope."""
    if not metastore_id:
        return {"status": None, "verdict": "NOT_ATTEMPTED",
                "means": "No metastore id to query."}
    status, payload = call(
        call_host := host, token,
        f"/api/2.1/unity-catalog/metastores/{metastore_id}")
    out = {"status": status}
    if status == 200:
        out["scope"] = payload.get("delta_sharing_scope")
        out["scope_observed"] = "delta_sharing_scope" in payload
        out["owner"] = payload.get("owner")
    else:
        out["error"] = str(payload)[:300]
        out["scope"] = None
        out["scope_observed"] = False
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true",
                    help="PATCH glovashu's metastore to "
                         "delta_sharing_scope=INTERNAL_AND_EXTERNAL")
    ap.add_argument("--token-lifetime", type=int, default=None,
                    metavar="SECONDS",
                    help="Also set "
                         "delta_sharing_recipient_token_lifetime_in_seconds. "
                         "Deliberately NOT set by default: the first PATCH "
                         "changes exactly one field, so if the API demands "
                         "this one too, the refusal tells us that enabling "
                         "external sharing is a two-field decision and the "
                         "second field is a credential expiry the client must "
                         "choose. Re-run with this flag to supply it.")
    args = ap.parse_args()

    load_env()
    call = probe14().call

    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN",
                "GLOVASHU_HOST", "GLOVASHU_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")
    p_host = os.environ["DATABRICKS_HOST"].strip().rstrip("/")
    p_token = os.environ["DATABRICKS_TOKEN"].strip()
    g_host = os.environ["GLOVASHU_HOST"].strip().rstrip("/")
    g_token = os.environ["GLOVASHU_TOKEN"].strip()

    res = {
        "script": "16_enable_glovashu_external_sharing",
        "task": "E1 Task 1.10 -> T-19 prerequisite",
        "run_at": now(),
        "mode": "apply" if args.apply else "read_only",
        "setting": "delta_sharing_scope",
        "wanted_on_provider": WANTED,
    }

    print("External Delta Sharing scope -- both metastores")
    print("=" * 68)

    primary = read_scope(call, "primary", p_host, p_token)
    glovashu = read_scope(call, "glovashu", g_host, g_token)

    for side in (primary, glovashu):
        if side.get("status") == 200 and not side.get("scope_observed"):
            side["full_object"] = read_scope_full(
                call, side["label"],
                p_host if side["label"] == "primary" else g_host,
                p_token if side["label"] == "primary" else g_token,
                side.get("metastore_id"))
            if side["full_object"].get("scope_observed"):
                side["scope"] = side["full_object"]["scope"]
                side["scope_observed"] = True
                side["scope_source"] = "metastores/{id}"
        elif side.get("scope_observed"):
            side["scope_source"] = "metastore_summary"

    res["before"] = {"primary": primary, "glovashu": glovashu}

    for side in (primary, glovashu):
        scope = side.get("scope")
        shown = scope if side.get("scope_observed") else "NOT REPORTED"
        print(f"  {side['label']:9} {side.get('metastore_id', '?')}  "
              f"scope = {shown}")
    print()

    # ---- the discriminator, stated before any change ----
    if primary.get("scope") == WANTED and glovashu.get("scope") != WANTED \
            and glovashu.get("scope_observed"):
        res["discriminator"] = {
            "verdict": "CONFIGURATION_DIFFERS_AT_SAME_TIER",
            "means": (f"Both metastores are Free Edition in "
                      f"{primary.get('region')}. The primary is {WANTED} and "
                      f"glovashu is {glovashu.get('scope')}. The capability "
                      f"is therefore available at this tier and probe 15's "
                      f"403 is an unset switch. This is the one-variable "
                      f"control for B-18."),
        }
        print("DIAGNOSIS: the two metastores differ on this setting at the")
        print("same tier and region, so Free Edition is not the constraint.")
        # Corroboration, and a security decision hiding behind the switch.
        p_life = primary.get("recipient_token_lifetime")
        g_life = glovashu.get("recipient_token_lifetime")
        if p_life != g_life:
            res["discriminator"]["corroboration"] = {
                "field": "delta_sharing_recipient_token_lifetime_in_seconds",
                "primary": p_life,
                "glovashu": g_life,
                "means": ("The side that has external sharing enabled also "
                          "carries a recipient token lifetime; the side that "
                          "does not carries none. That is independent "
                          "corroboration that glovashu has never had the "
                          "feature switched on, rather than having it "
                          "switched on and then restricted."),
                "decision_exposed": ("Recipient tokens are the credential "
                                     "that external recipients authenticate "
                                     "with. Their lifetime is therefore a "
                                     "security default the CONOPS must set "
                                     "explicitly, not inherit. Enabling the "
                                     "scope without choosing it is how a "
                                     "non-expiring external credential gets "
                                     "created by omission."),
            }
            print(f"         corroborating: recipient token lifetime is "
                  f"{p_life} on primary, {g_life} on glovashu")
    elif glovashu.get("scope") == WANTED:
        res["discriminator"] = {
            "verdict": "ALREADY_ENABLED",
            "means": ("glovashu already reports INTERNAL_AND_EXTERNAL, so "
                      "probe 15's refusal has a DIFFERENT cause and this "
                      "script must not act. Re-run probe 15 and read the "
                      "message again before changing anything."),
        }
        print("STOP: glovashu already reports INTERNAL_AND_EXTERNAL.")
        print("The refusal has another cause. Not issuing a PATCH -- a")
        print("no-op that reports success would hide the real problem.")
        write_evidence(res)
        print(f"\nWrote {OUT.relative_to(REPO)}")
        return 0
    else:
        res["discriminator"] = {
            "verdict": "INCONCLUSIVE",
            "means": ("Could not read the scope on one or both sides, so the "
                      "tier reading is not excluded by this script alone. "
                      "Probe 15's attribution against "
                      "capability-baseline-d2d.json still stands on its own "
                      "evidence."),
        }
        print("Could not read both scopes cleanly -- see the evidence file.")
    print()

    if not args.apply:
        print("Read-only. To change glovashu's setting:")
        print("    python3 scripts/16_enable_glovashu_external_sharing.py "
              "--apply")
        print()
        print("If that PATCH is refused (metastore updates often need "
              "ACCOUNT")
        print("admin, and .env holds workspace tokens), set it in the "
              "glovashu")
        print("account console instead:")
        print("    accounts.cloud.databricks.com -> Catalog / Metastores")
        print("    -> select the metastore -> enable Delta Sharing")
        print("      ('allow sharing outside your organization')")
        print("Then re-run probe 15; the switch is all T-19 needs.")
        write_evidence(res)
        print(f"\nWrote {OUT.relative_to(REPO)}")
        return 0

    mid = glovashu.get("metastore_id")
    if not mid:
        res["apply"] = {"verdict": "NOT_ATTEMPTED",
                        "means": "No glovashu metastore id could be read."}
        write_evidence(res)
        sys.exit("Cannot PATCH without glovashu's metastore id.")

    body = {"delta_sharing_scope": WANTED}
    if args.token_lifetime is not None:
        body["delta_sharing_recipient_token_lifetime_in_seconds"] = \
            args.token_lifetime

    print(f"PATCHing glovashu metastore {mid} -> {WANTED}")
    print(f"  fields in request: {', '.join(sorted(body))}")
    status, payload = call(g_host, g_token,
                           f"/api/2.1/unity-catalog/metastores/{mid}",
                           "PATCH", body)
    res["apply"] = {"status": status, "request": dict(body),
                    "fields_changed": sorted(body)}
    if status == 200:
        res["apply"]["verdict"] = "APPLIED"
        print(f"  [ok ] {status}")
    else:
        res["apply"]["verdict"] = "REFUSED"
        res["apply"]["error"] = str(payload)[:400]
        print(f"  [REF] {status}: {str(payload)[:220]}")
        blob = f"{status} {payload}".lower()
        if "lifetime" in blob:
            res["apply"]["second_field_required"] = {
                "field": ("delta_sharing_recipient_token_lifetime_in_"
                          "seconds"),
                "means": ("The refusal names the token lifetime, so "
                          "enabling external sharing is a two-field change "
                          "and the second field is a credential expiry. The "
                          "one-field PATCH was the right first attempt "
                          "precisely because this refusal is the finding."),
                "rerun": ("python3 scripts/16_enable_glovashu_external_"
                          "sharing.py --apply --token-lifetime 86400  "
                          "(86400 matches the primary; choose deliberately)"),
            }
            print("  -> the API names the recipient token lifetime. Re-run "
                  "with")
            print("     --token-lifetime 86400 (what primary carries), and "
                  "record")
            print("     that the expiry was chosen rather than defaulted.")
        res["apply"]["fallback"] = (
            "Set it in the glovashu ACCOUNT console: "
            "accounts.cloud.databricks.com -> Catalog / Metastores -> the "
            "metastore -> enable Delta Sharing (share outside your "
            "organization). Workspace PATs usually cannot update a "
            "metastore; that is a credential scope limit, not a tier limit, "
            "and the console route reaches the same setting.")

    # ---- verify, rather than trust the 200 ----
    after = read_scope(call, "glovashu", g_host, g_token)
    if after.get("status") == 200 and not after.get("scope_observed"):
        full = read_scope_full(call, "glovashu", g_host, g_token,
                               after.get("metastore_id"))
        if full.get("scope_observed"):
            after["scope"] = full["scope"]
            after["scope_observed"] = True
    res["after"] = after
    res["verified"] = {
        "scope_now": after.get("scope"),
        "verdict": ("ENABLED_AND_VERIFIED" if after.get("scope") == WANTED
                    else "NOT_IN_EFFECT"),
        "means": ("A 200 on the PATCH is not the finding; the re-read is. "
                  "An update that returns 200 and leaves the setting "
                  "unchanged is the 12.9 shape with a success code on it."),
    }
    print(f"  re-read: scope = {after.get('scope')} -> "
          f"{res['verified']['verdict']}")

    # An enabled scope with no credential expiry is a finding, not a success.
    if after.get("scope") == WANTED:
        life = after.get("recipient_token_lifetime")
        res["verified"]["recipient_token_lifetime"] = life
        if life in (None, 0):
            res["verified"]["credential_expiry"] = {
                "verdict": "NO_EXPIRY_SET",
                "means": ("External sharing is on and recipient tokens "
                          "carry no expiry, so any credential issued to an "
                          "external recipient is good until revoked by "
                          "hand. T-19 can proceed, but this must be "
                          "recorded as an open security decision, not left "
                          "to the default."),
                "fix": ("--token-lifetime 86400, or set it in the account "
                        "console alongside the switch"),
            }
            print("  WARNING: recipient token lifetime is unset -- external "
                  "credentials")
            print("           would not expire. See the evidence file.")
        else:
            res["verified"]["credential_expiry"] = {
                "verdict": "EXPIRY_SET",
                "seconds": life,
            }

    write_evidence(res)
    print()
    print(f"Wrote {OUT.relative_to(REPO)}")
    if res["verified"]["verdict"] == "ENABLED_AND_VERIFIED":
        print("Next: python3 scripts/15_probe_d2d_prereqs.py  (re-run the "
              "probe; the recipient step should now pass)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
