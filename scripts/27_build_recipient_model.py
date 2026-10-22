#!/usr/bin/env python3
"""
E1 Task 1.5 -- apply the recipient / credential model, then verify it.

Reads iac/config/recipients.yaml, which is the only definition of the
recipient side. Creates recipients, sets their IP access lists and DSA
references, grants them exactly the shares the config declares, and then
checks eight rules against what the platform actually holds.

WHY THIS SCRIPT IS CAREFUL ABOUT STDOUT
---------------------------------------
Creating a TOKEN recipient MINTS THE ACTIVATION LINK in the same call.
There is no create-now-issue-later shape on this branch, so unlike
rotation (gated behind --rotate-token) issuance cannot be gated at all:
if a recipient in the config does not exist, applying the config issues a
credential. Whoever holds the activation URL holds the credential, once.

So the link is written ONLY to _secrets/recipient-<name>.json with
owner-only permissions, and never to stdout and never to the evidence
file. scripts/14's `redact()` strips `bearerToken` and does NOT strip
`activation_url` -- it was written for a probe that never saw one. This
script therefore wraps it (`redact_full`) rather than trusting it, and
scrubs the recipient payload field-by-field through an ALLOW-LIST
(`safe_recipient`) instead of removing known-bad keys. A deny-list over
an API whose response shape can gain a field fails open; an allow-list
fails closed, which is the same argument this project uses to forbid
`SELECT * EXCEPT` in iac/config/entitlements.yaml.

WHY THE VERIFY HALF IS LONGER THAN THE APPLY HALF
-------------------------------------------------
B-23: a 200 on a mutation is not the finding; the re-read is. Every
mutation below is issued and then read back out of the sharing API.

RULE 3 IS DELIBERATELY WIDER THAN THIS FILE
-------------------------------------------
The grant check enumerates EVERY share on the metastore, not the three
this config names. B-31: the 22.3-hour base-table exposure lived in a
share no config had heard of, and any check scoped to the config's own
shares would have passed straight through it. A grant is only knowable
as "exactly the declared set" if the search space is the metastore.

WHAT THIS SCRIPT WILL NOT DO WITHOUT BEING TOLD
-----------------------------------------------
It will not remove a grant it did not expect (--prune-grants), it will
not rotate a token (--rotate-token NAME), and it will not delete a
recipient at all. Two writers of one object's state is the hazard that
B-31 and the outbound-allow-list contribution both come from, and a
leftover is labelled rather than erased (B-19).

Usage:
    python3 scripts/27_build_recipient_model.py --dry-run
    python3 scripts/27_build_recipient_model.py
    python3 scripts/27_build_recipient_model.py --prune-grants
    python3 scripts/27_build_recipient_model.py --rotate-token psp7-demo-recipient
"""

import argparse
import datetime
import importlib.util
import json
import os
import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "iac" / "config" / "recipients.yaml"
ENTITLEMENTS = REPO / "iac" / "config" / "entitlements.yaml"
EVIDENCE = REPO / "evidence" / "recipient-model.json"
SECRETS = REPO / "_secrets"
UC = "/api/2.1/unity-catalog"

DAY = 86400
YEAR_SECONDS = 365 * DAY


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this script reuses its helpers rather "
                 f"than restating them.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "s27_probe14")
P19 = load_probe("19_probe_token_path_same_pair.py", "s27_probe19")
S26 = load_probe("26_remediate_base_table_exposure.py", "s27_script26")

call = P14.call
err_bits = P14.err_bits
load_env = P19.load_env
recipient_state = S26.recipient_state
ms_to_iso = S26.ms_to_iso
age_seconds = S26.age_seconds


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


# ---------------------------------------------------------------------
# Secret handling. Everything that leaves this process goes through one
# of these two functions.
# ---------------------------------------------------------------------

SAFE_RECIPIENT_FIELDS = (
    "name", "authentication_type", "owner", "comment", "created_at",
    "created_by", "updated_at", "updated_by", "activated",
    "sharing_code", "cloud", "region", "metastore_id", "full_name",
    "securable_type", "data_recipient_global_metastore_id",
)
SAFE_TOKEN_FIELDS = ("id", "created_at", "created_by", "expiration_time",
                     "updated_at", "updated_by")


def redact_full(text):
    """scripts/14's redact() plus the two fields it never had to meet.

    `activation_url` is a one-time bearer-equivalent secret and
    `recipient_profile_str` is the whole credential as a string. Neither
    appears in the probe redact() was written for, so neither is stripped
    by it. This is not a criticism of that function -- it is the reason a
    redactor has to be re-read against every new payload shape it is
    pointed at.
    """
    text = P14.redact(text)
    if not isinstance(text, str):
        return text
    text = re.sub(r'"activation_url"\s*:\s*"[^"]*"',
                  '"activation_url":"<redacted-one-time-link>"', text)
    text = re.sub(r'"recipient_profile_str"\s*:\s*"[^"]*"',
                  '"recipient_profile_str":"<redacted>"', text)
    # Any remaining absolute URL carrying a long opaque path segment is
    # treated as an activation link whether or not it was labelled one.
    text = re.sub(r'https://[^\s"]*/data_sharing_activation/[^\s"]*',
                  "<redacted-one-time-link>", text)
    return text


def safe_recipient(payload):
    """Allow-list scrub. Unknown fields are DROPPED, not inspected.

    A deny-list ("remove activation_url") passes anything the API adds
    tomorrow straight into the evidence file. This keeps named fields
    only, and records the names it dropped so the omission is visible
    without the values being present.
    """
    if not isinstance(payload, dict):
        return {"unparsed": redact_full(str(payload))[:400]}
    out = {k: payload[k] for k in SAFE_RECIPIENT_FIELDS if k in payload}
    toks = payload.get("tokens") or []
    out["tokens"] = [
        {k: t.get(k) for k in SAFE_TOKEN_FIELDS if k in t}
        | {"activation_pending": bool(t.get("activation_url"))}
        for t in toks if isinstance(t, dict)
    ]
    ipl = (payload.get("ip_access_list") or {}).get("allowed_ip_addresses")
    out["ip_access_list_allowed"] = sorted(ipl) if ipl else None
    dropped = sorted(set(payload) - set(SAFE_RECIPIENT_FIELDS)
                     - {"tokens", "ip_access_list"})
    if dropped:
        out["fields_dropped_unread"] = dropped
    return out


def write_secret(name, payload):
    """The activation link's only destination."""
    SECRETS.mkdir(exist_ok=True)
    path = SECRETS / f"recipient-{name}.json"
    path.write_text(json.dumps(payload, indent=2, default=str))
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


# ---------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------

def get_recipient(host, token, name):
    st, pl = call(host, token, f"{UC}/recipients/{name}")
    return st, pl


def list_recipients(host, token):
    st, pl = call(host, token, f"{UC}/recipients")
    if st != 200:
        return None, {"http_status": st, "error": redact_full(json.dumps(pl))[:800]}
    return [r.get("name") for r in (pl.get("recipients") or [])], {"http_status": st}


def list_shares(host, token):
    st, pl = call(host, token, f"{UC}/shares")
    if st != 200:
        return None, {"http_status": st, "error": redact_full(json.dumps(pl))[:800]}
    return [s.get("name") for s in (pl.get("shares") or [])], {"http_status": st}


def share_permissions(host, token, share):
    """Returns {principal: [privileges]} or None if it cannot be read."""
    st, pl = call(host, token, f"{UC}/shares/{share}/permissions")
    if st != 200:
        return None, {"http_status": st,
                      "error": redact_full(json.dumps(pl))[:600]}
    out = {}
    for a in (pl.get("privilege_assignments") or []):
        out[a.get("principal")] = sorted(a.get("privileges") or [])
    return out, {"http_status": st}


# ---------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------

def desired_comment(r):
    """§3.3: the DSA reference travels on the recipient.

    The placeholder status is inside the same string on purpose. A
    reference that does not say it is a placeholder gets quoted as an
    executed agreement.
    """
    status = r.get("dsa_ref_status", "PLACEHOLDER")
    bits = [
        "AWOZ-1227",
        f"channel={r.get('channel')}",
        f"purpose={(r.get('purpose') or '').strip()}",
        f"dsa_ref={r.get('dsa_ref')} ({status})",
        "defined_by=iac/config/recipients.yaml",
    ]
    return " | ".join(b for b in bits if b)


def desired_ip_list(r):
    ipl = r.get("ip_access_list") or {}
    if ipl.get("mode") == "APPLIED":
        return sorted(ipl.get("allowed_ip_addresses") or [])
    return []


def apply_recipient(host, token, r, lifetime_days, dry, renew=False):
    """Create or update one recipient. Never deletes."""
    name = r["name"]
    out = {"recipient": name, "declared_exists_already": bool(r.get("exists_already"))}
    st, pl = get_recipient(host, token, name)
    present = st == 200

    out["found_on_platform"] = present if st in (200, 404) else None
    if st not in (200, 404):
        out["verdict"] = "CANNOT_SEE"
        out["http_status"] = st
        out["error"] = redact_full(json.dumps(pl))[:800]
        out["means"] = ("The recipient could not be read, so whether it "
                        "exists is unknown. Nothing is applied against an "
                        "unknown state.")
        return out

    if present != bool(r.get("exists_already")):
        # Not a failure -- a drift note. The config's claim about the
        # world was wrong, and that is worth recording either way.
        out["exists_already_drift"] = (
            "config says exists_already=%s, platform says %s"
            % (bool(r.get("exists_already")), present))

    body_common = {
        "comment": desired_comment(r),
        "ip_access_list": {"allowed_ip_addresses": desired_ip_list(r)},
    }

    if dry:
        out["verdict"] = "DRY_RUN"
        out["would"] = "PATCH" if present else "CREATE"
        out["would_comment"] = body_common["comment"]
        out["would_ip_list"] = desired_ip_list(r)
        return out

    if not present:
        expire_ms = int((datetime.datetime.now(datetime.timezone.utc)
                         + datetime.timedelta(days=lifetime_days))
                        .timestamp() * 1000)
        body = dict(body_common)
        body.update({
            "name": name,
            "authentication_type": r["authentication_type"],
            "expiration_time": expire_ms,
        })
        st, pl = call(host, token, f"{UC}/recipients", "POST", body)
        out["create_http_status"] = st
        if st == 200:
            out["verdict"] = "CREATED"
            out["credential_issued_by_this_call"] = bool(
                (pl.get("tokens") or [{}])[0].get("activation_url"))
            out["secret_written_to"] = str(write_secret(name, pl)
                                           .relative_to(REPO))
            out["secret_handling"] = (
                "The activation link is in that file and nowhere else. It "
                "is not in this evidence file and was not printed. Open it "
                "yourself; it is single-use.")
            out["recipient_after"] = safe_recipient(pl)
        else:
            code, msg = err_bits(pl)
            out["verdict"] = "CREATE_FAILED"
            out["error_code"] = code
            out["error"] = redact_full(msg)[:2000]
            out["error_budget_note"] = (
                "2000 chars, not 400. B-32b: a truncated refusal threw "
                "away the platform's own remedy once already.")
        return out

    patch_body = dict(body_common)
    if renew:
        patch_body["expiration_time"] = int(
            (datetime.datetime.now(datetime.timezone.utc)
             + datetime.timedelta(days=lifetime_days)).timestamp() * 1000)
        out["lifetime_renewed"] = True
        out["lifetime_renewed_note"] = (
            "--renew-lifetime was passed, so expiration_time was re-stamped. "
            "This EXTENDS an existing credential's life by the full window. "
            "It is a flag and not the default for that reason.")
    st, pl = call(host, token, f"{UC}/recipients/{name}", "PATCH", patch_body)
    out["patch_http_status"] = st
    if st == 200:
        out["verdict"] = "UPDATED"
        out["recipient_after"] = safe_recipient(pl)
    else:
        code, msg = err_bits(pl)
        out["verdict"] = "PATCH_FAILED"
        out["error_code"] = code
        out["error"] = redact_full(msg)[:2000]
    return out


def apply_grants(host, token, r, dry):
    name = r["name"]
    results = []
    for g in (r.get("grants") or []):
        share, privs = g["share"], sorted(g.get("privileges") or ["SELECT"])
        rec = {"recipient": name, "share": share, "privileges": privs}
        if dry:
            rec["verdict"] = "DRY_RUN"
            results.append(rec)
            continue
        st, pl = call(host, token, f"{UC}/shares/{share}/permissions", "PATCH",
                      {"changes": [{"principal": name, "add": privs}]})
        rec["http_status"] = st
        if st == 200:
            rec["verdict"] = "GRANTED"
        else:
            code, msg = err_bits(pl)
            rec["verdict"] = "GRANT_FAILED"
            rec["error_code"] = code
            rec["error"] = redact_full(msg)[:2000]
        results.append(rec)
    return results


# ---------------------------------------------------------------------
# Verify
# ---------------------------------------------------------------------

def rule1_existence(host, token, cfg):
    rows, bad, unseen = [], [], []
    for r in cfg["recipients"]:
        name = r["name"]
        st, pl = get_recipient(host, token, name)
        row = {"recipient": name, "declared_type": r["authentication_type"]}
        if st == 200:
            actual = pl.get("authentication_type")
            row["actual_type"] = actual
            row["verdict"] = ("EXISTS_TYPE_MATCHES" if actual == r["authentication_type"]
                              else "EXISTS_TYPE_DIFFERS")
            if row["verdict"] != "EXISTS_TYPE_MATCHES":
                bad.append(name)
        elif st == 404:
            row["verdict"] = "ABSENT"
            bad.append(name)
        else:
            row["verdict"] = "CANNOT_SEE"
            row["http_status"] = st
            unseen.append(name)
        rows.append(row)
    verdict = ("PARTIAL_CANNOT_SEE" if unseen
               else "ALL_PRESENT_TYPES_MATCH" if not bad
               else "DIVERGES")
    return {"rule": "RI-1 recipient exists with declared authentication_type",
            "rows": rows, "bad": bad, "cannot_see": unseen, "verdict": verdict,
            "means": "The authentication type IS the OD-5 branch. A TOKEN "
                     "recipient silently created as DATABRICKS would move "
                     "every credential conclusion to the other channel."}


def rule2_ip_lists(host, token, cfg):
    rows, bad, unseen = [], [], []
    for r in cfg["recipients"]:
        name = r["name"]
        declared = desired_ip_list(r)
        mode = (r.get("ip_access_list") or {}).get("mode")
        st, pl = get_recipient(host, token, name)
        row = {"recipient": name, "declared_mode": mode, "declared": declared}
        if st != 200:
            row["verdict"] = "CANNOT_SEE"
            row["http_status"] = st
            unseen.append(name)
            rows.append(row)
            continue
        actual = sorted((pl.get("ip_access_list") or {})
                        .get("allowed_ip_addresses") or [])
        row["actual"] = actual
        if mode == "APPLIED":
            row["verdict"] = "LIST_MATCHES" if actual == declared else "LIST_DIFFERS"
        else:
            row["verdict"] = "ABSENT_AS_DECLARED" if not actual else "UNDECLARED_LIST_PRESENT"
            if actual:
                row["why_this_is_a_failure"] = (
                    "A list nobody declared will deny a read, and a denial "
                    "is indistinguishable from an entitlement denial at the "
                    "client. T-04 would pass without touching the "
                    "mechanism it names.")
        if row["verdict"] not in ("LIST_MATCHES", "ABSENT_AS_DECLARED"):
            bad.append(name)
        rows.append(row)
    verdict = ("PARTIAL_CANNOT_SEE" if unseen
               else "IP_LISTS_AS_DECLARED" if not bad else "DIVERGES")
    return {"rule": "RI-2 IP access list equals the declared one, both directions",
            "rows": rows, "bad": bad, "cannot_see": unseen, "verdict": verdict}


def rule3_grants(host, token, cfg, prune):
    """Enumerates every share on the metastore. B-31."""
    shares, meta = list_shares(host, token)
    managed = {r["name"] for r in cfg["recipients"]}
    declared = {}
    for r in cfg["recipients"]:
        for g in (r.get("grants") or []):
            declared.setdefault(r["name"], {})[g["share"]] = sorted(
                g.get("privileges") or ["SELECT"])

    if shares is None:
        return {"rule": "RI-3 grants are exactly as declared, metastore-wide",
                "verdict": "CANNOT_SEE", "share_listing": meta,
                "means": "The share list could not be read, so 'no extra "
                         "grant exists' is unknown -- not true. §12.9."}

    observed, unmanaged_grants, unreadable = {}, {}, []
    for s in shares:
        perms, pmeta = share_permissions(host, token, s)
        if perms is None:
            unreadable.append({"share": s, **pmeta})
            continue
        for principal, privs in perms.items():
            if principal in managed:
                observed.setdefault(principal, {})[s] = privs
            else:
                # The first version of this rule dropped these on the
                # floor. B-33: the share search was widened to the
                # metastore (B-31) and the PRINCIPAL search was left
                # scoped to the config, so a grant held by a recipient
                # this file does not manage was invisible to a rule whose
                # stated job is "grants are exactly as declared". A
                # recipient nobody declared holding SELECT on a share
                # this config manages is the same defect as B-31 with
                # the two axes swapped.
                unmanaged_grants.setdefault(principal, {})[s] = privs

    missing, extra, mismatched, pruned = [], [], [], []
    for name in managed:
        want = declared.get(name, {})
        got = observed.get(name, {})
        for s, privs in want.items():
            if s not in got:
                missing.append({"recipient": name, "share": s, "want": privs})
            elif got[s] != privs:
                mismatched.append({"recipient": name, "share": s,
                                   "want": privs, "got": got[s]})
        for s, privs in got.items():
            if s not in want:
                item = {"recipient": name, "share": s, "privileges": privs}
                if prune:
                    st, pl = call(host, token, f"{UC}/shares/{s}/permissions",
                                  "PATCH",
                                  {"changes": [{"principal": name,
                                                "remove": privs}]})
                    item["prune_http_status"] = st
                    item["pruned"] = st == 200
                    if st != 200:
                        item["prune_error"] = redact_full(json.dumps(pl))[:800]
                    pruned.append(item)
                extra.append(item)

    # Reachability is attached to every unmanaged grant-holder, because
    # "an undeclared recipient holds SELECT" and "an undeclared
    # recipient holds SELECT and has a live credential" are different
    # findings and only the second one is a read.
    unmanaged_rows = []
    for principal, by_share in sorted(unmanaged_grants.items()):
        state = recipient_state(host, token, principal)
        unmanaged_rows.append({
            "principal": principal,
            "shares": by_share,
            "shares_also_managed_by_this_config": sorted(
                set(by_share) & {g["share"] for r in cfg["recipients"]
                                 for g in (r.get("grants") or [])}),
            "state": state.get("verdict"),
            "authentication_type": state.get("authentication_type"),
            "reachability": ("REACHABLE_NOW"
                             if state.get("verdict") == "ACTIVATED_WITH_LIVE_TOKEN"
                             else "REACHABLE_ON_ACTIVATION"
                             if state.get("verdict") == "ACTIVATION_PENDING"
                             else "CANNOT_SEE"
                             if state.get("verdict") == "CANNOT_SEE"
                             else "DORMANT_NO_LIVE_CREDENTIAL"),
        })
    unmanaged_reachable = [r["principal"] for r in unmanaged_rows
                           if r["reachability"] in ("REACHABLE_NOW",
                                                    "REACHABLE_ON_ACTIVATION")]

    verdict = ("PARTIAL_CANNOT_SEE_ALL_SHARES" if unreadable
               else "UNMANAGED_PRINCIPAL_HOLDS_REACHABLE_GRANT"
               if unmanaged_reachable
               else "GRANTS_DIVERGE" if (missing or extra or mismatched)
               else "DECLARED_GRANTS_EXACT_UNMANAGED_GRANTS_DORMANT"
               if unmanaged_rows
               else "GRANTS_EXACTLY_AS_DECLARED")
    return {"rule": "RI-3 grants are exactly as declared, metastore-wide, "
                    "for every principal and not only the declared ones",
            "shares_examined": len(shares),
            "shares_unreadable": unreadable,
            "observed": observed,
            "missing": missing, "mismatched": mismatched, "extra": extra,
            "pruned": pruned,
            "prune_requested": bool(prune),
            "unmanaged_principals_with_grants": unmanaged_rows,
            "unmanaged_principals_reachable": unmanaged_reachable,
            "verdict": verdict,
            "means": "Scoped to the metastore on BOTH axes. B-31 widened the "
                     "share search; B-33 widened the principal search. A "
                     "grant held by a recipient this config does not manage "
                     "was previously filtered out by a rule whose stated job "
                     "is 'grants are exactly as declared' -- the omission "
                     "made the rule's name false. Nothing unmanaged is "
                     "removed: an EXTRA grant on a MANAGED recipient needs "
                     "--prune-grants, and a grant on an unmanaged principal "
                     "is reported only, because this config does not own "
                     "that principal and two writers of one object is the "
                     "hazard."}


def rule4_tokens(host, token, cfg, lifetime_days):
    rows, bad, unseen = [], [], []
    for r in cfg["recipients"]:
        name = r["name"]
        state = recipient_state(host, token, name)
        if state.get("verdict") == "CANNOT_SEE":
            unseen.append(name)
            rows.append({"recipient": name, "verdict": "CANNOT_SEE"})
            continue
        n_tokens = (len(state.get("tokens_live") or [])
                    + len(state.get("tokens_activation_pending") or [])
                    + len(state.get("tokens_expired") or []))
        row = {"recipient": name,
               "token_count": n_tokens,
               "token_count_within_platform_bound": n_tokens <= 2,
               "state": state.get("verdict"),
               "state_means": state.get("means"),
               "tokens_live": state.get("tokens_live"),
               "tokens_expired": state.get("tokens_expired"),
               "tokens_activation_pending": state.get(
                   "tokens_activation_pending")}
        # Lifetime is observed, not assumed. The applier sets a lifetime
        # when it CREATES a recipient and never revisits it on update,
        # so a recipient born under an older policy keeps that policy
        # while this file claims a different one.
        all_toks = ((state.get("tokens_live") or [])
                    + (state.get("tokens_activation_pending") or [])
                    + (state.get("tokens_expired") or []))
        windows = []
        for t in all_toks:
            try:
                c0 = datetime.datetime.fromisoformat(
                    (t.get("created_at") or "").replace("Z", "+00:00"))
                e0 = datetime.datetime.fromisoformat(
                    (t.get("expiration_time") or "").replace("Z", "+00:00"))
                windows.append(round((e0 - c0).total_seconds()))
            except (TypeError, ValueError):
                windows.append(None)
        want_window = lifetime_days * DAY
        row["configured_window_seconds"] = want_window
        row["observed_token_windows_seconds"] = windows
        measurable = [w for w in windows if isinstance(w, int)]
        if not all_toks:
            row["lifetime_verdict"] = "NO_TOKEN_LIFETIME_UNENFORCEABLE"
            row["lifetime_means"] = (
                "There is no token, so the configured lifetime applies to "
                "nothing. This is not compliance with the policy; it is the "
                "policy having no subject.")
        elif not measurable:
            row["lifetime_verdict"] = "CANNOT_SEE"
        elif all(abs(w - want_window) <= 120 for w in measurable):
            row["lifetime_verdict"] = "LIFETIME_AS_CONFIGURED"
        else:
            row["lifetime_verdict"] = "LIFETIME_DIFFERS_SET_AT_BIRTH"
            row["lifetime_means"] = (
                "This recipient's token window is not the configured one. "
                "The applier sets expiration_time on CREATE and deliberately "
                "does not touch it on UPDATE, so the difference persists and "
                "is reported rather than corrected. Use --renew-lifetime to "
                "change it on purpose.")
        if n_tokens > 2:
            bad.append(name)
        if state.get("verdict") == "TOKEN_EXPIRED":
            row["consequence"] = (
                "This recipient cannot be read through today. A task that "
                "needs a consumer-side read must rotate first, and a "
                "failure observed before rotating is a credential failure "
                "wearing an entitlement failure's clothes.")
        rows.append(row)
    return {"rule": "RI-4 token count within the platform bound; configured "
                    "lifetime within the documented year",
            "configured_lifetime_days": lifetime_days,
            "configured_lifetime_within_documented_max": (
                lifetime_days * DAY) <= YEAR_SECONDS,
            "documented_max_days": 365,
            "documented_max_status": "DOCUMENTED_NOT_MEASURED",
            "documented_max_note": "Asserting our number against a bound we "
                                   "did not measure. The measurement is a "
                                   "year long.",
            "lifetime_is_a_birth_property": {
                "behaviour": "expiration_time is set on CREATE and is NOT "
                             "re-sent on UPDATE.",
                "because": "An applier that re-stamped the lifetime on every "
                           "run would extend every credential by the full "
                           "window each time it ran, which converts a "
                           "time-bounded control into an unbounded one for "
                           "any environment where the applier runs "
                           "regularly. Idempotent configuration and a "
                           "bounded credential lifetime pull in opposite "
                           "directions here, and silently extending is the "
                           "worse of the two failures because nothing looks "
                           "wrong.",
                "consequence": "Lifetime drift is REPORTED per recipient "
                               "(lifetime_verdict) and changed only under "
                               "--renew-lifetime.",
            },
            "rows": rows, "bad": bad, "cannot_see": unseen,
            "verdict": ("PARTIAL_CANNOT_SEE" if unseen
                        else "WITHIN_BOUNDS" if not bad else "DIVERGES")}


def rule5_dsa_refs(host, token, cfg):
    rows, bad, unseen = [], [], []
    for r in cfg["recipients"]:
        name = r["name"]
        st, pl = get_recipient(host, token, name)
        row = {"recipient": name, "dsa_ref": r.get("dsa_ref"),
               "dsa_ref_status": r.get("dsa_ref_status")}
        if st != 200:
            row["verdict"] = "CANNOT_SEE"
            unseen.append(name)
            rows.append(row)
            continue
        comment = pl.get("comment") or ""
        row["comment_read_back"] = comment
        has_ref = (r.get("dsa_ref") or "") in comment
        has_status = (r.get("dsa_ref_status") or "") in comment
        row["verdict"] = ("DSA_REF_CARRIED_WITH_STATUS" if has_ref and has_status
                          else "DSA_REF_CARRIED_STATUS_MISSING" if has_ref
                          else "DSA_REF_ABSENT")
        if row["verdict"] != "DSA_REF_CARRIED_WITH_STATUS":
            bad.append(name)
        rows.append(row)
    return {"rule": "RI-5 DSA reference and its placeholder status are "
                    "carried on the recipient, read back",
            "rows": rows, "bad": bad, "cannot_see": unseen,
            "verdict": ("PARTIAL_CANNOT_SEE" if unseen
                        else "ALL_CARRIED" if not bad else "DIVERGES"),
            "means": "§3.3 purpose limitation. The status is inside the same "
                     "string so a placeholder cannot be quoted as an "
                     "executed agreement reference."}


def rule6_inventory(host, token, cfg):
    names, meta = list_recipients(host, token)
    if names is None:
        return {"rule": "RI-6 unmanaged recipients inventoried with reachability",
                "verdict": "CANNOT_SEE", "listing": meta,
                "means": "An unreadable recipient list is not an empty one."}
    managed = {r["name"] for r in cfg["recipients"]}
    declared_leftovers = {x["name"] for x in
                          (cfg.get("unmanaged_recipients") or {})
                          .get("known_leftovers") or []}
    rows = []
    for n in sorted(set(names) - managed):
        state = recipient_state(host, token, n)
        rows.append({
            "recipient": n,
            "declared_as_known_leftover": n in declared_leftovers,
            "state": state.get("verdict"),
            "reachability": ("REACHABLE_NOW"
                             if state.get("verdict") == "ACTIVATED_WITH_LIVE_TOKEN"
                             else "REACHABLE_ON_ACTIVATION"
                             if state.get("verdict") == "ACTIVATION_PENDING"
                             else "DORMANT_NO_LIVE_CREDENTIAL"),
            "has_ip_access_list": state.get("ip_access_list"),
            "authentication_type": state.get("authentication_type"),
        })
    undeclared = [r["recipient"] for r in rows
                  if not r["declared_as_known_leftover"]]
    reachable = [r["recipient"] for r in rows
                 if r["reachability"] == "REACHABLE_NOW"]
    return {"rule": "RI-6 unmanaged recipients inventoried with reachability",
            "policy": (cfg.get("unmanaged_recipients") or {}).get("policy"),
            "recipients_on_metastore": len(names),
            "managed_by_this_config": sorted(managed),
            "rows": rows,
            "undeclared_leftovers": undeclared,
            "reachable_now": reachable,
            "verdict": ("INVENTORY_CLEAN" if not rows
                        else "LEFTOVERS_ALL_DECLARED_AND_DORMANT"
                        if not undeclared and not reachable
                        else "UNDECLARED_LEFTOVERS_PRESENT" if undeclared
                        else "LEFTOVER_REACHABLE_NOW"),
            "means": "Nothing here is deleted. A dormant leftover is not a "
                     "finding; one nobody is counting is how it becomes one "
                     "(B-31). A leftover that is REACHABLE_NOW is a "
                     "different claim and is named separately."}


def rule7_isolation(host, token, cfg, rule1):
    """Measures share_isolation's unmeasured half as a side effect."""
    by_type = {}
    for row in rule1["rows"]:
        if row.get("verdict", "").startswith("EXISTS"):
            by_type.setdefault(row.get("actual_type"), []).append(row["recipient"])
    token_recips = by_type.get("TOKEN", [])
    si = cfg.get("share_isolation") or {}
    measured = len(token_recips) >= 2
    return {"rule": "§3.1 share isolation -- per-use-case recipients, by channel",
            "conops_text": si.get("conops_text"),
            "token_recipients_coexisting": sorted(token_recips),
            "token_recipient_count": len(token_recips),
            "d2o_per_use_case_recipients": ("AVAILABLE_MEASURED" if measured
                                            else "NOT_YET_MEASURED"),
            "d2d_per_use_case_recipients": "REFUSED_MEASURED_B29",
            "d2d_evidence": "docs/11 §11.7 B-29; the error names the OTHER recipient",
            "verdict": ("ISOLATION_RULE_DIFFERS_BY_CHANNEL_MEASURED" if measured
                        else "ISOLATION_RULE_HALF_MEASURED"),
            "means": ("Two TOKEN recipients coexist for one logical consumer, "
                      "so §3.1's 'one recipient per consuming agency OR USE "
                      "CASE' is satisfiable per use case on D2O and refused "
                      "per use case on D2D. One sentence, two answers, and "
                      "the CONOPS does not split it by channel."
                      if measured else
                      "Fewer than two TOKEN recipients were observed, so the "
                      "D2O half is still unmeasured. Not a failure -- an "
                      "absence of the observation."),
            "conops_action": si.get("consequence_for_v1_6")}


def rule8_revocation(cfg):
    """Static: every declared trigger must name an operation this API has.

    A revocation policy whose enforcement column says something the
    platform cannot do is a policy that fails at the only moment it
    matters.
    """
    available = {
        "DELETE recipient": "DELETE /recipients/{name}",
        "rotate-token with existing_token_expire_in_seconds=0":
            "POST /recipients/{name}/rotate-token",
        "revoke the SHARE grant, keep the recipient":
            "PATCH /shares/{share}/permissions  changes[].remove",
        "review, no automatic action": "NOT_AN_API_CALL_BY_DESIGN",
    }
    pol = None
    for sd in ((cfg.get("token_policy") or {}).get("sub_decisions") or []):
        if sd.get("id") == "OD5-4":
            pol = sd
    rows = []
    for item in ((pol or {}).get("local") or []):
        enf = item.get("enforcement")
        rows.append({"trigger": item.get("trigger"), "enforcement": enf,
                     "api": available.get(enf),
                     "verdict": "ENFORCEABLE" if enf in available
                                else "NO_KNOWN_OPERATION"})
    bad = [r for r in rows if r["verdict"] != "ENFORCEABLE"]
    return {"rule": "OD5-4 revocation triggers name operations that exist",
            "scope": "STATIC -- no call is made; nothing is revoked",
            "rows": rows,
            "verdict": "ALL_TRIGGERS_ENFORCEABLE" if not bad else "UNENFORCEABLE_TRIGGER",
            "means": "Checked because a revocation path is only tested on the "
                     "worst day. Rotation with expire=0 is the compromise "
                     "path and is NOT exercised here -- RKI-2."}


# MEASURED 2026-10-22, and it is a CONOPS finding rather than a script
# detail: the platform REFUSES a rotation whose overlap would place the
# old token's new expiry AFTER its current one.
#
#   psp7-demo-recipient, 84 minutes from expiry, overlap 86400s
#   -> HTTP 400 INVALID_PARAMETER_VALUE
#      "Cannot extend the token expiration time."
#
# Read that failure carefully, because the obvious reading is the wrong
# one. It is not "rotation is broken". It is that rotation carrying the
# configured 24h overlap stops working once the token has less than 24h
# left -- the overlap request becomes an extension request, and extension
# is refused. The window in which the configured overlap is unusable is
# therefore exactly the window in which somebody notices the credential
# is about to expire. §3.4.1's rotation path has to say so, and the
# operational rule is: rotate before (expiry - overlap), or rotate with a
# shortened overlap and accept a hard cutover.
def rotate(host, token, name, overlap_seconds):
    st, pl = call(host, token, f"{UC}/recipients/{name}/rotate-token", "POST",
                  {"existing_token_expire_in_seconds": overlap_seconds})
    out = {"recipient": name, "http_status": st,
           "overlap_seconds_requested": overlap_seconds}
    if st == 200:
        out["verdict"] = "ROTATED"
        out["secret_written_to"] = str(write_secret(f"{name}-rotated", pl)
                                       .relative_to(REPO))
        out["recipient_after"] = safe_recipient(pl)
        out["note"] = ("A NEW activation link exists in that file. The old "
                       "credential is expected to keep working for the "
                       "overlap window -- expected, not measured. T-10 "
                       "measures it (RKI-2).")
    else:
        code, msg = err_bits(pl)
        out["verdict"] = "ROTATE_FAILED"
        out["error_code"] = code
        out["error"] = redact_full(msg)[:2000]
    return out


# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--prune-grants", action="store_true",
                    help="remove grants not declared in the config")
    ap.add_argument("--rotate-token", metavar="RECIPIENT",
                    help="rotate one recipient's token (issues a new link)")
    ap.add_argument("--renew-lifetime", action="store_true",
                    help="re-stamp expiration_time on existing recipients; "
                         "EXTENDS live credentials by the full window, which "
                         "is why it is not the default")
    ap.add_argument("--rotate-overlap-seconds", type=int, metavar="N",
                    help="override the configured overlap for THIS rotation. "
                         "0 is RKI-2's compromise path: the old credential "
                         "dies at once, so there is no window in which two "
                         "credentials are live. Needed because the platform "
                         "refuses an overlap that would fall AFTER the "
                         "existing token's expiry -- see the comment on "
                         "rotate() -- which means the configured 24h overlap "
                         "becomes unusable in the last 24h of a token's "
                         "life, exactly when rotation is most urgent")
    args = ap.parse_args()

    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required: pip install pyyaml --break-system-packages")

    if not CONFIG.exists():
        sys.exit(f"Missing {CONFIG}")
    cfg = yaml.safe_load(CONFIG.read_text())

    load_env()
    host = os.environ.get("DATABRICKS_HOST")
    token = os.environ.get("DATABRICKS_TOKEN")
    if not host or not token:
        sys.exit("DATABRICKS_HOST and DATABRICKS_TOKEN must be set (.env)")

    lifetime_days = 7
    overlap = DAY
    for sd in ((cfg.get("token_policy") or {}).get("sub_decisions") or []):
        if sd.get("id") == "OD5-2":
            lifetime_days = sd.get("local_days", lifetime_days)
        if sd.get("id") == "OD5-3":
            overlap = sd.get("local_overlap_seconds", overlap)

    print("=" * 70)
    print("E1 Task 1.5 -- recipient / credential model")
    print("=" * 70)
    print(f"  config:   {CONFIG.relative_to(REPO)}")
    print(f"  branch:   {(cfg.get('sign_in') or {}).get('built_branch')}  "
          f"(OD-5 is OPEN; this is a branch, not a decision)")
    print(f"  lifetime: {lifetime_days}d  overlap: {overlap}s  "
          f"[PROTOTYPE_DEFAULT_NOT_POLICY]")
    print(f"  mode:     {'DRY-RUN' if args.dry_run else 'APPLY'}")

    res = {
        "script": "scripts/27_build_recipient_model.py",
        "task": "E1 Task 1.5",
        "generated_at": now(),
        "config": str(CONFIG.relative_to(REPO)),
        "mode": "DRY_RUN" if args.dry_run else "APPLY",
        "open_decision": {
            "id": "OD-5", "status": "OPEN_NOT_DECIDED_HERE",
            "built_branch": (cfg.get("sign_in") or {}).get("built_branch"),
            "means": "Every policy number in this run is a prototype default "
                     "labelled as one. Nothing here decides OD-5.",
        },
        "token_policy_applied": {
            "lifetime_days": lifetime_days,
            "overlap_seconds": overlap,
            "status": "PROTOTYPE_DEFAULT_NOT_POLICY",
        },
    }

    # ---- pre-apply static guards ------------------------------------
    ent_shares = set()
    if ENTITLEMENTS.exists():
        ent = yaml.safe_load(ENTITLEMENTS.read_text())
        ent_shares = {s["name"] for s in (ent.get("shares") or [])}
    guards = []
    for r in cfg["recipients"]:
        for g in (r.get("grants") or []):
            known = g["share"] in ent_shares if ent_shares else None
            guards.append({"recipient": r["name"], "share": g["share"],
                           "declared_in_entitlements_yaml": known})
    unknown = [g for g in guards if g["declared_in_entitlements_yaml"] is False]
    res["pre_apply_guards"] = {
        "grant_targets": guards,
        "grants_to_shares_not_in_entitlements_yaml": unknown,
        "verdict": "ALL_GRANT_TARGETS_DEFINED" if not unknown else "GRANT_TO_UNDEFINED_SHARE",
        "means": "A grant to a share the entitlement model does not define "
                 "would be a hole with no column list behind it. Checked "
                 "before anything is applied.",
    }
    print("\n-- pre-apply guards -------------------------------------------")
    print(f"  {len(guards)} grant target(s): "
          f"{res['pre_apply_guards']['verdict']}")
    if unknown:
        for g in unknown:
            print(f"  !! {g['recipient']} -> {g['share']} is not in "
                  f"entitlements.yaml")
        res["verdict"] = "REFUSED_GRANT_TO_UNDEFINED_SHARE"
        EVIDENCE.parent.mkdir(exist_ok=True)
        EVIDENCE.write_text(json.dumps(res, indent=2, default=str))
        print(f"\n  VERDICT: {res['verdict']}  (nothing applied)")
        sys.exit(2)

    # ---- apply ------------------------------------------------------
    print("\n-- apply: recipients ------------------------------------------")
    res["recipients_applied"] = []
    for r in cfg["recipients"]:
        out = apply_recipient(host, token, r, lifetime_days, args.dry_run,
                              renew=args.renew_lifetime)
        res["recipients_applied"].append(out)
        extra = ""
        if out.get("credential_issued_by_this_call"):
            extra = "  [credential issued -> _secrets/, not printed]"
        print(f"  {r['name']}: {out['verdict']}{extra}")
        if out.get("verdict") in ("CREATE_FAILED", "PATCH_FAILED"):
            print(f"      {out.get('error_code')}: "
                  f"{(out.get('error') or '')[:200]}")

    print("\n-- apply: grants ----------------------------------------------")
    res["grants_applied"] = []
    for r in cfg["recipients"]:
        for row in apply_grants(host, token, r, args.dry_run):
            res["grants_applied"].append(row)
            print(f"  {row['recipient']} -> {row['share']}: {row['verdict']}")

    if args.rotate_token:
        print("\n-- rotate -----------------------------------------------------")
        if args.dry_run:
            res["rotation"] = {"verdict": "DRY_RUN",
                               "recipient": args.rotate_token}
            print(f"  {args.rotate_token}: DRY_RUN")
        else:
            # An explicit override is recorded as an override, so the
            # evidence never shows an overlap the config did not declare
            # without saying where it came from.
            rot_overlap = (overlap if args.rotate_overlap_seconds is None
                           else args.rotate_overlap_seconds)
            res["rotation"] = rotate(host, token, args.rotate_token,
                                     rot_overlap)
            if args.rotate_overlap_seconds is not None:
                res["rotation"]["overlap_source"] = (
                    "--rotate-overlap-seconds on the command line, "
                    f"overriding the configured {overlap}s")
            else:
                res["rotation"]["overlap_source"] = (
                    "local_overlap_seconds in iac/config/recipients.yaml")
            # The failure reason is printed, not only written. A console
            # line that says ROTATE_FAILED and stops is how an operator
            # reads a wrong recipient NAME as a platform refusal: the
            # first run of this rotation printed exactly that, and the
            # cause (404 RECIPIENT_DOES_NOT_EXIST) was only visible by
            # opening the evidence file.
            line = f"  {args.rotate_token}: {res['rotation']['verdict']}"
            if res["rotation"]["verdict"] != "ROTATED":
                line += (f"  [{res['rotation'].get('http_status')} "
                         f"{res['rotation'].get('error_code')}] "
                         f"{res['rotation'].get('error', '')}")
            print(line)

    # ---- verify -----------------------------------------------------
    print("\n-- verify -----------------------------------------------------")
    r1 = rule1_existence(host, token, cfg)
    r2 = rule2_ip_lists(host, token, cfg)
    r3 = rule3_grants(host, token, cfg, args.prune_grants)
    r4 = rule4_tokens(host, token, cfg, lifetime_days)
    r5 = rule5_dsa_refs(host, token, cfg)
    r6 = rule6_inventory(host, token, cfg)
    r7 = rule7_isolation(host, token, cfg, r1)
    r8 = rule8_revocation(cfg)
    res["verify"] = {"rule1_existence": r1, "rule2_ip_lists": r2,
                     "rule3_grants": r3, "rule4_tokens": r4,
                     "rule5_dsa_refs": r5, "rule6_inventory": r6,
                     "rule7_share_isolation": r7, "rule8_revocation": r8}

    print(f"  rule 1 existence:   {r1['verdict']}")
    print(f"  rule 2 ip lists:    {r2['verdict']}")
    print(f"  rule 3 grants:      {r3['verdict']}  "
          f"({r3.get('shares_examined', '?')} share(s) examined)")
    print(f"  rule 4 tokens:      {r4['verdict']}")
    # lifetime_verdict is printed, not only written. rule 4 has always
    # MEASURED it -- psp7-demo-recipient has carried
    # LIFETIME_DIFFERS_SET_AT_BIRTH (a 24h window against a configured 7d)
    # across every run -- but the console printed only state and token
    # count, so three recipients that differ read as three that agree.
    # The measurement was right and the summary was lossy, which is the
    # same shape as a label disagreeing with its evidence: anyone working
    # from the terminal would have planned around a 7-day credential.
    for row in r4["rows"]:
        line = (f"      {row['recipient']}: {row.get('state')}  "
                f"tokens={row.get('token_count')}")
        lv = row.get("lifetime_verdict")
        if lv and lv != "LIFETIME_AS_CONFIGURED":
            line += f"  lifetime={lv}"
        print(line)
    print(f"  rule 5 dsa refs:    {r5['verdict']}")
    print(f"  rule 6 inventory:   {r6['verdict']}  "
          f"({r6.get('recipients_on_metastore', '?')} recipient(s) on metastore)")
    print(f"  rule 7 isolation:   {r7['verdict']}")
    print(f"  rule 8 revocation:  {r8['verdict']}")

    # ---- verdicts, on two axes (B-32a) -------------------------------
    apply_states = {o["recipient"]: o["verdict"]
                    for o in res["recipients_applied"]}
    grant_states = [g["verdict"] for g in res["grants_applied"]]
    apply_bad = ([n for n, v in apply_states.items()
                  if v not in ("CREATED", "UPDATED", "DRY_RUN")]
                 + [v for v in grant_states
                    if v not in ("GRANTED", "DRY_RUN")])
    res["apply_outcome"] = {
        "per_recipient": apply_states,
        "grants": grant_states,
        "failed_or_blocked": apply_bad,
        "verdict": "APPLIED" if not apply_bad else "FAILED",
        "means": ("Every statement succeeded." if not apply_bad else
                  "At least one mutation failed. B-32a: this is its own axis "
                  "precisely so a correct end state cannot report green over "
                  "a failed step."),
    }

    # Three axes, not one. The first version of this block folded the
    # ENVIRONMENT inventory into the MODEL conformance verdict, so a
    # dormant recipient left behind by an earlier task -- something this
    # config deliberately does not manage -- reported
    # RECIPIENT_MODEL_DIVERGES while rules 1 to 5 were all clean. That is
    # B-20 inside the tooling: a verdict vocabulary too coarse to name
    # its own cause, failing toward blaming the model. Splitting them is
    # not a downgrade: the inventory finding is still a named,
    # non-clean verdict and still sets a non-zero exit code.
    conformance_rules = {"rule1_existence": r1, "rule2_ip_lists": r2,
                         "rule3_grants": r3, "rule4_tokens": r4,
                         "rule5_dsa_refs": r5}
    conf_cannot_see = [k for k, v in conformance_rules.items()
                       if "CANNOT_SEE" in str(v.get("verdict"))]
    conf_bad = [k for k, v in conformance_rules.items()
                if str(v.get("verdict")) in
                ("DIVERGES", "GRANTS_DIVERGE",
                 "UNMANAGED_PRINCIPAL_HOLDS_REACHABLE_GRANT")]
    res["model_conformance"] = {
        "rules": {k: v.get("verdict") for k, v in conformance_rules.items()},
        "cannot_see": conf_cannot_see, "diverged": conf_bad,
        "verdict": ("PARTIAL_CANNOT_SEE" if conf_cannot_see
                    else "CONFORMS" if not conf_bad else "DIVERGES"),
        "scope": "What this config declares, compared against what the "
                 "platform holds. Rules 1-5.",
    }
    env_bad = str(r6.get("verdict")) not in ("INVENTORY_CLEAN",
                                             "LEFTOVERS_ALL_DECLARED_AND_DORMANT")
    unmanaged_grants = r3.get("unmanaged_principals_with_grants") or []
    res["environment_inventory"] = {
        "rule6": r6.get("verdict"),
        "undeclared_leftovers": r6.get("undeclared_leftovers"),
        "leftovers_reachable_now": r6.get("reachable_now"),
        "unmanaged_principals_with_grants": [u["principal"] for u in unmanaged_grants],
        "unmanaged_principals_reachable": r3.get("unmanaged_principals_reachable"),
        "verdict": ("INVENTORY_CLEAN"
                    if not env_bad and not unmanaged_grants
                    else "UNMANAGED_OBJECTS_PRESENT_AND_DORMANT"
                    if not (r6.get("reachable_now")
                            or r3.get("unmanaged_principals_reachable"))
                    else "UNMANAGED_OBJECT_REACHABLE"),
        "scope": "What else is on the metastore. Separate from conformance "
                 "because an object this config does not manage is not "
                 "evidence that the model it does manage is wrong -- and "
                 "because the opposite error, letting it disappear into a "
                 "green model verdict, is how B-31 happened.",
        "policy": "Reported, never deleted (B-19).",
    }

    conf = res["model_conformance"]["verdict"]
    env = res["environment_inventory"]["verdict"]
    if conf == "PARTIAL_CANNOT_SEE":
        res["verdict"] = "PARTIAL_CANNOT_SEE"
    elif conf == "DIVERGES":
        res["verdict"] = "RECIPIENT_MODEL_DIVERGES"
    elif apply_bad:
        res["verdict"] = "VERIFIED_PROVIDER_SIDE_APPLY_NOT_REPEATABLE"
    elif env == "UNMANAGED_OBJECT_REACHABLE":
        res["verdict"] = "MODEL_VERIFIED_UNMANAGED_OBJECT_REACHABLE"
    elif env != "INVENTORY_CLEAN":
        res["verdict"] = "MODEL_VERIFIED_PROVIDER_SIDE_ENVIRONMENT_NOT_CLEAN"
    else:
        res["verdict"] = "RECIPIENT_MODEL_VERIFIED_PROVIDER_SIDE"

    res["verdict_scope"] = (
        "PROVIDER-SIDE ONLY, exactly as Task 1.4's was. Nothing here is a "
        "consumer-side read. RKI-1: no Delta Sharing client has used any of "
        "these credentials in this run, so 'the recipient sees only the "
        "entitled columns and rows' is NOT a claim this evidence supports.")
    res["known_incomplete"] = cfg.get("known_incomplete")

    EVIDENCE.parent.mkdir(exist_ok=True)
    EVIDENCE.write_text(redact_full(json.dumps(res, indent=2, default=str)))

    print(f"\n  apply:       {res['apply_outcome']['verdict']}")
    print(f"  conformance: {res['model_conformance']['verdict']}   "
          f"(rules 1-5)")
    print(f"  environment: {res['environment_inventory']['verdict']}   "
          f"(rule 6 + unmanaged grant-holders)")
    print(f"  VERDICT: {res['verdict']}")
    print("  scope:   provider-side only (RKI-1)")
    print(f"  Wrote {EVIDENCE.relative_to(REPO)}")
    if any(o.get("secret_written_to") for o in res["recipients_applied"]) \
            or (res.get("rotation") or {}).get("secret_written_to"):
        print("\n  A one-time activation link was written to _secrets/ "
              "(owner-only).\n  Open it yourself; it is single-use and is not "
              "in the evidence file.")
    print("\nNext: E1 Task 1.6 -- T-01 and the two-phase T-02/T-03 procedure "
          "in recipients.yaml")

    sys.exit(0 if res["verdict"] == "RECIPIENT_MODEL_VERIFIED_PROVIDER_SIDE"
             else 1)


if __name__ == "__main__":
    main()
