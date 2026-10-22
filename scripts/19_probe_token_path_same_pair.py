#!/usr/bin/env python3
"""Can these two metastores exchange data AT ALL? One variable: credential mode.

WHY THIS EXISTS
---------------
scripts/18 produced the strongest negative this project has:

  egress   chain=COMPLETE  provider_visible=False  NO_PROVIDER_CLEAN_NEGATIVE
  ingress  chain=COMPLETE  provider_visible=False  NO_PROVIDER_CLEAN_NEGATIVE
  DIRECTION VERDICT: VISIBILITY_UNVERIFIED

Complete chains both ways, every link verified by read-back, REST and
SQL agreeing, bounded at ~169s per direction. Direction is excluded as
the explanation. That is as far as that instrument can go, and the
verdict it returns is honest but almost unusable in a CONOPS: "D2D
provider visibility is unverified" names no cause and licenses no
remediation.

The reason it names no cause is that a very large family of explanations
is still live, and they are not distinguishable from each other by
anything scripts/18 measures:

  * the two accounts cannot exchange Delta Sharing data at all
  * the region pairing is wrong despite both reading aws:us-east-2
  * the share is syntactically valid but unservable
  * the table type/format cannot actually be served to a consumer
  * the grant is recorded but not honoured by the data plane
  * only the AUTOMATIC PROVIDER APPEARANCE step is unavailable here

Those are not close to equivalent. The first five would be product or
environment constraints of real consequence; the last is one missing
convenience step on a path whose data plane works. The whole CONOPS
claim for T-19 turns on which of them is true, and scripts/18 cannot
tell them apart because it never moved a single row.

WHAT THIS PROBE DOES
--------------------
Serves the SAME table from the SAME share with the SAME SELECT grant on
the SAME provider metastore to a SECOND recipient on that same share,
differing from the D2D recipient in credential mode: TOKEN instead of
DATABRICKS. Then the primary reads it.

If rows arrive, the first five explanations above are all excluded in
one stroke: these two metastores demonstrably exchange Delta Sharing
data, this share is servable, this table is serveable, and the grant is
honoured by the data plane. The unexplained residue collapses to the
automatic-provider-appearance mechanism alone, and T-19 gains a
documented working substitute path instead of a dead end.

If rows do NOT arrive, that is a much larger finding than T-19, and it
relocates the problem from a D2D convenience step to cross-account
sharing between these accounts generally.

HONESTY ABOUT "ONE VARIABLE"
----------------------------
The credential mode is one variable, but the surfacing mechanism is NOT
independent of it. TOKEN auth entails an explicit CREATE PROVIDER from a
downloaded credential; DATABRICKS auth entails automatic appearance.
Choosing the credential mode chooses the surfacing mechanism with it,
and no setting separates them.

So this probe does not and cannot show "automatic appearance is broken
while everything else works". It shows that the DATA PATH between this
specific pair works, which eliminates the five environmental readings
and leaves exactly one. That is a narrowing, not an isolation, and the
evidence file says so in those words. Claiming more would be B-18's
error in a new costume: a conclusion one variable wider than the
measurement that produced it.

TWO PHASES, BECAUSE THE MIDDLE STEP IS A HUMAN ONE
--------------------------------------------------
A TOKEN recipient's activation URL is a one-time-use, bearer-equivalent
secret: whoever holds it downloads the credential file ONCE. scripts/03
established this repo's handling -- the script writes it to _secrets/
with mode 0600 and never prints it, and a human opens it themselves.
Same here, for the same reason: an activation URL in a terminal
scrollback is a credential in a terminal scrollback (B-15).

  --mint     create the TOKEN recipient on glovashu, grant it the
             existing p18 share, write the activation URL to _secrets/
  --verify   import the downloaded credential on the primary, read the
             table, and check the rows came FROM GLOVASHU
  --cleanup  remove the provider and catalog on the primary and the
             token recipient on glovashu

THE ROWS MUST BE ATTRIBUTABLE, NOT MERELY PRESENT
-------------------------------------------------
scripts/17 built glovashu's table with 37 rows -- deliberately not the
primary's 50 -- and stamped every row with glovashu's live-read
metastore id. That was for this moment. A successful read of a table
called test_dataset proves nothing on its own: both sides have one, and
a misconfigured provider that silently resolved to the LOCAL copy would
produce a passing read and a false conclusion. The expected row count
and origin id are read out of evidence/glovashu-provider-dataset.json
rather than typed here, so the assertion cannot drift from the fixture
it is asserting about.
"""

import argparse
import datetime
import importlib.util
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "evidence" / "d2d-vs-d2o-same-pair.json"
SECRETS = REPO / "_secrets"
RECIPIENT_INFO = SECRETS / "glovashu-token-recipient-info.json"
CREDENTIAL = SECRETS / "glovashu-d2o-credential.json"

FIXTURE = REPO / "evidence" / "glovashu-provider-dataset.json"
SYMMETRY = REPO / "evidence" / "d2d-direction-symmetry.json"

UC = "/api/2.1/unity-catalog"
TAG = "awoz1227_p19"
TOKEN_RECIPIENT = f"{TAG}_token_recipient"
PROVIDER_NAME = f"{TAG}_glovashu_provider"
CATALOG_NAME = f"{TAG}_glovashu_catalog"

# The share scripts/18 left behind with --keep. Reusing it is the point:
# a NEW share would introduce a second variable, and then a successful
# TOKEN read would not be about the same object the D2D recipient failed
# to surface.
P18_SHARE = "awoz1227_p18_glovashu_share"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this probe reuses its helpers.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "probe14")
call = P14.call
classify = P14.classify
redact = P14.redact
profile_summary = P14.profile_summary


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit("No .env found.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if not v.strip():
            # A blank value is an ABSENCE, not a value (B-10b).
            continue
        os.environ.setdefault(k.strip(), v.strip())


def sides():
    load_env()
    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN",
                "GLOVASHU_HOST", "GLOVASHU_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")
    return {
        "p_host": os.environ["DATABRICKS_HOST"].strip().rstrip("/"),
        "p_token": os.environ["DATABRICKS_TOKEN"].strip(),
        "g_host": os.environ["GLOVASHU_HOST"].strip().rstrip("/"),
        "g_token": os.environ["GLOVASHU_TOKEN"].strip(),
    }


def expected_fixture():
    """Row count and origin stamp, READ from the fixture's own evidence.

    Typing 37 here would create a second source of truth for a number
    that already has one, and the two would diverge the first time the
    fixture is rebuilt with a different size. The assertion would then
    pass or fail for reasons unrelated to what it claims to test.
    """
    if not FIXTURE.exists():
        sys.exit(f"Missing {FIXTURE.relative_to(REPO)}. Run "
                 f"scripts/17_create_glovashu_provider_dataset.py --apply "
                 f"first; without it there is no attributable fixture and a "
                 f"successful read would be indistinguishable from reading "
                 f"the primary's own copy.")
    doc = json.loads(FIXTURE.read_text())
    # Read the OBSERVED block, not the intended one. scripts/17 records
    # both, and they are not the same claim: `intended` is what the
    # script meant to write, `observed` is what a read-back found. An
    # assertion built on `intended` would be comparing this probe's read
    # against a hope rather than against a measurement, and the two
    # diverge precisely when something is wrong.
    ver = (doc.get("verification") or {})
    obs = (ver.get("observed") or {})
    rows = obs.get("rows")
    origin = obs.get("origin")
    full = (doc.get("target") or {}).get("full_name")
    if rows is None or origin is None or not full:
        sys.exit(
            f"{FIXTURE.relative_to(REPO)} does not record a verified "
            f"row count, origin stamp and full table name under "
            f"verification.observed / target.full_name. The "
            f"attributability assertion would have nothing to assert "
            f"against. Re-run scripts/17 --apply rather than weakening "
            f"the check -- a probe that falls back to a default row count "
            f"here would pass on the primary's own table.")
    if doc.get("verdict") != "CREATED_AND_VERIFIED":
        sys.exit(f"{FIXTURE.relative_to(REPO)} verdict is "
                 f"{doc.get('verdict')!r}, not CREATED_AND_VERIFIED. The "
                 f"fixture is not known good, so a read against it proves "
                 f"nothing either way.")
    return {"row_count": rows,
            "origin_metastore": origin,
            "distinct_origins": obs.get("distinct_origins"),
            "table_full_name": full,
            "fixture_source": str(FIXTURE.relative_to(REPO))}


def find_warehouse(host, token):
    status, payload = call(host, token, "/api/2.0/sql/warehouses")
    if status != 200:
        return None
    for wh in (payload.get("warehouses") or []):
        return wh.get("id")
    return None


def run_sql(host, token, warehouse_id, statement):
    status, payload = call(
        host, token, "/api/2.0/sql/statements", "POST",
        {"statement": statement, "warehouse_id": warehouse_id,
         "wait_timeout": "50s", "on_wait_timeout": "CANCEL"})
    state = ((payload or {}).get("status") or {}).get("state", "").upper()
    if status != 200 or state != "SUCCEEDED":
        return None, {
            "http_status": status,
            "state": state or None,
            "error": redact(json.dumps(
                ((payload or {}).get("status") or {}).get("error") or {}))[:400],
        }
    return ((payload.get("result") or {}).get("data_array") or []), {
        "http_status": status, "state": state}


# =====================================================================
# PHASE 1 -- mint
# =====================================================================

def phase_mint(s):
    g_host, g_token = s["g_host"], s["g_token"]
    res = {"phase": "mint", "run_at": now(), "steps": {}}

    # Precondition. The p18 share must still exist and still hold the
    # table; if --keep was not used, or somebody cleaned up, a new share
    # would silently become the subject and the comparison would be with
    # a different object than the one D2D failed to surface.
    status, payload = call(
        g_host, g_token, f"{UC}/shares/{P18_SHARE}?include_shared_data=true")
    if status != 200:
        sys.exit(f"{P18_SHARE} is not present on glovashu (status {status}). "
                 f"Re-run scripts/18 with --direction ingress --keep so the "
                 f"SAME share this probe needs is in place. Creating a fresh "
                 f"share here would add a second variable and the result "
                 f"would not be about the object D2D failed to surface.")
    objs = [o.get("name") for o in (payload.get("objects") or [])]
    statuses = [o.get("status") for o in (payload.get("objects") or [])]
    res["steps"]["share_precondition"] = {
        "share": P18_SHARE, "objects": objs, "statuses": statuses,
        "verdict": "SHARE_NON_EMPTY" if objs else "SHARE_EMPTY",
    }
    print(f"    share {P18_SHARE}: {objs} {statuses}")
    if not objs:
        sys.exit("The share reads back empty. Nothing to serve.")

    # Also record which recipients already hold it, so the evidence shows
    # the TOKEN recipient was added ALONGSIDE the DATABRICKS one rather
    # than replacing it. Same share, same grant, two credential modes.
    status, payload = call(g_host, g_token, f"{UC}/shares/{P18_SHARE}/permissions")
    existing = [(a.get("principal"), a.get("privileges"))
                for a in ((payload or {}).get("privilege_assignments") or [])]
    res["steps"]["existing_grants_before"] = existing
    print(f"    existing grants: {existing}")

    status, payload = call(
        g_host, g_token, f"{UC}/recipients", "POST",
        {"name": TOKEN_RECIPIENT,
         "authentication_type": "TOKEN",
         "comment": "E1 credential-mode comparison (scripts/19) -- "
                    "safe to delete"})
    if status in (200, 201):
        res["steps"]["create_token_recipient"] = {"status": status,
                                                  "verdict": "PERMITTED"}
        print(f"    [ok ] create_token_recipient: PERMITTED ({status})")
    else:
        verdict, code, msg = classify(status, payload)
        res["steps"]["create_token_recipient"] = {
            "status": status, "verdict": verdict, "error_code": code,
            "message": redact(msg)[:400]}
        print(f"    [REF] create_token_recipient: {verdict} ({status})")
        print(f"          {code} {redact(msg)[:200]}")
        write_evidence({"mint": res})
        sys.exit("Cannot mint a TOKEN recipient, so the credential-mode "
                 "comparison cannot be made. That refusal is itself worth "
                 "reading: TOKEN auth on this metastore is what T-01..T-07 "
                 "already exercised on the PRIMARY, so a refusal here is a "
                 "one-variable result about glovashu's configuration, not "
                 "about the tier.")

    status, payload = call(
        g_host, g_token, f"{UC}/shares/{P18_SHARE}/permissions", "PATCH",
        {"changes": [{"principal": TOKEN_RECIPIENT, "add": ["SELECT"]}]})
    verdict, code, msg = classify(status, payload)
    res["steps"]["grant_share_to_token_recipient"] = {
        "status": status,
        "verdict": "PERMITTED" if status in (200, 201) else verdict,
        "error_code": code, "message": redact(msg)[:400] or None}
    print(f"    [{'ok ' if status in (200, 201) else 'REF'}] "
          f"grant_share_to_token_recipient: "
          f"{res['steps']['grant_share_to_token_recipient']['verdict']} "
          f"({status})")

    # Read the grant back. Same rule as everywhere else in this repo: a
    # 200 on a mutation is not the finding, the re-read is (B-23).
    status, payload = call(g_host, g_token, f"{UC}/shares/{P18_SHARE}/permissions")
    after = {a.get("principal"): a.get("privileges")
             for a in ((payload or {}).get("privilege_assignments") or [])}
    res["steps"]["grant_readback"] = {
        "privilege_assignments": after,
        "verdict": "GRANT_IN_EFFECT"
                   if "SELECT" in (after.get(TOKEN_RECIPIENT) or [])
                   else "GRANT_NOT_IN_EFFECT",
        "both_credential_modes_on_one_share": len(after) >= 2,
    }
    print(f"    [{'ok ' if res['steps']['grant_readback']['verdict'] == 'GRANT_IN_EFFECT' else 'REF'}] "
          f"grant_readback: {res['steps']['grant_readback']['verdict']} "
          f"-> {after}")

    # The activation URL. Written to _secrets/ ONLY, never printed, never
    # put in evidence/. Whoever holds it can download the credential file
    # once, which makes it bearer-equivalent (B-15). scripts/03 set this
    # convention and the hygiene gate enforces the file mode.
    status, payload = call(g_host, g_token, f"{UC}/recipients/{TOKEN_RECIPIENT}")
    if status != 200:
        sys.exit(f"Could not read the recipient back (status {status}).")
    SECRETS.mkdir(exist_ok=True)
    RECIPIENT_INFO.write_text(json.dumps(payload, indent=2, default=str))
    try:
        RECIPIENT_INFO.chmod(0o600)
    except OSError:
        pass

    toks = payload.get("tokens") or []
    res["steps"]["activation"] = {
        "tokens_present": len(toks),
        "activation_pending": [bool(t.get("activation_url")) for t in toks],
        "expiration_time": [t.get("expiration_time") for t in toks],
        "written_to": str(RECIPIENT_INFO.relative_to(REPO)),
        "url_recorded_in_evidence": False,
        "means": ("The one-time activation URL is in _secrets/ at mode "
                  "0600 and nowhere else. It is NOT in this file and was "
                  "NOT printed: it is bearer-equivalent for one use."),
    }
    res["verdict"] = "AWAITING_HUMAN_DOWNLOAD"
    print(f"    [ok ] activation URL written to "
          f"{RECIPIENT_INFO.relative_to(REPO)} (0600, not printed)")

    # Expiry matters here and is not a detail. scripts/16 had to set
    # delta_sharing_recipient_token_lifetime_in_seconds = 86400 on this
    # metastore because the API REFUSES to leave it unset -- so this
    # credential dies in 24h and phase 2 has a deadline.
    status, payload = call(g_host, g_token, f"{UC}/metastore_summary")
    res["steps"]["credential_lifetime"] = {
        "delta_sharing_recipient_token_lifetime_in_seconds":
            (payload or {}).get(
                "delta_sharing_recipient_token_lifetime_in_seconds"),
        "means": ("Platform-enforced, not chosen: scripts/16 established "
                  "that this field cannot be omitted. --verify must run "
                  "inside this window or the credential must be re-minted."),
    }
    print(f"    credential lifetime: "
          f"{res['steps']['credential_lifetime']['delta_sharing_recipient_token_lifetime_in_seconds']}s")
    return res


# =====================================================================
# PHASE 2 -- verify
# =====================================================================

def phase_verify(s):
    p_host, p_token = s["p_host"], s["p_token"]
    exp = expected_fixture()
    res = {"phase": "verify", "run_at": now(), "expected": exp, "steps": {}}

    if not CREDENTIAL.exists():
        sys.exit(
            f"No credential at {CREDENTIAL.relative_to(REPO)}.\n"
            f"Open {RECIPIENT_INFO.relative_to(REPO)} YOURSELF, take the "
            f"activation_url, open it in a browser, download the credential "
            f"file ONCE and save it to that path. The link self-destructs "
            f"after one use; if it has already been used, re-run --mint "
            f"with --rotate.")
    # Record the mode AS FOUND, before touching it. This is not
    # housekeeping, it is a finding about CONOPS 3.4.1 step 3.
    #
    # The run of 2026-10-19 downloaded this credential through a browser
    # and the file landed 0o664 -- group- and world-readable -- because a
    # browser download lands at the process umask, and the step that says
    # "download the credential file once" says nothing about the mode.
    # The hygiene gate caught it, correctly, but AFTER the fact: the live
    # bearer token sat readable by every local account for as long as it
    # took somebody to run the gate. Every other secret in _secrets/ is
    # 0600 because a SCRIPT wrote it and chmodded it; this one is the
    # only human-mediated write in the whole flow, and it is the only one
    # that was wrong. That is the generalisable point, so it goes in the
    # evidence rather than being silently corrected: the provisioning
    # runbook for 3.4.1 needs the mode as an explicit step, or the
    # control depends on the operator's umask. B-25.
    mode_before = None
    try:
        mode_before = CREDENTIAL.stat().st_mode & 0o777
    except OSError:
        pass
    try:
        CREDENTIAL.chmod(0o600)
    except OSError:
        pass
    mode_after = None
    try:
        mode_after = CREDENTIAL.stat().st_mode & 0o777
    except OSError:
        pass
    res["steps"]["credential_file_mode"] = {
        "path": str(CREDENTIAL.relative_to(REPO)),
        "mode_on_arrival": oct(mode_before) if mode_before is not None
                           else None,
        "mode_after_correction": oct(mode_after) if mode_after is not None
                                 else None,
        "arrived_restricted": mode_before == 0o600,
        "verdict": ("ARRIVED_RESTRICTED" if mode_before == 0o600 else
                    "ARRIVED_PERMISSIVE_CORRECTED"),
        "means": ("A browser download lands at the operator's umask. "
                  "CONOPS 3.4.1 step 3 tells a provisioning process to "
                  "download the credential file and does not state a file "
                  "mode, so on this run a live Delta Sharing bearer token "
                  "was world-readable until the hygiene gate flagged it. "
                  "Scripted writes in this repo are 0600 because the "
                  "script sets it; the one human-mediated write was the "
                  "one that failed. The runbook step needs the mode."),
    }
    print(f"    credential file mode on arrival: "
          f"{res['steps']['credential_file_mode']['mode_on_arrival']} "
          f"-> {res['steps']['credential_file_mode']['mode_after_correction']}")

    try:
        profile = json.loads(CREDENTIAL.read_text())
    except (json.JSONDecodeError, OSError) as e:
        sys.exit(f"Could not parse {CREDENTIAL.relative_to(REPO)}: {e}")

    # Summary only -- endpoint host, field names, token LENGTH and a
    # 12-char hash. Never the token (B-15).
    res["steps"]["credential"] = profile_summary(profile)
    print(f"    credential endpoint host: "
          f"{res['steps']['credential'].get('endpoint_host')}")
    print(f"    bearer token: len="
          f"{res['steps']['credential'].get('bearer_token_length')} "
          f"sha256[:12]={res['steps']['credential'].get('bearer_token_sha256_12')}")

    # WHICH SIDE DOES THIS CREDENTIAL POINT AT?
    #
    # The first version of this check compared the credential's endpoint
    # host against GLOVASHU_HOST's hostname and flagged a mismatch. On
    # the run of 2026-10-19 it fired:
    #
    #   [REF] endpoint host is NOT glovashu:
    #         b2ee813a-....opensharing.us-east-2.cloud.databricks.com
    #
    # and wrote "a read through it would not be evidence about the far
    # side" into the evidence file -- four lines above a read that WAS
    # attributable to glovashu by both row count and origin stamp. The
    # file contradicted itself, which is B-23b exactly, except this time
    # the false sentence came from a guard rather than a hard-coded note.
    #
    # The check was wrong because open sharing is NOT served from the
    # workspace hostname. Databricks serves it from a dedicated
    # <uuid>.opensharing.<region>.cloud.databricks.com endpoint, and that
    # uuid is neither metastore id. So hostname equality against the
    # workspace host cannot distinguish "points at the far side" from
    # "points at the far side's sharing endpoint" -- it reports the
    # NORMAL case as a failure.
    #
    # A guard that fires on the normal case is worse than no guard: it
    # trains the reader to skip the one line that would matter when it is
    # real. So the discriminator is rebuilt around what actually
    # discriminates. The decisive evidence of which side answered is the
    # origin stamp on the rows, which is already measured below; this
    # check is corroborative and says so.
    g_hostname = s["g_host"].split("://", 1)[-1].split("/")[0]
    p_hostname = s["p_host"].split("://", 1)[-1].split("/")[0]
    endpoint_host = res["steps"]["credential"].get("endpoint_host") or ""
    if endpoint_host == p_hostname:
        ep_verdict = "POINTS_AT_THE_CONSUMER"
        ep_means = ("The credential's endpoint is the PRIMARY's own "
                    "workspace host. A read through it would be the primary "
                    "reading itself and would pass while proving nothing. "
                    "This is the failure this check exists for.")
    elif endpoint_host == g_hostname:
        ep_verdict = "POINTS_AT_PROVIDER_WORKSPACE_HOST"
        ep_means = ("The endpoint is glovashu's workspace host directly, "
                    "which is not how Databricks normally issues open "
                    "sharing credentials. Not a problem, but worth noting "
                    "as a deviation from the observed pattern.")
    elif ".opensharing." in endpoint_host:
        ep_verdict = "DEDICATED_SHARING_ENDPOINT"
        ep_means = ("Databricks serves open sharing from a dedicated "
                    "<uuid>.opensharing.<region>.cloud.databricks.com host. "
                    "The uuid is NOT a metastore id -- neither glovashu's "
                    "nor the primary's -- so this hostname cannot by itself "
                    "attribute the data to a side. Attribution comes from "
                    "the origin stamp on the rows.")
    else:
        ep_verdict = "UNRECOGNISED_ENDPOINT"
        ep_means = ("The endpoint matches neither workspace host nor the "
                    "dedicated sharing pattern. Recorded unclassified for a "
                    "human rather than guessed at.")
    res["steps"]["credential"]["endpoint_check"] = {
        "endpoint_host": endpoint_host,
        "provider_workspace_host": g_hostname,
        "consumer_workspace_host": p_hostname,
        "verdict": ep_verdict,
        "is_decisive": ep_verdict == "POINTS_AT_THE_CONSUMER",
        "means": ep_means,
        # Genuinely useful beyond this probe. T-20 renders
        # iac/config/outbound-allow-list.yaml from observed hosts, and a
        # firewall rule written against the WORKSPACE hostname would
        # block open sharing outright, because the data plane never
        # touches that name. The egress allow-list needs this host, and
        # it is not derivable from anything in .env.
        "allow_list_implication": (
            f"Open sharing egress/ingress traverses {endpoint_host}, not "
            f"the workspace host. Any outbound allow-list built from "
            f"DATABRICKS_HOST / GLOVASHU_HOST alone would omit it and the "
            f"share would fail closed. Candidate addition to "
            f"iac/config/outbound-allow-list.yaml."),
    }
    print(f"    endpoint check: {ep_verdict}")
    if ep_verdict == "POINTS_AT_THE_CONSUMER":
        print("          ^ DECISIVE FAILURE: the credential points at the "
              "primary; stop here.")
        res["verdict"] = "CREDENTIAL_POINTS_AT_CONSUMER"
        return res

    status, payload = call(p_host, p_token, f"{UC}/providers", "POST", {
        "name": PROVIDER_NAME,
        "authentication_type": "TOKEN",
        "recipient_profile_str": json.dumps(profile),
        "comment": "E1 credential-mode comparison (scripts/19)",
    })
    verdict, code, msg = classify(status, payload)
    res["steps"]["create_provider"] = {
        "status": status,
        "verdict": "PERMITTED" if status in (200, 201) else verdict,
        "error_code": code, "message": redact(msg)[:400] or None}

    # Re-runnability, and a trap inside it. The first version of this
    # phase treated any non-2xx as a refusal, so a second --verify would
    # have reported BLOCKED_AT_PROVIDER_IMPORT on a 409 -- our own
    # leftover object filed as a platform refusal, which is B-20's
    # attribution error again.
    #
    # But simply adopting the existing provider is the subtler mistake: a
    # provider created by an earlier run still holds the credential from
    # THAT run. After a --mint --rotate the old credential is dead and
    # the new one is on disk, and an adopted provider would read through
    # the stale one -- so the probe would be measuring a credential it did
    # not load, and a failure would be unattributable. The profile is
    # therefore pushed onto the existing provider before any read.
    if status not in (200, 201):
        already = (status == 409 or "already exists"
                   in f"{code} {msg}".lower())
        if not already:
            print(f"    [REF] create_provider: "
                  f"{res['steps']['create_provider']['verdict']} ({status})")
            print(f"          {code} {redact(msg)[:200]}")
            res["verdict"] = "BLOCKED_AT_PROVIDER_IMPORT"
            return res
        ustatus, upayload = call(
            p_host, p_token, f"{UC}/providers/{PROVIDER_NAME}", "PATCH",
            {"recipient_profile_str": json.dumps(profile)})
        uverdict, ucode, umsg = classify(ustatus, upayload)
        res["steps"]["create_provider"].update({
            "verdict": ("PERMITTED_PREEXISTING_UPDATED"
                        if ustatus in (200, 201)
                        else "PREEXISTING_UPDATE_REFUSED"),
            "update_status": ustatus,
            "update_error_code": ucode,
            "update_message": redact(umsg)[:400] or None,
            "means": ("The provider already existed from an earlier run. "
                      "Its credential was replaced with the one loaded by "
                      "THIS run, so the read below goes through the "
                      "credential on disk rather than whichever one the "
                      "earlier run installed. If the update was refused, "
                      "run --cleanup --consumer-only (which removes the "
                      "provider and catalog on the primary but LEAVES the "
                      "glovashu recipient, so the credential on disk stays "
                      "valid) and then --verify again. Plain --cleanup "
                      "would revoke the recipient and kill that credential, "
                      "forcing a --mint --rotate for no reason."),
        })
        print(f"    [{'ok ' if ustatus in (200, 201) else 'REF'}] "
              f"create_provider: "
              f"{res['steps']['create_provider']['verdict']} "
              f"({status} -> update {ustatus})")
        if ustatus not in (200, 201):
            print(f"          {ucode} {redact(umsg)[:200]}")
            res["verdict"] = "BLOCKED_AT_PROVIDER_CREDENTIAL_UPDATE"
            return res
    else:
        print(f"    [ok ] create_provider: PERMITTED ({status})")

    status, payload = call(p_host, p_token,
                           f"{UC}/providers/{PROVIDER_NAME}/shares")
    shares = [sh.get("name") for sh in ((payload or {}).get("shares") or [])]
    res["steps"]["list_provider_shares"] = {
        "status": status, "shares": shares,
        "verdict": "SHARES_LISTED" if shares else "NO_SHARES",
        "means": ("This is 2.4.1's SHOW SHARES IN PROVIDER, reached by the "
                  "TOKEN route. Reaching it here while D2D could not even "
                  "produce the provider object to run it against is the "
                  "contrast D-6 is about."),
    }
    print(f"    [{'ok ' if shares else 'REF'}] list_provider_shares: "
          f"{shares or 'none'}")
    if not shares:
        res["verdict"] = "PROVIDER_IMPORTED_BUT_NO_SHARES"
        return res

    share = P18_SHARE if P18_SHARE in shares else shares[0]
    status, payload = call(p_host, p_token, f"{UC}/catalogs", "POST", {
        "name": CATALOG_NAME, "provider_name": PROVIDER_NAME,
        "share_name": share,
    })
    verdict, code, msg = classify(status, payload)
    already = (status == 409 or "already exists" in f"{code} {msg}".lower())
    res["steps"]["create_catalog_from_share"] = {
        "status": status, "share": share,
        "verdict": ("PERMITTED" if status in (200, 201) else
                    "PERMITTED_PREEXISTING" if already else verdict),
        "error_code": code, "message": redact(msg)[:400] or None}
    if already:
        # Safe to adopt, unlike the provider: a shared catalog is bound to
        # (provider, share) by name only and holds no credential of its
        # own, so it inherits whatever the provider now carries -- which
        # the step above has just made current.
        res["steps"]["create_catalog_from_share"]["means"] = (
            "Catalog existed from an earlier run. Adopted rather than "
            "recreated: it binds to the provider by name and carries no "
            "credential, so it serves whatever the refreshed provider now "
            "points at.")
    print(f"    [{'ok ' if status in (200, 201) or already else 'REF'}] "
          f"create_catalog_from_share: "
          f"{res['steps']['create_catalog_from_share']['verdict']} ({status})")
    if status not in (200, 201) and not already:
        print(f"          {code} {redact(msg)[:200]}")
        res["verdict"] = "BLOCKED_AT_CATALOG"
        return res

    # The read. Schema and table come from the fixture's full name, not
    # from a guess: the shared catalog preserves the provider's schema
    # name, and guessing "default" here would produce a confusing
    # SCHEMA_DOES_NOT_EXIST that reads like a sharing failure.
    parts = (exp.get("table_full_name") or "").split(".")
    schema, table = (parts[1], parts[2]) if len(parts) == 3 \
        else ("opensharing_provider", "test_dataset")
    target = f"{CATALOG_NAME}.{schema}.{table}"

    wh = find_warehouse(p_host, p_token)
    if not wh:
        res["steps"]["read"] = {
            "verdict": "NOT_RUN",
            "means": ("No SQL warehouse on the primary, so the shared table "
                      "could not be read. The provider and catalog exist, "
                      "which is already more than D2D achieved, but NO ROW "
                      "CROSSED -- and the point of this probe is rows "
                      "crossing. NOT_RUN, not a pass."),
        }
        print("    [---] read: NOT_RUN (no warehouse on the primary)")
        res["verdict"] = "CATALOG_CREATED_BUT_UNREAD"
        return res

    stmt = (f"SELECT count(*) AS n, "
            f"count(DISTINCT origin_metastore) AS origins, "
            f"min(origin_metastore) AS origin FROM {target}")
    rows, raw = run_sql(p_host, p_token, wh, stmt)
    res["steps"]["read"] = {"statement": stmt, "target": target, "raw": raw}
    if rows is None:
        res["steps"]["read"]["verdict"] = "READ_REFUSED"
        print(f"    [REF] read: REFUSED -- {raw}")
        res["verdict"] = "BLOCKED_AT_READ"
        return res

    n = int(rows[0][0]) if rows and rows[0][0] is not None else None
    origins = int(rows[0][1]) if rows and rows[0][1] is not None else None
    origin = rows[0][2] if rows else None
    count_ok = n == exp["row_count"]
    origin_ok = origin == exp["origin_metastore"]
    res["steps"]["read"].update({
        "row_count": n, "distinct_origins": origins, "origin_metastore": origin,
        "row_count_matches_fixture": count_ok,
        "origin_matches_glovashu": origin_ok,
        "verdict": ("READ_ATTRIBUTABLE_TO_GLOVASHU"
                    if count_ok and origin_ok else
                    "READ_SUCCEEDED_BUT_NOT_ATTRIBUTABLE"),
        "means": (f"The fixture ({exp['fixture_source']}) holds "
                  f"{exp['row_count']} rows -- deliberately a different "
                  f"count from the primary's own test_dataset -- each "
                  f"stamped {exp['origin_metastore']}. Matching BOTH is "
                  f"what distinguishes reading ACROSS the share from "
                  f"reading a local table of the same name. Matching "
                  f"neither, or only one, is a defect in this probe or a "
                  f"misdirected provider, NOT a pass."),
    })
    print(f"    [{'ok ' if count_ok and origin_ok else 'REF'}] read: "
          f"n={n} (expected {exp['row_count']}) "
          f"origins={origins} origin={origin}")
    print(f"          {res['steps']['read']['verdict']}")

    res["verdict"] = ("DATA_PATH_WORKS" if count_ok and origin_ok
                      else "DATA_PATH_UNATTRIBUTABLE")
    return res


# =====================================================================
# CLEANUP
# =====================================================================

def phase_cleanup(s, consumer_only=False):
    res = {"phase": "cleanup", "run_at": now(),
           "scope": "consumer_only" if consumer_only else "both_sides",
           "items": {}}
    targets = [
        ("primary_catalog", s["p_host"], s["p_token"],
         f"{UC}/catalogs/{CATALOG_NAME}?force=true"),
        ("primary_provider", s["p_host"], s["p_token"],
         f"{UC}/providers/{PROVIDER_NAME}"),
    ]
    if not consumer_only:
        # Revoking the recipient invalidates the bearer token on disk, and
        # the activation link that produced it is already spent -- so this
        # is a one-way door that costs a --mint --rotate to undo. Kept out
        # of the --consumer-only path for exactly that reason.
        targets.append(("glovashu_token_recipient", s["g_host"], s["g_token"],
                        f"{UC}/recipients/{TOKEN_RECIPIENT}"))
    else:
        res["preserved"] = {
            "glovashu_token_recipient": TOKEN_RECIPIENT,
            "means": ("Left alive deliberately, so the credential already "
                      "downloaded to _secrets/ stays valid and --verify can "
                      "be re-run without spending another one-time "
                      "activation link."),
        }
    for label, host, token, path in targets:
        dstatus, _ = call(host, token, path, "DELETE")
        vstatus, _ = call(host, token, path.split("?")[0])
        res["items"][label] = {
            "delete_status": dstatus, "verify_status": vstatus,
            "verdict": ("DELETED" if vstatus == 404 else
                        "STILL_PRESENT" if vstatus == 200 else "UNVERIFIED")}
        print(f"    {label}: {res['items'][label]['verdict']} "
              f"(delete {dstatus}, verify {vstatus})")
    # The downloaded credential is a live bearer token on disk. It is
    # deliberately NOT deleted here: the hygiene gate already covers
    # _secrets/ modes, and silently shredding evidence a human downloaded
    # by hand is worse than naming it.
    res["credential_note"] = (
        f"{CREDENTIAL.relative_to(REPO)} and "
        f"{RECIPIENT_INFO.relative_to(REPO)} are left in place at 0600. "
        f"Revoking the recipient above invalidates the token; shred the "
        f"files by hand if you want them gone.")
    print(f"    note: {res['credential_note']}")
    return res


# =====================================================================

def write_evidence(new_phases):
    doc = {"probe": "d2d-vs-d2o-same-pair",
           "task": "E1 Task 1.10 -> T-19 / proposed E-2",
           "run_at": now(),
           "question": ("Can this pair of metastores exchange Delta Sharing "
                        "data at all? scripts/18 showed the D2D provider "
                        "object never appears in either direction from a "
                        "complete verified chain. That verdict names no "
                        "cause. This narrows it."),
           "phases": {}}
    if OUT.exists():
        try:
            prior = json.loads(OUT.read_text())
        except (json.JSONDecodeError, OSError):
            prior = None
        if isinstance(prior, dict):
            doc["phases"] = prior.get("phases") or {}
            doc["prior_run_at"] = prior.get("run_at")

    for name, res in new_phases.items():
        history = list((doc["phases"].get(name) or {}).get("prior_attempts")
                       or [])
        existing = doc["phases"].get(name)
        if existing:
            history.append({k: v for k, v in existing.items()
                            if k != "prior_attempts"})
        res = dict(res)
        if history:
            res["prior_attempts"] = history
            res["prior_attempts_note"] = (
                "Earlier runs of this phase, carried forward. A later "
                "success must not erase the refusal it was derived from "
                "(B-19).")
        doc["phases"][name] = res

    # A retracted claim must be LABELLED, not just superseded. The first
    # verify run wrote "a read through it would not be evidence about the
    # far side" into steps.credential.warning, which was false and was
    # produced by a guard of ours that fires on the normal case. B-19's
    # carry-forward means that sentence is still in this file under
    # prior_attempts, which is correct -- destroying it would hide that
    # our own tooling misfired. But leaving it unlabelled would let a
    # reader of the history take it as an observation. So the annotation
    # is DERIVED from finding it, not asserted in advance (B-23b).
    retracted = []
    for name, phase in (doc.get("phases") or {}).items():
        for idx, prior in enumerate(phase.get("prior_attempts") or []):
            warn = (((prior.get("steps") or {}).get("credential") or {})
                    .get("warning"))
            if warn:
                retracted.append({
                    "phase": name,
                    "prior_attempt_index": idx,
                    "retracted_text": warn,
                    "status": "RETRACTED_OUR_DEFECT_NOT_AN_OBSERVATION",
                    "means": ("Produced by this probe's first endpoint "
                              "check, which compared the credential's "
                              "endpoint against the provider's WORKSPACE "
                              "hostname. Databricks serves open sharing "
                              "from a dedicated <uuid>.opensharing.<region> "
                              "host, so the check flagged the normal case "
                              "as a failure. The same run then read rows "
                              "attributable to glovashu by count and origin "
                              "stamp, which contradicts the warning. Kept "
                              "for the record, labelled so it is not read "
                              "as a platform finding. B-26."),
                })
    if retracted:
        doc["retracted_claims"] = retracted

    # ---- the comparison, derived from both evidence files ----
    d2d = None
    if SYMMETRY.exists():
        try:
            d2d = (json.loads(SYMMETRY.read_text()).get("comparison") or {})
        except (json.JSONDecodeError, OSError):
            d2d = None
    verify = doc["phases"].get("verify") or {}
    token_verdict = verify.get("verdict")

    if d2d is None:
        verdict, means = "NO_D2D_RESULT_TO_COMPARE", (
            "evidence/d2d-direction-symmetry.json is missing or unreadable, "
            "so there is nothing for the TOKEN result to be a contrast "
            "WITH. Run scripts/18 --direction both first.")
    elif token_verdict is None:
        verdict, means = "AWAITING_TOKEN_RESULT", (
            "The D2D side is on file; the TOKEN side has not completed. No "
            "comparison yet, and the D2D verdict stands unnarrowed.")
    elif token_verdict == "DATA_PATH_WORKS":
        verdict, means = "D2D_SURFACING_ONLY", (
            "The same table, from the same share, with the same SELECT "
            "grant, on the same provider metastore, reached the primary "
            "through a TOKEN recipient -- and the rows were attributable "
            "to glovashu by both row count and origin stamp. So this pair "
            "of metastores DOES exchange Delta Sharing data, the share IS "
            "servable, the table IS serveable, the grant IS honoured by "
            "the data plane, and the region pairing IS workable. Those "
            "five readings of scripts/18's negative are excluded. What "
            "remains unexplained is narrower and nameable: with "
            "authentication_type = DATABRICKS, no provider object appears "
            "on the consuming metastore within ~169s, in either "
            "direction, from a fully read-back chain. "
            "NOTE THE LIMIT: credential mode and surfacing mechanism are "
            "not separable, so this does NOT isolate automatic appearance "
            "as the broken component -- it narrows the candidate set to "
            "one. For T-19 and E-2 this is the usable result: the D2D "
            "confirming calls stay NOT_RUN with a named missing "
            "capability, and the open-sharing route is the evidenced "
            "substitute path, which is a CONOPS recommendation rather "
            "than a dead end.")
    elif token_verdict in ("DATA_PATH_UNATTRIBUTABLE",):
        verdict, means = "TOKEN_READ_UNATTRIBUTABLE", (
            "Rows arrived but did not match the fixture's row count and "
            "origin stamp, so they cannot be shown to have come from "
            "glovashu. This is NOT a passing data path -- the most likely "
            "readings are a provider resolving to a local table of the "
            "same name, or a stale fixture. Resolve before comparing "
            "anything.")
    else:
        verdict, means = "BOTH_PATHS_BLOCKED", (
            f"The TOKEN path also failed ({token_verdict}). That is a "
            f"LARGER finding than T-19 and relocates the problem: it is no "
            f"longer about a D2D convenience step but about whether these "
            f"two accounts can exchange Delta Sharing data at all. Note "
            f"what it does NOT establish -- open sharing from the PRIMARY "
            f"has already succeeded in this repo (T-01..T-07), so a "
            f"failure here is attributable to glovashu's side or to the "
            f"pairing, not to the tier or to Delta Sharing generally. The "
            f"one-variable control for that is already on file.")

    doc["comparison"] = {
        "d2d_verdict": (d2d or {}).get("verdict"),
        "d2d_egress_visible": ((d2d or {}).get("egress") or {}).get(
            "provider_visible"),
        "d2d_ingress_visible": ((d2d or {}).get("ingress") or {}).get(
            "provider_visible"),
        "token_path_verdict": token_verdict,
        "variable": "credential mode (DATABRICKS vs TOKEN) on the SAME "
                    "share, same table, same grant, same provider metastore",
        "variable_caveat": ("Credential mode and surfacing mechanism are "
                            "entailed by each other; no setting separates "
                            "them. The comparison narrows the candidate "
                            "explanations, it does not isolate one "
                            "component."),
        "verdict": verdict,
        "means": means,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(doc, indent=2))
    return doc


def main():
    ap = argparse.ArgumentParser(
        description="Narrow scripts/18's VISIBILITY_UNVERIFIED by serving "
                    "the same share to a TOKEN recipient.")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--mint", action="store_true",
                   help="Create the TOKEN recipient on glovashu, grant it "
                        f"the existing {P18_SHARE}, and write the one-time "
                        "activation URL to _secrets/ at 0600. Prints no "
                        "secret.")
    g.add_argument("--verify", action="store_true",
                   help="Import the downloaded credential on the primary, "
                        "read the shared table, and check the rows are "
                        "attributable to glovashu by row count AND origin "
                        "stamp.")
    g.add_argument("--cleanup", action="store_true",
                   help="Remove the provider and catalog on the primary and "
                        "the TOKEN recipient on glovashu, verifying each "
                        "deletion.")
    ap.add_argument("--consumer-only", action="store_true",
                    help="With --cleanup: remove only the provider and "
                         "catalog on the primary, leaving the glovashu "
                         "TOKEN recipient alive so the credential already "
                         "on disk stays valid. Use this to reset the "
                         "consumer side without spending another one-time "
                         "activation link.")
    ap.add_argument("--rotate", action="store_true",
                    help="With --mint: delete an existing TOKEN recipient "
                         "first. The activation URL is one-time-use, so a "
                         "recipient whose link was already consumed cannot "
                         "hand out a second credential -- rotation is the "
                         "only way back, and doing it silently would make a "
                         "fresh token look like the old one.")
    args = ap.parse_args()

    s = sides()
    print("Credential-mode comparison on the SAME share")
    print("=" * 68)
    print(f"  provider : glovashu {s['g_host']}")
    print(f"  consumer : primary  {s['p_host']}")
    print(f"  share    : {P18_SHARE}")
    print()

    if args.mint:
        if args.rotate:
            print("Rotating: removing any existing TOKEN recipient")
            d, _ = call(s["g_host"], s["g_token"],
                        f"{UC}/recipients/{TOKEN_RECIPIENT}", "DELETE")
            v, _ = call(s["g_host"], s["g_token"],
                        f"{UC}/recipients/{TOKEN_RECIPIENT}")
            print(f"    delete {d}, verify {v}")
        print("[1/1] Mint a TOKEN recipient on glovashu")
        doc = write_evidence({"mint": phase_mint(s)})
        print()
        print("=" * 68)
        print("NEXT, BY HAND -- do not ask me to do this part:")
        print(f"  1. Open {RECIPIENT_INFO.relative_to(REPO)} in your own "
              f"editor.")
        print("  2. Take the activation_url and open it in a browser.")
        print(f"  3. Download the credential file ONCE and save it as")
        print(f"     {CREDENTIAL.relative_to(REPO)}")
        print("  4. chmod 600 that file.")
        print("The link self-destructs after one use. If it is already "
              "spent, re-run with --mint --rotate.")
        print(f"Then: python3 scripts/19_probe_token_path_same_pair.py "
              f"--verify")
    elif args.verify:
        print("[1/1] Read the share from the primary via the TOKEN route")
        doc = write_evidence({"verify": phase_verify(s)})
    else:
        print(f"[1/1] Cleanup "
              f"({'consumer side only' if args.consumer_only else 'both sides'})")
        doc = write_evidence(
            {"cleanup": phase_cleanup(s, consumer_only=args.consumer_only)})

    print()
    print("=" * 68)
    c = doc["comparison"]
    print(f"D2D (scripts/18):  {c['d2d_verdict']} "
          f"(egress visible={c['d2d_egress_visible']}, "
          f"ingress visible={c['d2d_ingress_visible']})")
    print(f"TOKEN path:        {c['token_path_verdict']}")
    print(f"NARROWED VERDICT:  {c['verdict']}")
    print(c["means"])
    print()
    print(f"Wrote {OUT.relative_to(REPO)}")
    print("Then run: python3 scripts/check_secret_hygiene.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
