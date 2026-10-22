#!/usr/bin/env python3
"""
E1 Task 1.6, precondition -- exchange a one-time activation link for a
Delta Sharing credential file.

WHY THIS EXISTS
---------------
RKI-5 in iac/config/recipients.yaml records the blocking state verbatim:
"Two of the three recipients hold a token in ACTIVATION_PENDING ... No
credential in this model is live." Every test in Task 1.6 and Task 1.7
reads data AS A RECIPIENT, which means every one of them is blocked on
this exchange. scripts/03 handled it by telling the operator to open the
link in a browser and save the download by hand. That worked once. It
does not scale to three recipients, and more importantly it leaves no
record of WHICH link was exchanged WHEN -- so a credential on disk and a
credential someone copied from another recipient look identical.

WHY THE DEFAULT DOES NOT ACTIVATE
---------------------------------
The exchange is IRREVERSIBLE. The link is one-time: a successful call
consumes it, and a call that reaches the right host with the wrong path
can consume it just as finally while returning something unusable. There
is no recovery except minting a new token (scripts/27 --rotate-token),
which changes the credential every downstream test is pinned to.

So the default run makes only the NON-CONSUMING info call, and the
consuming call is refused unless the info call returned 200 AND --activate
was passed. This is B-33b applied to an irreversible operation: the dry
run is a genuine before-picture, and here it is also the guard that stops
a wrong URL from destroying the thing it was pointed at.

WHY THE RESPONSE IS WRITTEN TO DISK BEFORE IT IS PARSED
-------------------------------------------------------
Because the call cannot be repeated. If we parse first and the parse
raises, the link is gone and so is the only copy of what it returned --
the operator is left with a consumed token, no credential, and no way to
tell whether the platform returned a credential we failed to read or
never returned one at all. That is a silent negative on the one axis
where it cannot be re-measured. The raw bytes go to disk at 0600 first;
every judgement about them happens afterwards, against a file.

WHY IT DOES NOT REUSE scripts/14's call()
-----------------------------------------
Two reasons, both of which matter here and nowhere else in this repo.
call() always attaches `Authorization: Bearer $DATABRICKS_TOKEN`, and
this is a PUBLIC endpoint on a different host from the workspace -- the
activation host is the recipient's own. Sending the provider's PAT to it
is a credential leaving its blast radius for no reason. And call()
parses before it returns, which is exactly the order this operation
cannot afford.

Usage:
    python3 scripts/28_activate_credential.py                  # probe only
    python3 scripts/28_activate_credential.py --activate
    python3 scripts/28_activate_credential.py --activate \
        --recipient awoz1227-t02-iplist-recipient --also-rewrite

Writes: _secrets/credential-<recipient>.json           (0600, the secret)
        _secrets/credential-<recipient>.raw            (0600, only if unparsable)
        _secrets/rewritten-credential-<recipient>.json (0600, --also-rewrite)
        evidence/credential-activation.json            (redacted)
"""
import argparse
import datetime
import importlib.util
import json
import re
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "iac" / "config" / "recipients.yaml"
EVIDENCE = REPO / "evidence" / "credential-activation.json"
SECRETS = REPO / "_secrets"

INFO_PATH = "/api/2.0/unity-catalog/public/data_sharing_activation_info/"
GET_PATH = "/api/2.0/unity-catalog/public/data_sharing_activation/"

REQUIRED_CREDENTIAL_FIELDS = ("shareCredentialsVersion", "bearerToken", "endpoint")


def load_probe(filename, modname):
    path = REPO / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this script reuses its helpers rather "
                 f"than restating them.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "s28_probe14")
P19 = load_probe("19_probe_token_path_same_pair.py", "s28_probe19")
# The OD-4 rewrite's field list and its leak guard are imported, not
# restated. A second copy of ENDPOINT_FIELDS is how a credential ends up
# with `endpoint` swapped and `icebergEndpoint` still pointing at
# Databricks -- the exact bypass scripts/04's docstring was written about.
S04 = load_probe("04_rewrite_credential.py", "s28_script04")

load_env = P19.load_env
api_call = P14.call
err_bits = P14.err_bits


def load_test_module(filename, modname):
    """The attribution procedure lives in the test that owns it.

    Egress-address discovery and IP redaction are T-02's, written there
    first. Copying them here would give two answers to "which address
    does the platform see", and the two could disagree without either
    output saying so.
    """
    path = REPO / "tests" / filename
    if not path.exists():
        return None
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


T02 = load_test_module("t02_ip_access_list.py", "s28_t02")

UC = "/api/2.1/unity-catalog"
WIDEN_WAIT = 150


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


# ---------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------

def load_config():
    if not CONFIG.exists():
        sys.exit(f"Missing {CONFIG}.")
    try:
        import yaml
    except ImportError:
        sys.exit("PyYAML is required: pip install pyyaml")
    return yaml.safe_load(CONFIG.read_text())


def declared_recipients(cfg):
    """Only recipients this config manages are activatable here.

    A link found in _secrets/ for an object the config does not declare
    is left alone on purpose. Those are the B-19 leftovers -- inventoried,
    never operated on.
    """
    return {r["name"]: r for r in (cfg.get("recipients") or []) if r.get("name")}


# ---------------------------------------------------------------------
# The public, unauthenticated calls
# ---------------------------------------------------------------------

def public_get(url, timeout=60):
    """Returns (status, raw_text, headers). Never raises, never parses.

    No Authorization header: the activation host is the recipient's, not
    the provider's workspace, and the whole point of an activation link
    is that holding it is the only credential required.
    """
    req = urllib.request.Request(url, method="GET")
    req.add_header("Accept", "application/json")
    ctx = ssl.create_default_context()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers or {})
    except urllib.error.URLError as e:
        return 0, json.dumps({"error_code": "LOCAL_URLERROR",
                              "message": str(e.reason)}), {}
    except Exception as e:  # noqa: BLE001 -- a timeout here is a result
        return 0, json.dumps({"error_code": type(e).__name__,
                              "message": str(e)}), {}


def split_activation_url(url):
    """(host, opaque_blob) from the activation link.

    Measured shape, not assumed:
      https://<recipient-id>.opensharing.<region>.cloud.databricks.com
          /opensharing/retrieve_config.html?<172-char opaque blob>

    The blob is the activation token. It carries NO `=` and so parses to
    nothing through parse_qsl -- which is worth stating, because the
    obvious reading of that URL is that the token is a query PARAMETER,
    and code written on that assumption extracts an empty string and
    calls the endpoint with no token at all.
    """
    p = urlparse(url)
    if not p.hostname:
        return None, None
    blob = p.query or ""
    if not blob and p.fragment:
        blob = p.fragment
    return p.hostname, blob


# ---------------------------------------------------------------------
# Secret-safe writes
# ---------------------------------------------------------------------

def write_0600(path, text):
    SECRETS.mkdir(exist_ok=True)
    path.write_text(text)
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return path


def scrub(text):
    """P14.redact plus the activation blob itself.

    The blob is a bearer-equivalent secret right up to the moment it is
    consumed, and after that it is a used ticket -- but a FAILED exchange
    leaves it live, and the failure path is precisely where the URL ends
    up quoted in an error message.
    """
    text = P14.redact(text)
    if not isinstance(text, str):
        return text
    text = re.sub(r"(retrieve_config\.html)\?[^\s\"']+", r"\1?<redacted-blob>", text)
    text = re.sub(r"(data_sharing_activation(?:_info)?/)[^\s\"'/?]+",
                  r"\1<redacted-blob>", text)
    return text


# ---------------------------------------------------------------------
# Per-recipient work
# ---------------------------------------------------------------------

def credential_path(name):
    return SECRETS / f"credential-{name}.json"


def recipient_record_paths(name):
    """Every on-disk record for this recipient, best candidate first.

    scripts/27 writes `recipient-<name>.json` when it CREATES a recipient
    and `recipient-<name>-rotated.json` when it ROTATES one -- two naming
    conventions for one object, in one script. The first version of this
    function looked only at the first name and reported
    NO_RECIPIENT_RECORD_ON_DISK for `psp7-demo-recipient` while its
    freshly minted link sat beside it under the other name. B-37: "there
    is no record" and "the record is under a name I did not look for"
    are the same observation, and the second one is a filename.

    Ordered by whether a record holds an UNSPENT link and then by token
    age, so a rotation's new link wins over the record it superseded
    without the superseded record being deleted (B-19).
    """
    out = []
    for path in sorted(SECRETS.glob(f"recipient-{name}*.json")):
        try:
            doc = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        # A name that is a prefix of another recipient's name would match
        # the glob, so the record is confirmed against its own `name`.
        if doc.get("name") and doc["name"] != name:
            continue
        live = [t for t in (doc.get("tokens") or [])
                if isinstance(t, dict) and t.get("activation_url")
                and not str(t.get("activation_url")).startswith("<")]
        newest = max([t.get("created_at") or 0 for t in live], default=-1)
        out.append({"path": path, "doc": doc, "live": live, "newest": newest})
    out.sort(key=lambda r: (bool(r["live"]), r["newest"]), reverse=True)
    return out


def mark_link_consumed(path, token_id, outcome):
    """Replace the activation_url in place, never delete the record.

    B-19 carry-forward on a secret: the link is useless once consumed and
    dangerous to keep, so the value goes -- but the fact that this token
    HAD a link, and when it was spent, is the provenance that tells a
    later reader where the credential on disk came from.
    """
    if not path.exists():
        return False
    try:
        doc = json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return False
    changed = False
    for tok in doc.get("tokens") or []:
        if not isinstance(tok, dict) or tok.get("id") != token_id:
            continue
        url = tok.get("activation_url")
        if not url:
            continue
        _, blob = split_activation_url(url)
        tok["activation_url"] = "<consumed-by-scripts/28>"
        tok["activation_url_consumed_at"] = now()
        tok["activation_url_outcome"] = outcome
        tok["activation_blob_sha256_12"] = P14.fingerprint(blob or "")
        changed = True
    if changed:
        write_0600(path, json.dumps(doc, indent=2, default=str))
    return changed


def rewrite_for_gateway(name, cred):
    """OD-4's endpoint substitution, for this recipient's credential.

    scripts/04 does this for _secrets/raw-credential.json and only that
    file, with its paths baked into main(). Rather than generalise a
    settled script, its FIELD LIST and its LEAK GUARD are imported and
    the per-recipient paths live here. One source for the dangerous part;
    the filenames differ because the recipients do.
    """
    original = cred.get("endpoint")
    if not original:
        return {"verdict": "NO_ENDPOINT_FIELD"}
    provider_host = urlparse(original).hostname
    base = (os.environ.get("GRAVITEE_GATEWAY_EDGE_URL") or "").rstrip("/")
    if not base:
        return {"verdict": "GRAVITEE_GATEWAY_EDGE_URL_NOT_SET"}
    iceberg = os.environ.get("GRAVITEE_GATEWAY_ICEBERG_URL", f"{base}/iceberg")

    out = dict(cred)
    swapped = {}
    for field in S04.ENDPOINT_FIELDS:
        if field in out:
            swapped[field] = {"was_host": urlparse(str(out[field])).hostname,
                              "now": iceberg if field == "icebergEndpoint" else base}
            out[field] = swapped[field]["now"]

    leaks = [p for p, v in S04.walk_strings(out)
             if provider_host and re.search(re.escape(provider_host), v, re.IGNORECASE)]
    if leaks:
        return {"verdict": "REFUSED_LEAK_GUARD", "fields_still_naming_provider": leaks,
                "means": ("A client reading one of those fields would reach "
                          "Databricks directly and never traverse Gravitee. "
                          "Add the field to ENDPOINT_FIELDS in scripts/04.")}

    path = write_0600(SECRETS / f"rewritten-credential-{name}.json",
                      json.dumps(out, indent=2))
    return {"verdict": "REWRITTEN", "fields": swapped,
            "file": str(path.relative_to(REPO)),
            "leak_guard": "clean",
            "guard_source": "scripts/04 ENDPOINT_FIELDS + walk_strings (imported)"}


def set_ip_list(ws_host, ws_token, name, addresses):
    return api_call(ws_host, ws_token, f"{UC}/recipients/{name}", "PATCH",
                    {"ip_access_list": {"allowed_ip_addresses": addresses}})


def read_ip_list(ws_host, ws_token, name):
    st, pl = api_call(ws_host, ws_token, f"{UC}/recipients/{name}")
    if st != 200 or not isinstance(pl, dict):
        return st, None
    return st, sorted((pl.get("ip_access_list") or {})
                      .get("allowed_ip_addresses") or [])


def widen_and_retry_info(ws_host, ws_token, name, decl, rec, info_url):
    """Admit this client, then re-ask the SAME non-consuming question.

    This is the T-02 attribution procedure applied to the activation
    endpoint, and it is free: the info call does not consume the link, so
    the before-and-after pair can be taken as many times as needed. If
    403 becomes 200 with the allow-list as the only changed variable, the
    403 is attributable to the list -- which is an ENFORCEMENT
    observation, the thing RKI-3 says this repository has never had.

    The list is left WIDE on purpose. Restoring it here would make the
    consuming call that follows fail for the reason we just removed. The
    caller restores it, and verifies the restore (B-23).
    """
    declared = sorted((decl.get("ip_access_list") or {})
                      .get("allowed_ip_addresses") or [])
    out = {"declared_list": declared, "wait_bound_seconds": WIDEN_WAIT,
           "attempts": [], "list_left_wide": False}
    if T02 is None:
        out["verdict"] = "CANNOT_RUN_T02_MODULE_MISSING"
        return out

    ip, prov = T02.discover_egress_ip(rec)
    out["egress_address"] = dict(prov)
    if not ip:
        out["verdict"] = "NO_EGRESS_ADDRESS_NOTHING_MUTATED"
        return out
    out["egress_address"]["address_redacted"] = T02.redact_ip(ip)

    wide = sorted(set(declared) | {f"{ip}/32"})
    st, pl = set_ip_list(ws_host, ws_token, name, wide)
    out["patch_status"] = st
    if st != 200:
        code, msg = err_bits(pl)
        out["verdict"] = "PATCH_FAILED"
        out["error_code"] = code
        out["error"] = scrub(msg)[:600]
        return out
    out["list_left_wide"] = True
    vst, vlist = read_ip_list(ws_host, ws_token, name)
    out["list_after_patch"] = ([T02.redact_ip(a.split("/")[0]) for a in vlist]
                               if vlist is not None else None)
    out["list_read_back_status"] = vst

    started = time.time()
    delay = 10
    while True:
        st2, raw2, _ = public_get(info_url)
        elapsed = round(time.time() - started, 1)
        out["attempts"].append({"after_seconds": elapsed, "status": st2})
        out["info_status_after"] = st2
        if st2 == 200:
            out["settled_after_seconds"] = elapsed
            out["verdict"] = "IP_ACCESS_LIST_ENFORCEMENT_OBSERVED_ON_ACTIVATION_ENDPOINT"
            out["means"] = (
                "403 with this client excluded, 200 with it admitted, same "
                "link, same endpoint, same run. The refusal is attributable "
                "to the allow-list. SCOPE: this is the ACTIVATION endpoint, "
                "not the data endpoint -- T-02 still has to show the same "
                "thing on the read path, and the two are different services "
                "that happen to share a control.")
            return out
        if elapsed + delay > WIDEN_WAIT:
            out["verdict"] = "NEVER_ADMITTED_WITHIN_BOUND"
            out["means"] = (
                f"Still {st2} after {elapsed}s with a {WIDEN_WAIT}s bound. The "
                f"403 is therefore NOT attributed to the allow-list: it may be "
                f"propagation, a wrong address (see egress_address.quality), or "
                f"a different refusal wearing the same status code.")
            return out
        time.sleep(delay)


def activate_one(name, decl, do_activate, also_rewrite, force,
                 widen=False, ws_host=None, ws_token=None):
    rec = {"recipient": name,
           "declared_channel": decl.get("channel"),
           "declared_purpose": (decl.get("purpose") or "")[:120],
           "at": now()}

    cred_path = credential_path(name)
    if cred_path.exists() and not force:
        try:
            cred = json.loads(cred_path.read_text())
            rec["credential"] = P14.profile_summary(cred)
            rec["verdict"] = "CREDENTIAL_ALREADY_ON_DISK_SKIPPED"
            rec["means"] = ("A credential file already exists for this "
                            "recipient. The link is not re-exchanged, because "
                            "a second exchange cannot succeed and a failed one "
                            "cannot be told apart from a wrong path.")
        except (OSError, json.JSONDecodeError) as exc:
            rec["verdict"] = "CREDENTIAL_ON_DISK_UNPARSABLE"
            rec["error"] = scrub(str(exc))[:300]
            rec["remedy"] = (f"Inspect {cred_path.relative_to(REPO)} by hand. If it "
                             f"is junk, rotate the token (scripts/27 "
                             f"--rotate-token {name}) rather than re-running "
                             f"this with --force; the link is already spent.")
        if also_rewrite and rec.get("verdict") == "CREDENTIAL_ALREADY_ON_DISK_SKIPPED":
            rec["gateway_rewrite"] = rewrite_for_gateway(name, cred)
        return rec

    records = recipient_record_paths(name)
    if not records:
        rec["verdict"] = "NO_RECIPIENT_RECORD_ON_DISK"
        rec["searched"] = f"_secrets/recipient-{name}*.json"
        rec["means"] = ("No record on disk under any of the names scripts/27 "
                        "writes, so no activation link was ever captured "
                        "for this recipient.")
        rec["remedy"] = (f"python3 scripts/27_build_recipient_model.py "
                         f"--rotate-token {name}")
        return rec

    best = records[0]
    secret_path, doc, live = best["path"], best["doc"], best["live"]
    rec["record_used"] = str(secret_path.relative_to(REPO))
    if len(records) > 1:
        rec["records_considered"] = [str(r["path"].relative_to(REPO))
                                     for r in records]
        rec["record_selection"] = (
            "The record holding an UNSPENT link wins, then the newest token. "
            "Superseded records are kept, not deleted (B-19); scripts/27 "
            "writes `-rotated` under a second name and both are real history.")
    if not live:
        rec["verdict"] = "NO_ACTIVATION_LINK_HELD"
        rec["token_count_in_record"] = len(doc.get("tokens") or [])
        rec["means"] = ("The record holds no unspent activation link. Either "
                        "the recipient has no token at all (rule 4's "
                        "NO_TOKEN_LIFETIME_UNENFORCEABLE), or a link was "
                        "already consumed -- the per-token "
                        "activation_url_consumed_at field distinguishes those.")
        rec["remedy"] = (f"python3 scripts/27_build_recipient_model.py "
                         f"--rotate-token {name}")
        return rec

    tok = live[0]
    if len(live) > 1:
        rec["warning_multiple_live_links"] = (
            f"{len(live)} unspent links are held. The OLDEST is exchanged "
            f"first, so a rotation overlap resolves in the direction that "
            f"spends the credential closest to expiry.")
        live.sort(key=lambda t: t.get("created_at") or 0)
        tok = live[0]

    host, blob = split_activation_url(tok["activation_url"])
    rec["token"] = {"id": tok.get("id"),
                    "created_at": tok.get("created_at"),
                    "expiration_time": tok.get("expiration_time"),
                    "activation_host": host,
                    "activation_blob_length": len(blob or ""),
                    "activation_blob_sha256_12": P14.fingerprint(blob or "")}
    if not host or not blob:
        rec["verdict"] = "ACTIVATION_URL_UNPARSABLE"
        rec["means"] = ("No host or no opaque blob could be taken from the "
                        "link, so no call is attempted. Nothing is consumed.")
        return rec

    # --- Step 1: the NON-CONSUMING info call ---------------------------
    info_url = f"https://{host}{INFO_PATH}{blob}"
    st, raw, _ = public_get(info_url)
    rec["info_call"] = {"status": st, "path": INFO_PATH + "<blob>",
                        "body": scrub(raw)[:400]}
    try:
        info = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError:
        info = {}
    if isinstance(info, dict):
        rec["info_call"]["share_name"] = info.get("share_name") or info.get("shareName")
        rec["info_call"]["recipient_name"] = (info.get("recipient_name")
                                              or info.get("recipientName"))

    if st == 403 and (decl.get("ip_access_list") or {}).get("mode") == "APPLIED":
        # MEASURED, not guessed: the two recipients whose links were minted
        # by the same call in the same second differ in one property, and
        # the one carrying an IP access list got 403 on the same endpoint
        # where the other got 200. The activation endpoint is behind the
        # recipient's own allow-list. See B-38.
        rec["ip_access_list_suspected"] = {
            "declared_list": sorted((decl.get("ip_access_list") or {})
                                    .get("allowed_ip_addresses") or []),
            "basis": ("403 on the info endpoint for the recipient that "
                      "carries an APPLIED list, 200 on the same endpoint for "
                      "a recipient that does not, from this client in the "
                      "same run."),
            "consequence": ("The credential for an allow-listed recipient "
                            "cannot be collected from an address the list "
                            "excludes. The control gates its own enrolment."),
        }
        if widen and ws_host and ws_token:
            rec["widen_for_activation"] = widen_and_retry_info(
                ws_host, ws_token, name, decl, rec, info_url)
            st = rec["widen_for_activation"].get("info_status_after", st)

    if st != 200:
        rec["verdict"] = "INFO_REFUSED_LINK_NOT_EXCHANGEABLE"
        rec["means"] = (
            "The non-consuming info call did not return 200, so the "
            "CONSUMING call was not attempted and the link is still unspent. "
            "This is the guard working: a 403 or 404 here means the path is "
            "wrong, or the link is used, or the caller's address is not "
            "admitted -- and burning the token to find out which would "
            "answer none of them.")
        return rec

    if not do_activate:
        rec["verdict"] = "LINK_PARSES_INFO_OK_NOT_CONSUMED"
        rec["means"] = ("The link resolves and the platform will exchange it. "
                        "Nothing was consumed. Re-run with --activate.")
        return rec

    # --- Step 2: the CONSUMING call ------------------------------------
    # Everything from here is irreversible. Raw bytes to disk first.
    get_url = f"https://{host}{GET_PATH}{blob}"
    st, raw, headers = public_get(get_url)
    raw_path = SECRETS / f"credential-{name}.raw"
    write_0600(raw_path, raw)
    rec["exchange_call"] = {"status": st, "path": GET_PATH + "<blob>",
                            "content_type": headers.get("Content-Type"),
                            "body_length": len(raw),
                            "raw_saved_to": str(raw_path.relative_to(REPO))}

    if st != 200:
        rec["verdict"] = "CONSUMED_BUT_REFUSED"
        rec["exchange_call"]["body"] = scrub(raw)[:400]
        rec["means"] = (
            "The consuming endpoint was reached and refused. Whether the "
            "token survived that refusal is NOT knowable from here -- the API "
            "does not say -- so treat it as spent.")
        rec["remedy"] = (f"python3 scripts/27_build_recipient_model.py "
                         f"--rotate-token {name}")
        mark_link_consumed(secret_path, tok.get("id"), rec["verdict"])
        return rec

    try:
        cred = json.loads(raw)
    except json.JSONDecodeError as exc:
        rec["verdict"] = "CONSUMED_BUT_RESPONSE_UNUSABLE"
        rec["error"] = scrub(str(exc))[:300]
        rec["means"] = (
            "THE LINK IS SPENT AND NO CREDENTIAL WAS OBTAINED. The response "
            "body is on disk unparsed -- read it before doing anything else, "
            "because it is the only copy and it cannot be requested again.")
        rec["remedy"] = (f"Inspect {raw_path.relative_to(REPO)}, then "
                         f"python3 scripts/27_build_recipient_model.py "
                         f"--rotate-token {name}")
        mark_link_consumed(secret_path, tok.get("id"), rec["verdict"])
        return rec

    missing = [f for f in REQUIRED_CREDENTIAL_FIELDS if not cred.get(f)]
    if missing:
        rec["verdict"] = "CONSUMED_BUT_CREDENTIAL_INCOMPLETE"
        rec["fields_missing"] = missing
        rec["fields_present"] = sorted(cred.keys())
        rec["means"] = ("Parsed, but not a usable Delta Sharing profile. The "
                        "raw body is kept; the link is spent.")
        mark_link_consumed(secret_path, tok.get("id"), rec["verdict"])
        return rec

    write_0600(credential_path(name), json.dumps(cred, indent=2))
    raw_path.unlink(missing_ok=True)  # parsed cleanly; the duplicate is a second copy of a live token
    rec["exchange_call"].pop("raw_saved_to", None)
    rec["exchange_call"]["raw_copy_removed_after_successful_parse"] = True
    rec["credential"] = P14.profile_summary(cred)
    rec["credential_file"] = str(credential_path(name).relative_to(REPO))
    rec["verdict"] = "ACTIVATED_CREDENTIAL_WRITTEN"
    mark_link_consumed(secret_path, tok.get("id"), rec["verdict"])

    if also_rewrite:
        rec["gateway_rewrite"] = rewrite_for_gateway(name, cred)
    return rec


# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--recipient", action="append", default=None,
                    help="repeatable; default is every declared recipient")
    ap.add_argument("--activate", action="store_true",
                    help="make the IRREVERSIBLE consuming call")
    ap.add_argument("--also-rewrite", action="store_true",
                    help="also emit the OD-4 gateway-rewritten credential")
    ap.add_argument("--force", action="store_true",
                    help="re-exchange even if a credential file exists "
                         "(it will fail; the link is spent)")
    ap.add_argument("--widen-ip-list", action="store_true",
                    help="if the info call is refused 403 and the recipient "
                         "carries an APPLIED IP access list, admit this "
                         "client for the duration of the exchange and put "
                         "the declared list back afterwards")
    args = ap.parse_args()

    load_env()
    ws_host = (os.environ.get("DATABRICKS_HOST") or "").strip()
    ws_token = (os.environ.get("DATABRICKS_TOKEN") or "").strip()
    if args.widen_ip_list and not (ws_host and ws_token):
        sys.exit("--widen-ip-list mutates the recipient object, which needs "
                 "DATABRICKS_HOST and DATABRICKS_TOKEN in .env.")
    cfg = load_config()
    declared = declared_recipients(cfg)
    targets = args.recipient or sorted(declared)
    unknown = [t for t in targets if t not in declared]
    if unknown:
        sys.exit(f"Not declared in {CONFIG.relative_to(REPO)}: {unknown}. "
                 f"This script only operates on managed recipients.")

    print("Credential activation -- E1 Task 1.6 precondition (RKI-5)")
    print("=" * 68)
    print(f"mode: {'ACTIVATE (irreversible)' if args.activate else 'PROBE ONLY (nothing consumed)'}")
    print()

    out = {"task": "E1 Task 1.6 precondition",
           "closes": "RKI-5 (no credential in the recipient model is live)",
           "date": now(),
           "mode": "ACTIVATE" if args.activate else "PROBE",
           "config": str(CONFIG.relative_to(REPO)),
           "method": {
               "info_endpoint": INFO_PATH + "<blob>",
               "exchange_endpoint": GET_PATH + "<blob>",
               "auth": "none -- public endpoint on the recipient's own "
                       "activation host, not the provider workspace",
               "ordering": "info first; the consuming call is refused unless "
                           "info returned 200 AND --activate was passed",
               "durability": "the response body is written to disk at 0600 "
                             "BEFORE it is parsed, because the call cannot be "
                             "repeated",
           },
           "recipients": []}

    widened = []
    try:
        for name in targets:
            rec = activate_one(name, declared[name], args.activate,
                               args.also_rewrite, args.force,
                               widen=args.widen_ip_list,
                               ws_host=ws_host, ws_token=ws_token)
            if (rec.get("widen_for_activation") or {}).get("list_left_wide"):
                widened.append(name)
            out["recipients"].append(rec)
            print(f"  {name}")
            print(f"      verdict: {rec['verdict']}")
            if rec.get("record_used"):
                print(f"      record:  {rec['record_used']}")
            if rec.get("info_call"):
                print(f"      info:    {rec['info_call']['status']}"
                      f"  share={rec['info_call'].get('share_name')}")
            if rec.get("widen_for_activation"):
                w = rec["widen_for_activation"]
                print(f"      widen:   {w['verdict']}"
                      f"  (egress {w.get('egress_address', {}).get('source')})")
            if rec.get("credential"):
                c = rec["credential"]
                print(f"      cred:    endpoint_host={c['endpoint_host']}"
                      f"  token_sha12={c['bearer_token_sha256_12']}"
                      f"  expires={c.get('expiration_time')}")
            if rec.get("gateway_rewrite"):
                print(f"      od-4:    {rec['gateway_rewrite']['verdict']}")
            if rec.get("remedy"):
                print(f"      remedy:  {rec['remedy']}")
            print()
    finally:
        # The widened list is a perimeter this script opened. It closes it
        # in a finally and READS IT BACK (B-23) -- an exception between the
        # widening and the restore is exactly when an allow-list is left
        # open and the evidence file stays silent about it.
        out["restores"] = []
        for name in widened:
            dl = sorted((declared[name].get("ip_access_list") or {})
                        .get("allowed_ip_addresses") or [])
            rst, _ = set_ip_list(ws_host, ws_token, name, dl)
            vst, vlist = read_ip_list(ws_host, ws_token, name)
            ok = vlist is not None and sorted(vlist) == dl
            out["restores"].append({
                "recipient": name, "patch_status": rst,
                "read_back_status": vst, "declared": dl,
                "list_on_platform_now": vlist,
                "verdict": "RESTORED_AND_VERIFIED" if ok
                           else "RESTORE_NOT_VERIFIED",
                "means": ("" if ok else
                          "THE ALLOW-LIST IS NOT BACK AT ITS DECLARED VALUE. "
                          "Run scripts/27_build_recipient_model.py now; it "
                          "owns this field and will re-assert the config."),
            })
            print(f"  restore {name}: "
                  f"{out['restores'][-1]['verdict']} (list now: {vlist})")
        if widened:
            print()

    verdicts = {r["verdict"] for r in out["recipients"]}
    live = {"ACTIVATED_CREDENTIAL_WRITTEN", "CREDENTIAL_ALREADY_ON_DISK_SKIPPED"}
    lost = {v for v in verdicts if v.startswith("CONSUMED_BUT")}
    if lost:
        out["verdict"] = "LINK_SPENT_WITHOUT_CREDENTIAL"
    elif verdicts <= live:
        out["verdict"] = "ALL_DECLARED_RECIPIENTS_HOLD_A_LIVE_CREDENTIAL"
    elif verdicts & live:
        out["verdict"] = "PARTIAL_SOME_RECIPIENTS_STILL_HAVE_NO_CREDENTIAL"
    elif verdicts == {"LINK_PARSES_INFO_OK_NOT_CONSUMED"}:
        out["verdict"] = "EXCHANGEABLE_NOT_CONSUMED"
    else:
        out["verdict"] = "NO_CREDENTIAL_OBTAINED"

    out["rki_5_status"] = (
        "CLOSED" if out["verdict"] == "ALL_DECLARED_RECIPIENTS_HOLD_A_LIVE_CREDENTIAL"
        else "OPEN")
    out["scope"] = (
        "This establishes that a credential EXISTS and parses. It does not "
        "establish that it reads anything -- that is T-02's and T-04's job, "
        "and a credential that parses while the grant is missing is exactly "
        "the confound T-02's two-phase procedure exists to separate.")

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(scrub(json.dumps(out, indent=2, default=str)))

    print("=" * 68)
    print(f"VERDICT: {out['verdict']}")
    print(f"RKI-5:   {out['rki_5_status']}")
    print(f"\nWrote {EVIDENCE.relative_to(REPO)}")
    print("Now run: python3 scripts/check_secret_hygiene.py")
    return 0 if out["verdict"] in (
        "ALL_DECLARED_RECIPIENTS_HOLD_A_LIVE_CREDENTIAL",
        "EXCHANGEABLE_NOT_CONSUMED") else 1


if __name__ == "__main__":
    sys.exit(main())
