#!/usr/bin/env python3
"""
T-02 -- "Call straight to the Databricks sharing endpoint with a valid
token." CONOPS AC1. E1 Task 1.6.

WHAT T-02 IS ACTUALLY CLAIMING
------------------------------
docs/12 states the test as a direct call that must be refused, with the
note: "Recipient IP access lists work here (11.3), so the refusal is
real, not simulated." That note is about CONFIGURATION -- §11.3 measured
that the field is accepted and persists. It is not about ENFORCEMENT.
Nothing in this repo has yet observed the platform act on the list.

THE SILENT NEGATIVE WITH THE SIGN FLIPPED
-----------------------------------------
A single denial proves nothing. "Read denied while the list excludes me"
is also what a broken credential, an unactivated token, a missing grant,
a typo'd share name, an expired token and a wrong endpoint all look like
from the client's side -- a 403 and a 401 are a few characters apart in a
log, and several of those produce exactly the same outcome. A test that
observed one denial and reported PASS would be passing without touching
the mechanism it names.

So the denial is only attributable if THE SAME credential, grant, share
and client produce a SUCCESSFUL read when the list includes the
operator's address. That is the positive control, and without it this
test is INCONCLUSIVE rather than passing. The procedure below is the one
already written into iac/config/recipients.yaml under
`t02_procedure`, implemented rather than re-invented.

  phase 0  -- read with the declared list (203.0.113.5/32). Expect DENIED.
              A success here means the list is not enforced at all, which
              is a finding and not a failure of the test.
  phase 1  -- add the operator's egress address. Expect SUCCESS. THIS IS
              THE POSITIVE CONTROL. Without it nothing below counts.
  phase 1b -- with the list holding ONLY the operator's address, repeat
              the read THROUGH THE GRAVITEE GATEWAY. See the topology
              note below; this is the measurement, not an extra check.
  phase 2  -- narrow back to 203.0.113.5/32. Expect DENIED. The only
              variable changed since phase 1 is the list.

WHY PHASE 1b IS HERE AND NOT IN T-01
------------------------------------
T-02's production shape is an allow-list holding the GATEWAY's egress
address, so that a direct call from anywhere else is refused -- that is
how AC1's perimeter is supposed to work. On this machine the gateway runs
in a container on the same host as the test client, so both leave through
the same NAT address. If that is true, an IP allow-list CANNOT
distinguish "via the gateway" from "direct" here, and the perimeter claim
is not locally testable however many phases are added.

That is worth measuring rather than assuming, and it costs one extra
read: with the list holding only the operator's address, a successful
read THROUGH the gateway means the gateway's egress address IS the
operator's. Phase 2 then denies both, which closes it from the other
side. The CONOPS does not state the infrastructure assumption this
exposes -- that the gateway egresses from an address the recipient's
allow-list can name and the consumer cannot reach from.

WHAT IS RESTORED, AND WHY THE RESTORE IS VERIFIED
-------------------------------------------------
The declared list is put back in a `finally`, and then READ BACK. B-23: a
200 on a mutation is not the finding, the re-read is. A test that widens
a production allow-list and exits on an exception without checking the
restore leaves the perimeter open and the evidence file silent about it.

Usage:
    python3 tests/t02_ip_access_list.py
    python3 tests/t02_ip_access_list.py --wait 180 --skip-gateway

Writes: evidence/t02-direct-refusal.json
"""
import argparse
import datetime
import importlib.util
import ipaddress
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from common import Report, load_env  # noqa: E402

EVIDENCE = ROOT / "evidence" / "t02-direct-refusal.json"
CONFIG = ROOT / "iac" / "config" / "recipients.yaml"
UC = "/api/2.1/unity-catalog"

RECIPIENT = "awoz1227-t02-iplist-recipient"
SHARE = "awoz1227-psp7-demo-share"
SCHEMA = "opensharing_test"
TABLE = "v_entitled_t2"

# Addresses that may appear in evidence verbatim. Everything else that
# looks like an IPv4 is redacted on the way out -- an ALLOW-LIST, for the
# same reason the credential scrub is one: a deny-list over error text
# that can gain a field fails open.
PUBLISHABLE_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),    # RFC 5737 TEST-NET-1
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 -- the declared list
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("0.0.0.0/32"),
]

IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def load_probe(filename, modname):
    path = ROOT / "scripts" / filename
    if not path.exists():
        sys.exit(f"Missing {path}; this test reuses its helpers.")
    spec = importlib.util.spec_from_file_location(modname, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


P14 = load_probe("14_probe_d2o_provider_import.py", "t02_probe14")
call = P14.call
err_bits = P14.err_bits


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


# ---------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------

def redact_ip(addr):
    """203.0.113.5 survives; the operator's address becomes a /24 plus a
    fingerprint, so two observations of the same address can be shown to
    BE the same address without the address being in the file."""
    try:
        ip = ipaddress.ip_address(addr)
    except ValueError:
        return "<not-an-ip>"
    if any(ip in net for net in PUBLISHABLE_NETS):
        return str(ip)
    octets = str(ip).split(".")
    return (f"{octets[0]}.{octets[1]}.{octets[2]}.x/24"
            f"#sha12={P14.fingerprint(str(ip))}")


def scrub(text):
    if not isinstance(text, str):
        return text
    text = P14.redact(text)
    return IPV4.sub(lambda m: redact_ip(m.group(0)), text)


def scrub_json(payload):
    return scrub(json.dumps(payload, indent=2, default=str))


# ---------------------------------------------------------------------
# The recipient-side read, over the Delta Sharing REST protocol
# ---------------------------------------------------------------------

def sharing_get(endpoint, bearer, path, method="GET", body=None, timeout=45):
    url = endpoint.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {bearer}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, json.dumps({"error_code": "LOCAL_URLERROR",
                              "message": str(e.reason)})
    except Exception as e:  # noqa: BLE001
        return 0, json.dumps({"error_code": type(e).__name__, "message": str(e)})


def read_as_recipient(endpoint, bearer, label):
    """Four steps, graded as one observation but recorded separately.

    Separate because they fail for different reasons and a collapsed
    result cannot say which. `/shares` returns only what the recipient is
    GRANTED, so a 200 there is simultaneously the credential check and
    the grant check -- which is precisely why it makes a usable positive
    control.
    """
    steps = {}

    st, raw = sharing_get(endpoint, bearer, "/shares")
    shares = []
    try:
        shares = [s.get("name") for s in (json.loads(raw).get("items") or [])]
    except (json.JSONDecodeError, AttributeError):
        pass
    steps["list_shares"] = {"status": st, "shares_visible": shares,
                            "body": scrub(raw)[:400]}

    if st == 200:
        st2, raw2 = sharing_get(
            endpoint, bearer, f"/shares/{SHARE}/schemas/{SCHEMA}/tables")
        tables = []
        try:
            tables = [t.get("name") for t in (json.loads(raw2).get("items") or [])]
        except (json.JSONDecodeError, AttributeError):
            pass
        steps["list_tables"] = {"status": st2, "tables_visible": tables,
                                "body": scrub(raw2)[:400]}

        st3, raw3 = sharing_get(
            endpoint, bearer,
            f"/shares/{SHARE}/schemas/{SCHEMA}/tables/{TABLE}/metadata")
        steps["table_metadata"] = {"status": st3, "body": scrub(raw3)[:600]}

        st4, raw4 = sharing_get(
            endpoint, bearer,
            f"/shares/{SHARE}/schemas/{SCHEMA}/tables/{TABLE}/query",
            method="POST", body={"limitHint": 10})
        # The response is NDJSON: a protocol line, a metaData line, then
        # one line per file. File lines are what prove DATA was served,
        # not just metadata -- and each one carries a pre-signed URL, so
        # only the COUNT is kept (B-15).
        file_lines = 0
        for line in raw4.splitlines():
            if '"file"' in line:
                file_lines += 1
        steps["query"] = {"status": st4, "file_lines": file_lines,
                          "body_length": len(raw4),
                          "body": (scrub(raw4)[:300] if st4 != 200
                                   else "<withheld: carries pre-signed URLs>")}
        data_served = st4 == 200
    else:
        for k in ("list_tables", "table_metadata", "query"):
            steps[k] = {"status": None,
                        "means": "Not attempted; /shares was refused."}
        data_served = False

    first = steps["list_shares"]["status"]
    if first == 200:
        outcome = "READ_SUCCEEDED" if data_served else "DISCOVERY_ONLY"
    elif first in (401, 403):
        outcome = "DENIED"
    elif first == 0:
        outcome = "CANNOT_SEE_LOCAL_NETWORK_ERROR"
    else:
        outcome = f"UNCLASSIFIED_HTTP_{first}"

    code, msg = "", ""
    try:
        code, msg = err_bits(json.loads(steps["list_shares"]["body"]))
    except (json.JSONDecodeError, TypeError):
        msg = steps["list_shares"]["body"]
    return {"label": label, "at": now(), "outcome": outcome,
            "http_status": first, "error_code": code,
            "error_message": scrub(msg)[:400], "steps": steps,
            "share_granted_visible": SHARE in (steps["list_shares"]
                                               .get("shares_visible") or []),
            "data_served": data_served}


# ---------------------------------------------------------------------
# Egress address discovery
# ---------------------------------------------------------------------

def discover_egress_ip(phase0):
    """Prefer the platform's own denial message. Record which source won.

    The platform's message is the better source by a wide margin: it is
    the address DATABRICKS saw, which is the only address the allow-list
    is compared against. A third-party echo service reports the address
    IT saw, and on a host with more than one route out those can differ --
    in which case phase 1 would add an address that was never going to
    match and the test would report enforcement where there was none.
    """
    blob = json.dumps(phase0)
    for cand in IPV4.findall(blob):
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        if ip.is_global and not any(ip in n for n in PUBLISHABLE_NETS):
            return str(ip), {"source": "PLATFORM_DENIAL_MESSAGE",
                             "quality": "AUTHORITATIVE",
                             "means": ("The address Databricks itself reported "
                                       "seeing. This is the one the allow-list "
                                       "is compared against.")}
    for url in ("https://api.ipify.org", "https://checkip.amazonaws.com"):
        try:
            req = urllib.request.Request(url, method="GET")
            with urllib.request.urlopen(req, timeout=15) as r:
                text = r.read().decode().strip()
            ip = ipaddress.ip_address(text)
            if ip.is_global:
                return str(ip), {
                    "source": "THIRD_PARTY_ECHO",
                    "echo_host": urlparse(url).hostname,
                    "quality": "PRESUMED",
                    "means": ("The platform's refusal did not name an "
                              "address, so this is the address a third "
                              "party saw. If the host has more than one "
                              "route out it may not be the address "
                              "Databricks sees, and a phase 1 failure "
                              "should be read as that before it is read "
                              "as anything else.")}
        except Exception:  # noqa: BLE001
            continue
    return None, {"source": "NONE", "quality": "ABSENT",
                  "means": ("No egress address could be established. The "
                            "positive control is therefore impossible and "
                            "the test stops WITHOUT mutating the "
                            "allow-list.")}


# ---------------------------------------------------------------------
# Allow-list mutation
# ---------------------------------------------------------------------

def set_ip_list(host, token, addresses):
    st, pl = call(host, token, f"{UC}/recipients/{RECIPIENT}", "PATCH",
                  {"ip_access_list": {"allowed_ip_addresses": addresses}})
    return st, pl


def read_ip_list(host, token):
    st, pl = call(host, token, f"{UC}/recipients/{RECIPIENT}")
    if st != 200 or not isinstance(pl, dict):
        return st, None, pl
    got = (pl.get("ip_access_list") or {}).get("allowed_ip_addresses") or []
    return st, sorted(got), pl


def settle(host, token, addresses, endpoint, bearer, want, wait, label):
    """Mutate, then poll the READ until it agrees -- within a stated bound.

    B-21: "none" is three answers, and so is "denied". A single read
    taken immediately after a PATCH cannot distinguish "the list is wrong"
    from "the list has not propagated yet", and the two have opposite
    meanings. The bound is recorded beside the result so a timeout reads
    as a timeout and not as the outcome that was hoped for.
    """
    st, pl = set_ip_list(host, token, addresses)
    rec = {"label": label, "patch_status": st,
           "requested": [redact_ip(a.split("/")[0]) for a in addresses],
           "wait_bound_seconds": wait, "attempts": []}
    if st != 200:
        code, msg = err_bits(pl)
        rec["verdict"] = "PATCH_FAILED"
        rec["error_code"] = code
        rec["error"] = scrub(msg)[:800]
        return rec

    vst, vlist, _ = read_ip_list(host, token)
    rec["list_after_patch"] = ([redact_ip(a.split("/")[0]) for a in vlist]
                              if vlist is not None else None)
    rec["list_read_back_status"] = vst

    started = time.time()
    delay = 10
    while True:
        obs = read_as_recipient(endpoint, bearer, f"{label}#{len(rec['attempts']) + 1}")
        elapsed = round(time.time() - started, 1)
        rec["attempts"].append({"after_seconds": elapsed,
                                "outcome": obs["outcome"],
                                "http_status": obs["http_status"]})
        rec["last_observation"] = obs
        if obs["outcome"] == want:
            rec["settled_after_seconds"] = elapsed
            rec["verdict"] = "SETTLED_AS_EXPECTED"
            return rec
        if elapsed + delay > wait:
            rec["verdict"] = "NEVER_SETTLED_WITHIN_BOUND"
            rec["means"] = (
                f"Wanted {want}; last saw {obs['outcome']} after {elapsed}s "
                f"with a {wait}s bound. This is NOT the same observation as "
                f"{want} and must not be graded as one. Either the list does "
                f"not behave as the phase assumed, or propagation is slower "
                f"than the bound -- re-run with a larger --wait to separate "
                f"those.")
            return rec
        time.sleep(delay)


# ---------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--wait", type=int, default=150,
                    help="per-phase bound, seconds, for the list to take effect")
    ap.add_argument("--skip-gateway", action="store_true",
                    help="skip phase 1b (the topology measurement)")
    args = ap.parse_args()

    load_env()
    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")
    host = os.environ["DATABRICKS_HOST"].strip()
    token = os.environ["DATABRICKS_TOKEN"].strip()

    cred_path = ROOT / "_secrets" / f"credential-{RECIPIENT}.json"
    if not cred_path.exists():
        sys.exit(
            f"Missing {cred_path.relative_to(ROOT)}.\n"
            f"T-02 reads AS THE RECIPIENT, so it needs an activated "
            f"credential, and RKI-5 records that none is live yet. Run:\n"
            f"  python3 scripts/28_activate_credential.py --recipient {RECIPIENT}\n"
            f"  python3 scripts/28_activate_credential.py --recipient {RECIPIENT} "
            f"--activate --also-rewrite")
    cred = json.loads(cred_path.read_text())
    endpoint = cred.get("endpoint")
    bearer = cred.get("bearerToken")
    if not endpoint or not bearer:
        sys.exit(f"{cred_path.relative_to(ROOT)} is not a usable Delta Sharing "
                 f"profile (no endpoint or no bearerToken).")

    try:
        import yaml
        cfg = yaml.safe_load(CONFIG.read_text())
        decl = next(r for r in cfg["recipients"] if r["name"] == RECIPIENT)
        declared_list = sorted((decl.get("ip_access_list") or {})
                               .get("allowed_ip_addresses") or [])
    except Exception as exc:  # noqa: BLE001
        sys.exit(f"Could not read the declared allow-list from "
                 f"{CONFIG.relative_to(ROOT)}: {exc}. Refusing to mutate a "
                 f"list whose declared value is unknown -- the restore would "
                 f"have nothing to restore to.")
    if not declared_list:
        sys.exit(f"{RECIPIENT} declares no allowed_ip_addresses in "
                 f"{CONFIG.relative_to(ROOT)}, so there is no list to narrow "
                 f"back to and nothing to restore.")

    rep = Report()
    results = {
        "test_id": "T-02",
        "description": ("Call straight to the Databricks sharing endpoint "
                        "with a valid token (CONOPS AC1)"),
        "task": "E1 Task 1.6",
        "date": now(),
        "recipient": RECIPIENT,
        "share": SHARE,
        "credential": P14.profile_summary(cred),
        "declared_allow_list": declared_list,
        "procedure_source": (f"{CONFIG.relative_to(ROOT)} -> recipients[] "
                             f"{RECIPIENT}.t02_procedure (specified before "
                             f"this test was written, implemented here)"),
        "why_two_phases": (
            "A denial is not attributable on its own. A broken credential, an "
            "unactivated token, a missing grant, a typo'd share name and an "
            "expired token all produce the same observation at the client. "
            "The positive control in phase 1 is what makes phase 2's denial "
            "mean the allow-list."),
        "phases": {},
    }

    print("T-02 -- direct call to the Databricks sharing endpoint")
    print("=" * 68)
    print(f"recipient: {RECIPIENT}")
    print(f"endpoint:  {urlparse(endpoint).hostname}")
    print(f"declared allow-list: {declared_list}")
    print(f"token sha12: {results['credential']['bearer_token_sha256_12']}  "
          f"expires: {results['credential'].get('expiration_time')}")
    print()

    restored = None
    try:
        # --- phase 0: as declared ------------------------------------
        print("PHASE 0 -- read with the declared list (expect DENIED)")
        st0, list0, _ = read_ip_list(host, token)
        p0 = read_as_recipient(endpoint, bearer, "phase_0_as_declared")
        results["phases"]["phase_0_as_declared"] = {
            "list_on_platform_before_any_mutation": list0,
            "list_read_status": st0,
            "observation": p0,
            "means": (
                "The before-picture, taken against live state before anything "
                "is changed (B-33b). If this is DENIED the list may be "
                "enforced -- or six other things may be wrong. If it SUCCEEDED "
                "the list is not enforced at all, which is the finding, and "
                "phases 1 and 2 then measure how far that goes."),
        }
        print(f"  outcome: {p0['outcome']} (http {p0['http_status']})")

        # --- egress discovery ----------------------------------------
        ip, prov = discover_egress_ip(results["phases"]["phase_0_as_declared"])
        results["egress_address"] = dict(prov)
        if ip:
            results["egress_address"]["address_redacted"] = redact_ip(ip)
        print(f"  egress address: {prov['source']} "
              f"({results['egress_address'].get('address_redacted', 'none')})")

        if not ip:
            results["verdict"] = "CANNOT_SEE_NO_POSITIVE_CONTROL_POSSIBLE"
            results["means"] = prov["means"]
            rep.record("T-02", "Direct sharing-endpoint call is refused",
                       "denial attributable to the IP access list",
                       "no egress address could be established, so no "
                       "positive control was possible; nothing was mutated",
                       False, str(EVIDENCE.relative_to(ROOT)))
        else:
            # --- phase 1: positive control ---------------------------
            print(f"\nPHASE 1 -- add the operator's address (expect "
                  f"READ_SUCCEEDED), bound {args.wait}s")
            p1 = settle(host, token, [f"{ip}/32"], endpoint, bearer,
                        "READ_SUCCEEDED", args.wait, "phase_1_operator_allowed")
            results["phases"]["phase_1_operator_allowed"] = p1
            results["phases"]["phase_1_operator_allowed"]["means"] = (
                "THE POSITIVE CONTROL. The declared test-net address is "
                "removed and only the operator's is present, so phase 1 and "
                "phase 2 differ in the allow-list and in nothing else -- not "
                "the credential, not the grant, not the share, not the client, "
                "not the endpoint.")
            print(f"  verdict: {p1['verdict']}  "
                  f"attempts: {len(p1['attempts'])}  "
                  f"last: {p1.get('last_observation', {}).get('outcome')}")

            # --- phase 1b: the topology measurement ------------------
            gw = (os.environ.get("GRAVITEE_GATEWAY_EDGE_URL") or "").strip()
            if args.skip_gateway or not gw:
                results["phases"]["phase_1b_gateway_same_egress"] = {
                    "verdict": "NOT_RUN",
                    "reason": ("--skip-gateway" if args.skip_gateway
                               else "GRAVITEE_GATEWAY_EDGE_URL is not set"),
                    "consequence": ("The gateway-vs-direct question stays "
                                    "unmeasured, so T-02 must not be read as "
                                    "evidence for the perimeter claim in AC1 "
                                    "-- only for the mechanism."),
                }
            else:
                print(f"\nPHASE 1b -- same list, read THROUGH the gateway "
                      f"({urlparse(gw).hostname}:{urlparse(gw).port})")
                gwobs = read_as_recipient(gw, bearer, "phase_1b_via_gateway")
                same = gwobs["outcome"] in ("READ_SUCCEEDED", "DISCOVERY_ONLY")
                results["phases"]["phase_1b_gateway_same_egress"] = {
                    "gateway_edge": f"{urlparse(gw).scheme}://"
                                    f"{urlparse(gw).hostname}:{urlparse(gw).port}",
                    "observation": gwobs,
                    "allow_list_at_this_moment": "operator address only",
                    "verdict": ("GATEWAY_SHARES_THE_OPERATOR_EGRESS_ADDRESS"
                                if same else
                                "GATEWAY_EGRESS_DIFFERS_OR_GATEWAY_UNREACHABLE"),
                    "means": (
                        "The gateway was admitted by a list containing only "
                        "the OPERATOR's address, so the gateway's egress "
                        "address is the operator's. An IP allow-list therefore "
                        "cannot separate 'via the gateway' from 'direct' on "
                        "this host, and T-02's perimeter claim -- a list "
                        "holding the gateway's address only -- is NOT locally "
                        "testable. The mechanism is testable; the topology is "
                        "not. See docs/11 B-35."
                        if same else
                        "The read through the gateway did not succeed under a "
                        "list that admits the operator. Either the gateway "
                        "egresses from a different address -- in which case "
                        "the perimeter IS locally testable and T-02 should be "
                        "rebuilt around the gateway's address -- or the "
                        "gateway is down, or the route is misconfigured. The "
                        "three are not distinguished by this observation "
                        "alone; check the gateway before reading this as "
                        "topology."),
                }
                print(f"  verdict: {results['phases']['phase_1b_gateway_same_egress']['verdict']}")

            # --- phase 2: narrow back --------------------------------
            print(f"\nPHASE 2 -- narrow back to {declared_list} (expect DENIED)")
            p2 = settle(host, token, declared_list, endpoint, bearer,
                        "DENIED", args.wait, "phase_2_operator_excluded")
            results["phases"]["phase_2_operator_excluded"] = p2
            print(f"  verdict: {p2['verdict']}  "
                  f"attempts: {len(p2['attempts'])}  "
                  f"last: {p2.get('last_observation', {}).get('outcome')}")

            # --- grade ------------------------------------------------
            p1_ok = (p1["verdict"] == "SETTLED_AS_EXPECTED")
            p2_ok = (p2["verdict"] == "SETTLED_AS_EXPECTED")
            p0_denied = p0["outcome"] == "DENIED"

            if not p1_ok and p2_ok:
                verdict = "INCONCLUSIVE_NO_POSITIVE_CONTROL"
                means = (
                    "Phase 2 denied, but phase 1 never produced a successful "
                    "read, so the denial is unattributable: the credential, "
                    "the grant or the client may be the cause. This is the "
                    "case the test exists to refuse to call a pass.")
            elif p1_ok and not p2_ok:
                verdict = "ENFORCEMENT_ABSENT_READ_SURVIVED_EXCLUSION"
                means = (
                    "The read succeeded while the operator's address was NOT "
                    "on the list. The list is configured and persists (§11.3) "
                    "and is not acted on for this call path. That is an AC1 "
                    "finding of the first order -- the control the CONOPS "
                    "relies on for the direct-call refusal does not refuse.")
            elif p1_ok and p2_ok:
                verdict = "ENFORCED_MECHANISM_PROVEN"
                means = (
                    "Same credential, same grant, same share, same client, "
                    "same endpoint. The read succeeded with the operator's "
                    "address on the list and was denied without it. The "
                    "denial is attributable to the allow-list and to nothing "
                    "else. SCOPE: this proves the MECHANISM enforces. It does "
                    "not prove the TOPOLOGY claim -- see phase 1b.")
            else:
                verdict = "CANNOT_SEE"
                means = ("Neither phase settled within its bound. No claim "
                         "either way; re-run with a larger --wait.")

            results["verdict"] = verdict
            results["means"] = means
            results["phase_0_consistency"] = (
                "Phase 0 denied before any mutation, consistent with phase 2."
                if p0_denied else
                "Phase 0 did NOT deny before any mutation. Whatever phase 2 "
                "shows, the starting state was permissive -- read the two "
                "together.")
            rep.record(
                "T-02",
                "Direct call to the Databricks sharing endpoint is refused "
                "by the recipient IP access list",
                "DENIED with the operator excluded, SUCCESS with the operator "
                "included (same credential, grant, share and client)",
                f"{verdict}: phase1={p1['verdict']}, phase2={p2['verdict']}",
                verdict == "ENFORCED_MECHANISM_PROVEN",
                str(EVIDENCE.relative_to(ROOT)))

    finally:
        # --- restore, then READ IT BACK (B-23) -----------------------
        print(f"\nRESTORE -- putting {declared_list} back")
        rst, rpl = set_ip_list(host, token, declared_list)
        vst, vlist, vpl = read_ip_list(host, token)
        ok = vlist is not None and sorted(vlist) == declared_list
        comment_survived = isinstance(vpl, dict) and bool(vpl.get("comment"))
        restored = {
            "patch_status": rst,
            "read_back_status": vst,
            "list_on_platform_now": vlist,
            "declared": declared_list,
            "verdict": "RESTORED_AND_VERIFIED" if ok else "RESTORE_NOT_VERIFIED",
            "comment_field_still_present": comment_survived,
            "means": (
                "The declared list is back and was re-read to prove it (B-23). "
                "The PATCH body carried only ip_access_list, so the comment "
                "that carries the dsa_ref and the purpose was checked too -- a "
                "partial PATCH that silently blanked it would move the drift "
                "into a field nothing in this test looks at."
                if ok else
                "THE ALLOW-LIST WAS NOT VERIFIED BACK TO ITS DECLARED VALUE. "
                "Run `python3 scripts/27_build_recipient_model.py` now: it is "
                "the applier that owns this field and it will re-assert the "
                "config. Do not leave the recipient in this state."),
        }
        results["restore"] = restored
        print(f"  {restored['verdict']}  (list now: {vlist})")
        if not ok:
            print("  WARNING: run scripts/27_build_recipient_model.py to "
                  "re-assert the declared list.")

        results.setdefault("verdict", "ABORTED")
        results["scope"] = (
            "T-02 as run here measures the recipient IP access list as a "
            "MECHANISM: configured, then observed to admit and to refuse the "
            "same read. It does not measure the perimeter topology the CONOPS "
            "assumes -- that the gateway egresses from an address the "
            "allow-list can name and the consumer cannot reach from. Phase 1b "
            "records why that is not measurable on a single-host deployment.")
        results["still_open"] = [
            {"id": "RKI-3",
             "was": "IP access list enforcement is configured, not observed",
             "now": ("Closed for the mechanism if the verdict is "
                     "ENFORCED_MECHANISM_PROVEN; the topology half becomes "
                     "B-35 and stays open.")},
            {"id": "T-03",
             "note": ("T-03 is the same observation at the GATEWAY layer "
                      "(403 ip-filtering, already passed once on "
                      "2026-10-17). It is E2-owned and unaffected by this "
                      "run, but it now has the attribution procedure it "
                      "lacked.")},
        ]

        EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
        EVIDENCE.write_text(scrub_json(results))
        rep.write(ROOT / "evidence" / "t02-report.json")

        print("\n" + "=" * 68)
        print(f"T-02 VERDICT: {results['verdict']}")
        print(f"\nWrote {EVIDENCE.relative_to(ROOT)}")
        print("Now run: python3 scripts/check_secret_hygiene.py")

    return 0 if results["verdict"] == "ENFORCED_MECHANISM_PROVEN" else 1


if __name__ == "__main__":
    sys.exit(main())
