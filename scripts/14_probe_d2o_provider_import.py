#!/usr/bin/env python3
"""
E1 Task 1.10 -- the probe that gates step 5 of the §2.4.1 D2O sequence.

§2.4.1 step 5, D2O column, reads: "Import the provider from the file
(Catalog Explorer, OpenSharing, Shared with me), then create a catalog
from the share. Validate the read with the connector, loading the file
from the vault."

That single cell contains TWO actions in TWO DIFFERENT ENVIRONMENTS, and
the whole shape of T-20 depends on noticing it:

  * "Import the provider ... create a catalog" happens in the Databricks
    CONTROL PLANE. Databricks itself must hold the credential and call
    the provider's endpoint.
  * "Validate the read with the connector" happens on the CLIENT, with
    the local `delta_sharing` library opening the connection itself.

Our provider is `http://localhost:8086/delta-sharing`. Databricks SaaS
cannot reach it, and a tunnel does not fix it either: /query answers with
pre-signed URLs naming `objectstore:8000`, and the host and port are
INSIDE the SigV4 signature (docs/11 B-9), so a cloud consumer can neither
resolve that host nor rewrite it without invalidating the signature.

So the control-plane half is expected to stop. THAT IS A FINDING, NOT A
FAILURE -- but only if we can say WHY it stopped, and this is exactly the
silent-negative shape the project keeps hitting (docs/12 §12.9): a tier
that forbids the feature and a tier that permits it but cannot route to
localhost BOTH come back as "no provider was created". Recording the
first when the truth is the second would put a false capability
limitation into the v1.6 CONOPS, and a client on a routable network
would be told a thing that is not true of their environment.

Four probes, ordered so each can only be read one way:

  1. GET /providers -- is the API surface present and readable at all?
     No side effect. A tier with Delta Sharing recipient support off
     refuses here, before any credential is involved.

  2. POST /providers with a profile that has NO `endpoint` field and a
     DUMMY token. This is the discriminator. No network call is possible
     with a profile that names no endpoint, so whatever comes back is
     about CAPABILITY and PRIVILEGE, never about reachability:
       - a validation error naming the field  => the feature is ON and
         the principal may create providers
       - PERMISSION_DENIED / FEATURE_DISABLED => the feature or the
         privilege is absent, and T-20's control-plane half is
         NOT_RUN for a stated tier reason
     The dummy token matters: the request we EXPECT to be rejected is
     the one request that must not carry a live credential.

  3. POST /providers with the real vaulted profile. Only now do we learn
     whether creation validates reachability or just stores metadata.

  4. If 3 created the object, GET /providers/{name}/shares -- the
     equivalent of SHOW SHARES IN PROVIDER. This is the first call that
     REQUIRES the control plane to actually reach our endpoint, so it is
     here, not earlier, that the localhost boundary shows up as itself.

Cleanup is unconditional: whatever probe 3 created is deleted in a
finally block, and the deletion is verified rather than assumed.

The live bearer token is sent to Databricks in probe 3, which is correct
and is itself §2.4.1 step 4 -> 5: the custodian hands the vaulted file to
the metastore admin. It is NEVER written to the evidence file. What gets
recorded is the endpoint, the field names present, the token length and a
sha256 prefix -- enough to prove which credential was used and to detect
drift, insufficient to use.

Usage:
    python3 scripts/14_probe_d2o_provider_import.py

Writes: evidence/capability-baseline-d2o-import.json
"""
import datetime
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "evidence" / "capability-baseline-d2o-import.json"

# Named so it is obviously disposable and obviously ours. If a probe run
# is killed between create and delete, the next run finds this name
# already present and says so rather than colliding.
PROBE_PROVIDER = "awoz1227_probe_d2o_import"
PROBE_PROVIDER_INVALID = "awoz1227_probe_d2o_noendpoint"
PROBE_PROVIDER_PUBLIC = "awoz1227_probe_d2o_guardscope"

UC = "/api/2.1/unity-catalog"


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit(f"Missing {env_path}. Copy .env.example to .env and fill it in first.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A blank value is an ABSENCE, not a value -- docs/11 B-10b.
        if not v.strip():
            continue
        os.environ.setdefault(k, v)


def require(*names):
    missing = [n for n in names if not os.environ.get(n, "").strip()]
    if missing:
        sys.exit(f"Missing required .env values: {', '.join(missing)}")
    return [os.environ[n].strip() for n in names]


def call(host, token, path, method="GET", body=None, timeout=90):
    """Returns (status, parsed_or_raw). Never raises on an HTTP error --
    the error BODY is the evidence here, so it must survive."""
    url = host.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw) if raw.strip() else {}
            except json.JSONDecodeError:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw
    except urllib.error.URLError as e:
        return 0, {"error_code": "LOCAL_URLERROR", "message": str(e.reason)}
    except Exception as e:  # noqa: BLE001 -- a timeout here is a result
        return 0, {"error_code": type(e).__name__, "message": str(e)}


def err_bits(payload):
    """Pull (error_code, message) out of whatever Databricks returned."""
    if isinstance(payload, dict):
        code = payload.get("error_code") or payload.get("errorCode") or ""
        msg = payload.get("message") or payload.get("error") or ""
        return str(code), str(msg)
    return "", str(payload)[:600]


# Classification is kept as three EXPLICIT vocabularies rather than one
# fuzzy score, because the point of this probe is that these three
# refusals must never be collapsed into each other. If a refusal matches
# none of them, it is reported as UNCLASSIFIED and the raw text is kept
# -- an honest "I do not know what this is" beats a confident wrong
# bucket, which is how §12.9's first instance happened.
TIER_CODES = {
    "PERMISSION_DENIED", "FEATURE_DISABLED", "UNAUTHORIZED",
    "ENDPOINT_NOT_IMPLEMENTED", "NOT_IMPLEMENTED", "UNSUPPORTED_OPERATION",
}
TIER_PHRASES = [
    "not available", "not enabled", "not supported", "unsupported",
    "upgrade", "does not have", "requires", "privilege", "create provider",
    "metastore admin", "entitlement", "free edition", "not permitted",
    "feature", "quota", "limit",
]
REACH_PHRASES = [
    "connect", "connection", "unreachable", "timed out", "timeout",
    "resolve", "refused", "localhost", "127.0.0.1", "dns", "host",
    "ioexception", "sockettimeout", "unknownhost", "ssl", "handshake",
    "gateway", "no route", "network",
]
VALIDATION_PHRASES = [
    "endpoint", "recipient_profile", "profile", "sharecredentialsversion",
    "bearertoken", "missing", "invalid", "malformed", "cannot be",
    "must be", "required", "parse", "field",
]


def classify(status, payload):
    code, msg = err_bits(payload)
    blob = f"{code} {msg}".lower()
    if 200 <= status < 300:
        return "ACCEPTED", code, msg
    if code.upper() in TIER_CODES or any(p in blob for p in TIER_PHRASES):
        # Checked FIRST and then re-checked against reachability below,
        # because "host" appears in both vocabularies and a message that
        # names a network failure is a network failure whatever else it
        # also says.
        if any(p in blob for p in REACH_PHRASES):
            return "REFUSED_AMBIGUOUS_TIER_OR_REACH", code, msg
        return "REFUSED_TIER_OR_PRIVILEGE", code, msg
    if any(p in blob for p in REACH_PHRASES):
        return "REFUSED_REACHABILITY", code, msg
    if any(p in blob for p in VALIDATION_PHRASES):
        return "REFUSED_VALIDATION", code, msg
    return "UNCLASSIFIED", code, msg


def fingerprint(secret):
    return hashlib.sha256(secret.encode()).hexdigest()[:12]


def redact(text):
    """Last line of defence before anything reaches the evidence file.

    Databricks echoes parts of the request in some error messages, and
    `recipient_profile_str` is the whole credential as a string. A
    message that quoted it back would put a live token into
    evidence/, which the hygiene gate would then fail on -- correctly,
    but after the fact. Strip anything token-shaped on the way out.
    """
    if not isinstance(text, str):
        return text
    text = re.sub(r'"bearerToken"\s*:\s*"[^"]*"', '"bearerToken":"<redacted>"', text)
    text = re.sub(r"\\\"bearerToken\\\"\s*:\s*\\\"[^\\\"]*\\\"",
                  '\\\\"bearerToken\\\\":\\\\"<redacted>\\\\"', text)
    return text


def profile_summary(profile):
    return {
        "endpoint": profile.get("endpoint"),
        "endpoint_host": urlparse(profile.get("endpoint", "")).hostname,
        "endpoint_port": urlparse(profile.get("endpoint", "")).port,
        "share_credentials_version": profile.get("shareCredentialsVersion"),
        "fields_present": sorted(profile.keys()),
        "bearer_token_length": len(profile.get("bearerToken", "")),
        "bearer_token_sha256_12": fingerprint(profile.get("bearerToken", "")),
        "expiration_time": profile.get("expirationTime"),
    }


def main():
    load_env()
    host, token = require("DATABRICKS_HOST", "DATABRICKS_TOKEN")
    profile_rel, = require("OSS_PROVIDER_PROFILE")

    profile_path = REPO / profile_rel if not os.path.isabs(profile_rel) else Path(profile_rel)
    if not profile_path.exists():
        sys.exit(f"Missing {profile_path}. Run scripts/10_setup_oss_provider.py first.")
    profile = json.loads(profile_path.read_text())

    results = {
        "probe": "d2o provider import (CONOPS 2.4.1 step 5, control-plane half)",
        "task": "E1 Task 1.10",
        "gates": ["T-20"],
        # Not utcnow(): deprecated in 3.12 and removal-scheduled. The
        # rendered STRING is deliberately identical in shape to the
        # other evidence files, so E7 can sort across them.
        "date": datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z"),
        "databricks_host": host,
        "credential": profile_summary(profile),
        "checks": {},
    }

    print("D2O provider import capability probe")
    print("=" * 68)
    print(f"Workspace: {host}")
    print(f"Credential: {profile_path.relative_to(REPO)} "
          f"-> endpoint {profile.get('endpoint')} "
          f"(token sha256:{results['credential']['bearer_token_sha256_12']}, "
          f"{results['credential']['bearer_token_length']} chars)")

    # --- 1. Is the providers API surface there at all? -------------------
    print("\n[1] GET /providers -- API surface and read privilege")
    status, payload = call(host, token, f"{UC}/providers")
    verdict, code, msg = classify(status, payload)
    existing = []
    if verdict == "ACCEPTED" and isinstance(payload, dict):
        existing = [p.get("name") for p in (payload.get("providers") or [])]
    results["checks"]["providers_api"] = {
        "status": status,
        "verdict": "READABLE" if verdict == "ACCEPTED" else verdict,
        "error_code": code or None,
        "message": redact(msg)[:400] or None,
        "existing_providers": existing,
        "means": (
            f"The Delta Sharing recipient API answers and this principal can read it. "
            f"{len(existing)} provider(s) already registered: {existing}."
            if verdict == "ACCEPTED" else
            "The providers API did not answer readably. Probes 2-4 are "
            "interpreted against this: a refusal here means the tier or the "
            "principal lacks Delta Sharing recipient support, and nothing "
            "below can distinguish anything finer."
        ),
    }
    print(f"  status {status} -> {results['checks']['providers_api']['verdict']}")
    if code or msg:
        print(f"  {code} {redact(msg)[:200]}")
    if PROBE_PROVIDER in existing:
        print(f"  NOTE: {PROBE_PROVIDER} already exists -- a previous run did not "
              f"clean up. It will be deleted at the end of this run.")

    # --- 2. The discriminator: no endpoint, dummy token -----------------
    # A profile with no endpoint cannot produce a network call, so this
    # separates "the feature is off" from "the feature is on but cannot
    # route to localhost" without ever leaving the control plane.
    print("\n[2] POST /providers with NO endpoint and a dummy token -- "
          "capability vs reachability discriminator")
    bad_profile = {"shareCredentialsVersion": 1, "bearerToken": "dummy-not-a-real-token"}
    status, payload = call(host, token, f"{UC}/providers", "POST", {
        "name": PROBE_PROVIDER_INVALID,
        "authentication_type": "TOKEN",
        "recipient_profile_str": json.dumps(bad_profile),
        "comment": "AWOZ-1227 capability probe -- expected to be rejected",
    })
    verdict, code, msg = classify(status, payload)
    created_invalid = verdict == "ACCEPTED"
    if verdict == "REFUSED_VALIDATION" or verdict == "UNCLASSIFIED":
        capability = "PRESENT"
        means = (
            "The request was rejected for the CONTENT of the profile, not for "
            "the right to make it. CREATE PROVIDER is therefore available on "
            "this tier to this principal: step 5's control-plane half is "
            "permitted, and anything that stops it later is a routing or "
            "endpoint fact, not a tier fact."
        )
    elif verdict == "REFUSED_TIER_OR_PRIVILEGE":
        capability = "ABSENT"
        means = (
            "Refused on capability or privilege with no endpoint in play, so "
            "reachability cannot be the cause. T-20's control-plane half is "
            f"NOT_RUN for a stated tier reason: {code} {msg[:160]}"
        )
    elif verdict == "REFUSED_REACHABILITY":
        # This cannot literally be true. Check 2 sends a profile with no
        # endpoint, so there is no host to fail to reach. Either the
        # message is a VALIDATION message that happens to use the word
        # "host", or these vocabularies need widening. Say which
        # possibilities remain and print the raw text rather than
        # quietly filing it as UNDETERMINED -- an impossible
        # classification is information about the classifier.
        capability = "PRESENT_CLASSIFIER_CAVEAT"
        means = (
            "Refused with a message matching the REACHABILITY vocabulary in a "
            "request where no network call was possible -- there was no "
            "endpoint to connect to. So this is a validation refusal whose "
            "wording overlaps ('host' appears in both vocabularies), which "
            "means capability is PRESENT; or the classifier is wrong and must "
            "be corrected before T-20 is graded. Settle it by reading the raw "
            f"message: {code} {msg[:200]}"
        )
    elif created_invalid:
        capability = "PRESENT_UNVALIDATED"
        means = (
            "A provider with NO endpoint was ACCEPTED. Creation stores "
            "metadata without validating the profile, so a successful "
            "CREATE PROVIDER proves nothing about the provider being "
            "reachable or even well-formed -- probe 4 is the only call that "
            "does. Worth recording as a CONOPS note: §2.4.1 step 5 treats "
            "import as confirmation, and on this tier it is not."
        )
    else:
        capability = "UNDETERMINED"
        means = ("Refusal did not classify. Raw code and message are kept; do "
                 "not grade T-20 off this row without reading them.")
    results["checks"]["create_provider_capability"] = {
        "status": status,
        "verdict": capability,
        "classification": verdict,
        "error_code": code or None,
        "message": redact(msg)[:500] or None,
        "endpoint_in_request": None,
        "live_credential_used": False,
        "means": means,
    }
    print(f"  status {status} -> capability {capability} ({verdict})")
    if code or msg:
        print(f"  {code} {redact(msg)[:260]}")

    if created_invalid:
        d_status, d_payload = call(host, token,
                                   f"{UC}/providers/{PROBE_PROVIDER_INVALID}", "DELETE")
        print(f"  cleanup: DELETE {PROBE_PROVIDER_INVALID} -> {d_status}")
        results["checks"]["create_provider_capability"]["cleanup_status"] = d_status

    # --- 3, 4 and 5 only make sense if the API answered at all ----------
    created = False
    to_cleanup = []
    try:
        if results["checks"]["providers_api"]["verdict"] != "READABLE":
            for key in ("create_provider_live", "show_shares_in_provider"):
                results["checks"][key] = {
                    "verdict": "NOT_ATTEMPTED",
                    "means": "Skipped: the providers API is not readable (check 1).",
                }
        elif capability == "ABSENT":
            for key in ("create_provider_live", "show_shares_in_provider"):
                results["checks"][key] = {
                    "verdict": "NOT_ATTEMPTED",
                    "means": ("Skipped deliberately: check 2 established the tier "
                              "refuses provider creation with no endpoint in play. "
                              "Sending the live credential now would add risk and "
                              "no information."),
                }
        else:
            # --- 3. The real credential ---------------------------------
            print("\n[3] POST /providers with the VAULTED credential -- "
                  "does creation validate reachability?")
            print("    (this is §2.4.1 step 4 -> 5: the custodian hands the file "
                  "to the metastore admin)")
            status, payload = call(host, token, f"{UC}/providers", "POST", {
                "name": PROBE_PROVIDER,
                "authentication_type": "TOKEN",
                "recipient_profile_str": json.dumps(profile),
                "comment": "AWOZ-1227 T-20 probe -- local OSS provider, deleted after run",
            })
            verdict, code, msg = classify(status, payload)
            created = verdict == "ACCEPTED"
            if status == 409 or "already exists" in f"{code} {msg}".lower():
                created = True
                verdict = "ACCEPTED"
                msg = (msg or "") + " [object already present from a prior run]"
            results["checks"]["create_provider_live"] = {
                "status": status,
                "verdict": "CREATED" if created else verdict,
                "error_code": code or None,
                "message": redact(msg)[:500] or None,
                "endpoint_in_request": profile.get("endpoint"),
                "live_credential_used": True,
                "means": (
                    "The provider object exists in the metastore. Creation did NOT "
                    "require the endpoint to be reachable -- so 'the import "
                    "succeeded' is not evidence that the share is readable, and "
                    "check 4 is the one that tests the connection."
                    if created else
                    "Creation was refused with the real endpoint present. Read "
                    "this against check 2: if capability is PRESENT there, this "
                    "refusal is about the endpoint, not the tier."
                ),
            }
            print(f"  status {status} -> {results['checks']['create_provider_live']['verdict']}")
            if code or msg:
                print(f"  {code} {redact(msg)[:260]}")

            # --- 4. The call that must cross the network ----------------
            if created:
                print("\n[4] GET /providers/{name}/shares -- SHOW SHARES IN PROVIDER.")
                print("    First call requiring the Databricks control plane to "
                      "reach our endpoint.")
                status, payload = call(host, token, f"{UC}/providers/{PROBE_PROVIDER}/shares")
                verdict, code, msg = classify(status, payload)
                shares = []
                if verdict == "ACCEPTED" and isinstance(payload, dict):
                    shares = [s.get("name") for s in (payload.get("shares") or [])]
                if verdict == "ACCEPTED" and shares:
                    v = "SHARES_LISTED"
                    means = (
                        f"The Databricks control plane reached our provider and "
                        f"listed {shares}. The control-plane half of step 5 is "
                        f"RUNNABLE end to end -- which, with a localhost endpoint, "
                        f"means something is forwarding for it. Record what."
                    )
                elif verdict == "ACCEPTED":
                    v = "EMPTY"
                    means = (
                        "HTTP 200 and an empty list. Do not read this as "
                        "'no shares': a 200 with nothing in it is the silent "
                        "negative this project keeps meeting (§12.9). Compare "
                        "against scripts/11, which lists awoz_share from the "
                        "client, before concluding anything."
                    )
                else:
                    v = verdict
                    means = (
                        "The control plane could not list shares. This is the "
                        "EXPECTED outcome and the substantive T-20 finding: the "
                        "endpoint is http://localhost:8086, which resolves inside "
                        "this machine and nowhere else. Note that even a tunnel "
                        "would not finish the job -- /query returns pre-signed "
                        "URLs naming objectstore:8000, and host and port are "
                        "inside the SigV4 signature (docs/11 B-9), so a cloud "
                        "consumer can neither resolve nor rewrite them. The "
                        "control-plane half of step 5 is blocked by TOPOLOGY, "
                        "not by tier."
                    )
                results["checks"]["show_shares_in_provider"] = {
                    "status": status,
                    "verdict": v,
                    "error_code": code or None,
                    "message": redact(msg)[:500] or None,
                    "shares": shares,
                    "means": means,
                }
                print(f"  status {status} -> {v}")
                if code or msg:
                    print(f"  {code} {redact(msg)[:300]}")
            else:
                results["checks"]["show_shares_in_provider"] = {
                    "verdict": "NOT_ATTEMPTED",
                    "means": "Skipped: no provider object was created in check 3.",
                }

            # --- 5. Bound the guard -------------------------------------
            # Check 4 came back `java.lang.SecurityException`, which is
            # NOT what a network failure looks like: no timeout, no
            # connection-refused, no UnknownHost. The control plane
            # declined to ATTEMPT the call. That distinction decides what
            # we may claim, so it has to be measured rather than assumed:
            #
            #   * a guard on the ADDRESS CLASS (loopback / private range)
            #     tells a client nothing about their own environment,
            #     because their provider endpoint is routable
            #   * a BROADER guard -- every non-allow-listed outbound
            #     target, say -- IS a client-facing constraint and belongs
            #     in v1.6, and in §2.4.3, which already says Databricks
            #     does not publish recipient-side firewall requirements
            #
            # One public, routable, non-sharing endpoint separates them.
            # If the error class CHANGES, the guard was about the address;
            # if it stays SecurityException, it is broader than loopback.
            #
            # example.com is the IANA-reserved documentation domain,
            # which exists for exactly this. The token is a DUMMY: this
            # request makes Databricks send `Authorization: Bearer ...`
            # to a third-party host, so sending the real credential would
            # be handing it to someone else to settle a question that
            # resolves long before authentication is reached.
            if str(results["checks"]["show_shares_in_provider"].get("verdict", "")) \
                    .startswith("REFUSED"):
                print("\n[5] Is the guard about the ADDRESS CLASS or broader? "
                      "Same call against a public endpoint, dummy token.")
                public_profile = {
                    "shareCredentialsVersion": 1,
                    "endpoint": "https://example.com/delta-sharing",
                    "bearerToken": "dummy-not-a-real-token",
                }
                c_status, c_payload = call(host, token, f"{UC}/providers", "POST", {
                    "name": PROBE_PROVIDER_PUBLIC,
                    "authentication_type": "TOKEN",
                    "recipient_profile_str": json.dumps(public_profile),
                    "comment": "AWOZ-1227 probe -- guard scope, dummy token, deleted after run",
                })
                c_verdict, c_code, c_msg = classify(c_status, c_payload)
                public_created = c_verdict == "ACCEPTED" or c_status == 409
                if public_created:
                    to_cleanup.append(PROBE_PROVIDER_PUBLIC)
                    status, payload = call(host, token,
                                           f"{UC}/providers/{PROBE_PROVIDER_PUBLIC}/shares")
                    verdict, code, msg = classify(status, payload)
                    prior = results["checks"]["show_shares_in_provider"].get("message") or ""
                    loopback_was_security = "securityexception" in prior.lower()
                    now_security = "securityexception" in f"{code} {msg}".lower()
                    if loopback_was_security and not now_security:
                        v = "GUARD_SCOPED_TO_ADDRESS_CLASS"
                        means = (
                            "The error class CHANGED once the endpoint was publicly "
                            "routable, so the SecurityException in check 4 was about "
                            "the ADDRESS, not about outbound calls in general. The "
                            "control plane will call a routable provider. This is the "
                            "load-bearing result for T-20: Path A is blocked by OUR "
                            "topology and by nothing a client would inherit, so the "
                            "§2.4.1 procedure transfers intact and only the hostnames "
                            "do not (§2.4.3)."
                        )
                    elif loopback_was_security and now_security:
                        v = "GUARD_BROADER_THAN_LOOPBACK"
                        means = (
                            "SecurityException again, against a public routable host. "
                            "The guard is NOT merely about loopback, so this is a real "
                            "recipient-side egress restriction on this tier and a "
                            "client-facing constraint. That makes it a v1.6 addition to "
                            "§2.4.3, which states Databricks does not publish "
                            "recipient-side firewall requirements -- here is a captured "
                            "instance of one. Do not claim the procedure transfers "
                            "without saying this sits in front of it."
                        )
                    elif verdict == "ACCEPTED":
                        v = "PUBLIC_ENDPOINT_CALLED"
                        means = (
                            "The call completed against a host that is not a sharing "
                            "server, so the control plane does make outbound requests "
                            "to routable endpoints. Whatever stopped check 4 was "
                            "specific to the loopback address."
                        )
                    else:
                        v = "INCONCLUSIVE"
                        means = (
                            "Neither error mentions SecurityException in the expected "
                            "place, so the comparison does not hold. Read both raw "
                            "messages before using either."
                        )
                    results["checks"]["guard_scope"] = {
                        "status": status,
                        "verdict": v,
                        "error_code": code or None,
                        "message": redact(msg)[:500] or None,
                        "endpoint_in_request": public_profile["endpoint"],
                        "live_credential_used": False,
                        "compared_against": prior[:300],
                        "means": means,
                    }
                    print(f"  status {status} -> {v}")
                    if code or msg:
                        print(f"  {code} {redact(msg)[:300]}")
                else:
                    results["checks"]["guard_scope"] = {
                        "status": c_status,
                        "verdict": "NOT_ATTEMPTED",
                        "error_code": c_code or None,
                        "message": redact(c_msg)[:400] or None,
                        "means": ("Could not create the public-endpoint provider, so the "
                                  "comparison never ran. The guard's scope is UNKNOWN; "
                                  "do not assume either reading."),
                    }
                    print(f"  status {c_status} -> NOT_ATTEMPTED ({c_code})")
    finally:
        # Unconditional, and VERIFIED per object. A probe that leaves a
        # provider holding a live bearer token in the metastore has
        # created a credential custody problem of exactly the kind
        # §2.4.3 forbids -- and `created` alone is not the right
        # condition, because check 1 may have found an orphan from a run
        # that died between create and delete.
        if created or PROBE_PROVIDER in existing:
            if PROBE_PROVIDER not in to_cleanup:
                to_cleanup.append(PROBE_PROVIDER)
        results["cleanup"] = {}
        for name in to_cleanup:
            print(f"\n[cleanup] DELETE /providers/{name}")
            d_status, _ = call(host, token, f"{UC}/providers/{name}", "DELETE")
            v_status, v_payload = call(host, token, f"{UC}/providers/{name}")
            gone = v_status in (404, 400) or "does not exist" in str(v_payload).lower()
            results["cleanup"][name] = {
                "delete_status": d_status,
                "verify_status": v_status,
                "verdict": "DELETED" if gone else "STILL_PRESENT",
                "held_live_credential": name == PROBE_PROVIDER,
                "means": ("Probe provider removed and its absence confirmed."
                          if gone else
                          "DELETE DID NOT TAKE. A provider object is still "
                          "registered in the metastore"
                          + (" AND IT HOLDS A LIVE BEARER TOKEN."
                             if name == PROBE_PROVIDER else ".")
                          + " Remove it by hand before doing anything else: "
                          f"DELETE {UC}/providers/{name}"),
            }
            print(f"  delete {d_status}, verify {v_status} -> "
                  f"{results['cleanup'][name]['verdict']}")
            if not gone:
                print("  " + results["cleanup"][name]["means"])
        if not to_cleanup:
            results["cleanup"] = {"verdict": "NOTHING_TO_DELETE"}

    # --- Verdict ---------------------------------------------------------
    cap = results["checks"]["create_provider_capability"]["verdict"]
    shares_v = results["checks"].get("show_shares_in_provider", {}).get("verdict")
    PRESENT = ("PRESENT", "PRESENT_UNVALIDATED", "PRESENT_CLASSIFIER_CAVEAT")
    guard = results["checks"].get("guard_scope", {}).get("verdict")
    if cap in PRESENT and shares_v == "SHARES_LISTED":
        plane = "CONTROL_PLANE_RUNNABLE"
    elif cap in PRESENT and guard in ("GUARD_SCOPED_TO_ADDRESS_CLASS",
                                      "PUBLIC_ENDPOINT_CALLED"):
        plane = "CONTROL_PLANE_BLOCKED_BY_LOCAL_TOPOLOGY"
    elif cap in PRESENT and guard == "GUARD_BROADER_THAN_LOOPBACK":
        plane = "CONTROL_PLANE_BLOCKED_BY_RECIPIENT_EGRESS_POLICY"
    elif cap in PRESENT:
        plane = "CONTROL_PLANE_BLOCKED_SCOPE_UNKNOWN"
    elif cap == "ABSENT":
        plane = "CONTROL_PLANE_BLOCKED_BY_TIER"
    else:
        plane = "UNDETERMINED"
    results["verdict"] = plane
    # The three BLOCKED verdicts are deliberately NOT one verdict. They
    # produce the same observable -- no shares listed -- and they say
    # completely different things to a client. Collapsing them is the
    # §12.9 defect shape, and here it would decide whether the v1.6
    # CONOPS tells a client their own environment is affected.
    results["t20_design"] = {
        "CONTROL_PLANE_RUNNABLE": "Run all eight steps in Databricks; no split needed.",
        "CONTROL_PLANE_BLOCKED_BY_LOCAL_TOPOLOGY": (
            "T-20 splits along the seam §2.4.1 step 5 already contains. Path A: "
            "the control-plane steps, recorded up to the exact call that fails "
            "and why. Path B: the connector read, host capture and allow-list, "
            "which is where §2.4.3's actual requirement lives -- 'the allow-list "
            "is built from that capture'. Capability is PRESENT and the guard is "
            "scoped to the address class, so the blocker is OUR loopback endpoint "
            "and nothing a client inherits: the procedure transfers intact, and "
            "only the hostnames do not."
        ),
        "CONTROL_PLANE_BLOCKED_BY_RECIPIENT_EGRESS_POLICY": (
            "Same split, but the claim is narrower and the finding is bigger. The "
            "guard refused a PUBLIC routable endpoint too, so this tier restricts "
            "recipient-side outbound sharing calls in a way Databricks does not "
            "document -- precisely the gap §2.4.3 names. Write it up for v1.6 as a "
            "captured instance, and do NOT claim the procedure transfers without "
            "saying this sits in front of it."
        ),
        "CONTROL_PLANE_BLOCKED_SCOPE_UNKNOWN": (
            "Capability is PRESENT and the control plane did not list shares, but "
            "the guard's scope was not established. Path B proceeds; Path A's "
            "write-up must say the scope is unmeasured rather than implying it is "
            "local. Re-run check 5 before the v1.6 text is settled."
        ),
        "CONTROL_PLANE_BLOCKED_BY_TIER": (
            "Path A is NOT_RUN with the tier capability named. Path B still "
            "yields the host capture, which is the half §2.4.3 asks for."
        ),
        "UNDETERMINED": "Read the raw messages before designing anything.",
    }[plane]

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(results, indent=2))
    print("\n" + "=" * 68)
    print(f"Verdict: {plane}")
    print(results["t20_design"])
    print(f"\nWrote {OUT.relative_to(REPO)}")
    print("Now run: python3 scripts/check_secret_hygiene.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
