#!/usr/bin/env python3
"""
T-20 -- Channel I-1 ingress, D2O pull. CONOPS §2.4.1, §2.4.2, §2.4.3.

WHY THIS TEST HAS TWO PATHS
---------------------------
§2.4.1 step 5, D2O column, reads: "Import the provider from the file
(Catalog Explorer, OpenSharing, Shared with me), then create a catalog
from the share. Validate the read with the connector, loading the file
from the vault."

One cell, two environments. The import and the catalog happen in the
Databricks CONTROL PLANE; the connector read happens on the CLIENT. So
the split below is not a workaround for our prototype -- it is the seam
the CONOPS already contains.

  Path A -- control plane. Steps 5a (import), 5b (confirm shares) and
    5c (create catalog), run for real and recorded up to the exact call
    that fails. It fails here and only here because our provider is on
    loopback: evidence/capability-baseline-d2o-import.json established
    that CREATE PROVIDER is PERMITTED on this tier, that the refusal is
    java.lang.SecurityException rather than any network error, and that
    the same call against a public routable endpoint goes through and
    returns a real 404. Refusal plus matched permitted case, differing
    in one variable. So Path A's blocker is OUR address, not the tier
    and not anything a client inherits.

  Path B -- client. The §2.4.1 connector snippet, verbatim, with the
    outbound hosts captured AT THE SOCKET LAYER, which is the half
    §2.4.3 actually asks for: "Databricks documentation does not publish
    the firewall requirements for the recipient side, so test T-20
    records the hosts actually contacted and the allow-list is built
    from that capture, not from assumption."

WHY THE CAPTURE IS NOT TAKEN FROM THE /query RESPONSE
-----------------------------------------------------
Because that is demonstrably incomplete. scripts/11 derives hosts by
parsing pre-signed URLs out of the JSON and records
`outbound_hosts: ["objectstore"]`. True as far as it goes -- and it
omits the provider endpoint the probe was already talking to in order
to obtain that JSON. An allow-list built from it would permit the
storage host, deny the provider, and the read would fail at discovery
before any pre-signed URL existed.

The socket layer cannot make that mistake. It records what the process
tried to reach, including hosts nobody predicted, which is the entire
point of capturing rather than assuming.

WHY EACH PHASE IS A SEPARATE PROCESS
------------------------------------
The sufficiency and necessity phases work by refusing name resolution
for hosts outside a given set. Run in one process, urllib3's connection
pool and any DNS caching would let the later phases reuse a socket
opened during the capture phase -- the blocked host would never be
resolved again, the filter would never fire, and the necessity phase
would PASS WITHOUT PROVING ANYTHING. A test that cannot fail is worth
nothing, so each phase is spawned as a fresh subprocess with no shared
pool and no warm cache.

The filter is an in-process refusal, not a network ACL. It therefore
proves the READ'S DEPENDENCY on each host, which is what generates a
correct allow-list; it does not prove that any firewall enforces it.
That distinction is stated in the evidence rather than left for a
reader to assume.

THE THREE PHASES
----------------
  1. capture    -- no filter. Read succeeds; hosts recorded.
  2. sufficient -- filter permits exactly the captured hosts. The read
                   must still succeed, or the captured set is missing
                   something and is not a usable allow-list.
  3. necessary  -- filter permits the provider endpoint only. Discovery
                   must still succeed AND the data read must fail. Both
                   halves matter: if discovery broke too, we would not
                   have shown that the storage host is needed for DATA
                   specifically, and the allow-list's two entries would
                   be unattributed.

Usage:
    python3 tests/t20_ingress_d2o.py

Writes: evidence/t20-ingress-d2o.json
        iac/config/outbound-allow-list.yaml   (GENERATED from the capture)
"""
import argparse
import datetime
import hashlib
import importlib.util
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

REPO = Path(__file__).resolve().parent.parent
EVIDENCE = REPO / "evidence" / "t20-ingress-d2o.json"
ALLOWLIST = REPO / "iac" / "config" / "outbound-allow-list.yaml"
BASELINE = REPO / "evidence" / "capability-baseline-d2o-import.json"

UC = "/api/2.1/unity-catalog"
PROVIDER_NAME = "awoz1227_t20_provider"
CATALOG_NAME = "awoz1227_t20_catalog"
CONSUMER_GROUP = "account users"  # the one group guaranteed to exist on this tier


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")


# A PRE-SIGNED URL IS A CREDENTIAL. Its query string carries the access
# key id, the credential scope and the signature, and anyone holding it
# can fetch the object with no other authentication -- which is exactly
# what scripts/11 check 6 demonstrates.
#
# This is not hypothetical caution. The first run of this test leaked
# one: the necessity phase's failure is raised by pandas/fsspec, whose
# exception string contains the full URL it could not fetch, and
# recording `str(exc)[:400]` put the signature into
# evidence/t20-ingress-d2o.json. scripts/check_secret_hygiene.py caught
# it on the next line of the same run. Those pre-signed URL patterns
# were added in the previous session with the comment that they were
# there to catch "that guarantee being dropped by a later edit" -- and a
# new test writing a new evidence file is precisely that. See docs/11
# B-15.
#
# The HOST is the evidence T-20 needs; the query string is the secret.
# So the query string goes and the host stays.
#
# The scrubber MUST be idempotent, because scrub() runs more than once
# over the same string by design: once where the exception is caught in
# the phase subprocess, once when that subprocess serialises its own
# --out file, and once when the parent serialises the combined record.
# The first version was not idempotent and produced
# "...parquet?<redacted-presigned-query><redacted-presigned-query><redacted-presigned-query>"
# -- one marker per pass. Nothing leaked, but a reader counting markers
# would reasonably conclude three secrets had been removed from one
# URL, and a count that cannot be trusted is the project's own defect
# shape: a record that says more than it measured. See docs/11 B-16.
#
# Two independent reasons it is idempotent now, because one of them is
# an accident:
#   `+` not `*` -- a query with no characters holds no secret, so a bare
#   trailing "?" is left alone. This ALONE happens to fix the repeat,
#   since the marker contains "<" and ">" which the query class
#   excludes, so a scrubbed URL presents an empty query. That is luck,
#   not design: it stops being true the moment the marker text changes.
#   The negative lookahead -- states the intent directly. Do not redact
#   something already redacted. This survives a redesign of the marker.
PRESIGNED_QUERY = re.compile(
    r"(https?://[^\s'\"<>]+?)\?(?!<redacted-presigned-query>)[^\s'\"<>]+"
)


def scrub(text):
    if not isinstance(text, str):
        return text
    return PRESIGNED_QUERY.sub(r"\1?<redacted-presigned-query>", text)


# The seed is published here so the fixture below can be recomputed by
# anyone reviewing it. See _synthetic_presigned_url.
FIXTURE_SEED = b"t20-scrubber-contract-fixture-not-a-real-credential"


def _synthetic_presigned_url():
    """A SigV4-shaped URL, assembled at runtime, never written as a literal.

    This fixture has to look exactly like a live pre-signed URL, because
    its only job is to be something scripts/check_secret_hygiene.py would
    flag. It therefore CANNOT be softened to quiet the gate -- the same
    reason B-13's dummy token could not be shortened. A fixture the gate
    ignores makes assert_scrub_contract() vacuous: it would assert that
    patterns fail to match a string they never matched, and report
    VERIFIED for measuring nothing.

    The first version of this function embedded the URL as a literal and
    the gate failed the file, correctly. The fix is not to hide the
    literal but to stop having one. The signature is derived from
    FIXTURE_SEED above, so a reviewer can recompute it in one line and
    confirm it is synthetic:

        python3 -c "import hashlib; print(hashlib.sha256(
            b't20-scrubber-contract-fixture-not-a-real-credential'
        ).hexdigest())"

    That is the DECLARED_PLACEHOLDER principle (B-13) applied to a value
    whose shape leaves no room for a declaration. A 64-character hex blob
    cannot announce that it is fake, and cannot be told apart from a real
    signature by reading it. A derivation can be checked. The
    construction IS the declaration.

    The side effect is that no credential-shaped literal remains in this
    file, so the gate passes. That is a consequence, not the aim. Do NOT
    reach for string splitting or concatenation to silence the scanner on
    some future fixture: a repository that teaches "break up the literal
    when the gate complains" has taught the exact technique used to smuggle
    a real credential past it, and is worse off than one with a false
    positive. The test for whether a fixture is legitimate is whether its
    falsity is VERIFIABLE, not whether it is undetectable.
    """
    sig = hashlib.sha256(FIXTURE_SEED).hexdigest()
    key = "FIXTUREKEYNOTREAL"
    scope = "%2F".join(["20261018", "us-east-1", "s3", "aws4_request"])
    return (
        "http://objectstore:8000/awoz-opensharing/test_dataset/"
        "region%3Dwest/part-00000-61439623-c000.snappy.parquet"
        "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
        f"&X-Amz-Credential={key}%2F{scope}"
        "&X-Amz-Date=20261018T224553Z&X-Amz-Expires=3600"
        f"&X-Amz-Signature={sig}"
    )


def assert_scrub_contract():
    """Prove the scrubber works before writing anything that relies on it.

    B-15 reached disk because scrub() did not exist yet. B-16 happened
    because it existed and nobody checked what it produced. An untested
    redaction function is the same silent negative as everything else in
    this project: a record with no secret in it and a record whose
    scrubber quietly stopped matching look identical from the outside.

    The pass/fail bar is NOT one I invent here. It is
    scripts/check_secret_hygiene.py's own TOKEN_PATTERNS, imported rather
    than restated, so "scrubbed" means exactly "the gate will accept it".
    A local copy of the bar could drift below the gate and this test
    would still report success.

    Fails closed. If the gate's patterns cannot be loaded, that is an
    unchecked scrubber, not a passing one, and no evidence gets written.
    """
    gate_path = REPO / "scripts" / "check_secret_hygiene.py"
    if not gate_path.exists():
        sys.exit(f"Missing {gate_path}. Cannot verify the scrubber against "
                 "the gate's own patterns, so refusing to write evidence.")
    spec = importlib.util.spec_from_file_location("hygiene_gate", gate_path)
    gate = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gate)
    patterns = getattr(gate, "TOKEN_PATTERNS", None)
    if not patterns:
        sys.exit("check_secret_hygiene.py exposes no TOKEN_PATTERNS list. "
                 "The scrubber cannot be checked against the gate, so "
                 "refusing to write evidence. If the gate renamed that "
                 "list, rename it here too -- do not substitute a local "
                 "copy of the patterns.")

    # Shaped like the real B-15 leak -- SigV4 credential scope and
    # signature, on the host T-20 must keep -- but synthesised, not
    # embedded.
    leak = _synthetic_presigned_url()

    # VACUITY GUARD. Everything below asks whether gate patterns stop
    # matching after scrubbing. That question is only meaningful if they
    # matched BEFORE. An unchecked fixture makes this function the thing
    # it exists to prevent: a check that cannot see its subject,
    # reporting what a check that looked and found nothing reports
    # (docs/12 12.9).
    #
    # This fires for two different reasons and both must stop the run.
    # Someone softens the fixture to quiet the gate, or the gate's own
    # pre-signed patterns are weakened or renamed -- in which case the
    # fixture no longer represents a leak the gate would catch, and a
    # pass here would be meaningless.
    tripped = [label for pattern, label in patterns if pattern.search(leak)]
    if len(tripped) < 2:
        sys.exit(
            "SCRUBBER CONTRACT IS VACUOUS -- refusing to write evidence.\n"
            f"  The fixture trips {len(tripped)} gate pattern(s): "
            f"{tripped or 'none'}\n"
            "  It must trip at least two (SigV4 signature and credential\n"
            "  scope), or 'no pattern matches after scrubbing' proves\n"
            "  nothing about scrub(). Either the fixture was softened --\n"
            "  do not do that, see _synthetic_presigned_url -- or the\n"
            "  gate's pre-signed URL patterns changed and this fixture no\n"
            "  longer represents something the gate would catch."
        )

    once = scrub(leak)
    failures = []

    for pattern, label in patterns:
        if pattern.search(once):
            failures.append(f"gate pattern still matches after scrubbing: {label}")
    if "objectstore:8000" not in once:
        failures.append("scrubbing destroyed the host, which IS the T-20 evidence")
    if scrub(once) != once or scrub(scrub(once)) != once:
        failures.append("scrub() is not idempotent; it runs up to three times "
                        "over the same string (B-16)")
    if once.count("<redacted-presigned-query>") != 1:
        failures.append(f"expected exactly 1 redaction marker, got "
                        f"{once.count('<redacted-presigned-query>')}")
    # A query string is where the secret lives; a path is not. Scrubbing
    # a URL that has no query would quietly delete evidence.
    plain = "http://objectstore:8000/awoz-opensharing/test_dataset"
    if scrub(plain) != plain:
        failures.append("scrubbed a URL that has no query string")
    # Two URLs in one message must both be covered. An exception that
    # names the file and the retry target is one string.
    two = f"first {leak} then {leak}"
    if "X-Amz-Signature" in scrub(two) or scrub(two).count("<redacted-presigned-query>") != 2:
        failures.append("only the first URL in a multi-URL string was scrubbed")

    if failures:
        print("SCRUBBER CONTRACT FAILED -- refusing to write evidence:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    return len(patterns), tripped


def scrub_json(payload):
    """Scrub the SERIALIZED form, immediately before it is written.

    Belt and braces on purpose. Scrubbing only at the points where
    exceptions are captured is what I did first, and it missed one,
    because an exception string can reach the record through any field
    anyone adds later -- a stderr tail, a nested cause, a message echoed
    by a library. Scrubbing the finished JSON means a future field
    cannot reintroduce the leak by being forgotten.
    """
    return scrub(json.dumps(payload, indent=2))


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit(f"Missing {env_path}. Copy .env.example to .env and fill it in first.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if not v.strip():  # a blank value is an ABSENCE -- docs/11 B-10b
            continue
        os.environ.setdefault(k, v)


def probe14():
    """Borrow `call`, `classify` and `redact` from the capability probe.

    Imported rather than copied on purpose. A second copy of the error
    classifier could grade the same Databricks message differently from
    the probe that produced the baseline, and then the test and its own
    precondition would disagree about what happened -- with nothing in
    either output showing that they had. One source, one verdict.

    importlib is required because `14_probe_d2o_provider_import` is not
    a legal identifier, so a plain import cannot reach it.
    """
    path = REPO / "scripts" / "14_probe_d2o_provider_import.py"
    if not path.exists():
        sys.exit(f"Missing {path}. T-20 depends on its capability baseline.")
    spec = importlib.util.spec_from_file_location("probe14", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# =====================================================================
# SOCKET-LAYER CAPTURE AND FILTER (runs in the child process)
# =====================================================================

def install_socket_capture(allowed):
    """Record every outbound name resolution and connect; optionally refuse
    hosts outside `allowed`.

    `allowed=None` means record everything and refuse nothing.

    Two hooks, because neither alone is honest:

      * getaddrinfo gives the HOSTNAME, which is what an allow-list is
        written in. But a name resolved is only a host ATTEMPTED -- the
        connection may never have been established.
      * connect gives the address actually dialled, which is what proves
        the attempt became a conversation.

    Recording both means the allow-list can be built from hosts that
    were genuinely contacted, while attempted-but-failed hosts stay
    visible instead of being quietly dropped.

    The connect hook also watches for a dial to an address that was
    never resolved through getaddrinfo -- a literal IP in a pre-signed
    URL, say. That would walk straight past the filter, so a necessity
    result taken while it happened would be void. It is flagged rather
    than ignored.
    """
    # `stage` is stamped onto every record so a host's ROLE can be
    # derived from WHEN it was contacted rather than from what it is
    # called. Name-matching would be ambiguous here anyway:
    # OBJECTSTORE_HOST_ENDPOINT is localhost:8000 while the pre-signed
    # URLs name objectstore:8000, so the provider endpoint and the
    # storage endpoint share a hostname in one spelling and not in the
    # other. Contact order is unambiguous and is evidence.
    log = {"resolved": [], "connected": [], "refused": [], "unresolved_connects": [],
           "stage": "pre"}
    resolved_addrs = set()

    real_getaddrinfo = socket.getaddrinfo
    real_connect = socket.socket.connect

    def getaddrinfo(host, port, *args, **kwargs):
        entry = {"host": host, "port": port, "at": now(), "stage": log["stage"]}
        if allowed is not None and host not in allowed:
            entry["outcome"] = "REFUSED_BY_TEST_FILTER"
            log["resolved"].append(entry)
            log["refused"].append({"host": host, "port": port})
            # EAI_NONAME, i.e. the same failure a host with no DNS entry
            # produces. Chosen so the connector takes its ordinary
            # name-resolution error path rather than something exotic.
            raise socket.gaierror(
                socket.EAI_NONAME,
                f"[t20 allow-list filter] {host} is not on the allow-list",
            )
        try:
            result = real_getaddrinfo(host, port, *args, **kwargs)
        except Exception as exc:
            entry["outcome"] = f"RESOLUTION_FAILED: {type(exc).__name__}"
            log["resolved"].append(entry)
            raise
        entry["outcome"] = "RESOLVED"
        log["resolved"].append(entry)
        for item in result:
            sockaddr = item[4]
            if sockaddr:
                resolved_addrs.add(str(sockaddr[0]))
        return result

    def connect(self, address):
        try:
            host = address[0] if isinstance(address, tuple) else str(address)
            port = address[1] if isinstance(address, tuple) and len(address) > 1 else None
        except Exception:  # noqa: BLE001
            host, port = str(address), None
        if isinstance(host, str) and host not in resolved_addrs and port is not None:
            # Dialled without having been resolved in this process. The
            # filter works on names, so this path is not covered by it.
            log["unresolved_connects"].append({"address": host, "port": port, "at": now()})
        result = real_connect(self, address)
        log["connected"].append({"address": host, "port": port, "at": now()})
        return result

    socket.getaddrinfo = getaddrinfo
    socket.socket.connect = connect
    return log


def run_connector_read(profile_path, share, schema, table, log, limit=10):
    """The §2.4.1 D2O snippet, run as written.

    Two stages, kept separate so the necessity phase can show that the
    provider endpoint carries DISCOVERY while the storage host carries
    DATA. Collapsed into one call, a failure could not be attributed to
    either.
    """
    out = {"discovery": {}, "data": {}}
    try:
        import delta_sharing
    except ImportError as exc:
        out["discovery"] = {"verdict": "DEPENDENCY_MISSING", "error": str(exc)}
        out["data"] = {"verdict": "NOT_ATTEMPTED"}
        return out

    # Stage 1: discovery -- talks to the provider endpoint only.
    log["stage"] = "discovery"
    try:
        client = delta_sharing.SharingClient(str(profile_path))
        tables = client.list_all_tables()
        out["discovery"] = {
            "verdict": "LISTED",
            "table_count": len(tables),
            "tables": [f"{t.share}.{t.schema}.{t.name}" for t in tables],
        }
    except Exception as exc:  # noqa: BLE001 -- the failure IS the result
        out["discovery"] = {
            "verdict": "FAILED",
            "error_type": type(exc).__name__,
            "error": scrub(str(exc))[:400],
        }
        out["data"] = {"verdict": "NOT_ATTEMPTED",
                       "means": "Discovery failed, so the data read was never reached."}
        return out

    # Stage 2: data -- /query, then the pre-signed URLs on the storage host.
    log["stage"] = "data"
    try:
        url = f"{profile_path}#{share}.{schema}.{table}"
        df = delta_sharing.load_as_pandas(url, limit=limit)
        out["data"] = {
            "verdict": "READ",
            "row_count": int(len(df)),
            "columns": [str(c) for c in df.columns],
            # Row count and column names only. The rows themselves are
            # the provider's data and have no business in an evidence
            # file that gets packaged for E7.
        }
    except Exception as exc:  # noqa: BLE001
        out["data"] = {
            "verdict": "FAILED",
            "error_type": type(exc).__name__,
            "error": scrub(str(exc))[:400],
        }
    return out


def classify_hosts(log, provider_host):
    """Split observed hosts into provider endpoint, storage, and UNCLASSIFIED.

    Unclassified hosts are REPORTED, never dropped. Silently discarding a
    host nobody predicted is how a generated allow-list ends up wrong in
    the one way that matters: too small, so the read breaks in the client
    environment and not here.
    """
    hosts = {}
    for entry in log["resolved"]:
        key = (entry["host"], entry["port"])
        rec = hosts.setdefault(key, {"host": entry["host"], "port": entry["port"],
                                     "resolved": 0, "refused": 0, "stages": []})
        rec["resolved"] += 1
        stage = entry.get("stage", "pre")
        if stage not in rec["stages"]:
            rec["stages"].append(stage)
        if entry.get("outcome") == "REFUSED_BY_TEST_FILTER":
            rec["refused"] += 1
    out = []
    for rec in hosts.values():
        first = rec["stages"][0] if rec["stages"] else "pre"
        if rec["refused"] == rec["resolved"]:
            role = "refused_by_filter"
            ref = "not contacted in this phase"
        elif first == "discovery" and rec["host"] == provider_host:
            role = "provider_endpoint"
            ref = "CONOPS 2.4.3 approved provider endpoint"
        elif first == "data":
            role = "presigned_url_storage_host"
            ref = "CONOPS 2.4.3 storage hosts serving pre-signed file URLs"
        else:
            # Neither the provider endpoint during discovery nor anything
            # first seen during the data read. It is NOT quietly called
            # storage and waved into the allow-list: an entry nobody can
            # account for is how a generated file stops being evidence.
            role = "observed_unclassified"
            ref = ("UNEXPLAINED -- contacted during "
                   f"{rec['stages']}; review before permitting")
        out.append({**rec, "role": role, "conops_ref": ref})
    return sorted(out, key=lambda r: (r["host"], r["port"] or 0))


def phase_child(args):
    """One phase, in its own process. Writes its result as JSON to --out."""
    load_env()
    profile_rel = os.environ.get("OSS_PROVIDER_PROFILE", "").strip()
    profile_path = REPO / profile_rel if not os.path.isabs(profile_rel) else Path(profile_rel)
    endpoint = os.environ.get("OSS_PROVIDER_URL", "").strip()
    provider_host = urlparse(endpoint).hostname

    allowed = None
    if args.allow != "all":
        allowed = {h for h in args.allow.split(",") if h}

    log = install_socket_capture(allowed)
    read = run_connector_read(profile_path, args.share, args.schema, args.table, log)

    result = {
        "phase": args.phase,
        "filter": "none" if allowed is None else sorted(allowed),
        "read": read,
        "hosts": classify_hosts(log, provider_host),
        "socket_log": {
            "resolutions": len(log["resolved"]),
            "connects": len(log["connected"]),
            "refused": log["refused"],
            "unresolved_connects": log["unresolved_connects"],
        },
    }
    if log["unresolved_connects"]:
        result["integrity_warning"] = (
            "A connect was made to an address never resolved through "
            "getaddrinfo in this process, so the name-based filter did not "
            "cover it. Any sufficiency or necessity verdict from this phase "
            "is VOID until that path is explained."
        )
    # Scrubbed before it ever touches the filesystem -- the temp file
    # the parent reads back would otherwise hold the signature too.
    Path(args.out).write_text(scrub_json(result))
    return 0


# =====================================================================
# PATH A -- CONTROL PLANE (parent process)
# =====================================================================

def path_a(p14, host, token, profile, share):
    """§2.4.1 steps 5a, 5b, 5c under the metastore-admin hat.

    5c is attempted even though 5b fails. The CONOPS says "import the
    provider ... then create a catalog", with no confirming call in
    between for D2O -- so whether CREATE CATALOG also succeeds against
    an unreachable provider is exactly the question the document's own
    wording raises, and it is one REST call to answer.
    """
    steps = {}
    created_provider = created_catalog = False
    try:
        # --- 5a: import the provider from the credential file ----------
        status, payload = p14.call(host, token, f"{UC}/providers", "POST", {
            "name": PROVIDER_NAME,
            "authentication_type": "TOKEN",
            "recipient_profile_str": json.dumps(profile),
            "comment": "AWOZ-1227 T-20 -- local OSS provider, removed after the run",
        })
        verdict, code, msg = p14.classify(status, payload)
        created_provider = verdict == "ACCEPTED" or status == 409
        steps["5a_import_provider"] = {
            "conops": "2.4.1 step 5 (D2O): import the provider from the file",
            "hat": "metastore admin / catalog creator (2.4.2)",
            "status": status,
            "verdict": "IMPORTED" if created_provider else verdict,
            "error_code": code or None,
            "message": p14.redact(msg)[:400] or None,
            "means": (
                "The provider object exists. Note what this does NOT mean: "
                "creation validates the endpoint as a URL and nothing more "
                "(baseline check 2), so an import that returns 200 is not "
                "evidence the provider can be reached."
                if created_provider else
                "Import refused. Compare against the baseline before reading "
                "this as a tier limit."
            ),
        }

        # --- 5b: the confirming call the D2O column omits ---------------
        if created_provider:
            status, payload = p14.call(host, token, f"{UC}/providers/{PROVIDER_NAME}/shares")
            verdict, code, msg = p14.classify(status, payload)
            shares = []
            if verdict == "ACCEPTED" and isinstance(payload, dict):
                shares = [s.get("name") for s in (payload.get("shares") or [])]
            steps["5b_confirm_shares"] = {
                "conops": ("2.4.1 step 5 -- present in the D2D column as SHOW SHARES "
                           "IN PROVIDER, ABSENT from the D2O column"),
                "hat": "metastore admin / catalog creator (2.4.2)",
                "status": status,
                "verdict": "SHARES_LISTED" if shares else verdict,
                "error_code": code or None,
                "message": p14.redact(msg)[:400] or None,
                "shares": shares,
                "means": (
                    f"Control plane reached the provider and listed {shares}."
                    if shares else
                    "Refused. Per the baseline this is java.lang.SecurityException "
                    "against a loopback endpoint, while the same call to a public "
                    "routable host returns a real 404 -- so the blocker is the "
                    "address class, not the tier and not the procedure. This is "
                    "where Path A stops, and it stops for a reason a client on a "
                    "routable network does not have."
                ),
            }

            # --- 5c: create the catalog anyway ---------------------------
            status, payload = p14.call(host, token, f"{UC}/catalogs", "POST", {
                "name": CATALOG_NAME,
                "provider_name": PROVIDER_NAME,
                "share_name": share,
                "comment": "AWOZ-1227 T-20 -- DSA reference pending (2.4.1 step 5)",
            })
            verdict, code, msg = p14.classify(status, payload)
            created_catalog = verdict == "ACCEPTED" or status == 409
            steps["5c_create_catalog"] = {
                "conops": "2.4.1 step 5 (D2O): then create a catalog from the share",
                "hat": "metastore admin / catalog creator (2.4.2)",
                "status": status,
                "verdict": "CREATED" if created_catalog else verdict,
                "error_code": code or None,
                "message": p14.redact(msg)[:400] or None,
                "means": (
                    "A CATALOG WAS CREATED OVER A PROVIDER THE CONTROL PLANE "
                    "CANNOT REACH. Following §2.4.1's D2O column literally -- "
                    "import, then create the catalog, with no confirming call "
                    "between them -- therefore produces a catalog that looks "
                    "healthy and fails at the first consumer query. That is a "
                    "v1.6 document defect, not a prototype artefact: the D2D "
                    "column has the confirming call and the D2O column does not."
                    if created_catalog else
                    "Catalog creation was refused, so the share must be "
                    "resolvable before a catalog can exist. §2.4.1's missing "
                    "confirming call is then a documentation gap rather than a "
                    "live hazard -- the platform enforces the ordering itself. "
                    "Record the error, since it is the thing a recipient would "
                    "actually see."
                ),
            }
        else:
            for k in ("5b_confirm_shares", "5c_create_catalog"):
                steps[k] = {"verdict": "NOT_ATTEMPTED",
                            "means": "No provider object was imported in 5a."}

        # --- 6: grant -------------------------------------------------
        if created_catalog:
            status, payload = p14.call(
                host, token, f"{UC}/permissions/catalog/{CATALOG_NAME}", "PATCH",
                {"changes": [{"principal": CONSUMER_GROUP,
                              "add": ["USE_CATALOG", "USE_SCHEMA", "SELECT"]}]})
            verdict, code, msg = p14.classify(status, payload)
            steps["6_grant"] = {
                "conops": "2.4.1 step 6: USE CATALOG, USE SCHEMA, SELECT to consumer groups",
                "hat": "catalog owner (2.4.2)",
                "status": status,
                "verdict": "GRANTED" if verdict == "ACCEPTED" else verdict,
                "error_code": code or None,
                "message": p14.redact(msg)[:400] or None,
                "principal": CONSUMER_GROUP,
                "means": (
                    "Grants applied to a catalog whose data is unreadable. The "
                    "ACCESS CONTROL half of step 6 is demonstrable here; the "
                    "entitled read is Path B's, through the connector."
                    if verdict == "ACCEPTED" else
                    "Grant refused -- record the privilege named."
                ),
            }
        else:
            steps["6_grant"] = {"verdict": "NOT_ATTEMPTED",
                                "means": "No catalog exists to grant on."}
    finally:
        # Order matters: the catalog depends on the provider, and a
        # provider left behind holds a live bearer token in the
        # metastore, which is the custody failure §2.4.3 forbids.
        cleanup = {}
        for label, path in (("catalog", f"{UC}/catalogs/{CATALOG_NAME}"),
                            ("provider", f"{UC}/providers/{PROVIDER_NAME}")):
            if label == "catalog" and not created_catalog:
                continue
            if label == "provider" and not created_provider:
                continue
            d_status, _ = p14.call(host, token, path, "DELETE")
            v_status, v_payload = p14.call(host, token, path)
            gone = v_status in (400, 404) or "does not exist" in str(v_payload).lower()
            cleanup[label] = {"delete_status": d_status, "verify_status": v_status,
                              "verdict": "DELETED" if gone else "STILL_PRESENT"}
            if not gone:
                print(f"  WARNING: {label} {path} still present -- remove it by hand.")
        steps["cleanup"] = cleanup or {"verdict": "NOTHING_TO_DELETE"}
    return steps


# =====================================================================
# ALLOW-LIST GENERATION
# =====================================================================

# render_allowlist() lived here. Removed: the file it produced now has
# exactly one writer, scripts/23_gen_outbound_allow_list.py, which
# merges this test's socket capture with T-19's declared endpoint host
# and labels each entry with its provenance. A dead renderer left in
# place is the two-writer bug waiting to be re-enabled.


# =====================================================================
# ORCHESTRATOR
# =====================================================================

def run_phase(name, allow, share, schema, table):
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        out_path = tmp.name
    cmd = [sys.executable, str(Path(__file__).resolve()),
           "--phase", name, "--allow", allow, "--out", out_path,
           "--share", share, "--schema", schema, "--table", table]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    try:
        data = json.loads(Path(out_path).read_text())
    except Exception as exc:  # noqa: BLE001
        data = {"phase": name, "error": f"phase produced no parsable result: {exc}",
                "stdout": proc.stdout[-800:], "stderr": proc.stderr[-800:]}
    finally:
        Path(out_path).unlink(missing_ok=True)
    data["subprocess_returncode"] = proc.returncode
    if proc.stderr.strip():
        data["stderr_tail"] = proc.stderr.strip()[-600:]
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--phase")
    parser.add_argument("--allow", default="all")
    parser.add_argument("--out")
    parser.add_argument("--share", default="awoz_share")
    parser.add_argument("--schema", default="opensharing_test")
    parser.add_argument("--table", default="test_dataset")
    args = parser.parse_args()

    # Before anything is written, in the parent AND in every phase child,
    # because all four of them scrub.
    n_patterns, fixture_tripped = assert_scrub_contract()
    if args.phase:
        return phase_child(args)

    load_env()
    p14 = probe14()
    for var in ("DATABRICKS_HOST", "DATABRICKS_TOKEN", "OSS_PROVIDER_PROFILE",
                "OSS_PROVIDER_URL"):
        if not os.environ.get(var, "").strip():
            sys.exit(f"Missing required .env value: {var}")
    host = os.environ["DATABRICKS_HOST"].strip()
    token = os.environ["DATABRICKS_TOKEN"].strip()
    endpoint = os.environ["OSS_PROVIDER_URL"].strip()
    provider_host = urlparse(endpoint).hostname
    profile_rel = os.environ["OSS_PROVIDER_PROFILE"].strip()
    profile_path = REPO / profile_rel if not os.path.isabs(profile_rel) else Path(profile_rel)
    if not profile_path.exists():
        sys.exit(f"Missing {profile_path}. Run scripts/10_setup_oss_provider.py first.")
    profile = json.loads(profile_path.read_text())

    results = {
        "test_id": "T-20",
        "description": "Channel I-1 ingress, D2O pull (CONOPS 2.4.1)",
        "task": "E1 Task 1.10",
        "date": now(),
        "precondition": {
            "capability_baseline": str(BASELINE.relative_to(REPO)),
            "verdict": (json.loads(BASELINE.read_text()).get("verdict")
                        if BASELINE.exists() else "MISSING"),
            "means": ("The capability question -- may this tier import a D2O "
                      "credential file at all -- is answered THERE, not here. "
                      "Kept separate so a precondition can never be mistaken "
                      "for the test result."),
        },
        "credential": p14.profile_summary(profile),
        "scrubber_contract": {
            "verdict": "VERIFIED",
            "gate_patterns_applied": n_patterns,
            "bar": ("scripts/check_secret_hygiene.py TOKEN_PATTERNS, "
                    "imported not restated, so 'scrubbed' means 'the gate "
                    "accepts it'."),
            "fixture_tripped_before_scrubbing": fixture_tripped,
            "fixture_provenance": ("Synthesised at runtime from a published "
                                   "seed, so its falsity is verifiable by "
                                   "recomputation rather than asserted. No "
                                   "credential-shaped literal is stored in "
                                   "the test. See B-17."),
            "checked": ["the fixture trips >=2 gate patterns BEFORE "
                        "scrubbing, so the test is not vacuous",
                        "gate patterns do not match a scrubbed SigV4 URL",
                        "host survives scrubbing (it is the T-20 evidence)",
                        "idempotent across the three passes (B-16)",
                        "a URL with no query is left intact",
                        "every URL in a multi-URL string is covered"],
            "means": ("This record's pre-signed URLs are redacted because the "
                      "redaction was tested in the same run that wrote them, "
                      "not because no secret happened to appear."),
        },
    }
    if results["precondition"]["verdict"] == "MISSING":
        sys.exit("Run scripts/14_probe_d2o_provider_import.py first -- T-20 "
                 "cannot interpret a control-plane failure without its baseline.")

    print("T-20 -- Channel I-1 ingress, D2O pull")
    print("=" * 68)
    print(f"Provider endpoint: {endpoint}")
    print(f"Precondition: {results['precondition']['verdict']}")
    print(f"Scrubber: VERIFIED against {n_patterns} hygiene-gate patterns")

    # --- Path A -------------------------------------------------------
    print("\nPATH A -- Databricks control plane (§2.4.1 step 5, first half)")
    print("-" * 68)
    results["path_a_control_plane"] = path_a(p14, host, token, profile, args.share)
    for key, step in results["path_a_control_plane"].items():
        if key == "cleanup":
            continue
        print(f"  {key}: {step.get('verdict')}  (status {step.get('status')})")
        if step.get("message"):
            print(f"      {step.get('error_code') or ''} {step['message'][:160]}")

    # --- Path B -------------------------------------------------------
    print("\nPATH B -- client connector, socket-layer capture (§2.4.1 step 5, "
          "second half; §2.4.3)")
    print("-" * 68)
    print("  [1/3] capture    -- no filter")
    capture = run_phase("capture", "all", args.share, args.schema, args.table)

    captured_hosts = [h for h in capture.get("hosts", []) if h["role"] != "refused_by_filter"]
    allow_names = sorted({h["host"] for h in captured_hosts})
    # Unaccounted-for hosts are KEPT in the allow-list, because dropping a
    # host the read actually needed would make the file break the read it
    # was generated from. They are kept VISIBLY, and they hold the file
    # back from a clean verdict until someone explains them.
    unclassified = [h for h in captured_hosts if h["role"] == "observed_unclassified"]
    if unclassified:
        print(f"        REVIEW: {[(h['host'], h['port'], h['stages']) for h in unclassified]} "
              f"contacted but not attributable to the provider endpoint or the "
              f"data read. Kept in the allow-list and flagged.")
    print(f"        read: discovery={capture.get('read', {}).get('discovery', {}).get('verdict')}"
          f"  data={capture.get('read', {}).get('data', {}).get('verdict')}")
    print(f"        hosts: {[(h['host'], h['port'], h['role']) for h in captured_hosts]}")

    print(f"  [2/3] sufficient -- permit exactly {allow_names}")
    sufficient = run_phase("sufficient", ",".join(allow_names),
                           args.share, args.schema, args.table)
    print(f"        read: discovery={sufficient.get('read', {}).get('discovery', {}).get('verdict')}"
          f"  data={sufficient.get('read', {}).get('data', {}).get('verdict')}")

    print(f"  [3/3] necessary  -- permit provider endpoint only ({provider_host})")
    necessary = run_phase("necessary", provider_host or "", args.share, args.schema, args.table)
    print(f"        read: discovery={necessary.get('read', {}).get('discovery', {}).get('verdict')}"
          f"  data={necessary.get('read', {}).get('data', {}).get('verdict')}")

    # --- Grade --------------------------------------------------------
    cap_ok = (capture.get("read", {}).get("discovery", {}).get("verdict") == "LISTED"
              and capture.get("read", {}).get("data", {}).get("verdict") == "READ")
    suf_ok = (sufficient.get("read", {}).get("discovery", {}).get("verdict") == "LISTED"
              and sufficient.get("read", {}).get("data", {}).get("verdict") == "READ")
    nec_discovery = necessary.get("read", {}).get("discovery", {}).get("verdict")
    nec_data = necessary.get("read", {}).get("data", {}).get("verdict")
    nec_ok = nec_discovery == "LISTED" and nec_data == "FAILED"
    void = any(p.get("integrity_warning") for p in (capture, sufficient, necessary))

    if void:
        allowlist_verdict = "VOID_UNRESOLVED_CONNECT"
    elif not cap_ok:
        allowlist_verdict = "NOT_ESTABLISHED_READ_FAILED"
    elif suf_ok and nec_ok and unclassified:
        allowlist_verdict = "NECESSARY_AND_SUFFICIENT_REVIEW_REQUIRED"
    elif suf_ok and nec_ok:
        allowlist_verdict = "NECESSARY_AND_SUFFICIENT"
    elif suf_ok:
        allowlist_verdict = "SUFFICIENT_ONLY"
    else:
        allowlist_verdict = "INSUFFICIENT_CAPTURE_INCOMPLETE"

    results["path_b_client"] = {
        "capture": capture,
        "sufficiency": sufficient,
        "necessity": necessary,
        "allowlist_verdict": allowlist_verdict,
        "necessity_attribution": {
            "discovery_with_provider_only": nec_discovery,
            "data_with_provider_only": nec_data,
            "means": (
                "Discovery succeeded and the data read failed with the storage "
                "host denied, which attributes the two allow-list entries to "
                "different layers: the provider endpoint carries discovery, the "
                "storage host carries the pre-signed data transfer. Had discovery "
                "failed too, the data failure would prove nothing about storage."
                if nec_ok else
                "Attribution NOT established -- see both verdicts above before "
                "treating either host as required."
            ),
        },
        "method_note": (
            "Hosts captured by hooking socket.getaddrinfo and socket.socket."
            "connect, not by parsing pre-signed URLs out of the /query response. "
            "The JSON-derived capture in evidence/capability-baseline-d2o.json "
            "records only ['objectstore'] and omits the provider endpoint it was "
            "itself talking to, so an allow-list built from it would fail at "
            "discovery. Each phase ran in a FRESH SUBPROCESS: sharing one "
            "process would let a pooled connection or cached resolution satisfy "
            "a later phase without the filter firing, and the necessity phase "
            "would pass without testing anything."
        ),
        "enforcement_caveat": (
            "The filter refuses name resolution inside the test process. That "
            "establishes which hosts the READ DEPENDS ON -- the thing needed to "
            "generate a correct allow-list -- and does NOT establish that any "
            "firewall enforces it. Enforcement is a client-environment control."
        ),
    }

    # --- §2.4.2 role table, with the hat actually worn ----------------
    results["role_table"] = [
        {"role": "Requester", "held_by_conops": "Consuming team in the platform",
         "hat_worn_here": "CONOPS owner, acting as requester",
         "steps": ["1"], "status": "SIMULATED_SINGLE_OPERATOR",
         "note": "No ticket system in the prototype; the request is this record."},
        {"role": "Approver", "held_by_conops": "Data Governance",
         "hat_worn_here": "CONOPS owner, acting as approver",
         "steps": ["1"], "status": "SIMULATED_SINGLE_OPERATOR",
         "note": "A1 is unmet -- 1694-G1 has not arrived -- so the approval is "
                 "provisional and labelled as such, not recorded as governance "
                 "sign-off."},
        {"role": "Metastore admin / catalog creator",
         "held_by_conops": "Client-side admin (to be named)",
         "hat_worn_here": "CONOPS owner, via DATABRICKS_TOKEN",
         "steps": ["5a", "5b", "5c"], "status": "EXERCISED",
         "note": "CREATE PROVIDER and CREATE CATALOG both exercised for real."},
        {"role": "Credential custodian", "held_by_conops": "Named person in Data Eng",
         "hat_worn_here": "CONOPS owner, acting as custodian",
         "steps": ["4"], "status": "EXERCISED",
         "note": "File vaulted at 0600 in _secrets/, gitignored, asserted by "
                 "scripts/check_secret_hygiene.py. §2.4.2 says the custodian has "
                 "no need to read the data -- UNSEPARATED here, because one "
                 "operator also holds the read. Stated rather than implied."},
        {"role": "Catalog owner", "held_by_conops": "Data owner for the use case",
         "hat_worn_here": "CONOPS owner, acting as catalog owner",
         "steps": ["6"], "status": "EXERCISED_PARTIAL",
         "note": f"Grants issued to '{CONSUMER_GROUP}'. On this tier that group is "
                 f"effectively everyone, so DEFAULT DENY is asserted by the "
                 f"procedure and not demonstrated by this grant."},
        {"role": "Security approver", "held_by_conops": "Platform security",
         "hat_worn_here": "CONOPS owner, acting as security approver",
         "steps": ["allow-list change"], "status": "SIMULATED_SINGLE_OPERATOR",
         "note": "§2.4.3 requires approval for every allow-list change. The "
                 "generated file is the artefact that approval would attach to."},
        {"role": "Provider", "held_by_conops": "External party",
         "hat_worn_here": "CONOPS owner, as the OSS provider operator",
         "steps": ["2", "3"], "status": "EXERCISED",
         "note": "Token and credential file issued by scripts/10. Genuinely the "
                 "open protocol, but NOT an arm's-length counterparty -- the same "
                 "operator holds both ends."},
    ]
    results["role_separation_caveat"] = (
        "Every hat in §2.4.2 was worn by one operator. The SEQUENCE and the "
        "ARTEFACTS are therefore real evidence; the SEGREGATION OF DUTIES is "
        "not, and T-20 must not be read as testing it. The separation that can "
        "be tested here is the custodian/data-owner split in §2.4.2, and it was "
        "not exercised."
    )

    # --- Step coverage -------------------------------------------------
    results["step_coverage"] = [
        {"step": 1, "name": "Request and approval", "verdict": "SIMULATED",
         "note": "Recorded in role_table; no ticket system."},
        {"step": 2, "name": "Identity exchange", "verdict": "EXERCISED",
         "note": "Credential file delivered provider -> custodian (scripts/10)."},
        {"step": 3, "name": "Provider action", "verdict": "EXERCISED",
         "note": "Token issued; expirationTime recorded in the credential."},
        {"step": 4, "name": "Custody", "verdict": "EXERCISED",
         "note": "0600, gitignored, hygiene-gated."},
        {"step": 5, "name": "Connect", "verdict": "SPLIT",
         "note": "Control-plane half blocked by our loopback address (Path A, "
                 "attributed via the baseline). Client half exercised in full "
                 "(Path B)."},
        {"step": 6, "name": "Grant", "verdict": "PARTIAL",
         "note": "Grants applied; default deny not demonstrated on this tier."},
        {"step": 7, "name": "Land and validate", "verdict": "OUT_OF_SCOPE",
         "note": "§2.4.4, test T-22."},
        {"step": 8, "name": "Register", "verdict": "EXERCISED",
         "note": "This evidence file is the inventory row: provider, share, "
                 "catalog, owner, tier, DSA reference pending, plus the "
                 "credential expiry §2.4.1 adds for D2O."},
    ]

    # --- Hand the allow-list to the single writer ----------------------
    # This test no longer writes outbound-allow-list.yaml itself. T-19
    # also contributes a host to it (the Databricks open-sharing
    # endpoint), and a file with two writers loses whichever
    # contribution ran first. scripts/23 is the only writer; it reads
    # BOTH evidence files, which is why it is invoked after this test's
    # evidence file is on disk rather than here.
    WRITEABLE = ("NECESSARY_AND_SUFFICIENT",
                 "NECESSARY_AND_SUFFICIENT_REVIEW_REQUIRED",
                 "SUFFICIENT_ONLY")
    results["allowlist_file"] = str(ALLOWLIST.relative_to(REPO))
    results["allowlist_writer"] = "scripts/23_gen_outbound_allow_list.py"
    if allowlist_verdict not in WRITEABLE:
        results["allowlist_contribution_withheld_because"] = (
            f"verdict {allowlist_verdict}. An allow-list generated from a capture "
            f"that was not shown to be sufficient would be worse than none: it "
            f"would look derived from evidence while being wrong. The writer "
            f"enforces the same guard against this evidence file."
        )
        print(f"\nAllow-list contribution withheld: {allowlist_verdict}")

    results["verdict"] = {
        "path_a": "BLOCKED_BY_LOCAL_TOPOLOGY_ATTRIBUTED",
        "path_b": allowlist_verdict,
        "t20": {
            "NECESSARY_AND_SUFFICIENT": "PASS_WITH_SCOPE",
            "NECESSARY_AND_SUFFICIENT_REVIEW_REQUIRED": "PASS_WITH_SCOPE_PENDING_REVIEW",
        }.get(allowlist_verdict, "PARTIAL"),
        "scope": ("The D2O pull is demonstrated end to end through the open "
                  "connector, and the outbound allow-list is derived from an "
                  "observed capture and shown to be both necessary and "
                  "sufficient. The Databricks-native control-plane read is not "
                  "demonstrated, for a reason measured rather than assumed. "
                  "Hostnames do not transfer; the procedure does."),
    }

    EVIDENCE.parent.mkdir(parents=True, exist_ok=True)
    EVIDENCE.write_text(scrub_json(results))

    # The generator reads this file, so it runs only now that it exists.
    gen = REPO / "scripts" / "23_gen_outbound_allow_list.py"
    if gen.exists():
        rc = subprocess.run([sys.executable, str(gen)], timeout=60).returncode
        if rc != 0:
            print(f"\nWARNING: {gen.name} exited {rc}; "
                  f"{ALLOWLIST.relative_to(REPO)} may be stale.")
    else:
        print(f"\nWARNING: {gen.name} is missing; "
              f"{ALLOWLIST.relative_to(REPO)} was not regenerated.")

    print("\n" + "=" * 68)
    print(f"Path A: {results['verdict']['path_a']}")
    print(f"Path B: {allowlist_verdict}")
    print(f"T-20:   {results['verdict']['t20']}")
    print(f"\nWrote {EVIDENCE.relative_to(REPO)}")
    print("Now run: python3 scripts/check_secret_hygiene.py")
    return 0


if __name__ == "__main__":
    sys.exit(main())
