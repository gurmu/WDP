#!/usr/bin/env python3
"""Epic 1 Task 1.10 probe -- does the D2O far side actually speak the protocol?

Eight checks, in dependency order. Each records its own verdict; a later
failure never overwrites an earlier pass, because "the server is up but
/query is unimplemented" and "the server is down" are different findings
and the test matrix needs to tell them apart.

  1. /shares                      -- is this a Delta Sharing server at all?
  2. /shares/{s}/schemas          -- does it expose our schema?
  3. .../tables                   -- does it expose our table?
  4. .../query (POST)             -- does it return pre-signed URLs, and
                                     WHICH HOSTS do those URLs name?
  5. wrong token                  -- does it REFUSE?
  6. GET a pre-signed URL         -- is the data actually retrievable by
                                     a consumer holding only that URL?
  7. PUT the same URL             -- is it refused?
  8. PUT a PUT-signed URL         -- is THAT accepted? The control
                                     that makes check 7 attributable:
                                     without it, a refusal cannot be
                                     told apart from a store that
                                     refuses all pre-signed writes.

Check 5 is the one that makes 1-4 mean anything. A server that accepts
every request would pass 1-4 identically, so without a demonstrated
refusal there is no evidence that authentication exists. This is the same
lesson as docs/12 Sec 12.9: a control observed only passing has not been
observed working.

Check 6 exists because /query returning 200 proves only that the server
can SIGN a URL, not that the URL WORKS. Those come apart in exactly one
way worth catching: if the signer's endpoint and the storage endpoint
disagree, every URL is syntactically perfect and points somewhere the
data is not. Check 4 therefore also inspects the hostname rather than
merely counting URLs.

Check 7 is T-21's read-only evidence, and it is stronger than what it
replaced. Read-only used to rest on a `:ro` bind mount -- a flag we set
ourselves on our own container, which demonstrates nothing about what a
RECIPIENT can do. The signer builds GeneratePresignedUrlRequest with
HttpMethod.GET, so the recipient's URL is signed for GET alone and a
write with it is refused by the object store. That is a property of the
protocol, not of our configuration.

Check 4 doubles as the T-20 outbound-host capture. Per CONOPS 2.4.3 the
deliverable there is the *procedure* for building a recipient-side
allow-list, which Databricks does not document. The hostnames themselves
are local and do not transfer -- but the shape of the finding does, and
sharply: the signed host is the one the PROVIDER knows, because it sits
inside the signature. A recipient cannot substitute a name it finds more
convenient.

Writes: evidence/capability-baseline-d2o.json
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qs, urlparse

REPO = Path(__file__).resolve().parent.parent
PROFILE = REPO / "_secrets" / "oss-provider-credential.json"
SHARE, SCHEMA, TABLE = "awoz_share", "opensharing_test", "test_dataset"
# Must match REGION in scripts/10 and AWS_REGION in docker-compose.yml:
# the region sits inside the SigV4 credential scope, so a mismatch here
# would fail check 8 for a reason that has nothing to do with method
# binding -- and a control that fails for the wrong reason is worse
# than no control, because it reads as a real negative.
REGION = "us-east-1"


def call(endpoint, token, path, method="GET", body=None, timeout=20):
    url = endpoint.rstrip("/") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {token}")
    if data:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode()
            try:
                return r.status, json.loads(raw)
            except json.JSONDecodeError:
                # /query replies NDJSON: one JSON object per line.
                lines = [json.loads(ln) for ln in raw.splitlines() if ln.strip()]
                return r.status, lines or raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode(errors="ignore")
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, raw[:500]
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def fetch_url(url, method="GET", data=None, timeout=20):
    """Hit a pre-signed URL with NO Authorization header.

    Deliberately unauthenticated. The whole claim being tested is that
    the signature in the query string is the only credential a consumer
    needs -- adding a bearer token would make a pass unattributable.
    Returns (status, byte_count_or_message).
    """
    req = urllib.request.Request(url, data=data, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, len(r.read())
    except urllib.error.HTTPError as e:
        return e.code, e.read(400).decode(errors="ignore")
    except Exception as e:
        return None, f"{type(e).__name__}: {e}"


def load_env():
    """Read .env for the object-store credentials check 8 needs.

    Blank values are skipped: a placeholder means "unset", and
    forwarding one as an empty string is what produced the
    `ProfileNotFound: The config profile () could not be found` crash in
    docs/11 B-10b.
    """
    env_path = REPO / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        if not v.strip():
            continue
        os.environ.setdefault(k, v)


def signature_version(url):
    """V4 if the URL carries X-Amz-Signature, V2 if plain Signature."""
    q = parse_qs(urlparse(url).query)
    if "X-Amz-Signature" in q:
        return "SigV4"
    if "Signature" in q and "AWSAccessKeyId" in q:
        return "SigV2"
    return "UNKNOWN"


def method_binding_control(target_url):
    """Check 8: does this store accept a PUT-signed URL at all?

    WHY THIS EXISTS. Check 7 replays the recipient's GET-signed URL as a
    PUT and gets 403. That is consistent with TWO explanations:

      (a) the HTTP method is inside the signature, so a GET-signed URL
          cannot be used to write -- T-21's claim; or
      (b) this object store refuses pre-signed PUTs generally, in which
          case check 7 says nothing about method binding and T-21 would
          be resting on a property of our stand-in store rather than on
          the protocol.

    Check 7 alone cannot separate them, and the difference matters: (a)
    transfers to the client environment and to any S3-compatible store,
    (b) does not. So sign a URL for PUT and confirm it is ACCEPTED. If
    it is, the 403 in check 7 is attributable to the method and nothing
    else. If it is not, T-21 keeps only the weaker inference and must
    say so.

    This is a CONTROL, so it must differ from check 7 in exactly one
    variable. Same store, same bucket, same endpoint spelling (parsed
    out of the recipient's own URL, so host and port match the signature
    byte for byte), same credentials, same unauthenticated request path.
    Only the signed method differs.

    ONE DEVIATION, stated deliberately: the control writes to a scratch
    key, not to the Parquet file check 7 targeted. Overwriting a data
    file would corrupt the Delta table and poison every later read. The
    store's authorization does not vary by key within a bucket, so this
    does not weaken the comparison -- but it is a deviation and belongs
    in the record rather than in a footnote nobody reads.
    """
    parsed = urlparse(target_url)
    endpoint = f"{parsed.scheme}://{parsed.netloc}"
    # /bucket/key... -- path-style, as core-site.xml mandates.
    bucket = parsed.path.lstrip("/").split("/", 1)[0]
    key = "_t21_method_binding_control/probe.bin"

    chk = {
        "endpoint_signed_against": endpoint,
        "bucket": bucket,
        "scratch_key": key,
        "deviation_from_check_7": (
            "Different object key (a scratch key, not the shared Parquet "
            "file). Writing to the real data file would corrupt the Delta "
            "table. Store authorization does not vary by key within a "
            "bucket, so the comparison holds."
        ),
    }

    access = os.environ.get("OBJECTSTORE_ACCESS_KEY", "")
    secret = os.environ.get("OBJECTSTORE_SECRET_KEY", "")
    if not access or not secret:
        chk.update(
            verdict="NOT_ATTEMPTED",
            means=(
                "OBJECTSTORE_ACCESS_KEY / OBJECTSTORE_SECRET_KEY not in "
                ".env, so no PUT-signed URL could be produced. Check 7's "
                "refusal therefore remains UNATTRIBUTED: it is consistent "
                "with method binding and with a store that refuses all "
                "pre-signed writes."
            ),
        )
        return chk

    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        chk.update(
            verdict="NOT_ATTEMPTED",
            means=(
                "boto3 not installed, so the control could not run and "
                "check 7 stays unattributed. Install it with:\n"
                "    pip install boto3 --break-system-packages"
            ),
        )
        return chk

    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if not os.environ.get(var, "").strip():
            os.environ.pop(var, None)

    session = boto3.session.Session(profile_name=None, region_name=REGION)
    s3 = session.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=access,
        aws_secret_access_key=secret,
        region_name=REGION,
        config=Config(
            s3={"addressing_style": "path"},
            retries={"max_attempts": 2},
            # EXPLICIT SigV4. Without this, botocore signs pre-signed
            # URLs with SigV2 against a custom endpoint, and the store
            # answered SignatureDoesNotMatch -- a failure of the control
            # itself, which read identically to the store refusing the
            # write. The recipient's URL is SigV4, so the control must
            # be too or it is not a control.
            signature_version="s3v4",
        ),
    )

    put_url = s3.generate_presigned_url(
        "put_object", Params={"Bucket": bucket, "Key": key}, ExpiresIn=300
    )
    chk["control_signature_version"] = signature_version(put_url)
    chk["recipient_signature_version"] = signature_version(target_url)

    # A control signed differently from the thing it controls for proves
    # nothing. Say so, rather than reporting a failure that the reader
    # would take as a finding about the store.
    if chk["control_signature_version"] != chk["recipient_signature_version"]:
        chk.update(
            verdict="INVALID_CONTROL",
            means=(
                f"The control signed {chk['control_signature_version']} but "
                f"the recipient's URL is "
                f"{chk['recipient_signature_version']}. Any result from "
                f"this comparison would be about signature versions, not "
                f"about the HTTP method, so it is reported as an invalid "
                f"control rather than as a verdict on the store."
            ),
        )
        return chk

    payload = b"t21-method-binding-control"
    status, detail = fetch_url(put_url, "PUT", data=payload)
    chk["status"] = status

    if status in (200, 201, 204):
        chk.update(
            verdict="CONTROL_PASSES",
            means=(
                f"HTTP {status}. A PUT-signed URL for the same store, "
                f"bucket and endpoint is ACCEPTED, with no Authorization "
                f"header -- exactly as the GET-signed URL was in check 6. "
                f"So this store does serve pre-signed writes, and check "
                f"7's refusal is attributable to the SIGNED METHOD rather "
                f"than to a blanket refusal of writes. T-21's read-only "
                f"claim is now isolated to the protocol property: the "
                f"provider signs with HttpMethod.GET, the method is "
                f"covered by the signature, and a recipient cannot "
                f"promote a read URL into a write."
            ),
        )
    elif status in (400, 401, 403, 405):
        chk.update(
            verdict="CONTROL_FAILS",
            detail=str(detail)[:300],
            means=(
                f"HTTP {status}. This store refused a correctly PUT-signed "
                f"URL too, so check 7's 403 does NOT isolate method "
                f"binding -- both explanations remain open. Do not present "
                f"T-21 as protocol-level evidence on this run. The claim "
                f"falls back to the constant-pool reading of S3FileSigner "
                f"(HttpMethod.GET is what it signs), which is static "
                f"evidence rather than observed behaviour. Likely causes: "
                f"the store disallows presigned writes by policy, or the "
                f"bucket is read-only to these credentials."
            ),
        )
    else:
        chk.update(
            verdict="INCONCLUSIVE",
            detail=str(detail)[:300],
            means=(
                f"PUT-signed control returned HTTP {status}: neither a "
                f"clean accept nor a clean refusal, so it attributes "
                f"nothing."
            ),
        )

    # Clean up, through the authenticated client. Leaving the scratch
    # object behind would put a writable artifact inside the shared
    # bucket and muddy any later T-21 or T-23 capture.
    if chk["verdict"] == "CONTROL_PASSES":
        try:
            s3.delete_object(Bucket=bucket, Key=key)
            chk["cleanup"] = "scratch object deleted"
        except Exception as e:
            chk["cleanup"] = f"FAILED to delete scratch object: {type(e).__name__}: {e}"
    return chk


def main():
    load_env()
    if not PROFILE.exists():
        sys.exit(
            f"Missing {PROFILE}.\n"
            "Run scripts/10_setup_oss_provider.py first -- it renders the\n"
            "consumer profile that this probe (and T-20) consumes."
        )
    prof = json.loads(PROFILE.read_text())
    endpoint, token = prof["endpoint"], prof["bearerToken"]

    results = {"endpoint": endpoint, "share_path": f"{SHARE}.{SCHEMA}.{TABLE}", "checks": {}}
    print(f"Probing {endpoint}\n" + "=" * 60)

    # --- 1. Is it a Delta Sharing server? --------------------------------
    status, payload = call(endpoint, token, "/shares")
    chk = {"status": status, "response": payload if status == 200 else str(payload)[:400]}
    if status == 200 and isinstance(payload, dict) and "items" in payload:
        names = [i.get("name") for i in payload["items"]]
        chk.update(verdict="WORKS", shares=names)
        chk["means"] = f"Delta Sharing protocol confirmed. Shares: {names}"
    elif status is None:
        chk.update(
            verdict="UNREACHABLE",
            means=(
                "Nothing answered. The container is not up, or 8086 is not "
                "published. Run: docker compose up -d delta_sharing_server "
                "&& docker compose logs --tail=40 delta_sharing_server. "
                "This is NOT evidence about the protocol -- record it as "
                "setup-incomplete, not as a provider limitation."
            ),
        )
    elif status in (401, 403):
        chk.update(
            verdict="REFUSED",
            means=(
                "Server is up but rejected our own token. The rendered "
                "config and the consumer profile have drifted apart -- "
                "re-run scripts/10_setup_oss_provider.py so both come from "
                "the same OSS_PROVIDER_TOKEN, then restart the container."
            ),
        )
    else:
        chk.update(
            verdict="NOT_DELTA_SHARING",
            means=(
                f"Answered HTTP {status} but not a Delta Sharing /shares "
                f"body. Something else is on this port, or the endpoint "
                f"prefix differs from /delta-sharing."
            ),
        )
    results["checks"]["shares"] = chk
    print(f"[1] /shares            {chk['verdict']}")

    if chk["verdict"] != "WORKS":
        out = REPO / "evidence" / "capability-baseline-d2o.json"
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(results, indent=2))
        print(f"\nStopped at check 1. {chk['means']}\n\nWritten to {out}")
        return 1

    # --- 2 & 3. Schema and table discovery -------------------------------
    for label, path, key in [
        ("schemas", f"/shares/{SHARE}/schemas", SCHEMA),
        ("tables", f"/shares/{SHARE}/schemas/{SCHEMA}/tables", TABLE),
    ]:
        status, payload = call(endpoint, token, path)
        listed = (
            status == 200
            and isinstance(payload, dict)
            and any(i.get("name") == key for i in payload.get("items", []))
        )

        # THREE OUTCOMES, NOT TWO. "The listing does not contain it" and
        # "the listing call failed" are different findings, and they used
        # to collapse into a single verdict of MISSING whose remedy text
        # sent the reader hunting for a name mismatch in a config that
        # was correct. The server was actually answering HTTP 500 from a
        # NullPointerException over a table declared without an id. Same
        # shape as everything else in docs/12 Sec 12.9: a check that
        # could not see the answer reported what a check that looked and
        # found nothing would report.
        if listed:
            verdict = "WORKS"
            means = f"'{key}' is published."
        elif status == 200:
            verdict = "MISSING"
            means = (
                f"The server answered 200 and '{key}' is genuinely absent "
                f"from the list. Check the shares block in the rendered "
                f"config; a name mismatch is the usual cause."
            )
        else:
            verdict = "ERROR"
            means = (
                f"The listing call itself FAILED with HTTP {status}. That is "
                f"NOT evidence that '{key}' is unpublished and must not be "
                f"recorded as such. The stack trace this response body "
                f"omits is in the server's own log:\n"
                f"    docker compose logs --tail=80 delta_sharing_server\n"
                f"INTERNAL_ERROR with an empty message is characteristic of "
                f"a table declared without an 'id' (docs/11 B-11)."
            )

        results["checks"][label] = {
            "status": status,
            "verdict": verdict,
            "looked_for": key,
            "response": payload if status == 200 else str(payload)[:300],
            "means": means,
        }
        print(f"[{2 if label == 'schemas' else 3}] /{label:<17} {results['checks'][label]['verdict']}")

    # --- 4. Query, and capture the outbound hosts (T-20) -----------------
    signed_urls = []
    status, payload = call(
        endpoint,
        token,
        f"/shares/{SHARE}/schemas/{SCHEMA}/tables/{TABLE}/query",
        method="POST",
        body={"predicateHints": [], "limitHint": 100},
    )
    chk = {"status": status}
    if status == 200 and isinstance(payload, list):
        files = [ln["file"] for ln in payload if isinstance(ln, dict) and "file" in ln]
        urls = [f.get("url", "") for f in files]
        signed_urls = [u for u in urls if u]
        hosts = sorted({urlparse(u).hostname for u in urls if u})
        chk.update(
            verdict="WORKS",
            file_count=len(files),
            outbound_hosts=hosts,
            protocol_lines=len(payload),
            means=(
                f"{len(files)} pre-signed file URL(s) returned across "
                f"{len(payload)} protocol lines. Outbound hosts a consumer "
                f"must reach: {hosts}. This is the T-20 capture. The "
                f"PROCEDURE transfers to the client environment; these "
                f"hostnames do not (CONOPS 2.4.3)."
            ),
        )
        if not hosts:
            # Under file:// the URLs carry no hostname at all. That is a
            # backend property, not a result -- and an empty list reads
            # indistinguishably as "no egress required", which is the
            # Sec 12.9 failure shape. Refuse to let it pass as a finding.
            chk["verdict"] = "NO_HOSTS"
            chk["caveat"] = (
                "Host list is EMPTY, which means the table is still on a "
                "local filesystem rather than in object storage. Do NOT "
                "write this up as 'no outbound hosts needed'. Check the "
                "location in the rendered config -- it must be s3a://, "
                "not file:// (docs/11 B-8)."
            )
        elif any(h and h.endswith("amazonaws.com") for h in hosts):
            # The failure this check exists to catch. /query answered
            # 200, the URLs are well-formed, and they point at AWS for
            # data that is in MinIO. Nothing upstream notices.
            chk["verdict"] = "SIGNER_ENDPOINT_IGNORED"
            chk["caveat"] = (
                f"Signed URLs name AWS ({hosts}) while the table lives in "
                "the local object store. The server's S3 client is not "
                "picking up fs.s3a.endpoint, so oss-provider/core-site.xml "
                "is not on the classpath -- confirm with: docker compose "
                "exec delta_sharing_server cat /opt/docker/conf/core-site.xml "
                "and rebuild with --build if it is absent. A consumer would "
                "see a 403 from AWS and would have no way to attribute it."
            )
    else:
        chk.update(
            verdict="FAILED",
            response=str(payload)[:500],
            means=(
                "Discovery worked but /query did not. Record this split: "
                "metadata exposure and data access are separate "
                "capabilities and the matrix should not collapse them."
            ),
        )
    results["checks"]["query"] = chk
    print(f"[4] /query             {chk['verdict']}")

    # --- 5. Does it refuse a bad token? ----------------------------------
    status, payload = call(endpoint, token + "-tampered", "/shares")
    chk = {"status": status}
    if status in (401, 403):
        chk.update(
            verdict="REFUSES",
            means=(
                f"HTTP {status} on a tampered token. Authentication is "
                f"demonstrably enforced, so checks 1-4 are evidence of an "
                f"authorised read rather than an open endpoint."
            ),
        )
    elif status == 200:
        chk.update(
            verdict="ACCEPTS_ANYTHING",
            means=(
                "SERIOUS: the server served /shares with a tampered token. "
                "Authentication is not enforced, which invalidates checks "
                "1-4 as evidence of authorised access and makes T-21's "
                "read-only claim unverifiable on this path. Check the "
                "authorization block in the rendered config."
            ),
        )
    else:
        chk.update(
            verdict="INCONCLUSIVE",
            response=str(payload)[:300],
            means=f"Tampered token produced HTTP {status}, neither a clean refusal nor a pass.",
        )
    results["checks"]["auth_refusal"] = chk
    print(f"[5] bad-token refusal  {chk['verdict']}")

    # --- 6 & 7. Is the signed URL usable, and only for reading? ----------
    #
    # Both checks are skipped rather than failed when there is no URL to
    # test. "Not attempted" and "attempted and refused" are different
    # findings, and collapsing them would reintroduce the Sec 12.9 defect
    # inside the very script that warns about it.
    if not signed_urls:
        for label, n in (("presigned_get", 6), ("presigned_put_refused", 7)):
            results["checks"][label] = {
                "verdict": "NOT_ATTEMPTED",
                "means": (
                    "No pre-signed URL was returned by check 4, so this was "
                    "not run. Record as not attempted -- NOT as a pass and "
                    "NOT as a failure."
                ),
            }
            print(f"[{n}] {label:<21} NOT_ATTEMPTED")
    else:
        target = signed_urls[0]
        host = urlparse(target).hostname

        status, detail = fetch_url(target, "GET")
        chk = {"status": status, "host": host}
        if status == 200:
            chk.update(
                verdict="RETRIEVABLE",
                bytes=detail,
                means=(
                    f"{detail} bytes of Parquet fetched from {host} with no "
                    f"credential but the signature itself. End-to-end D2O "
                    f"read confirmed: discovery, signing and data transfer."
                ),
            )
        elif status is None:
            chk.update(
                verdict="UNRESOLVABLE",
                detail=str(detail)[:300],
                means=(
                    f"Could not reach {host}. The signed host is the one "
                    f"the PROVIDER knows, and it is inside the signature, "
                    f"so it cannot be rewritten to something reachable. "
                    f"Add to /etc/hosts:  127.0.0.1 {host}  -- and note "
                    f"that this IS the T-20 finding in miniature: the "
                    f"recipient must resolve the provider's storage name "
                    f"exactly."
                ),
            )
        elif status == 403:
            chk.update(
                verdict="SIGNATURE_REJECTED",
                detail=str(detail)[:300],
                means=(
                    "Host reachable but the signature was rejected. Usual "
                    "cause is a region or endpoint mismatch between signer "
                    "and store (the store's region vs AWS_REGION), or the "
                    "server holding different credentials from the store."
                ),
            )
        else:
            chk.update(
                verdict="FAILED",
                detail=str(detail)[:300],
                means=f"Pre-signed GET returned HTTP {status}.",
            )
        results["checks"]["presigned_get"] = chk
        print(f"[6] presigned GET      {chk['verdict']}")

        status, detail = fetch_url(target, "PUT", data=b"tamper")
        # Keep the error CODE, not just the status. It discriminates the
        # two mechanisms that both answer 403: SignatureDoesNotMatch
        # means the store recomputed a signature over this request and
        # got a different value -- i.e. the method is part of what was
        # signed. AccessDenied would instead suggest a bucket policy,
        # which is OUR configuration and would prove nothing about the
        # protocol. Discarding the body would discard that distinction.
        code = ""
        if isinstance(detail, str) and "<Code>" in detail:
            code = detail.split("<Code>", 1)[1].split("</Code>", 1)[0]
        chk = {"status": status, "error_code": code or None,
               "detail": str(detail)[:300]}
        if status in (400, 401, 403, 405):
            chk.update(
                verdict="REFUSES_WRITE",
                means=(
                    f"HTTP {status} on a write to the same URL that just "
                    f"served a read. This is half of T-21's evidence: the "
                    f"URL appears signed for GET only, so the recipient's "
                    f"read-only position would be enforced by the "
                    f"signature rather than by a mount option on our side "
                    f"of the boundary. NOT YET ATTRIBUTED -- check 8 is "
                    f"what rules out a store that refuses every "
                    f"pre-signed write regardless of method."
                ),
            )
        elif status in (200, 201, 204):
            chk.update(
                verdict="ACCEPTS_WRITE",
                means=(
                    "SERIOUS: a recipient's pre-signed URL accepted a PUT. "
                    "T-21's read-only claim fails on this path and the "
                    "shared object has been overwritten -- re-run "
                    "scripts/10_setup_oss_provider.py --force before "
                    "trusting any later read."
                ),
            )
        else:
            chk.update(
                verdict="INCONCLUSIVE",
                detail=str(detail)[:300],
                means=f"Write attempt returned HTTP {status}; neither a clean refusal nor a write.",
            )
        results["checks"]["presigned_put_refused"] = chk
        print(f"[7] presigned PUT      {chk['verdict']}")

        # --- 8. The control that makes check 7 attributable ------------
        ctrl = method_binding_control(target)
        results["checks"]["put_signed_control"] = ctrl
        print(f"[8] PUT-signed control {ctrl['verdict']}")

    verdicts = {k: v["verdict"] for k, v in results["checks"].items()}
    results["summary"] = verdicts
    # T-21 needs BOTH halves. A refusal on its own is unattributed: it
    # becomes evidence about the signed method only once a PUT-signed
    # URL has been shown to succeed against the same store. So the
    # read-only claim is graded separately from the rest, and the
    # conclusion states which of the two it earned.
    t21_refused = verdicts.get("presigned_put_refused") == "REFUSES_WRITE"
    t21_controlled = verdicts.get("put_signed_control") == "CONTROL_PASSES"
    results["t21_strength"] = (
        "PROTOCOL_LEVEL" if (t21_refused and t21_controlled)
        else "UNATTRIBUTED" if t21_refused
        else "NOT_DEMONSTRATED"
    )

    conclusive = (
        verdicts.get("query") == "WORKS"
        and verdicts.get("auth_refusal") == "REFUSES"
        and verdicts.get("presigned_get") == "RETRIEVABLE"
        and t21_refused
        and t21_controlled
    )
    if conclusive:
        results["conclusion"] = (
            "T-20/T-21/T-23 provider confirmed: protocol, discovery, data "
            "access, authentication, retrievability, and recipient-side "
            "read-only demonstrated AND attributed to the signed method "
            "by a passing PUT-signed control."
        )
    elif t21_refused and not t21_controlled:
        results["conclusion"] = (
            "Provider works, but T-21 is UNATTRIBUTED: the write was "
            "refused and no passing PUT-signed control explains why. Do "
            "not present the refusal as protocol-level read-only "
            "evidence until check 8 passes."
        )
    else:
        results["conclusion"] = (
            "Partial. See individual verdicts -- do not summarise as pass or fail."
        )

    out = REPO / "evidence" / "capability-baseline-d2o.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(results, indent=2))
    print("\n" + "=" * 60)
    print(json.dumps(verdicts, indent=2))
    print(f"\n{results['conclusion']}")
    for label, c in results["checks"].items():
        if c.get("caveat"):
            print(f"\nCAVEAT [{label}]: {c['caveat']}")
    # Print the reasoning for anything that did not come out clean, so
    # the next action is visible without opening the JSON.
    for label, c in results["checks"].items():
        if c["verdict"] not in ("WORKS", "REFUSES", "RETRIEVABLE", "REFUSES_WRITE"):
            print(f"\n{label}: {c.get('means', '')}")
    print(f"\nWritten to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
