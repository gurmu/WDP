#!/usr/bin/env python3
"""Epic 1 Task 1.10 -- stand up the D2O far side: a real open-protocol provider.

Builds the four things the Delta Sharing reference server needs, and
nothing else:

  1. A bucket in the local `objectstore` service (Scality CloudServer;
     MinIO was withdrawn mid-build, which is why the service is named
     for its role rather than its product -- see docs/11 B-10).
  2. A genuine Delta table inside it (written with delta-rs -- no Spark,
     no JVM).
  3. _secrets/delta-sharing-server-config.yaml, rendered from the
     tracked template with OSS_PROVIDER_TOKEN and the table location
     injected, mode 0600.
  4. _secrets/oss-provider-credential.json -- the Delta Sharing profile
     file a CONSUMER uses, which is the artifact T-20 imports "from the
     vault" and the one route-rewriting in OD-4 operates on.

WHY OBJECT STORAGE AND NOT A LOCAL DIRECTORY. The server has no
local-filesystem implementation. /query answers with pre-signed URLs,
which a local path cannot have, so a file:// location fails with
"File system class org.apache.hadoop.fs.LocalFileSystem is not
supported" and arrives at the client as a bare HTTP 500. Recorded as
docs/11 B-8. This is not a laptop limitation: it holds wherever the
open-source provider is hosted, so the client environment needs object
storage behind any self-hosted D2O channel too.

Why this is a provider and not a stand-in (matters for the T-20/T-23
verdicts): the server implements the Delta Sharing REST protocol, issues
its own bearer token, and serves pre-signed URLs for real Parquet files.
Nothing about it is mocked. The CONOPS distinction is between a real
open-protocol provider we happen to operate and a *simulation* of one;
this is the former, which is why T-20, T-21 and T-23 are BUILD rather
than STANDIN.

A GitHub URL cannot take this role. GitHub serves files over HTTPS but
does not implement /shares, /schemas, /tables or /query, so it cannot
answer a Delta Sharing client. GitHub's role here is versioning the
table-building code and this config -- provenance, not protocol.

Idempotent: safe to re-run. Pass --force to rewrite the Delta table.

Prerequisites:
    pip install deltalake pandas boto3 --break-system-packages
    docker compose up -d objectstore
"""

import json
import os
import secrets
import stat
import sys
import uuid
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
SECRETS = REPO / "_secrets"
TEMPLATE = REPO / "oss-provider" / "delta-sharing-server-config.template.yaml"
RENDERED = SECRETS / "delta-sharing-server-config.yaml"
PROFILE = SECRETS / "oss-provider-credential.json"

SHARE, SCHEMA, TABLE_NAME = "awoz_share", "opensharing_test", "test_dataset"
HOST_PORT = 8086

# Two endpoints for one object store, and the difference matters.
#
#   HOST_ENDPOINT      -- what THIS script uses to write the table, and
#                         what the probe uses to act as a consumer.
#   container endpoint -- http://objectstore:8000, in core-site.xml, used by
#                         the SERVER and therefore baked into the
#                         signature of every pre-signed URL it issues.
#
# They must name the same bytes but they are not interchangeable: the
# signed host is the container one, so a consumer has to be able to
# resolve `objectstore`. That is a finding, not an inconvenience --
# see B-9.
DEFAULT_HOST_ENDPOINT = "http://localhost:8000"
REGION = "us-east-1"


def load_env():
    env_path = REPO / ".env"
    if not env_path.exists():
        sys.exit(f"Missing {env_path}. Copy .env.example to .env first.")
    for line in env_path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        # A BLANK VALUE IS AN ABSENCE, NOT A VALUE. `.env` carries blank
        # placeholders (AWS_PROFILE=, AWS_REGION=) as prompts for the
        # reader. Injecting those verbatim turns "nothing was set" into a
        # positive assertion: botocore read AWS_PROFILE="" as a request
        # for a profile whose name is the empty string and died with
        # `ProfileNotFound: The config profile () could not be found`.
        #
        # Same shape as docs/12 Sec 12.9 and docs/11 B-10a -- an absence
        # that became indistinguishable from a deliberate setting. The
        # `require()` check below could not catch it either, because by
        # then the damage is in os.environ, not in the variables this
        # script reads.
        if not v.strip():
            continue
        os.environ.setdefault(k, v)


def require(name, hint):
    val = os.environ.get(name, "")
    if not val or val.startswith("<"):
        sys.exit(f"{name} is unset in .env.\n{hint}")
    return val


def stable_table_id():
    """A table id that is reproducible from code, stored nowhere.

    The server REQUIRES an id per table even though TableConfig does not
    validate one (B-11). A random uuid4 would work, but it would change
    on every redeploy, and a recipient that cached the old id would see
    a different table after an AC6 / T-12 rebuild. A uuid5 over the
    share/schema/table names is deterministic, so the rebuild produces
    byte-identical config without persisting any state.
    """
    return str(uuid.uuid5(uuid.NAMESPACE_URL,
                          f"awoz-1227/{SHARE}/{SCHEMA}/{TABLE_NAME}"))


def verify_rendered_config(rendered, server_location, table_id):
    """Parse what we just wrote, and assert the fields the server needs.

    Substitution checks only prove no placeholder SURVIVED. They say
    nothing about whether the result is valid YAML or carries the fields
    the server dereferences. Both failures we hit here were of exactly
    that kind: a config the server accepted at load and then 500'd on
    (missing table id), and a config the parser rejected outright while
    the process carried on with defaults (core-site.xml). So check the
    product, not the procedure.
    """
    try:
        import yaml
    except ImportError:
        print("  [skip] PyYAML not installed; cannot verify the rendered "
              "config.\n         pip install pyyaml --break-system-packages")
        return
    try:
        doc = yaml.safe_load(rendered)
    except yaml.YAMLError as e:
        sys.exit(f"Rendered config is not valid YAML:\n{e}")

    try:
        tbl = doc["shares"][0]["schemas"][0]["tables"][0]
    except (KeyError, IndexError, TypeError) as e:
        sys.exit(f"Rendered config has no share/schema/table path: {e}")

    problems = []
    if tbl.get("name") != TABLE_NAME:
        problems.append(f"table name is {tbl.get('name')!r}, expected {TABLE_NAME!r}")
    if tbl.get("location") != server_location:
        problems.append(f"location is {tbl.get('location')!r}")
    # The field the server validates nowhere and dereferences anyway.
    if not tbl.get("id"):
        problems.append(
            "table 'id' is missing or empty. The server will load this "
            "config, start cleanly, serve /shares and /schemas, and then "
            "throw NullPointerException on /tables (B-11)."
        )
    if tbl.get("id") != table_id:
        problems.append(f"id is {tbl.get('id')!r}, expected {table_id!r}")
    if not doc.get("authorization", {}).get("bearerToken"):
        problems.append("authorization.bearerToken is empty")
    if problems:
        sys.exit("Rendered config is wrong:\n  - " + "\n  - ".join(problems))
    print("  verified: parses, and declares name + location + id")


def verify_core_site():
    """Assert core-site.xml parses, because Hadoop will not.

    Hadoop logs `error parsing conf core-site.xml` at ERROR level and
    then CONTINUES with default configuration. The server starts, serves
    discovery, and signs URLs against s3.amazonaws.com -- a healthy-
    looking provider with none of its storage settings applied. A broken
    config file and an absent one are indistinguishable from the
    outside, so the only place this can be caught is here, before the
    image is built. See docs/11 B-11.
    """
    import xml.etree.ElementTree as ET

    path = REPO / "oss-provider" / "core-site.xml"
    if not path.exists():
        sys.exit(f"Missing {path} -- the server has no endpoint without it.")
    try:
        root = ET.parse(path).getroot()
    except ET.ParseError as e:
        sys.exit(
            f"{path.relative_to(REPO)} is not well-formed XML: {e}\n"
            "Hadoop would log this at ERROR and run with DEFAULTS, which "
            "means no endpoint override and pre-signed URLs aimed at AWS.\n"
            "Most likely cause: two adjacent hyphens used as a prose dash "
            "inside an XML comment, which XML forbids."
        )
    names = {p.findtext("name") for p in root.findall("property")}
    required = {
        "fs.s3a.endpoint",
        "fs.s3a.path.style.access",
        "fs.s3a.aws.credentials.provider",
    }
    missing = required - names
    if missing:
        sys.exit(f"{path.relative_to(REPO)} parses but omits: {sorted(missing)}")
    print("  verified: core-site.xml parses and sets endpoint + path-style")


def write_0600(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    # Set the mode explicitly. umask on this machine is 0002, so a fresh
    # file lands 0664 and the hygiene check fails on it. Asserting the
    # mode here is what stops that from recurring on every re-run.
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)


def s3_client(endpoint, key, secret):
    try:
        import boto3
        from botocore.config import Config
    except ImportError:
        sys.exit(
            "boto3 is not installed. Install it with:\n"
            "    pip install boto3 --break-system-packages\n"
            "It is used only to create the bucket and to clear it on "
            "--force; the table itself is written by delta-rs."
        )
    # An OWN SESSION, not boto3's implicit default one.
    #
    # boto3.client() builds a module-global default Session, and that
    # constructor reads AWS_PROFILE / AWS_DEFAULT_PROFILE from the
    # environment before it ever looks at the arguments below. So an
    # empty AWS_PROFILE crashes the call even though every credential
    # needed is passed explicitly. Fixing load_env() stops `.env` from
    # being the source; clearing the vars here stops the user's shell
    # from being one too, which matters because the symptom
    # (`ProfileNotFound: The config profile () could not be found`)
    # names neither file.
    for var in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE"):
        if not os.environ.get(var, "").strip():
            os.environ.pop(var, None)

    session = boto3.session.Session(profile_name=None, region_name=REGION)
    return session.client(
        "s3",
        endpoint_url=endpoint,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        region_name=REGION,
        # Path style, matching fs.s3a.path.style.access on the server
        # side. CloudServer is reached here as localhost, and
        # bucket.localhost does not resolve, so virtual-host addressing
        # would fail before any signature was checked.
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 2}),
    )


def ensure_bucket(s3, bucket):
    from botocore.exceptions import ClientError, EndpointConnectionError

    try:
        existing = [b["Name"] for b in s3.list_buckets()["Buckets"]]
    except EndpointConnectionError:
        sys.exit(
            f"Cannot reach the object store at {s3.meta.endpoint_url}.\n"
            "Start it first:  docker compose up -d objectstore\n"
            "Then:            docker compose logs --tail=20 objectstore\n"
            "This is setup-incomplete, NOT a provider finding -- do not "
            "record it in the test matrix as a capability result."
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "?")
        sys.exit(
            f"Object store refused list_buckets ({code}).\n"
            "Most likely OBJECTSTORE_ACCESS_KEY / OBJECTSTORE_SECRET_KEY in .env "
            "differ from what the running container was started with. "
            "Recreate it:  docker compose up -d --force-recreate objectstore"
        )

    if bucket in existing:
        print(f"  bucket s3://{bucket} exists")
    else:
        s3.create_bucket(Bucket=bucket)
        print(f"  created bucket s3://{bucket}")
    return existing


def clear_prefix(s3, bucket, prefix):
    """Delete every object under prefix. Used only by --force."""
    token, removed = None, 0
    while True:
        kw = {"Bucket": bucket, "Prefix": prefix}
        if token:
            kw["ContinuationToken"] = token
        page = s3.list_objects_v2(**kw)
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": keys})
            removed += len(keys)
        if not page.get("IsTruncated"):
            break
        token = page.get("NextContinuationToken")
    if removed:
        print(f"  --force: removed {removed} object(s) under {prefix}")


def table_file_count(dt):
    """Number of active data files, across deltalake API generations.

    `DeltaTable.files()` was removed in deltalake 1.x in favour of
    `file_uris()`. Pinning a version would be the other fix, but this
    script is a setup helper that has to run on whatever delta-rs the
    operator installed, so it probes for the method instead of assuming
    one. Returns None rather than raising if neither exists -- a file
    count is diagnostic output, and failing the whole setup over a
    cosmetic number would be the wrong trade.
    """
    for attr in ("file_uris", "files"):
        fn = getattr(dt, attr, None)
        if callable(fn):
            try:
                return len(fn())
            except Exception:
                continue
    return None


def build_table(uri, storage_options, force):
    try:
        import pandas as pd
        from deltalake import DeltaTable, write_deltalake
    except ImportError:
        sys.exit(
            "deltalake is not installed. Install it with:\n"
            "    pip install deltalake pandas --break-system-packages\n"
            "This is delta-rs: it writes real Delta tables with no Spark "
            "and no JVM, which is why the provider can run on a laptop."
        )

    def open_existing():
        try:
            return DeltaTable(uri, storage_options=storage_options)
        except Exception:
            return None

    if not force:
        dt = open_existing()
        if dt is not None:
            n = table_file_count(dt)
            extra = f", {n} file(s)" if n is not None else ""
            print(f"  table exists, version {dt.version()}{extra}, left alone (--force to rewrite)")
            return dt.version()

    # Deliberately shaped for the tests that read it:
    #  - `classification` gives T-01/T-19 something to grant and deny on.
    #  - a NULL in `amount` makes T-22's bad-schema contrast meaningful.
    #  - two partitions produce more than one pre-signed URL, which is
    #    the whole point of capturing the outbound host list for T-20.
    df = pd.DataFrame(
        {
            "record_id": [1, 2, 3, 4, 5, 6],
            "region": ["east", "east", "east", "west", "west", "west"],
            "classification": ["UNCLASS", "UNCLASS", "CUI", "UNCLASS", "CUI", "CUI"],
            "amount": [100.0, 250.5, 75.25, None, 410.0, 12.75],
            "note": ["alpha", "bravo", "charlie", "delta", "echo", "foxtrot"],
        }
    )
    write_deltalake(
        uri, df, partition_by=["region"], mode="overwrite",
        storage_options=storage_options,
    )

    # A second commit, so the table has real version history. T-23's
    # rotation and T-19's "refresh behaviour recorded" both need a table
    # whose version advances; a single-commit table cannot show that.
    df2 = pd.DataFrame(
        {
            "record_id": [7],
            "region": ["east"],
            "classification": ["UNCLASS"],
            "amount": [999.99],
            "note": ["golf-appended-v1"],
        }
    )
    write_deltalake(
        uri, df2, partition_by=["region"], mode="append",
        storage_options=storage_options,
    )

    dt = DeltaTable(uri, storage_options=storage_options)
    n = table_file_count(dt)
    extra = f", {n} data file(s)" if n is not None else ""
    print(f"  wrote Delta table, version {dt.version()}{extra}")
    return dt.version()


def main():
    force = "--force" in sys.argv
    load_env()
    print("Task 1.10 -- open-protocol D2O provider setup\n" + "=" * 60)

    bucket = os.environ.get("OSS_PROVIDER_BUCKET", "awoz-opensharing")
    host_endpoint = os.environ.get("OBJECTSTORE_HOST_ENDPOINT", DEFAULT_HOST_ENDPOINT)
    key = require(
        "OBJECTSTORE_ACCESS_KEY",
        "Add OBJECTSTORE_ACCESS_KEY and OBJECTSTORE_SECRET_KEY to .env. These are "
        "the object store's credentials; docker-compose.yml passes them "
        "to BOTH objectstore (as its access key) and delta_sharing_server (as "
        "AWS_ACCESS_KEY_ID), so one value configures both sides.",
    )
    secret = require("OBJECTSTORE_SECRET_KEY", "See the OBJECTSTORE_ACCESS_KEY hint above.")

    token = os.environ.get("OSS_PROVIDER_TOKEN", "")
    if not token or token.startswith("<"):
        token = secrets.token_urlsafe(32)
        print("\n[token] OSS_PROVIDER_TOKEN was unset, generated one.")
        print("        Add this line to .env (NOT .env.example):")
        print(f"\n            OSS_PROVIDER_TOKEN={token}\n")
        print("        Re-run after adding it, so the server and the")
        print("        consumer profile are rendered from the same value.")
        generated = True
    else:
        print("\n[token] using OSS_PROVIDER_TOKEN from .env")
        generated = False

    if not TEMPLATE.exists():
        sys.exit(f"Missing template: {TEMPLATE}")

    print("\n[1] Object store")
    s3 = s3_client(host_endpoint, key, secret)
    ensure_bucket(s3, bucket)
    if force:
        clear_prefix(s3, bucket, f"{TABLE_NAME}/")

    print("\n[2] Delta table")
    # delta-rs talks to the store directly over its own object_store
    # layer -- no Hadoop, no JVM. AWS_ALLOW_HTTP is required because the
    # local endpoint is plain HTTP; AWS_S3_ALLOW_UNSAFE_RENAME because
    # delta-rs otherwise insists on a DynamoDB lock table for concurrent
    # S3 writers, which a single-writer setup script does not need and
    # MinIO cannot provide.
    storage_options = {
        "AWS_ENDPOINT_URL": host_endpoint,
        "AWS_ACCESS_KEY_ID": key,
        "AWS_SECRET_ACCESS_KEY": secret,
        "AWS_REGION": REGION,
        "AWS_ALLOW_HTTP": "true",
        "AWS_S3_ALLOW_UNSAFE_RENAME": "true",
    }
    table_uri = f"s3://{bucket}/{TABLE_NAME}"
    version = build_table(table_uri, storage_options, force)

    print("\n[3] Server config")
    # The location the SERVER is given uses s3a:// (its Hadoop client)
    # and resolves against the CONTAINER endpoint from core-site.xml,
    # not the host one used above.
    server_location = f"s3a://{bucket}/{TABLE_NAME}"
    table_id = stable_table_id()
    rendered = (
        TEMPLATE.read_text()
        .replace("__BEARER_TOKEN__", token)
        .replace("__TABLE_LOCATION__", server_location)
        .replace("__TABLE_ID__", table_id)
    )
    for placeholder in ("__BEARER_TOKEN__", "__TABLE_LOCATION__", "__TABLE_ID__"):
        if placeholder in rendered:
            sys.exit(f"Template substitution failed -- {placeholder} still present.")
    write_0600(RENDERED, rendered)
    print(f"  {RENDERED.relative_to(REPO)} (0600)")
    print(f"  table location given to server: {server_location}")
    print(f"  table id: {table_id}")
    verify_rendered_config(rendered, server_location, table_id)
    verify_core_site()

    print("\n[4] Consumer profile (the artifact T-20 imports)")
    profile = {
        "shareCredentialsVersion": 1,
        "endpoint": f"http://localhost:{HOST_PORT}/delta-sharing",
        "bearerToken": token,
        "expirationTime": None,
    }
    write_0600(PROFILE, json.dumps(profile, indent=2) + "\n")
    print(f"  {PROFILE.relative_to(REPO)} (0600)")
    print(f"  share path: {SHARE}.{SCHEMA}.{TABLE_NAME}")

    print("\n" + "=" * 60)
    if generated:
        print("INCOMPLETE -- put the generated token in .env and re-run.")
        print("The config and profile written above use a token that is")
        print("not in .env, so they will drift the moment anything else")
        print("reads .env. Re-running makes all three agree.")
        return 1

    print("Ready. Next:")
    print("  docker compose up -d --build delta_sharing_server")
    print("  python3 scripts/11_probe_oss_provider.py")
    print(f"\nTable version {version}; two commits, so refresh behaviour")
    print("(T-19) and rotation (T-23) have real history to observe.")
    print("\nNOTE: the probe fetches pre-signed URLs, whose hostname is")
    print("the one the SERVER knows (objectstore), not localhost. If check 6")
    print("cannot resolve it, add to /etc/hosts:  127.0.0.1 objectstore")
    return 0


if __name__ == "__main__":
    sys.exit(main())
