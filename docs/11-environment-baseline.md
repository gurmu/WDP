# 11. Environment Baseline and Capability Matrix

Status: verified 2026-10-17/18 against the live workspace and the live
local Gravitee stack. Everything in this document is something that was
actually executed and observed, not read in documentation. Where a claim
comes from documentation rather than observation it is marked
**(doc only)**.

This is the foundation document. The implementation manual, the test
matrix and the epic playbooks all depend on the facts recorded here. If
any of these facts change, re-run the probes in Section 11.6 and update
this file first.

---

## 11.1 Why this document exists

CONOPS v1.5 was written against the *client-side* Databricks workspace
with Unity Catalog on AWS, a Gravitee test environment supplied by Data
Tooling, and partner teams supplying DSA templates, telemetry and
IaC/CaC tooling (Section 5.1, Section 8). None of that exists on a
single laptop.

The purpose of this prototype is to de-risk the parts of the milestone
one person can build alone, and to make *visible* the parts that cannot
start until a partner team is engaged. That only works if the gap
between CONOPS assumptions and the real local environment is written
down explicitly. Two findings in Section 11.4 and 11.5 contradict the
CONOPS text directly; both were proven empirically and both change how
Epic 1 must be built.

---

## 11.2 Local stack inventory

### Databricks

| Item | Value |
|---|---|
| Workspace host | `https://dbc-0c6ebc56-563d.cloud.databricks.com` |
| Tier | Free Edition |
| Cloud | AWS (matches OD-3, which decided AWS + Unity Catalog E2) |
| Auth used | Personal access token (PAT) in `.env` as `DATABRICKS_TOKEN` |
| Catalog / schema / table | `awoz1227_demo` / `opensharing_test` / `test_dataset` |
| SQL warehouse | `Serverless Starter Warehouse` (type PRO). Starts `STOPPED`; auto-starts on first statement, so allow ~1-2 min on the first SQL call of a session |
| Existing recipient | `psp7-demo-recipient`, auth type `TOKEN`, id `13ad6c00-c648-44ba-85c3-5bdb52f6a53e` |
| Share history | `history_data_sharing_status: ENABLED` on the shared table |

### Gravitee (local, `docker-compose.yml`)

| Service | Container | Port | Role in the CONOPS |
|---|---|---|---|
| `gateway` | `awoz1227-gateway` | 8082 | The "Gravitee edge domain", CONOPS 2.2 step 1 |
| `management_api` | `awoz1227-management-api` | 8083 | IaC/CaC target for Epic 6 (T-12) |
| `management_console` | `awoz1227-management-console` | 8084 | Admin UI |
| `developer_portal` | `awoz1227-developer-portal` | 8085 | Stands in for the OD-10 developer portal |
| `mongodb` | `awoz1227-mongodb` | internal | Management repo *and* rate-limit/spike-arrest counters |
| `elasticsearch` | `awoz1227-elasticsearch` | internal | Stands in for the SIEM (CONOPS 3.5) |

Image tag is `graviteeio/apim-*:4`; the resolved version in use is
**4.12.23 Community Edition**.

Two configuration facts in `docker-compose.yml` were established the hard
way and must be carried into the rebuild. They are not cosmetic; without
them the stack looks healthy and silently misbehaves.

The management API and gateway read Elasticsearch config from
`ds.elastic.host` / `ds.elastic.port`, **not** from
`analytics.elasticsearch.endpoints[0]`. The latter is not a key in this
image's schema, is ignored without warning, and leaves both services
trying to reach Elasticsearch on `localhost:9200`. The compose file sets
`gravitee_ds_elastic_host=elasticsearch` and
`gravitee_ds_elastic_port=9200` on both services.

The rate-limit and spike-arrest policies build their own Mongo
connection from `ds.mongodb.host` / `port` / `dbname`, which is a
*different* key from `gravitee_management_mongodb_uri` (that one only
configures the management repository). Those default to
`localhost:27017`, where nothing is listening inside the gateway
container, so every request that touches a rate-limit or spike-arrest
policy hangs until timeout rather than erroring. The compose file sets
`gravitee_ds_mongodb_host=mongodb`, `..._port=27017`,
`..._dbname=gravitee` on the gateway.

### Python

`requirements.txt` pins `databricks-sdk>=0.30.0`, `delta-sharing>=1.1.0`,
`pandas>=2.0.0`, `requests>=2.31.0`. Installed with
`pip install -r requirements.txt --break-system-packages`.

---

## 11.3 Verified-working capabilities

Each row was executed against the live workspace. These are the
capabilities the prototype may rely on.

| Capability | Evidence | CONOPS relevance |
|---|---|---|
| PAT authenticates and the REST API answers | `WorkspaceClient.current_user.me()` returns the user | A5; `00_check_capabilities.py` |
| Unity Catalog is enabled and catalogs are listable | `w.catalogs.list()` returns `awoz1227_demo` | 3.1 |
| Shares can be created, listed, altered | `w.shares` CRUD succeeds | 2.3.1, AC1/AC4 |
| Recipients can be created, listed, dropped | `w.recipients` CRUD succeeds | 2.3.1, AC4 |
| **Recipient IP access lists work** | Throwaway recipient `awoz1227_captest_tmp` created with `sharing.IpAccessList(allowed_ip_addresses=["203.0.113.5/32"])`; echoed back on read; recipient then deleted | 3.1 "defense in depth", 3.4.1 step 2, T-02/T-03, R7 |
| **Sharing a VIEW works** | `v_entitled_probe` created excluding `internal_notes`, added to the share successfully | The only working path for column scope — see 11.4 |
| Arbitrary SQL executes | `w.statement_execution` against the serverless warehouse | needed by every DDL step |
| Change data feed is shareable | `history_data_sharing_status: ENABLED` on the shared table | S9 route, T-19 refresh behaviour |
| Activation link retrievable by the provisioning process | `DESCRIBE RECIPIENT` / SDK returns it once | OD-4 step 3 |

Earlier in this project I assumed recipient IP access lists were a
Premium-tier feature and that T-02/T-03 defense-in-depth could not be
tested locally. **That assumption was wrong** and the README still
carries it as "Partial". They work on this Free Edition workspace, so
the Databricks-side half of the perimeter is genuinely testable here.

---

## 11.4 CORRECTION 1: column masks and row filters cannot be used on OpenSharing tables

CONOPS Section 3.1 ("Granular access in Unity Catalog", bullet "Table,
column and row scope") and Section 2.3.1 both state that sensitive
columns are excluded by *"sharing a view, **or applying column masks and
row filters**"*. Section 3.4 step 2 repeats it: the publish pipeline
*"applies masks and filters for the tier"*.

The second half of that is not possible. Both of these failed:

```sql
ALTER TABLE awoz1227_demo.opensharing_test.test_dataset
  ALTER COLUMN internal_notes SET MASK <fn>;

ALTER TABLE awoz1227_demo.opensharing_test.test_dataset
  SET ROW FILTER <fn> ON (tier);
```

with:

```
INVALID_PARAMETER_VALUE.ROW_COLUMN_SECURITY_NOT_SUPPORTED_WITH_TABLE_IN_DELTA_SHARING
Table ... is being shared with OpenSharing, and cannot use row/column security
```

This is architectural, not a tier limit. A table that is in an
OpenSharing share cannot carry row/column security at all, and a table
that carries row/column security cannot be added to an OpenSharing
share. The two features are mutually exclusive by design.

**Verified alternative, and the pattern this prototype adopts: share a
view.** A view that selects only the entitled columns (and, with a
`WHERE` clause, only the entitled rows) adds to the share without
complaint. `v_entitled_probe` proved this and was then cleaned up.

Consequences carried into the build:

| Where | Change |
|---|---|
| Epic 1 (T04-10) | The granular-access model is *view-based only*. Masks and filters are off the table. |
| Epic 4 (T04-13), publish pipeline | Step 2 creates a per-tier **view**, not masks and filters. |
| T-04 | Must be re-specified against a shared view, not a shared table. |
| CONOPS v1.6 | Section 3.1, 2.3.1 and 3.4 need the "or apply column masks and row filters" clause struck, with this error as the evidence. This is a document defect to raise, not a local workaround. |

This finding is worth more to the milestone than anything else in the
prototype: it would otherwise have been discovered in the client
workspace during the Section 5.3 verification session, in front of
stakeholders, against an AC1 claim that cannot be met as written.

---

## 11.5 CORRECTION 2: T-04 is invalid as currently built

`scripts/02_create_share.py` has a docstring claiming it withholds
`internal_notes` from the share. It does not. The live share contains:

```
awoz1227_demo.opensharing_test.test_dataset   data_object_type: TABLE
```

`internal_notes` is a column on that table, so a recipient with
`SELECT` on the share can read it. T-04 ("Request a table or column
outside the grant → Denied by Unity Catalog") therefore proves nothing
in the current build — the column is inside the grant.

T-04 must be rebuilt on the 11.4 view pattern: the share carries
`v_entitled_*` only, the base table is never added, and the test asserts
that the column is absent from the share metadata *and* that a direct
request for the base table is refused.

---

## 11.6 Free Edition capability matrix

The decisive question for this prototype was whether Free Edition can
act as an OpenSharing **provider**. Databricks documentation confirms
Free Edition can *consume* shares but does not document provider-side
support, and states Free Edition has "no access to the account console
or account-level APIs". The probe answered it empirically.

| Area | Free Edition status | Impact |
|---|---|---|
| PAT + workspace REST API | Works | none |
| Unity Catalog, catalogs/schemas/tables | Works | none |
| `CREATE SHARE`, `ALTER SHARE` | Works | none |
| `CREATE RECIPIENT` (bearer token), activation link | Works | none |
| Recipient IP access list | Works | T-02/T-03 fully testable |
| Share a view | Works | the granular-access pattern |
| Serverless SQL warehouse | Works (auto-start) | first call is slow |
| Column masks / row filters on shared tables | **Blocked — architectural, all tiers** | see 11.4 |
| Account console / account-level APIs | Not available **(doc only)** | no account-level audit log delivery config |
| `system.access.audit` system table | **Unconfirmed — must be probed in Epic 5** | AC5 join key depends on it (T-11) |
| Unity AI Gateway (surface) | **Available as of 2026-10-18** — live at `/ml/ai-gateway`; thirteen governed models in `system.ai`; tabs for Models, Providers, MCPs, Skills, Agents | M1/M2 routes, T-15/T-16 no longer blocked on tier availability; R11 downgraded |
| Model **invocation** through the AI Gateway | **Works — probed 2026-10-18.** `databricks-gpt-oss-20b` returned HTTP 200; `/api/2.0/serving-endpoints` lists 12 endpoints to an automation token | T-15 → BUILD. No quota refusal on Free Edition. Response `content` is an **array of typed blocks**, not a string, and the test call truncated at `max_tokens=16` — see §12.7 before writing gateway schemas |
| `databricks-genie` as a governed object | **Present but not a serving endpoint** — console lists 13, the API returns 12 | Workspace-located, `databricks-product: genie` tag. No row in the §3.1 access matrix; E6 IaC must target serving endpoints specifically |
| A callable Unity Gateway **MCP server** | **Still unconfirmed** — both guessed API paths returned `404 ENDPOINT_NOT_FOUND` to an authenticated token, while the console shows an MCPs tab | The open half of T-16. A 404 is neither a refusal nor a permission error, so the tab is likely on an unguessed path. M3's negative half is unaffected and remains BUILD — but see §12.7 item 4 on why M3's evidence must be a *gateway-generated* refusal |
| Unity Gateway **in GovCloud / at IL5** | **Not answerable here, ever** | This is commercial-region Free Edition. The surviving half of R11; ask 9a |
| Second metastore for D2D | **Available as of 2026-10-18** — the `glovashu` Unity Catalog with its own token | Unblocks T-19 and channel E-2; two probes still required (below) |
| Distinct-metastore identity of `glovashu` | **Unconfirmed — probe in Epic 1 Task 1.2** | D2D is metastore-to-metastore. Compare `SELECT CURRENT_METASTORE()` in both workspaces; identical IDs mean no D2D between them |
| Recipient with `authentication_type = DATABRICKS` | **Unconfirmed — probe in Epic 1 Task 1.2** | The existing recipient is `TOKEN` (D2O). Whether this tier permits a D2D recipient at all is untested |
| External open-protocol provider for D2O | **Available as of 2026-10-18** — open-source OpenSharing server, Delta tables versioned in GitHub | Unblocks T-20 and T-23; closes the D2O half of A10/R14 |

The "unconfirmed" rows are the highest-value unknowns left, and
2026-10-18 changed their character twice over. The AI Gateway row used
to be a **tier capability** that no amount of local work could resolve,
with A8 standing by to record it as not run. It is now split into four
rows, and the split is the point: the *surface* is confirmed, two
**local questions with a one-call answer** remain, and only the Gov
question is permanently out of reach. The two D2D rows are local
questions of the same cheap kind. So of the unknowns that once looked
like hard tier limits, exactly one — GovCloud availability — actually
is, and the rest are a morning's work in Epic 1 Tasks 1.2 and 1.9.

That pattern is worth noticing on its own, because it recurs: three
separate items on this baseline were recorded as tier limits and two of
the three turned out to be untested assumptions. The recipient IP
access list (11.3) was the first. The AI Gateway is the second. It is a
reason to probe before writing anything off, and a reason the ARB
package should distinguish *tested and unavailable* from *assumed
unavailable* in every row it carries.

One caution worth recording before the probe runs. A second *catalog* is
not a second *metastore*. On Free Edition a metastore is provisioned per
account per region, so `glovashu` supplies the D2D far side only if it
sits in a separate account; if it is another catalog under metastore
`48cda780-1dc7-459d-bee0-77abde9af938`, D2D between the two is refused
by construction, because a recipient cannot carry the provider's own
sharing identifier. The probe is cheap and the distinction is
load-bearing, so it is worth settling before any T-19 work is scheduled.

---

## 11.7 Open blockers carried into the rebuild

### B-1 Gravitee edge 404 — **reclassified 2026-10-18: upstream target error**

**Original diagnosis (2026-10-17 evening, now superseded).** All of
`/delta-sharing/`, `/delta-sharing/shares` and `/storage-proxy/`
returned 404 at `localhost:8082` while both APIs reported
`state: STARTED` but `lifecycleState: CREATED`. It looked like a
regression, because at 15:40 the same day T-03 produced a correct 403
from the `ip-filtering` policy, recorded in
`_secrets/t03-refusal-evidence.json` with the message
`Your IP (172.21.0.1) ... not allowed`. The hypotheses were (a) the
lifecycle was never moved to `PUBLISHED`, so the gateway ignored the
deployment, and (b) the 23:43 re-import created a duplicate API,
leaving two definitions fighting over deployment.

**Both hypotheses are wrong.** Re-probed 2026-10-18 09:27 UTC:

| API | Listener | Flows | Upstream target | Result |
|---|---|---|---|---|
| `a45a3c30…` *OpenSharing Perimeter* | `/delta-sharing/` | `perimeter-controls`, `storage-proxy-download` | `https://dbc-0c6ebc56-563d.cloud.databricks.com/api/2.0/delta-sharing` | **404** |
| `97a9f494…` *Metastore 48cda780* | `/opensharing-demo/` | none | `https://634cbc18-….opensharing.us-east-2.cloud.databricks.com/api/2.0/opensharing/metastores/48cda780-…` | **200** |

Both report `deploymentState: DEPLOYED`, and the gateway log carries
`ApiManagerImpl - API id[…] has been deployed` for each — so the gateway
picked up both. `lifecycleState: CREATED` governs **portal
publication**, not gateway serving. It is a red herring and should not
be cited again.

The decisive evidence is the body of the 404:

```json
{"error_code":"ENDPOINT_NOT_FOUND",
 "message":"No API found for 'GET /delta-sharing/shares'",
 "details":[{"@type":"type.googleapis.com/google.rpc.RequestInfo","request_id":"07793b21-…"}]}
```

That is a **Databricks** error envelope with a Databricks request id.
The gateway proxied correctly; the *upstream* rejected the path.
Gravitee's own 404 comes from `NotFoundProcessor` and does appear in the
log — but only for `/storage-proxy/`, which is B-3.

**Actual root cause.** `https://<workspace>.cloud.databricks.com/api/2.0/delta-sharing`
is not the sharing endpoint on this tier. Every issued credential file
carries
`https://<uuid>.opensharing.<region>.cloud.databricks.com/api/2.0/opensharing/metastores/<metastore-id>`,
and CONOPS §2.3.2 requires the target to be *"the endpoint from the
credential file plus the same path"*. The original API was built against
an assumed URL rather than the issued one.

Proof the gateway path works end to end:

```
GET /opensharing-demo/shares                      → 200
  {"items":[{"name":"awoz1227_demo_share1ashu","id":"7fdbadf0-…"}]}
GET /opensharing-demo/shares/…/all-tables         → 200
  {"items":[{"name":"ashu","schema":"default",…,"accessModes":["url"]}]}
GET /opensharing-demo/shares  (no Authorization)  → 401   (Databricks, not the edge)
```

So the two APIs are each half right — one has the policy flows and the
wrong target, the other the right target and no flows. Epic 2 Task 2.1
converges them into one. The duplication remains a real defect, but a
separate one: the import is not idempotent, which also fails AC6's T-12
by construction (E2 Task 2.2).

Three incidental findings from the same probe, all carried into E2:

- `accessModes: ["url"]` confirms this tier vends pre-signed URLs, so
  F1 / OD-1(b) does have response-body URLs to rewrite, in
  newline-delimited JSON on route S8.
- The working 200 leaks `server: databricks`, `server-timing`,
  `x-request-id` and three `X-Gravitee-*` headers, so **T-07 fails as
  currently configured** (E2 Task 2.8).
- The live share is `awoz1227_demo_share1ashu` exposing `default.ashu`,
  which does not match the `awoz1227_demo.opensharing_test.test_dataset`
  naming assumed elsewhere in this document and in
  `scripts/02_create_share.py`. Reconcile in E1 Task 1.4; see also 11.5.

### B-2 V4 APIs are invisible on the v1 management API

`GET /management/organizations/DEFAULT/environments/DEFAULT/apis`
returns `[ ]` even with APIs present. V4 API definitions are only
visible through v2:

```
POST /management/v2/environments/DEFAULT/apis/_search?page=1&perPage=20
```

Every import/verify script must use v2. The existing
`05_import_gravitee_api.py` predates this finding.

### B-3 Storage proxy path contradiction

`gravitee/api-definition.json` declares `/storage-proxy` as a *flow
selector* beneath the `/delta-sharing` listener, so the real edge path is
`/delta-sharing/storage-proxy`. But `.env` sets
`GRAVITEE_STORAGE_PROXY_URL=http://localhost:8082/storage-proxy`.
One of the two must change. Recommendation: give F1 its own listener
path so the OD-1(b) proxy route is independent of the sharing listener,
and keep `.env` as the source of truth.

### B-4 Secret hygiene violations in `_secrets/`

`.gitignore` covers `_secrets/`, so nothing leaked to git, but the
CONOPS test-data and custody rules (1.4 "never tokens, credential
files"; 2.4.3 "credential custody") are violated locally:

| File | Mode | Problem |
|---|---|---|
| `raw-credential1.json` | 664 | live bearer token world-readable |
| `gateway-credential1.json` | 664 | live bearer token world-readable |
| `rewrite_credential.py` | 664 | a divergent untracked copy of `scripts/04_rewrite_credential.py`, modified *later* than the tracked one — code living in the secrets directory |

**RESOLVED 2026-10-18, E1 Task 1.1.** All six files under `_secrets/`
are mode 0600, the stray script was **merged** into
`scripts/04_rewrite_credential.py` rather than deleted, and
`scripts/check_secret_hygiene.py` now asserts the rule on five axes.
Evidence: `evidence/secret-hygiene.json`, clean.

Three things came out of the fix that are worth more than the fix.

**The stray script was the more correct of the two.** It handled
`icebergEndpoint`; the tracked one did not. Deleting it — the obvious
reading of "reconcile or delete" above — would have destroyed the only
working iceberg handling in the repository. The lesson generalises:
*divergent copies in an unreviewed directory are not automatically the
inferior copy*, and the hygiene check now fails on any `.py` under
`_secrets/` precisely because code there is invisible to review.

**The live bypass is closed, and closed generically.** The repaired
script derives the provider host from the input file, walks every string
in the output, and refuses to write if any reference survives. That
converts OD-4 from "remember to rewrite the right fields" into an
assertion. A credential format that adds a fourth endpoint field will
fail loudly rather than silently shipping a perimeter bypass.

**The umask is the real root cause and is not fixed by this.** The repo
runs under `umask 0002`, so new files under `_secrets/` still arrive as
664. `chmod` cleans the past; only the check catches the future. Script
04 now chmods its own output to 0600 explicitly rather than trusting the
process umask.

### B-5 Repository staleness against v1.5

| Artifact | Problem |
|---|---|
| ~~`README.md`~~ | **Resolved 2026-10-18.** Rewritten against v1.5: epics cited to §1.6/§7/§10.2, coverage stated as all 25 tests by verdict, the recipient-IP-list verdict corrected per 11.3 |
| `tests/run_verification_session.py` | Docstring says "Section 6.3 ... seven steps". v1.5 puts the client verification session at **§5.3** with **eight** steps. Note the script is not simply wrong about the count — CONOPS §3.8 says "seven" too, which is defect **D-5** (docs/10 §10.7); the script must follow §5.3's eight |
| `docker-compose.yml` | Comments reference `tests/test_t11_trace_correlation.py`, which does not exist |
| `scripts/02_create_share.py` | Docstring claims a column exclusion it does not perform (11.5) |

### B-6 Upstream Delta Sharing image is arm64-only — **resolved 2026-10-18**

Found while standing up the D2O provider in Task 1.3, and recorded
because the failure mode is a trap for AC6 / T-12 rather than a
one-off annoyance.

| Observation | Detail |
|---|---|
| Tag availability | `deltaio/delta-sharing-server` publishes **no `latest` tag at all**. `latest`, `1.0.0` and `1.0.2` all fail `docker manifest inspect`; `0.7.5` and `0.7.0` resolve |
| Architecture | Both resolving tags are **single-manifest arm64**. The build host is amd64 (`x86_64`, Threadripper) |
| Symptom | `docker pull` succeeds, `docker compose config` validates, and the container then **exits immediately on start**. Nothing in the configuration is wrong |
| Emulation | No qemu binfmt handlers registered on this host, so arm64 cannot be emulated without additional setup |

**Why this is a T-12 finding and not a footnote.** Every surface that
normally catches a bad image reference passed: the reference resolved,
the pull succeeded, the compose file validated. The breakage appeared
only as a container that would not stay up — which, had it not been
investigated, would most plausibly have been written up as "the
open-source provider does not work here", i.e. as a *capability* finding
rather than a *packaging* one. That is the same error class as §12.9:
a condition that cannot be distinguished from a different condition.

**Resolution.** `oss-provider/Dockerfile` uses the arm64 image as a
build-stage **file source only** and copies `/opt/docker` onto an amd64
`eclipse-temurin:11-jre-jammy` runtime. The server is Scala/Java
bytecode plus a shell launcher, so nothing architecture-specific is
executed. Rejected alternatives, with reasons: downloading the release
zip at build time (adds a network dependency to every rebuild and pins
to a URL instead of a digest); vendoring the jars into git (~100 MB of
binaries for no traceability gain); qemu emulation (not installed, and
an emulated JVM is a poor basis for timing-sensitive gateway tests).

Three lessons, all generalisable to the client environment:

1. **Pin image tags, and verify the pin resolves for the target
   architecture.** `latest` would have failed here outright rather than
   drifting. An image reference is not validated by the pull succeeding.
2. **A container that exits is not evidence about the software.**
   Separate "will not start" from "does not work" before classifying.
3. **Java version is part of the pin.** The host runs JDK 21; the server
   predates it and the JPMS tightening in 17+ breaks reflective access
   in its Hadoop filesystem layer. The JRE is pinned inside the image so
   a host JDK upgrade cannot silently change the provider.

Verified by smoke test on the repackaged image: starts as uid 1000,
serves on 8080, returns **401 with no token** and
`{"items":[{"name":"smoketest"}]}` with a valid one — so startup,
protocol and authentication enforcement are all confirmed before any
test depends on them.

---

### B-7 A numeric uid with no `/etc/passwd` entry breaks the provider's filesystem layer — **resolved 2026-10-18**

Found immediately after B-6, on the first probe of the repackaged image.
Recorded separately because it produced a *different* symptom with the
same apparent cause ("the provider returns 500").

| Observation | Detail |
|---|---|
| Trigger | `user: "1000:1000"` in `docker-compose.yml`, set so the container could read a 0600 config bind-mounted from `_secrets/`. uid 1000 existed on the host but **not in the image** |
| Internal error | `KerberosAuthException: failure to login: LoginException: NullPointerException: invalid null input: name` |
| Reported to client | bare `HTTP 500 {"errorCode": "INTERNAL_ERROR", "message": ""}` |
| Affected routes | `/tables` and `/query` only. `/shares` and `/schemas` answered correctly throughout |

**Mechanism.** The server's filesystem layer is Hadoop, and Hadoop's
`UserGroupInformation` performs an OS login before it opens a path.
Running as a bare numeric uid makes that name lookup return null, and
the login throws. Nothing about the share configuration is involved,
which is why only the two routes that touch the filesystem failed.

**The diagnostic signature is the useful part.** `/shares` and
`/schemas` are served from the config file held in memory; `/tables` and
`/query` are the only routes that open a path. So *metadata fine, data
access failing* points at the filesystem layer, and a config error —
wrong share name, wrong indentation, unparseable YAML — would instead
have broken all four. Check which routes fail before blaming the table
or the protocol version.

**Resolution.** `oss-provider/Dockerfile` now creates a named `provider`
user at the build uid (`--build-arg APP_UID`/`APP_GID`, defaulting to
1000) and sets `HADOOP_USER_NAME=provider` as a belt-and-braces
short-circuit for the lookup. Verified in the running container:
`uid=1000(provider) gid=1000(provider)`.

Generalisable: **`--user` with a bare uid is not equivalent to running
as that user.** Any image whose software performs an OS-level identity
lookup — Hadoop, anything Kerberos-aware, anything calling `getpwuid` —
needs the uid baked in as a named account. The failure surfaces far from
its cause and arrives at the client as a bare 500.

---

### B-8 The Delta Sharing server cannot serve a `file://` table at all — **RESOLVED 2026-10-18**

**Resolution.** The finding itself stands unchanged and is permanent —
object storage is mandatory, not an upgrade. What is resolved is the
*blocker*: the table now lives in a local S3-compatible store
(`s3a://awoz-opensharing/test_dataset`, Scality CloudServer, B-10) with
the server's S3A client aimed at it by `oss-provider/core-site.xml`,
and the probe answers `query: WORKS` with `presigned_get:
RETRIEVABLE` — 1456 bytes of Parquet fetched from host `objectstore`
by signature alone. The empty-host-list caveat described below is
therefore no longer exercised, but the guard that produces it stays in
the probe: it is what would catch a regression to a local path, and
B-11 showed how quietly a storage misconfiguration can hide behind a
healthy-looking server.

Found on the next probe, after B-7 was fixed and the 500s persisted
unchanged.

| Observation | Detail |
|---|---|
| Internal error | `IllegalStateException: File system class org.apache.hadoop.fs.LocalFileSystem is not supported`, wrapped in `UncheckedExecutionException` |
| Reported to client | identical bare `HTTP 500 INTERNAL_ERROR` — **the same response as B-7** |
| Affected routes | `/tables`, `/query`. Discovery routes unaffected |
| Scope | Not a packaging or permissions problem. The server selects a cloud *file signer* by filesystem class and has no implementation for a local one |

**Why this is architectural, not configuration.** The Delta Sharing
protocol does not stream data: `/query` returns **pre-signed URLs** that
the consumer fetches directly from object storage. A local filesystem
has no concept of a pre-signed URL, so there is nothing for the server
to return. Object storage is therefore **mandatory for any D2O test
that reads data**, not an optional upgrade — and that holds in the
client environment too, however the provider is hosted.

**Consequence for the test matrix.** T-20's outbound-host capture is
only meaningful against object storage: under `file://` the URL list
carries no hostname, and an empty host list reads indistinguishably as
"no egress required". `scripts/11_probe_oss_provider.py` therefore
attaches an explicit caveat rather than reporting an empty list as a
result. Same shape as §12.9: **a check that cannot see a thing must not
be allowed to report what a check that looked and found nothing would
report.**

**Third instance of one response hiding two causes.** B-7 and B-8 both
arrive as `HTTP 500 {"errorCode": "INTERNAL_ERROR", "message": ""}`,
with identical route-level symptoms. The container log is the only
surface that distinguishes them. Fixing B-7 and re-probing produced
*byte-identical* probe output, which is precisely the condition under
which a fix gets mistakenly judged ineffective. For the client
environment: **the provider's error body is not a diagnostic. Budget
for log access on the provider side, or D2O faults are untriageable.**

**Open work.** Repoint the table at S3-compatible storage. Confirmed
viable from inside the image: `/opt/docker/conf` exists and is the last
entry on the launcher's `app_classpath` (`$lib_dir/../conf`), so a
`core-site.xml` dropped there is picked up; and the S3A stack is already
bundled — `hadoop-aws-2.10.1.jar`, `aws-java-sdk-bundle-1.12.189.jar`,
`jets3t-0.9.0.jar`. One question decides the design and is being probed
before any of it is built: **whether this version's S3 signer honours
`fs.s3a.endpoint`**, or signs against `s3.amazonaws.com` regardless. If
it honours the endpoint, a local MinIO service completes the provider.
If it does not, MinIO is a dead end and the table must live in real S3.

**Probe result, same day: it honours the endpoint.** `S3FileSigner`'s
constant pool contains `(Ljava/net/URI;)Lcom/amazonaws/services/s3/AmazonS3;`
— the signature of Hadoop's `S3ClientFactory.createS3Client(URI)`, which
reads `fs.s3a.endpoint` and `fs.s3a.path.style.access` and calls
`setEndpoint` itself. The decisive evidence is a **negative**: there is
no `AmazonS3ClientBuilder` reference. That class is the one that resolves
AWS endpoints independently of Hadoop config and would have pinned every
signed URL to `s3.amazonaws.com`. Its absence is why a local object store
is viable, and why **no AWS account is required for the D2O channel**.
Endpoint strings do not appear in the class because they live in
hadoop-aws's `Constants` — consistent with delegation, which is what the
descriptor already indicated.

---

### B-9 The pre-signed URL's hostname is inside its own signature — **by design, and it is the sharpest form of T-20**

Not a defect. Recorded because it converts T-20 from a procedural
deliverable into a hard constraint, and because the local workaround
looks like a hack while being a faithful miniature of the real problem.

The provider signs URLs using the endpoint *it* knows — here
`http://minio:9000`, the container-side name on the `awoz1227-backend`
network. SigV4 covers the `Host` header, so that hostname is part of what
is signed. A recipient therefore **cannot rewrite the host to something
it finds more convenient**: changing it invalidates the signature, and
the object store answers 403 with no indication that a rewrite was the
cause.

Consequences, in increasing order of how much they matter to the client:

1. Locally, the consumer must resolve the provider's storage name. One
   line in `/etc/hosts` — `127.0.0.1 minio` — and port 9000 published.
2. A recipient-side allow-list must name the **provider's** storage
   endpoint exactly as the provider spells it. An allow-list built from
   an IP range, a CNAME, or a proxy alias will fail on the signature
   rather than on connectivity, and the error will not say so.
3. This is why CONOPS 2.4.3's T-20 deliverable is the *procedure* and not
   the host list. The procedure transfers; the hostnames belong to
   whichever storage account the provider happens to use, and they change
   when the provider's storage changes without the sharing configuration
   changing at all.
4. It also bounds what a gateway can do on this path. Gravitee can front
   the Delta Sharing **control plane** (`/shares`, `/query`), but the
   **data plane** is a direct signed fetch from the recipient to the
   provider's object store. A gateway cannot transparently proxy that
   without breaking the signature. Any claim that the gateway mediates
   D2O traffic must be qualified to mean metadata only — see also B-3's
   storage-proxy path contradiction.

**T-21 improves as a side effect.** Read-only used to rest on a `:ro`
bind mount, which is a flag we set on our own container and demonstrates
nothing about what a recipient can do. The signer builds
`GeneratePresignedUrlRequest` with `HttpMethod.GET` (visible in the same
constant pool), so the recipient's URL is signed for reading only and a
`PUT` with it is refused by the store. `scripts/11_probe_oss_provider.py`
check 7 now tests that directly. Enforcement moved from our side of the
boundary to the protocol's.

---

### B-10 The MinIO community image is no longer anonymously obtainable, from either registry — **OPEN, store being swapped**

A dependency that was freely pullable became gated, which is a supply
risk rather than a bug, and it is recorded as one.

| Registry | Reference | Response |
|---|---|---|
| quay.io (MinIO's own) | `minio/minio:latest` | `401 Unauthorized` on `HEAD /v2/minio/minio/manifests/latest` |
| quay.io | `minio/minio:RELEASE.2025-04-22T22-12-26Z` | `401 Unauthorized` |
| Docker Hub | `minio/minio:latest` | `pull access denied ... repository does not exist or may require 'docker login'` |
| Docker Hub | `minio/minio:RELEASE.2024-06-13T22-53-53Z` | same |
| quay.io API | `GET /api/v1/repository/minio/minio/tag/` | `{"detail": "Requires authentication", "error_type": "invalid_token", "status": 401}` |
| dl.min.io | `/server/minio/release/linux-amd64/minio` | **HTTP 410 Gone** |
| dl.min.io | `…/minio.sha256sum` | **HTTP 410 Gone** |

The 410 is the decisive line. A 404 would leave "moved, renamed, or
mistyped" open; **410 Gone is a deliberate statement that the resource
existed and has been withdrawn.** Together with quay's explicit
`Requires authentication`, that closes off the three remaining escape
routes at once: there is no alternate registry, no older tag, and no
direct binary download to pin by checksum. The last of those had been
the preferred fallback, because a published SHA256 is as strong a pin as
a registry digest.

**Ruled out before concluding**, which is the only reason the above can
be read as a statement about the image rather than about the host:
`docker pull hello-world` succeeds; `docker manifest inspect
hello-world:latest` returns a manifest; `docker info` shows no registry
mirror, proxy or allow-list. Egress, DNS, daemon configuration and the
anonymous rate limit are all eliminated. Two independent registries
refusing the same repository, while a third-party image on one of them
pulls normally, leaves only the repository itself.

Note the two registries express one condition in two incompatible
vocabularies. quay.io is precise — `401 Unauthorized` means
*authenticate*. Docker Hub returns a single message for at least four
conditions: removed, private, rate-limited, and never-existed. Taken
alone, the Hub message would have sent us looking for a typo.

**Impact.** No test verdict changes. The store is a local stand-in for
the client's S3/ADLS; the `s3a://` table location, the pre-signed URL
mechanics and B-9's signature constraint are properties of the protocol
and the S3A client, not of MinIO.

**Resolution: Scality CloudServer.**
`scripts/13_probe_object_stores.sh` probed the field rather than
selecting on reputation. All four non-MinIO candidates pulled on amd64:
`zenko/cloudserver:latest`, `dxflrs/garage:v1.0.1`,
`chrislusf/seaweedfs:3.69`, `localstack/localstack:3`. Selection
criteria were path-style addressing, SigV4, GET pre-signing, **refusal
of a write with a GET-signed URL**, and amd64.

That fourth criterion decided it, and it is doing real work rather than
being thorough for its own sake. A store that ignores signatures would
pass probe checks 1–6 and then *accept* the tampering PUT in check 7,
producing a false `ACCEPTS_WRITE` against T-21. **A permissive stand-in
is worse than no stand-in, because it manufactures a negative finding
about the protocol that the protocol does not deserve.** On that basis
SeaweedFS was ranked below CloudServer and Garage (its S3 gateway
permits anonymous access until identities are configured) and LocalStack
last (historically lenient about signature verification). Garage remains
the documented fallback; it is equally strict but needs a TOML config
and a key-creation step.

**Two naming decisions taken because of this, not because of tidiness.**
The compose service is `objectstore` and the credentials are
`OBJECTSTORE_ACCESS_KEY` / `OBJECTSTORE_SECRET_KEY`. The service name
ends up inside the signature of every pre-signed URL (B-9), so a
product name there would require re-editing `core-site.xml`,
`/etc/hosts` and every captured T-20 artifact at the next swap — and
`MINIO_ROOT_USER` configuring a Scality server is precisely the kind of
stale name that misleads a reader six months later. Name the role. For
the same reason `scripts/12_pin_object_store.sh` anchors its rewrite on
a `# PIN-TARGET` sentinel comment rather than on the vendor string:
a rule keyed to the old vendor matches nothing after a swap.

**For the client environment — the transferable point.** This is not a
laptop inconvenience; it is the ordinary failure of an unmirrored
dependency, hit live. A pinned digest guarantees *which* bytes, not
*that they remain fetchable*. T-12's "redeploy from code" is only true if
the code's dependencies are still obtainable at redeploy time, which is
an argument for an internal registry mirror holding every pinned image
rather than for tighter pins.

#### B-10a The pinning step wrote a broken reference, twice

Worth its own heading because it is the same defect as §12.9 and B-6,
and because I introduced it a second time *inside the fix for it*.

**First instance.** Three shell lines chained with no assertion between
them: `docker pull` failed, `docker image inspect` failed, `DIGEST`
resolved to the empty string, and `sed` substituted it into a tracked
file, producing `image: minio/minio@`. Every command reported its own
error; the net result was still a silently corrupted artifact that
failed later, at `docker compose up`, as `invalid reference format` —
far from the step that caused it.

**Second instance.** The replacement script put `docker manifest
inspect` in front of the pull as a cheap pre-check and discarded its
stderr with `2>/dev/null`. Every candidate then reported "does not
resolve" regardless of why, and the real 401 stayed hidden for a round
trip. A failure in the *check* had been made indistinguishable from a
failure in the *thing being checked*.

So the rule is not "add assertions". It is:

> **Never discard the error text of the thing you are asserting on, and
> never put a weaker check in front of the authoritative one.**

`docker pull` is authoritative; `docker manifest inspect` is a
convenience. `scripts/12_pin_object_store.sh` now gates on the pull
alone, prints each candidate's verbatim failure, and writes nothing
unless the reference pulls, reports `amd64` (B-6's trap) and yields a
digest matching `^sha256:[0-9a-f]{64}$`. It rewrites exactly one image
line and aborts if it matches any other number.

Carried forward as a requirement: **every registry reference in this
repository is pinned by digest; the pin is produced by a step that
verifies before it writes and fails closed; and no diagnostic step
discards the error text it is diagnosing.**

#### B-10b A blank placeholder in `.env` became a positive assertion

**Status: resolved.** Fifth instance of the §12.9 shape, and the
cheapest one to misdiagnose.

`scripts/10_setup_oss_provider.py` died before touching the object
store at all:

```
botocore.exceptions.ProfileNotFound: The config profile () could not be found
```

raised from inside `boto3.client("s3", ...)` — a call that passes the
endpoint, both credentials and the region explicitly, and so appears to
need nothing from the environment. The empty parentheses are the whole
finding: something had set `AWS_PROFILE` to the **empty string**, and
botocore does not treat that as "no profile selected". It treats it as a
profile whose name happens to be `""`, looks it up, and fails.

The path in: `.env` carries `AWS_REGION=` and `AWS_PROFILE=` as blank
prompts for a reader who might be on a Databricks tier that provisions
into their own AWS account (and, from an earlier edit, carries each of
them twice). The script's `.env` loader did
`os.environ.setdefault(k, v)` on every `k=v` line it could parse, so a
placeholder written to mean *"nothing is set here"* was injected as
*"use the profile named `''`"*. An absence had been converted into an
assertion, and the error named neither the file, nor the variable, nor
the conversion.

Note what did **not** catch it. The script's own `require()` guard
rejects unset and `<...>`-style values, but it only inspects the four
`OBJECTSTORE_*` / `OSS_PROVIDER_*` variables this script actually reads.
`AWS_PROFILE` is not one of them, so the damage was already in
`os.environ` before any validation ran. Validating the variables you
consume does not protect you from the ones you merely forward.

Two fixes, deliberately both:

1. The loader now `continue`s on a blank value instead of setting it,
   so a placeholder in `.env` stays an absence.
2. `s3_client()` pops `AWS_PROFILE` / `AWS_DEFAULT_PROFILE` when blank
   and builds its own
   `boto3.session.Session(profile_name=None, ...)` rather than boto3's
   implicit module-global default session.

The second is not redundant. The symptom names no file, so if the empty
value is exported by the user's shell rather than coming from `.env`,
fix (1) cannot see it and the same crash returns with the same
unhelpful message. Fix (2) also covers the delta-rs write that follows,
because the Rust `object_store` credential chain reads the same
variables; `s3_client()` runs before `build_table()`, so the pop
protects both.

**Consequence for the probe results captured during this failure.**
`scripts/11_probe_oss_provider.py` reported `tables: MISSING`,
`query: FAILED`, and `presigned_get` / `presigned_put_refused` as
`NOT_ATTEMPTED`, while `shares`, `schemas` and `auth_refusal` passed.
That is entirely explained by setup never having run: discovery is
served from the in-memory config, so only `/tables` and `/query` touch
storage. **It is setup-incomplete, not a finding about the D2O channel,
and must not be entered in the test matrix as a T-20/T-21/T-23
result.** The probe's `NOT_ATTEMPTED` verdicts are the B-10a design
working as intended — "not attempted" and "attempted and refused" are
different findings and are reported differently.

Carried forward as a requirement: **a placeholder is an absence, so
every `.env` loader in this repository treats a blank value as unset
rather than forwarding it; and where a third-party SDK reads
configuration from the environment behind an explicit API, pass an
explicit session rather than trusting the environment to be clean.**

#### B-11 A healthy-looking provider with two invisible faults

**Status: resolved.** With B-10b fixed, setup completed: bucket created,
Delta table written at version 1 with 3 data files, config and consumer
profile rendered. The server rebuilt, started, and answered `/shares`
and `/schemas` correctly. It was nonetheless broken in two independent
ways, and **neither was visible from the outside**, which is why both
belong here rather than in a commit message.

**Fault 1: the server's Hadoop config never loaded.** `/tables`
returned `{"errorCode":"INTERNAL_ERROR","message":""}` with HTTP 500 and
an empty message. The container log carried what the response omitted,
including this, logged while serving an unrelated request:

```
ERROR org.apache.hadoop.conf.Configuration - error parsing conf core-site.xml
com.ctc.wstx.exc.WstxParsingException: String '- -' not allowed in comment
 at [row,col,system-id]: [17,35,"file:/opt/docker/conf/core-site.xml"]
```

XML forbids two adjacent hyphens inside a comment. The header comment
used the sequence three times as a prose dash, as most of this
repository's comments do. So the file was rejected **in its entirety**,
Hadoop logged it at ERROR, and **then continued with default
configuration**. Consequences: `fs.s3a.endpoint` unset, so the S3A
client would resolve `s3.amazonaws.com`; `path.style.access` unset;
and, worst, the credential provider unpinned, restoring exactly the
multi-minute `169.254.169.254` hang that B-5 pinned it to avoid.

The provider would have *looked* correct — container healthy, discovery
served, `docker compose ps` green — while signing every URL against
AWS. A config file that fails to parse and one that was never installed
are indistinguishable from outside the process. This is the §12.9 shape
again, and this time it was load-bearing: had the table id fault not
masked it, the first conclusive T-20 evidence would have been captured
from a server whose storage configuration was absent.

**Fault 2: `id` is mandatory on a table, and nothing says so.** The 500
on `/tables` was a `NullPointerException`:

```
java.lang.NullPointerException
  at SharedTableManager.$anonfun$listAllTables$4(SharedTableManager.scala:168)
  at SharedTableManager.listAllTables(SharedTableManager.scala:160)
  at SharedTableManager.listTables(SharedTableManager.scala:140)
```

Read from the shipped jar's constant pool, that lambda touches exactly
two `TableConfig` members — `getName()` and **`id()`** — and builds a
`protocol.Table` from them. `TableConfig` itself validates two fields
and only two; its error strings are `'name' in a table must be
provided` and `'location' in a table must be provided`. **There is no
validation of `id`**, so a table without one loads cleanly, the server
starts, and the omission surfaces only later, as an empty-messaged
HTTP 500, on every endpoint that lists tables.

Note which endpoints survived. `/shares` and `/schemas` build their
responses via `withName`/`withShare` and never read a table, so they
answered 200 throughout. Only `/tables` and `/all-tables` enumerate
tables, and both route through `listAllTables`. Discovery working is
therefore *not* evidence that a share is usable — a split worth keeping
in mind when reading §12.8's per-test rows.

The fix is a `id` on the table, rendered by
`scripts/10_setup_oss_provider.py` as a **uuid5 over the
share/schema/table names**, not a uuid4. Determinism is a T-12
requirement here: a rebuild from code must produce the same table id,
because a recipient that cached the old one would otherwise see a
different table after the provider is redeployed.

**Fault 3, mine: the probe conflated "absent" with "could not look".**
`scripts/11_probe_oss_provider.py` reported `tables: MISSING` and
advised checking the shares block for a name mismatch — in a config
that was correct. It had two outcomes where three exist, so HTTP 500
read as "not published". The remedy text then actively misdirected.
Check 3 now reports `WORKS` / `MISSING` (200 and genuinely absent) /
`ERROR` (the call failed, which is *not* evidence about publication),
and the `ERROR` branch points at the container log, because the useful
text is there and never in the response body.

Three guards were added, all asserting on the **product** rather than
the procedure, because the existing placeholder-substitution check
passed throughout: it proved only that no placeholder *survived*, never
that the result was valid or complete.

1. `verify_core_site()` parses `oss-provider/core-site.xml` and asserts
   the endpoint, path-style and credential-provider properties are
   present — before the image is built, since Hadoop will not fail on
   it afterwards.
2. `verify_rendered_config()` parses the rendered YAML and asserts the
   table carries `name`, `location` **and `id`**, naming B-11 in the
   failure text.
3. The comments in both files now record why: `core-site.xml` states
   the hyphen rule, and the config template states that `id` is
   required despite being unvalidated.

Carried forward as a requirement: **a configuration file that the
runtime parses leniently must be parsed strictly by the step that
installs it, and every field the runtime dereferences must be asserted
by that step even when the runtime's own validator ignores it.** The
general form, now at seven instances: *an artifact that cannot be read
must never be allowed to resemble an artifact that was read and found
empty.*

Also fixed in passing: the config template's header comment contained a
literal copy of the bearer-token placeholder, so rendering substituted
the live token into a comment as well as into the `authorization`
block. The rendered file is 0600 and gitignored, so nothing leaked, but
the token appeared twice in a file people are invited to paste excerpts
from. The comment no longer spells the placeholder out.

#### B-12 T-21: the refusal, the control, and the error code

**Status: resolved, and T-21's evidence is now protocol-level.**

Check 7 replaying the recipient's URL as a `PUT` and getting 403 was
never sufficient on its own. A 403 is consistent with two
explanations: the HTTP method is inside the signature (T-21's claim,
which transfers to any S3-compatible store and to the client
environment), or this particular stand-in store refuses pre-signed
writes as a matter of policy (which transfers nowhere and would mean
T-21 rested on a property of a vendor we picked by availability). Check
7 cannot distinguish them, so presenting it alone to an ARB would be
inviting the obvious question with no answer ready.

Check 8 is the control: sign a URL **for PUT** against the same store,
bucket, endpoint spelling and credentials, send it with no
`Authorization` header, and confirm it is accepted. It differs from
check 7 in one variable, the signed method. One deviation is recorded
in the evidence rather than hidden: the control writes to a scratch key
instead of the shared Parquet file, because overwriting a data file
would corrupt the Delta table and poison every later read; store
authorization does not vary by key within a bucket, so the comparison
holds. The scratch object is deleted afterwards, since leaving a
writable artifact inside the shared bucket would muddy any later T-21
or T-23 capture.

**The control's first run failed, and nearly produced a false
negative.** It returned 403 `SignatureDoesNotMatch`, and had the probe
recorded only the status it would have read as *"this store refuses
pre-signed writes"* — the stronger and wrong conclusion. What saved it
was recording the signature version of both URLs: the control was
**SigV2**, the recipient's URL **SigV4**. Botocore signs pre-signed URLs
with SigV2 against a custom endpoint unless `signature_version="s3v4"`
is set explicitly. So the control had failed on its own invalidity
while reporting a verdict about the store.

This is the eighth instance of the §12.9 shape and the most dangerous
form of it so far, because the artifact at risk was not a config file
but a **finding**. Two guards followed. The probe now asserts the two
signature versions match and reports `INVALID_CONTROL` — not
`CONTROL_FAILS` — when they do not, because a control signed
differently from the thing it controls for yields a result about
signature versions, not about methods. And `t21_strength` is recorded
as a separate field with three values: `PROTOCOL_LEVEL` (refusal plus
passing control), `UNATTRIBUTED` (refusal alone), `NOT_DEMONSTRATED`.
The run's conclusion line refuses to claim T-21 at anything above what
the control earned.

**The evidence, with the control passing:**

| Request | Signed for | Result |
|---|---|---|
| GET the recipient's URL | GET | **200**, 1456 bytes of Parquet, no `Authorization` header |
| PUT the same URL | GET | **403 `SignatureDoesNotMatch`** |
| PUT a PUT-signed URL, same store/bucket/endpoint | PUT | **200** |

The error code is the sharpest line in the table, and it is why the
body was worth keeping rather than just the status. `AccessDenied`
would have indicated a bucket policy — our own configuration, proving
nothing about the protocol. **`SignatureDoesNotMatch` means the store
recomputed a signature over the request as presented and got a
different value**: the method is part of the signed material. Combined
with the constant-pool reading of `S3FileSigner`
(`GeneratePresignedUrlRequest` with `com/amazonaws/HttpMethod`, B-9),
the claim is now both static and observed.

So the T-21 sentence for the ARB package is: *a Delta Sharing recipient
cannot promote a read URL into a write, because the provider signs each
URL for GET and the method is covered by the signature — demonstrated
by a refused write whose error code shows signature recomputation, with
a PUT-signed control against the same store accepted.* That replaces
the original evidence, a `:ro` bind mount, which was a flag we set on
our own container and demonstrated nothing about a recipient.

Carried forward as a requirement: **a refusal is not evidence until a
matching permitted case has been shown to succeed, and any control must
be verified to differ from its subject in exactly one variable — a
control that fails for its own reasons is worse than no control,
because it reads as a real negative.**

#### B-13 The hygiene gate's first false positive, and the two fixes that were wrong

**Status: resolved. The gate is now stricter, not looser.**

`scripts/14_probe_d2o_provider_import.py` needs a Delta Sharing profile
that names **no endpoint**, because that is the discriminator which makes
reachability impossible by construction and so leaves capability as the
only thing check 2 can be measuring. The token in it is
`dummy-not-a-real-token`. The gate's bearer-token pattern has a 20
character floor; the dummy is 22, so the gate failed the run.

Two fixes presented themselves and both were refused.

**Shorten the dummy below 20 characters.** This makes the scanner quiet
without making the repository safer. Worse, it leaves the trap armed:
the next probe that needs a placeholder token writes a plausible-length
one and the gate says nothing, because the gate's threshold was never
the problem.

**Add the file to the gate's exclusion list.** This repeats, exactly,
the mistake already rejected for the `X-Amz-Credential` pattern and
recorded in the gate's own comments — *it makes one file the single
place the scanner cannot see*. The file it would blind the scanner to is
a file that handles live credentials.

The fix taken: the pattern now **captures** the matched value, and a
value is exempt only if it asserts in its own text that it is not real,
anchored at both ends:

```python
DECLARED_PLACEHOLDER = re.compile(
    r"^(?:"
    r"<redacted[^<>]*>"
    r"|__[A-Z0-9_]+__"
    r"|[a-z0-9-]*not-a-real-(?:token|secret|credential|password)[a-z0-9-]*"
    r")$"
)
```

A real token cannot claim to be a placeholder, because a real token
does not contain the words `not-a-real-token`. So the exemption cannot
be reached by accident, only by writing a value whose own text is the
declaration. And **every exemption is printed** rather than silently
skipped:

```
note  declared placeholder exempted -- Delta Sharing bearer token in
      scripts/14_probe_d2o_provider_import.py: dummy-not-a-real-token
```

That last detail is the §12.9 shape again. An exemption that leaves no
trace in the output makes a clean run and a run that skipped three
checks indistinguishable from the outside. The run prints
`3 declared placeholder(s) exempted` next to `48 files scanned`, so the
count of things *not* checked is on the same line as the count of things
checked.

---

#### B-14 `CREATE PROVIDER` from a file returns 200 without validating anything, and the refusal that follows is not a network error

**Status: characterised, and it is the foundation of defect D-6.**

Importing a D2O credential file on Free Edition **succeeds**. The
provider object is created, returns `200`, and appears in the metastore.
It is created without the control plane ever contacting the endpoint
inside the file. Creation validates the endpoint's **URL syntax only** —
supply a malformed one and the refusal is explicit about which stage
rejected it:

```
DS_INVALID_FIELD: ... endpoint is not a valid URL
```

The first call that actually crosses the network is the confirming one
(`SHOW SHARES IN PROVIDER`, §2.4.1's D2D column). Against a loopback
endpoint it returns:

```
400 DS_FAILED_REQUEST_TO_OPEN_DS_SERVER: Error while connecting to the
sharing server at http://localhost:8086/delta-sharing/shares
... error: class java.lang.SecurityException
```

**`SecurityException` is not a network error**, and the distinction
carries the whole finding. There is no timeout, no connection-refused,
no `UnknownHostException`. The control plane declined to *attempt* the
call. Which leaves two readings — the tier cannot do this, or the
address cannot be reached — and those two are indistinguishable from the
observable, because both produce "no shares were listed".

Check 5 of probe 14 separates them: the same call, same dummy-token
shape, against `https://example.com/delta-sharing` — one public
routable host on the IANA documentation domain. It returned
`404 DS_RESOURCE_NOT_FOUND_ON_DS_SERVER` **with the upstream HTML body
echoed back**, which only happens if the request genuinely left the
control plane and something answered it. So the guard is scoped to the
**address class**, not to the tier and not to Delta Sharing:
`GUARD_SCOPED_TO_ADDRESS_CLASS`.

That is what licenses the transfer claim. The procedure in §2.4.1 runs
against a client's routable provider; it cannot run against this
prototype's loopback provider. The limitation is in our topology, which
is why T-20's verdict is `PASS_WITH_SCOPE` and not `FAIL`, and why the
evidence says `CONTROL_PLANE_BLOCKED_BY_LOCAL_TOPOLOGY` rather than
`..._BY_TIER`. Probe 14 keeps those as three separate verdicts
(`_BY_LOCAL_TOPOLOGY`, `_BY_RECIPIENT_EGRESS_POLICY`, `_SCOPE_UNKNOWN`)
deliberately, because collapsing them would let a local artefact be
reported as a tier limitation in a CONOPS.

**Then the part that matters for v1.6.** With the confirming call
already refused, step 5c created the catalog from the share anyway —
`200 CREATED` — and step 6 granted `USE CATALOG`, `USE SCHEMA` and
`SELECT` on it — `200 GRANTED`. The platform does not enforce the
ordering. Following §2.4.1's D2O column literally produces a catalog
that is registered, granted, visible in the consuming team's namespace,
and dead at the first `SELECT`. Recorded as **D-6** in docs/10 §10.7.

---

#### B-15 A live pre-signed URL reached the evidence file

**Status: resolved, and caught by a guard written for exactly this.**

T-20's necessity phase permits only the provider endpoint, so the data
read is *supposed* to fail. `delta_sharing.load_as_pandas` fails by
raising `FileNotFoundError` **whose message is the full pre-signed URL
it could not fetch**, and the capture recorded `str(exc)[:400]`. That
put `X-Amz-Credential`, the credential scope and a live
`X-Amz-Signature` into `evidence/t20-ingress-d2o.json`, at
`/path_b_client/necessity/read/data/error`.

The gate caught it on the next command of the same run, with two
violations. The patterns that caught it were added in the previous
session, with a comment saying they existed "to catch that guarantee
being dropped by a later edit". **A new test writing a new evidence
file is precisely that edit, and it took one session.**

B-9 already establishes that a pre-signed URL *is* a credential. What
T-20 needs from it is the **host** — that is the whole point of the
§2.4.3 capture. What must never be recorded is the **query string**. So
the scrubber keeps the host and replaces the query:

```python
def scrub(text):
    if not isinstance(text, str):
        return text
    return PRESIGNED_QUERY.sub(r"\1?<redacted-presigned-query>", text)
```

Scrubbing is applied at the points where exceptions are captured **and
over the serialized JSON immediately before each write**. Belt and
braces on purpose: scrubbing only at capture is what was done first,
and it missed one, because an exception string can arrive through any
field a later edit adds — a stderr tail, a nested cause, a message
echoed by a library.

The file was untracked, so nothing reached git history, and it was
scrubbed in place at once to take the live signature off disk. But a
repaired artefact is not evidence that the repair works, so the test
was re-run and the file **generated** clean.

---

#### B-16 The redaction marker was appended three times, because nobody checked its output

**Status: resolved. The scrubber is now idempotent and tested in-run.**

The regenerated evidence was clean of secrets but read:

```
...part-00000-...-c000.snappy.parquet?<redacted-presigned-query><redacted-presigned-query><redacted-presigned-query>
```

Three markers, one URL. `scrub()` runs three times over the same string
by design — once where the exception is caught inside the phase
subprocess, once when that subprocess serializes its own `--out` file,
once when the parent serializes the combined record — and it was not
idempotent. The cause is subtle and worth recording: the marker contains
`<` and `>`, which the pattern's query character class **excludes**, so
an already-scrubbed URL presents an *empty* query to the regex, and
`[^\s'\"<>]*` matches empty quite happily and appends another marker.

Nothing leaked. But a reader counting markers would reasonably conclude
three secrets had been removed from one URL, and a count that cannot be
trusted is this project's own defect shape in miniature: **a record
asserting more than was measured.**

The pattern now refuses to re-redact, for two independent reasons,
because one of them is luck:

```python
PRESIGNED_QUERY = re.compile(
    r"(https?://[^\s'\"<>]+?)\?(?!<redacted-presigned-query>)[^\s'\"<>]+"
)
```

`+` rather than `*` — a query with no characters holds no secret, so a
bare trailing `?` is left alone. That alone happens to fix the repeat,
but only by accident of `<>` being outside the class, and it stops being
true the moment the marker text changes. The negative lookahead states
the intent directly and survives a redesign of the marker.

**The real finding is that the scrubber had no test.** B-15 reached disk
because `scrub()` did not exist; B-16 happened because it existed and
its output was never asserted on. An unchecked redaction function is the
§12.9 shape once more — a record with no secret in it and a record whose
scrubber silently stopped matching look identical from the outside.

`assert_scrub_contract()` now runs in the parent and in every phase
child before anything is written, against the real B-15 leak value, and
checks five properties: the gate's patterns no longer match; the host
survives (it *is* the T-20 evidence); the function is idempotent across
all three passes; a URL with no query is untouched; every URL in a
multi-URL string is covered. The pass/fail bar is
`check_secret_hygiene.py`'s own `TOKEN_PATTERNS`, **imported rather than
restated**, so "scrubbed" means exactly "the gate will accept it" — the
same one-source-one-verdict rule that makes T-20 import probe 14's
classifier instead of copying it. If that list cannot be loaded the test
**refuses and exits**, because an unchecked scrubber must not be
reported as a passing one.

The contract was then verified to be capable of failing, against four
deliberately broken scrubbers:

| Scrubber under test | Result |
|---|---|
| Current | **PASS**, 10 gate patterns applied |
| The old non-idempotent pattern | **REFUSED** — "scrub() is not idempotent" |
| A no-op (`lambda t: t`) | **REFUSED** — SigV4 signature *and* credential scope still match |
| Over-eager (replaces whole URLs) | **REFUSED** — "scrubbing destroyed the host, which IS the T-20 evidence" |

The last row is the one worth keeping. A scrubber that deletes too much
passes every secret-detection check ever written and quietly destroys
the finding the test exists to produce.

Carried forward as a requirement: **a redaction function is test
infrastructure and must be tested against the gate's own patterns in the
same run that relies on it, including a case that proves it has not
over-redacted the evidence.**

---

#### B-17 The test that proves the scrubber works needs a fake credential, and the gate cannot tell

**Status: resolved. The fixture is now derived rather than embedded, and
the test can no longer pass vacuously.**

B-16's fix introduced `assert_scrub_contract()`, which needs a
pre-signed URL to scrub. The first version embedded one as a literal: a
fabricated 64-character hex signature and a SigV4 credential scope. The
gate failed the file, with two violations, and it was right to. **A
credential scanner that can distinguish a test fixture from a live
credential by looking at it is not a credential scanner.**

The same two bad fixes as B-13 were available, and the second is worse
here than it was there.

*Exclude the test file.* It repeats the rejected pattern, on a file that
genuinely handles live pre-signed URLs.

*Soften the fixture until the gate ignores it.* This one is not merely
unsafe, it is self-defeating. **The fixture's only job is to be
something the gate would flag.** Every assertion in the contract asks
whether gate patterns stop matching *after* scrubbing; if they never
matched *before*, each one passes trivially and the function prints
`VERIFIED` having measured nothing.

Which exposed the hole that mattered: **nothing checked that the fixture
tripped the gate in the first place.** Had the fixture been softened —
or had the gate's pre-signed patterns later been renamed or weakened —
the contract would have reported success. The function written to
prevent the §12.9 shape contained it.

Two fixes, and the second is the important one.

**The fixture is synthesised at runtime from a published seed**, so no
credential-shaped literal exists in the file:

```python
FIXTURE_SEED = b"t20-scrubber-contract-fixture-not-a-real-credential"
sig = hashlib.sha256(FIXTURE_SEED).hexdigest()
```

The reasoning is not "hide it from the scanner" — that is the technique
used to smuggle a real credential past one, and a repository that
teaches *break up the literal when the gate complains* is worse off than
one carrying a false positive. The reasoning is that **a hard-coded hex
blob cannot be verified as fake by reading it**, whereas a derivation
can be recomputed in one line. This is B-13's `DECLARED_PLACEHOLDER`
principle applied to a value whose shape has no room for a declaration:
a signature cannot announce that it is synthetic, so the *construction*
becomes the declaration. The test of a legitimate fixture is whether its
falsity is **verifiable**, not whether it is undetectable. The gate
passing on the file is a consequence of that, not the goal.

**A vacuity guard runs before the contract.** The fixture must trip at
least two gate patterns, or the run stops:

```
SCRUBBER CONTRACT IS VACUOUS -- refusing to write evidence.
  The fixture trips 0 gate pattern(s): none
  It must trip at least two (SigV4 signature and credential
  scope), or 'no pattern matches after scrubbing' proves
  nothing about scrub().
```

It fires for two independent causes, and both must stop the run: someone
softens the fixture, or the gate's own patterns drift so the fixture no
longer represents a leak the gate would catch. The labels it tripped are
recorded in the evidence (`fixture_tripped_before_scrubbing`), so a
reviewer can see what the test was actually exercising rather than take
`VERIFIED` on trust.

Verified in both directions, which is the standing requirement from
B-12:

| | Result |
|---|---|
| Gate patterns against the test **source** | **none** — no credential-shaped literal remains |
| Gate patterns against the **assembled** fixture | **SigV4 signature + credential scope** — still a flaggable leak |
| Contract with the real fixture | PASS, 10 patterns applied, 2 tripped beforehand |
| Contract with a softened fixture | **REFUSED — VACUOUS** |

Carried forward as a requirement: **a test that asserts a pattern no
longer matches must first assert that it did match, and any fixture
standing in for a credential must be constructed so that its falsity can
be recomputed rather than merely claimed.**

---

#### B-18 A configuration gap reported as a tier ceiling

Probe 15 tried to enable external Delta Sharing on the primary metastore
and got **403**. The probe's verdict vocabulary had one bucket for every
negative, so it recorded the 403 as a Free Edition limit.

Script 16 then read both metastores' settings and found they **differ on
this setting at the same tier and in the same region**. That is a
one-variable control: if the tier were the constraint, `glovashu` could
not have the switch on. So the 403 was an unset switch.

| | Goes into the CONOPS as | Starts |
|---|---|---|
| Tier limit | A constraint on the product | A procurement conversation |
| Configuration gap | One line of a prerequisites runbook | Nothing |

The distinction is not cosmetic, and getting it wrong is expensive in one
direction only. **The rule carried forward:** check for a setting
somebody can switch on *before* concluding the tier does not sell the
capability — and check it first, because the two vocabularies overlap on
the word "enabled".

A security decision was hiding behind the same switch: the platform
**refuses to enable external sharing without a recipient token
lifetime**, so the operator cannot turn this on without choosing a
credential expiry. That belongs in the OD-5 discussion as a fact rather
than a preference.

#### B-19 Carry-forward: a later success must not erase the negative it came from

Script 16's first `--apply` run was **REFUSED 400**:
`delta_sharing_recipient_token_lifetime_in_seconds must be set`. That
refusal is the most transferable thing the script produced — it is what
proves the expiry choice is mandatory rather than advisory. The second
run succeeded and the evidence writer **overwrote the file**, leaving a
record that showed only a clean 200.

An evidence file in that state reports "enabling external sharing is a
single call", which is false, and it destroys the finding its own fix was
derived from.

Every probe and test in this repo that writes an evidence file now
carries `prior_attempts` or `prior_runs`, newest last, truncated to the
last few. Three consequences worth stating because they are not obvious:

- A **retracted claim is labelled, not deleted.** Script 19's first
  verify run wrote "a read through it would not be evidence about the far
  side" into the evidence; the same run then read rows attributable to
  the far side by count and origin stamp, which contradicts it. The
  sentence stays in the history under `retracted_claims`, annotated, so a
  reader cannot take it for an observation and cannot miss that our own
  tooling misfired.
- The annotation is **derived from finding the claim**, not typed in
  advance (see B-23b).
- Carry-forward is what let T-19's `object_visibility` figures from
  before the membership fix be marked `RETRACTED` automatically, keyed on
  the absence of the `membership_new` field that the fix introduced.

#### B-20 Ours before theirs: a refusal in an evidence record is a claim about the platform

Probe 15's verdicts were all `REFUSED_*`, so three different negatives
landed in one vocabulary:

| What happened | Whose fault | Where it should go |
|---|---|---|
| The platform declined | Theirs | A capability finding |
| The thing was never there | Nobody's | An absence, bounded |
| We called the wrong thing | **Ours** | A probe defect |

A vocabulary that cannot separate these **fails toward blaming the far
side**, and the far side's name ends up in the CONOPS as a product
constraint.

The sharpest instance: a 404 whose message names an object *this run had
just created with a 2xx*. The object exists; the call resolved its name in
a namespace it does not live in. That is a defect of ours, and the
classifier now checks it **before** the absence and privilege buckets,
both of which the same message also matches.

Two more caught by the same rule. Script 19's re-run path would have
filed a **409 on our own leftover object** as
`BLOCKED_AT_PROVIDER_IMPORT` — but simply adopting the existing object is
the subtler mistake, since a provider created by an earlier run still
holds *that* run's credential, so an adopted provider would read through
a dead token and the failure would again look like the platform's. And
T-19 part 4 would have reported "never appeared" for a share entry whose
provider-side table had been dropped by hand, publishing our housekeeping
as snapshot-at-create behaviour; it now checks `provider_side_exists` and
returns `NOT_READABLE_BUT_SOURCE_TABLE_GONE_UNATTRIBUTABLE`.

**The rule:** find the explanation that makes the defect ours before
accepting one that makes it the platform's.

#### B-21 Bounded negatives: "none" is three different answers

Probe 15 granted a share successfully and the primary metastore still
listed **no providers**. An empty list one second after a grant has at
least three readings — nothing was granted to us, it was granted but has
not propagated, or we cannot see it — and a single immediate call cannot
tell them apart.

Polling does not prove visibility. It **removes propagation as an
explanation up to the bound**, which converts "none" from ambiguous into
"none after N polls over T seconds". The bound is therefore recorded next
to the result, not buried in the code.

Probe 15 bounded at 16.5s and said so, which is what made that negative
reportable. 16.5s is also a weak bound for an undocumented cross-account
path with **no documented SLA for provider appearance**, so probe 18
moved the bound to minutes and recorded it. A negative at 180s is a much
more expensive claim than one at 16s, and is worth the wait exactly once.

#### B-22 `.env` held its opening block twice, with different token values

`.env` contained its first block twice. **Both copies defined
`DATABRICKS_TOKEN`, with different values**, and every loader in this
repo uses `os.environ.setdefault()`, so the first copy silently won.

Two hygiene consequences, not style ones. A second live credential
existed that nothing in the repo could reach, so it could never be
rotated through configuration. And anyone editing the visible later copy
— the obvious thing to do after rotating a token — would change nothing
and believe they had.

`scripts/check_secret_hygiene.py` check 6 now asserts no duplicate keys in
`.env`. It currently reports 24 keys, no duplicates.

#### B-23 A 200 on a mutation is not the finding; the re-read is

Probe 15's run 4 created a share, added a table, created a recipient and
granted the share — four 2xx responses — and the primary still saw no
provider. The evidence recorded four accepted calls and **no evidence
that any of them was in effect**, so the four could not be eliminated as
the cause of the negative they preceded. A negative downstream of an
unverified mutation chain means nothing.

Every mutation in this repo is now read back, and the readback verdict is
what the evidence carries. The rule matters most where a probe's whole
output is a *comparison*: a comparison between one verified chain and one
unverified chain compares nothing.

**B-23b — explanations must be derived, not pre-written.** An explanation
typed in advance of a run describes the run the author imagined. Where an
evidence field explains an outcome, it is built from the fields actually
observed in that run; where it cannot be, the field says so rather than
offering prose that fits any outcome.

#### B-24 — number not used

No finding was recorded under this number. Kept as a declared gap rather
than renumbered, because B-numbers are cited from code comments and from
docs/12, and silently reusing one would make a citation point at the
wrong finding.

#### B-25 A downloaded credential arrives at the operator's umask

CONOPS §3.4.1 step 3 has the credential file downloaded and vaulted but
**names no file mode**. The file therefore lands at whatever the
operator's umask gives it — 0664 in this environment, i.e. a live bearer
token readable by anyone on the host. This is the same class of problem as
B-4, but B-4 was a file *we* wrote and this one is a file the platform
hands over through a browser.

It is recorded as a **measurement, not a correction**: the probe stats the
file before touching it, because chmod-then-check would record the mode
the probe just set and prove nothing about the mode the download
produced.

Carried into the provisioning runbook: §3.4.1 needs the mode as an
explicit step, or the control depends on the operator's umask. The seam is
unavoidable — the activation URL is single-use and is opened by a human in
a browser — so T-19 grants its own share to the existing recipient rather
than re-minting, and records that dependency instead of hiding it behind a
step the operator would have to babysit.

#### B-26 A guard that fires on the normal case is worse than no guard

T-19 part 2 checks that the credential it reads through does not point at
the consumer, because a read through such a credential is a local read
wearing a sharing costume. The first version compared the endpoint
hostname against the *provider's workspace hostname* — and Databricks
serves open sharing from a dedicated `<uuid>.opensharing.<region>` host
whose UUID is **neither metastore id**. So the guard fired on every
healthy run.

A guard that fires on the normal case trains the reader to skip the line
that matters when it is real. The same reasoning marks the table-level
grant in part 3b **OPTIONAL**: a refusal on a Delta Sharing securable
there would grade the whole grant `PARTIAL` and make a working positive
control look broken.

The guard now keys on the one condition that is decisive —
`POINTS_AT_THE_CONSUMER` — and the opensharing host shape is recorded as
expected rather than suspicious.

**Privilege dialect, settled by measurement.** The API accepts
`USE CATALOG` with a space and **normalises it to `USE_CATALOG`**:
`SPACED_NORMALISED_TO_UNDERSCORE (stored=['USE_CATALOG'])`. An earlier
reading of this behaviour held that the API "accepted and discarded" the
spaced form, inferred from a readback that reported `NOT_IN_EFFECT` for a
different reason. **That reading is retracted.** The spaced form is SQL
`GRANT` syntax and the underscored form is the REST enum; both reach the
same stored privilege, and the probe that establishes this prints the
stored value rather than the request value.

#### B-27 The SQL Statement API returns HTTP 200 on a denied read

A Unity Catalog denial on the SQL Statement API does **not** arrive as a
4xx. It arrives as:

```
{"http_status": 200, "state": "FAILED",
 "error": "... [INSUFFICIENT_PERMISSIONS] ... does not have USE CATALOG ..."}
```

The denial lives in `state` and in the error body. **Any check keyed on
HTTP status grades a denial as a success** — and in an access-control
test, grading a denial as a success is the one direction that produces a
false clean bill of health. T-19 part 3b's refusal verdict is keyed on
`state` and on a named cause extracted from the error, with a paired
positive control through the same path so the refusal cannot be a broken
read.

#### B-28 A service principal needs SCIM entitlements before the SQL API works at all

A freshly created service principal must hold **`workspace-access` and
`databricks-sql-access`** before it can use the SQL Statement API.
Without them the API returns **403 with an empty body** — which is
indistinguishable from a Unity Catalog denial, and in a denial test that
is the wrong indistinguishability: the test would report "access
correctly refused" when the principal was never admitted to the workspace
in the first place.

The entitlements are therefore a precondition the test asserts and
records, and `UNGRANTED_CONFIRMED` with `groups=none` is established
before any refusal is attributed to Unity Catalog.

#### B-29 One recipient per sharing identifier, and the error names a different object

Creating a second recipient with a sharing identifier already in use
fails with `RECIPIENT_ALREADY_EXISTS ... with the same sharing
identifier` — **and the message names the OTHER recipient**, not the one
being created. A classifier matching on object names will conclude the
call failed because of the object it was creating, which is not what
happened.

The operational consequence matters for §3.1's share-isolation rule:
isolation is achieved with **one recipient per consuming metastore and
several shares granted to it**, not with one recipient per purpose,
because the metastore identifier is the unique key. §3.1's "one recipient
per consuming agency or use case" is satisfiable for *agency* and not for
*use case* when both use cases sit in the same consuming metastore. v1.6
should say so.

#### B-30 A carry-forward is only as good as the fields the earlier run wrote

`scripts/21_probe_refresh_trigger.py` carries bounds across runs
deliberately, and its own `aggregation_means` note states why: "a re-run
of this probe has a LOOSER upper bound than its first run by
construction, since the object keeps ageing." It then quoted the looser
one. `evidence/t19-refresh-trigger.json` records
`tightest_upper_bound_across_runs: 1978.0` from the second run, while
the first run — in the same file, under `prior_runs` — observed the
object PRESENT at `age_minutes_at_read: 17.4`, which is **1044s** and a
materially tighter bound. The first run stored
`upper_bound_seconds: null`, so the comparison had nothing to compare.

The defect is not in the aggregation logic; it is in what the earlier
run **recorded**. The bound existed in that run's output as a derivable
timestamp and in its prose, but not in the field the aggregator reads,
which is the only place that counts. This is the B-19 carry-forward rule
pointed at a run's own future self: a number that a later run will need
has to be written to the field that later run will look in, because
prose is not an interface and a derivable value is not a recorded one.

Per B-19 the figure is labelled rather than deleted — the evidence file
keeps 1978.0s, and docs/12 §12.11 carries the corrected bracket
(170.8s–1044s) as the figure to quote. The probe is **not** re-run to
fix the prose: re-running it would produce a looser bound, not a tighter
one, and the finding it was built to establish (`REFRESH_IS_TIME_BASED`)
is unaffected by which end of the bracket the prose quotes.

#### B-31 The share nobody was looking at, again — and a grant with no credential behind it

Task 1.4's rule 1 enumerates **every** share on the metastore rather
than the two `iac/config/entitlements.yaml` declares. On its first run
both declared shares came back `MATCHES_CONFIG` — the base table
removed, the entitled view added — and the overall verdict was still
`ENTITLEMENT_MODEL_DIVERGES`, because `awoz1227_p18_primary_share` still
carried `awoz1227_demo.opensharing_test.test_dataset`. That share is a
probe artifact from `scripts/18`, kept deliberately so `scripts/19`
could reuse it. **A check scoped to the shares in the config would have
reported a clean pass with the base table still shared.** §11.5's defect
was a share nobody looked at; this is the same defect one layer out, and
the control that catches it is a metastore-wide standing assertion, not
a naming convention or a publish-time check. v1.6's §3.1 should require
the standing form.

The second half of the finding is the more useful one for a corporate
conversation. `scripts/26` reads the share's grants and each granted
recipient's token state **before** it removes anything, and the
measurement was:

| What | Value |
|---|---|
| Share | `awoz1227_p18_primary_share` |
| Grant | `awoz1227_p18_primary_recipient`, `['SELECT']` |
| Recipient token state | `NO_TOKEN` |
| Reachability | `DORMANT_NO_LIVE_CREDENTIAL` |
| Exposure window | `added_at` 2026-10-19T21:59:20Z, **80,362s (22.3h)** in the share at the read |

So a grant existed and a credential never did. Membership and
reachability are different claims, and collapsing them fails in both
directions: reported as a breach, a dormant share gets the finding
dismissed in the argument about whether anything was actually exposed;
reported as fine, the one case that is not fine — an activated recipient
with a live token — is waved through on the same logic. The ordering is
what makes the distinction available at all: a `REMOVE` issued before
the permissions read destroys the only record of whether anyone could
have read the withheld column, and the question becomes unanswerable.
**Evidence first, mutation second**, for the same reason B-23 insists on
the re-read after.

One thing this finding cannot supply, stated because it is tempting to
assume the symmetric number exists: the exposure window for
`awoz1227-psp7-demo-share`, the share §11.5 actually found. `scripts/24`
captured `objects_before` as a list of **names** when it removed the
base table, and the sharing API's `added_at` and `added_by` were on the
records it discarded. So that window is unmeasured, not zero. The
generalisable rule is to capture the whole record before a REMOVE rather
than the one field the next assertion happens to need.

#### B-32 `CREATE OR REPLACE VIEW` works exactly once on a shared view

The second run of `scripts/24` failed both of its view statements:

```
INVALID_STATE.DELTA_SHARING_SECURABLE_DELETE_BLOCKED.BY_SHARES
TABLE awoz1227_demo.opensharing_test.v_entitled_t2 cannot be deleted
because it is being shared via OpenSharing. It is shared through the
following shares: awoz1227-psp7-demo-share. If you just want to update
a shared view, please use
```

`REPLACE` is implemented as a drop followed by a create, and the drop is
blocked while the object is in a share. The applier therefore worked on
the run that created the views and could not repeat itself on any run
after — which is precisely what AC6's redeploy-from-code (T-12) exists
to detect, so building it in would have made T-12 pass against a script
that only ever works on an empty metastore. The fix is to branch:
`CREATE VIEW` when the view is absent, `ALTER VIEW ... AS` plus a
separate `COMMENT ON VIEW` when it is present, since `ALTER VIEW ... AS`
carries no COMMENT clause.

Two secondary findings came out of the same run and matter more than the
first.

**B-32a — the verdict covered the failure.** Both statements failed and
the run still printed `ENTITLEMENT_MODEL_VERIFIED_PROVIDER_SIDE`,
because the verification half only reads platform state and the state
had been left correct by the earlier run. A green verdict over a failed
step is the shape of §12.4's retracted closure claim, one level down and
inside the tooling this time. Apply outcome is now its own axis, with
three values: `APPLIED`, `NO_CHANGE_NEEDED` (statements failed and the
stored definition, column set and COMMENT already match the config), and
`FAILED`. `NO_CHANGE_NEEDED` is only honest because a new check compares
the **stored view definition** against the configured one — rules 3 and
4 compare the column set and the COMMENT, and a changed `WHERE` clause
passes both. Without that comparison, "the apply failed but the state is
already right" would be a guess dressed as a reading. The top-level
verdict `VERIFIED_PROVIDER_SIDE_APPLY_NOT_REPEATABLE` exists so neither
neighbour absorbs the case: `VERIFIED` hides a T-12 defect, and
`DIVERGES` would blame the platform for being wrong when it is not
(B-20).

**B-32b — the error budget threw away the remedy.** `scripts/19`'s
`run_sql` truncates the error at 400 characters, and the platform's
message ends `If you just want to update a shared view, please use` —
the clause naming the fix was cut off mid-sentence. The platform told us
how to repair it and the evidence file kept only the half that says no.
`scripts/24` now wraps the call with a larger budget rather than editing
a settled probe. A truncation limit is a decision about which part of a
refusal is worth keeping, and the default answer here was the wrong one.

**The fix is confirmed, with one limb still untested.** The next run
reported `view v_entitled_t2: UPDATED (strategy ALTER)` and
`v_entitled_t2_us: UPDATED (strategy ALTER)`, apply outcome `APPLIED`,
rule 2b `EXACT` on both, rule 1 `BASE_TABLE_IN_NO_SHARE` over four
shares, and rule 5 `ROW_SCOPE_MEASURED` at 50 and 16 rows. So `ALTER
VIEW ... AS` is not blocked by share membership where `REPLACE` is, and
the applier is now idempotent against a metastore that already holds the
model.

**B-32c — what that run did *not* test.** `iac/config/entitlements.yaml`
was unchanged between the two runs, so the definition `ALTER` wrote was
identical to the definition already stored. The run proves the
**statement** is accepted on a shared view; it does not prove that a
*changed* definition propagates to a live share, and a change is the only
case T-12 actually cares about — nobody redeploys to keep a view the
same. The gap matters because the plausible failure is silent rather than
loud: an `ALTER` that returns 200 while consumers continue to resolve the
previous definition would read as `APPLIED` / `EXACT` here, since rule 2b
reads the provider's catalog, not the consumer's. Closing it needs a
deliberate edit to the config — widening `v_entitled_t2_us`'s predicate
so the row count moves off 16 — applied, verified provider-side, then
read back **through the share** by the activated recipient that E1 Task
1.7 stands up. Until then the idempotency claim is bounded: repeatable
for an unchanged model, unmeasured for a changed one.

**B-32c — CLOSED 2026-10-22, with a negative answer.** The paragraph
above is left standing because it describes the gap correctly; what
follows is the measurement that filled it. `tests/b32c_change_propagation.py`
was built to do exactly what that paragraph asks: edit the config, apply
through `scripts/24` as a subprocess rather than reimplementing it, read
the provider's catalog, then read **through the share** as the activated
recipient, and finally restore. It was run twice, in both directions.

| Direction | Predicate | Provider | Consumer | Verdict |
|---|---|---|---|---|
| Widening | `region = 'us-east'` → `region IN ('us-east','us-west')` | 16 → **33** | 16 → **16**, 18 polls / 600s | `B32C_CONFIRMED_PROVIDER_MOVED_CONSUMER_DID_NOT_WITHIN_600S` |
| Narrowing | `region = 'us-east'` → `region = 'us-east' AND record_id % 2 = 0` | 16 → **8** | 16 → **16**, 19 polls / 600s | `B32C_NARROWING_DID_NOT_REACH_THE_CONSUMER_REVOKED_ROWS_STILL_READABLE_AFTER_600S` |

Both phases restored cleanly: the consumer count returned to 16, the
provider count returned to 16, and `iac/config/entitlements.yaml` came
back byte-identical from the gitignored backup with all 68 comments
intact (`git diff` empty after each run).

**So `ALTER VIEW ... AS` is accepted, takes effect in the provider's own
catalog immediately, and does not reach a live Delta Sharing consumer
within ten minutes.** The failure is exactly the silent shape this
paragraph predicted: provider-side rule 2b reports `EXACT`, the applier
reports `APPLIED`, and the consumer keeps resolving the previous
definition with nothing anywhere saying so.

**Why the second run exists, and why one direction was not enough.**
Widening and narrowing are not the same experiment with the sign
flipped. A stale consumer under a *widened* predicate sees **less** than
it is entitled to — wrong, but an operational complaint. A stale
consumer under a *narrowed* predicate keeps reading the 8 rows that were
just taken out of scope, which is a disclosure; and because the
provider's catalog reports the narrow definition, every provider-side
check agrees the reduction is in force. The narrowing run is therefore
the one the CONOPS has to answer for, and it is the one that failed.

**Two bounds this does not exceed.** 600s is a **floor, not a ceiling** —
it says the change had not arrived within ten minutes, not that it never
arrives; the verdict label carries the wait for that reason (B-46), and
T-19 has separately measured a newly shared object unreadable at 170.8s
and readable 7.7h later, so the mechanism is plausibly the same cache.
And the first version of this test read the consumer **once**, straight
after the applier returned, which could not have distinguished "never
propagates" from "propagates in four minutes"; that single-sample
reading is retracted in place inside
`evidence/b32c-change-propagation.json` under
`what_this_does_not_prove.propagation_latency`.

**What v1.6 owes this finding:** a stated propagation expectation for
entitlement *reductions*, and a revocation path that does not depend on
editing a view. Removing the recipient's grant or rotating its credential
acts at the share boundary rather than inside the view definition, and is
the only reduction this prototype has measured as immediate.

#### B-33 Half a widening reads as a whole one

B-31's lesson was that a check has to look wider than the config that
defines it, and Task 1.5's grant check was written with that lesson in
hand: it enumerates every share on the metastore rather than the three
`iac/config/recipients.yaml` names. It then filtered the principals:

```python
for principal, privs in perms.items():
    if principal in managed:
        observed.setdefault(principal, {})[s] = privs
```

A grant is a pair. Widening the share axis and leaving the principal
axis scoped to the config means a recipient this config does not manage,
holding `SELECT` on a share it *does* manage, was dropped on the floor by
a rule whose stated name is "grants are exactly as declared". The rule's
verdict `GRANTS_EXACTLY_AS_DECLARED` was true of the half it looked at
and read as a statement about the whole. This is B-31 with the two axes
swapped, found one task later, in code written by somebody who had just
written B-31 down.

What made it visible was rule 6, which exists for a different purpose:
it inventories recipients the config does not manage, and it found
**`awoz1227_demo_recipientashu`** — a TOKEN recipient that no script in
this repository creates. Grepping `scripts/` for the name returns
nothing, so the honest provenance is `UNKNOWN_NOT_PRODUCED_BY_ANY_SCRIPT
_IN_THIS_REPO` rather than a guess at which step made it. It is
`NO_TOKEN` and therefore `DORMANT_NO_LIVE_CREDENTIAL`, so it is not an
exposure today. Whether it holds a grant on anything was **unanswerable
from that run**, because the only check that reads share permissions was
the one that had just filtered it out. Rule 3 now reports every
grant-holding principal, splits them into managed and unmanaged, and
attaches reachability to each — because "an undeclared recipient holds
SELECT" and "an undeclared recipient holds SELECT and has a live
credential" are different findings and only the second one is a read.

**B-33a — the verdict blamed the model for the environment.** The run
reported `RECIPIENT_MODEL_DIVERGES` with rules 1 through 5 all clean.
The single driver was rule 6's `UNDECLARED_LEFTOVERS_PRESENT`: a dormant
recipient from an earlier session, which this config deliberately does
not manage and whose policy is explicitly inventory-never-delete. So the
top-line verdict said the declared model diverged from the platform when
what was true is that the platform holds an object the model never
claimed. That is B-20 inside the tooling — a verdict vocabulary too
coarse to name its own cause, failing toward blaming the nearest thing.
Conformance (rules 1-5) and environment inventory (rule 6 plus the new
unmanaged grant-holders) are now separate axes with a composed top
verdict, which adds `MODEL_VERIFIED_PROVIDER_SIDE_ENVIRONMENT_NOT_CLEAN`
and `MODEL_VERIFIED_UNMANAGED_OBJECT_REACHABLE`. The split is not a
downgrade: the inventory finding keeps a named non-clean verdict and
still sets a non-zero exit code. The failure mode being avoided is the
opposite one — an undeclared object disappearing into a green model
verdict, which is how the 22.3 hours happened.

**B-33b — the dry run was the before-picture, and that is why one
finding is attributable.** `psp7-demo-recipient` came back `NO_TOKEN`
with zero tokens, and the applier had just issued a `PATCH` against it.
From the after-picture alone, "the PATCH destroyed the token" and "there
was never a token" are the same observation. The `--dry-run` pass had
already reported `NO_TOKEN tokens=0` before any mutation, which rules
the applier out. Worth stating as a method rather than a lucky break: a
dry run whose verify half runs against live state is a free
before-picture, and it is the only thing that makes a post-mutation
absence attributable to something other than the mutation.

#### B-34 Credential lifetime is a birth property, and making it otherwise is worse

`iac/config/recipients.yaml` declares a 7-day token lifetime. The
applier sets `expiration_time` when it **creates** a recipient and does
not re-send it on update, so `psp7-demo-recipient` — created by
`scripts/03` under a one-day lifetime — keeps the older policy while the
config claims the newer one, and the applier still reports `UPDATED`.

The obvious fix is wrong. An applier that re-stamps the lifetime on
every run extends every credential by the full window each time it runs,
so in any environment where the applier runs on a schedule a "7-day
token" never expires. Idempotent configuration and a bounded credential
lifetime pull in opposite directions at exactly this field, and the
silent failure is the extension: a lapsed credential announces itself
the next time somebody tries to read, while an indefinitely renewed one
looks correct in both the config and the platform forever.

So lifetime drift is **reported** per recipient (`lifetime_verdict`:
`LIFETIME_AS_CONFIGURED`, `LIFETIME_DIFFERS_SET_AT_BIRTH`, or
`NO_TOKEN_LIFETIME_UNENFORCEABLE`) and changed only under an explicit
`--renew-lifetime`. The third value matters for honesty: a recipient
with no token at all is not complying with the lifetime policy, it is a
policy with no subject, and a check that collapsed those two into "no
violation found" would be the §12.9 silent negative applied to a control
rather than to a test.

This is an OD-5 input and belongs in the §13.2 ask. The real programme
has to decide not just the lifetime but *when the lifetime is
evaluated*, and an IaC pipeline that applies configuration nightly
answers that question by accident unless somebody answers it on purpose.

#### B-35 An IP allow-list cannot tell the gateway from the client when both leave through one address

T-02 is written in docs/12 as "call straight to the Databricks sharing
endpoint with a valid token", with the note that recipient IP access
lists work here "so the refusal is real, not simulated". Read carefully,
that note is about §11.3, which measured that the field is **accepted and
echoed back**. It is a configuration read. Nothing in this repository had
ever observed the platform act on the list, which is why RKI-3 exists.

Building the enforcement test exposes a second thing, and it is the
larger of the two. The production shape of this control is an allow-list
holding the **gateway's** egress address, so that a call arriving from
anywhere else is refused — that is the whole of AC1's perimeter. On this
machine the Gravitee container and the test client sit on one host behind
one NAT address. If the gateway and the client present the same address
to Databricks, no allow-list can distinguish "via the gateway" from
"direct", and the perimeter claim is not locally testable however many
phases the test grows.

Two distinct claims were being carried as one:

| Claim | Status |
| --- | --- |
| The recipient IP access list is a live control — it admits an address on the list and refuses one that is not | Testable here. `tests/t02_ip_access_list.py` phases 1 and 2 |
| Traffic through the gateway is admitted and direct traffic is refused | **Not testable here**, if the two share an egress address |

The second is measured rather than assumed, and the measurement costs one
extra read: with the list narrowed to the operator's address **only**, the
same read is repeated *through the gateway*. If it succeeds, the gateway
was admitted by a list naming the operator, so the two addresses are the
same one. Phase 2 then closes it from the other side by denying both.
A failure there is deliberately **not** read as topology on its own — a
gateway that is down and a gateway that egresses elsewhere produce the
same refusal, which is B-20 again.

The reason this is a finding and not a prototype limitation is what it
says about the document. AC1's direct-call refusal rests on an
infrastructure assumption the CONOPS never states: that the gateway
egresses from an address the recipient allow-list can name, **and** that
no consumer can reach the sharing endpoint from an address on that list.
In a real deployment that is a NAT gateway or a dedicated egress IP, and
somebody has to own it. A T-02 that reported a pass without separating
the mechanism from the topology would have carried the assumption
silently into v1.6 — the §12.4 error in a more expensive form than the
original, because it is not a verdict upgraded ahead of its measurement
but a claim nobody noticed was two claims.

So the mechanism half closes RKI-3 when the test runs, and the topology
half is recorded as RKI-6 with `closes_when: NEVER_LOCALLY`. The
deliverable for the topology half is a sentence in the CONOPS naming the
egress requirement, not a test.

#### B-36 The one-time link is an irreversible operation, and the ordinary way to write one loses it

RKI-5 blocks every consumer-side test in Tasks 1.6 and 1.7: three
recipients, no live credential. `scripts/03` handled the exchange by
telling the operator to open the link in a browser and save the
download, which works once and records nothing — a credential on disk
and a credential copied from a different recipient look identical
afterwards.

Automating it runs into a property this repository has not had to handle
before. The exchange **cannot be retried**. A call to the right host with
the wrong path consumes the link just as finally as a correct one, and
there is no recovery except minting a new token, which changes the
credential every downstream test is pinned to. Two consequences follow,
and neither is the obvious way to write the script:

The consuming call is **guarded by a non-consuming one**. Databricks
exposes `data_sharing_activation_info/<blob>` beside
`data_sharing_activation/<blob>`; the first is idempotent. `scripts/28`
calls it first and refuses the second unless it returned 200 *and*
`--activate` was passed. This is B-33b — the dry run as a before-picture
— applied to an operation where the before-picture is also the only thing
standing between a wrong URL and the destruction of what it points at.

The response is **written to disk before it is parsed**. The natural
order is parse, validate, then persist. Here a parse error leaves the
operator with a spent token, no credential, and no copy of what the
platform returned, so "the platform returned something we failed to read"
and "the platform returned nothing" become the same observation on the
one axis that cannot be re-measured. Raw bytes go to `_secrets/` at 0600
first; every judgement happens afterwards against a file. The duplicate
is removed only once a parse has succeeded, because by then it is a
second copy of a live bearer token.

One shape detail is worth recording because the obvious reading of it is
wrong. The activation URL is
`https://<recipient-id>.opensharing.<region>.cloud.databricks.com/opensharing/retrieve_config.html?<172-char blob>`.
That blob is the activation token and it contains no `=`, so it parses to
**nothing** through `parse_qsl`. Code written on the assumption that the
token is a query *parameter* extracts an empty string and calls the
endpoint with no token at all — and on the consuming path, finds out by
spending it.

#### B-37 One object, two filenames, and a consumer that reported it missing

`scripts/27` writes `_secrets/recipient-<name>.json` when it **creates** a
recipient and `_secrets/recipient-<name>-rotated.json` when it **rotates**
one. Two naming conventions for one object, inside one script, neither
wrong on its own.

`scripts/28` looked for the first name and reported
`NO_RECIPIENT_RECORD_ON_DISK` for `psp7-demo-recipient` while its freshly
minted activation link sat in the directory it had just searched, under
the other name. The remedy it printed — rotate the token — would have
minted a *second* link and left the first unspent, so the defect's own
suggested fix compounded it.

This is the §12.9 silent negative with a filename as the cause: "there is
no record" and "the record is under a name I did not look for" are the
same output. The fix globs `recipient-<name>*.json`, confirms each
candidate against its own `name` field (a recipient whose name is a
prefix of another's would otherwise match), and orders by *unspent link
first, then newest token* — so a rotation's link wins without the
superseded record being deleted (B-19). Measured after the fix:
`record: _secrets/recipient-psp7-demo-recipient-rotated.json`, info 200.

#### B-34a Rotation inherits the birth lifetime, which is B-34 arriving on schedule

`scripts/27 --rotate-token psp7-demo-recipient` succeeded and minted a
link. The new token expires **2026-10-22T08:59Z — about 24 hours after
it was minted**, while `recipients.yaml` declares 7 days.

The rotate endpoint does not take a lifetime. It inherits the
*recipient's* `expiration_time`, and that recipient was created by
`scripts/03` under a one-day policy. So B-34's "lifetime is a birth
property" is stronger than it was written: it survives rotation, and a
rotation is exactly the operation an operator would expect to reset it.
A credential rotated to fix an expiry problem comes back with the same
expiry problem, and the applier reports `ROTATED` either way.

Deliberately not fixed by default. `--renew-lifetime` re-stamps the
recipient and then a rotation inherits the new window; that is one
command and an explicit decision, which is the point. The OD-5 ask in
§13.2 gains a third sub-question: not just what the lifetime is and when
it is evaluated, but **which operation is allowed to change it**.

#### B-38 The IP access list gates its own enrolment

`awoz1227-t02-iplist-recipient` returned **403 on the activation info
endpoint**. `awoz1227-psp7-t2-us-recipient` returned 200 on the same
endpoint, from the same client, in the same run, against a link minted by
the same call in the same second. The recipients differ in one property:
the first carries an APPLIED IP access list of `203.0.113.5/32`.

So the activation endpoint is behind the recipient's own allow-list. The
credential for an allow-listed recipient **cannot be collected from an
address the list excludes**, and a list written before enrolment locks
out the enrolment.

Two things follow, and they pull in opposite directions.

The first is good news that has to be bounded carefully. This is an
*enforcement* observation — the thing RKI-3 says this repository has
never had — and it comes with a free attribution procedure, because the
info call does not consume the link and can therefore be asked before and
after a change. `scripts/28 --widen-ip-list` admits this client, re-asks
the identical question, and records `403 → 200` with the allow-list as the
only changed variable. That is a positive control on the activation path.
It is **not** T-02: the activation service and the data service are
different endpoints that happen to share a control, and a refusal on one
is not evidence about the other. T-02 still has to show admit-then-refuse
on the read path.

The second is a CONOPS defect, D-8. §3.4.1's provisioning sequence
creates the recipient, applies the perimeter, and delivers the credential
through an authenticated portal — in that order, with no mention that the
third step is inside the perimeter the second one built. Whoever
implements it will either widen the list for the duration of enrolment
(which needs an approver, a window and a record) or collect the
credential from inside the allowed range. The document has to say which.

#### B-39 Two scanners, two exemption vocabularies, one string

T-21 half B scans the tree for credential *shape* and needs a positive
control: a file that genuinely looks like a credential, so that a clean
scan means "nothing here" rather than "the scanner is broken". The first
version of that control was a token-shaped literal in the test's own
source. `scripts/check_secret_hygiene.py` — the commit gate — flagged it
immediately: *Delta Sharing bearer token found in
tests/t21_readonly_nosecrets.py*.

The obvious repair made things worse. Renaming the literal to
`awoz1227-t21-synthetic-not-a-real-token` satisfied the gate, and then
T-21's own scanner — once it had been taught the same placeholder
vocabulary — exempted the exact string it existed to detect. The positive
control passed by being invisible.

Neither scanner is wrong. They ask different questions. The hygiene gate
asks *is a real secret committed here*; T-21 asks *can my scanner see
credential shape at all*. For one placeholder string the correct answers
are NO and YES. The defect is not a bad rule in either tool, it is **two
exemption vocabularies maintained independently**, which drift and then
disagree about a single string with no mechanism for noticing.

Fixed in two halves. T-21 now imports `DECLARED_PLACEHOLDER` from the
hygiene script rather than restating it, so there is one vocabulary and
drift is structurally impossible; and the synthetic credential is
**generated at call time**, written to `evidence/` for the duration of one
scan and removed in a `finally`. The gate scans files on disk, so no
token-shaped literal exists in source for it to find, and the scanner
still gets a real target. All three shape patterns fire on the synthetic.

Carry forward to v1.6: this is a general property of layered scanning,
which §6's secret-hygiene requirement will acquire the moment a second
tool is added. Any two detectors over the same tree need a **shared
exemption list, imported not copied**, and a test that fails when they
disagree.

#### B-40 T-21 passed without touching the mechanism it names

RETRACTED VERDICT, CARRIED FORWARD PER B-19. T-21's first run reported
`READ_ONLY_AND_NO_LEAK_BOTH_MEASURED`, and the verdict was worthless.

Half A fires seven mutation verbs at the sharing surface and reads the
responses. All seven returned 404, which classified as `METHOD_ABSENT`,
which aggregated to `NO_WRITE_VERB_ON_THE_SHARING_SURFACE`. But the
recipient selector had chosen `awoz1227-psp7-t2-us-recipient`, whose only
grant is on `awoz1227-psp7-t2-us-share`, while the seven paths were built
against the `--share` default of `awoz1227-psp7-demo-share`. Every 404
meant *no such share for you*. The test proved that a share the credential
cannot see cannot be written to, which is true of every string.

What let it through was the positive control, printed as
`DISCOVERY_ONLY`. I accepted a 200 on `/shares` as sufficient. A 200 on
`/shares` proves the host resolves, the credential is live and some grant
exists somewhere. It proves nothing whatever about the path being mutated.
**A control must be the same PATH as the subject, not the same host.**

The repair: `discover_readable_target()` walks shares → schemas → tables
and keeps the first object whose `/metadata` GET returns 200; the
`--share/--schema/--table` defaults are gone so there is nothing to be
silently wrong; an explicit override is verified readable before it is
honoured; and the emitted evidence now carries `control_path` and
`control_status` beside the mutation results, so a reader can check the
attribution without rerunning. The corrected run reaches the same verdict
against `awoz1227-psp7-t2-us-share / opensharing_test /
v_entitled_t2_us`, with `same-path control → 200`, and the verdict is now
attributable. The retraction is recorded in `defect_history` inside
`evidence/t21-report.json` so it survives re-runs.

The class matters more than the instance. §12.9 names the silent
negative: a check that cannot see reports the same output as a check that
looked and found nothing. This is **the silent negative with the sign
flipped** — a test that *passes* without touching the mechanism it names.
It is more dangerous, because a `CANNOT_SEE` invites a second look and a
PASS closes the question. Every negative assertion in this repository
needs a same-path positive control, and v1.6's evidence rule (§6.1) should
require the control's path to be *printed* next to the finding, which is
the only reason this one was catchable by reading the output.

#### B-41 A 200 for a column that does not exist

T-04 assertion 4 sends `predicateHints: ["internal_notes IS NOT NULL"]`
against `v_entitled_t2_us`, which does not publish `internal_notes`. The
platform returned **200** with file actions.

This is protocol-legal. Delta Sharing defines `predicateHints` as
advisory; a server may ignore any or all of them, and ignoring a hint it
cannot evaluate is a reasonable reading. The assertion is therefore
recorded as `HINT_IGNORED_NOT_A_CONTROL` and **excluded from AC1
evidence** — it is not a leak and not a failure of column scope, which
assertions 1 to 3 proved independently.

It is still worth writing down, because of what it means for a consumer. A
caller can filter on a withheld column, receive a successful response, and
get back rows the filter was meant to exclude, with **no signal anywhere
in the response that the filter did not apply**. A consumer who treats
`predicateHints` as a security or correctness boundary is wrong, and
nothing in the exchange tells them so.

Carry forward to v1.6: §2.3.2's consumer guidance should state that a
recipient must read the published schema to learn what it may filter on,
and that `predicateHints` is an optimisation, never a control. The
provider-side corollary is that row scope must live in the view
definition, which is where this repository already puts it.

#### B-42 The sharing endpoint host is per-recipient, so one gateway route cannot front it

The largest finding of the day, and it reshapes T-01.

§2.3.2 describes channel E-1 as one Gravitee route with one upstream
target, serving all recipients. That model cannot be built. Each
recipient's credential carries **its own endpoint hostname** —
`aa8b5b00-…` for `awoz1227-psp7-t2-us-recipient`, `a7066515-…` for
`awoz1227-t02-iplist-recipient`, `13ad6c00-…` for `psp7-demo-recipient` —
and the platform validates the binding between host and bearer. Sending
one recipient's token to another recipient's host returns:

```
400 BAD_REQUEST: Request URL hostname '634cbc18-...' does not match
with the recipient id 'aa8b5b00-...'
```

So a single fixed upstream target is wrong for every recipient but one.

Three options, none free. **One route per recipient** works today and is
what the consolidation will do, but it collides with §3.4's self-service
onboarding portal — adding a recipient becomes a gateway change, which
makes AC4 a deployment rather than a form submission. **Dynamic upstream
resolution** keeps one route, and requires the gateway to map
token → recipient → host, which means the edge holds a credential
directory: a new secret-handling surface in exactly the place OD-4 exists
to avoid putting one. **Accept that E-1 is per-recipient by nature** and
say so in the CONOPS, which costs nothing to implement and forces §3.4 to
describe route provisioning as part of onboarding.

Two immediate consequences for the build. T-01 must be constructed and
reported **per recipient**, with the endpoint read from that recipient's
own credential file rather than from a constant. And E2 Task 2.1's
consolidated definition must be **generated** from `recipients.yaml` plus
the credential files, not merged by hand from the two live definitions —
work AC6 and T-12 want anyway, since "redeploy from code" is the
requirement.

One note in the platform's favour, worth citing in E5. The error names
**both halves of the mismatch** — the hostname it received and the
recipient id the token belongs to — which is precisely what B-20's
denial messages do not do. It is the model for E5's error contract: an
error that lets the caller locate the fault without guessing, and without
the operator having to blame the nearest thing.

This is CONOPS defect **D-9**; see §10.7.

**Measured 2026-10-21, and now a measurement rather than an inference.**
T-01 phase 2 sent `psp7-demo`'s credential to `psp7-t2-us`'s route with
its own route as the same-run control: control 200, crossed **400**, one
variable, and the refusal named both halves. Verdict
`BINDING_ENFORCED_AND_THE_ERROR_NAMES_BOTH_HALVES`. The probe existed
precisely so that a 200 here would have *falsified* D-9 and handed
§2.3.2 its single-route model back; it did not. D-9 stands on evidence.

---

### B-43: the aggregator manufactured a silent negative

My defect, found by reading T-01's own first-run output. Six routes
produced an attributable finding and two did not, and because the
roll-up tested `CANNOT_SEE_NO_DIRECT_CONTROL` **first**, the two erased
the six and the test reported `CANNOT_SEE`.

§12.9 names the silent negative as a check that cannot see reporting the
same output as one that looked and found nothing. This is a third and
worse case: a check that *did* look, *did* find, and then **generated**
the silent negative in its own summary. The information existed in the
record and was destroyed on the way out of it.

The rule, now implemented in `aggregate()` and in T-01's top-level
roll-up: **`CANNOT_SEE` is the verdict of last resort, never of first
match.** It is returned only when *no* unit of observation produced an
attributable result, and the count of unobservable units is carried
beside the verdict so the gap stays visible without being decisive.
Every aggregator in this repository needs auditing against this; a
verdict function is the one place where a reader has no way to notice
what was dropped.

### B-44: an edge refusal and a forwarded upstream refusal are the same status code with opposite remedies

T-01's first run returned 404 on every gateway path and was read as the
gateway refusing. It was not. A **different** API — the legacy
`AWOZ-1227 OpenSharing - Metastore 48cda780` at context path
`/opensharing-demo/` — prefix-matched the new per-recipient paths,
forwarded them upstream, and glued the recipient slug into the protocol
path. Databricks produced the 404:
`ENDPOINT_NOT_FOUND / No API found for 'GET /opensharing/metastores/48cda780-…/psp7-t2-us/shares'`.
The edge was not refusing. **It was forwarding to the wrong place.**

Those two states have opposite remedies — fix the policy versus fix the
target — and the same status code. This is B-20 (*ours before theirs*)
in its most expensive form: a verdict vocabulary too coarse to name the
refusing party fails toward blaming the nearest thing, and the nearest
thing was the perimeter we had just built.

Three discriminators, all verified by hand against this installation:

- Gravitee's own unmatched-path refusal is `Content-Type: text/plain`,
  body `No context-path matches the request URI.`, and carries **no**
  `x-gravitee-*` headers.
- Databricks answers JSON carrying `error_code` and
  `details[].@type: type.googleapis.com/google.rpc.*`.
- A response that round-tripped the edge carries `x-gravitee-*` headers.

Two independent axes — who owns the error *vocabulary*, and whether the
response *round-tripped* the edge — because either alone can be
defeated. `classify_responder()` applies both, in `compare_one` and in
`binding_probe`. Phase 2 is where this mattered most: its **expected**
result is a refusal, so an edge 404 arriving for an unrelated reason
would have been scored as the probe *succeeding*. That is B-40's silent
negative with the sign flipped, reached by a second route.

**Every test in this repository that asserts a refusal must name the
refusing party**, and v1.6's evidence rule (§6.1) should require the
responder attribution to be printed next to any non-2xx finding.

### B-45: three headers were strippable and two are out of the policy chain's reach

A by-product of T-01's before/after capture, and the first real
measurement for T-07. Reading the same path directly and through the
edge in the same run:

- `server`, `server-timing` and `x-request-id` appear in the direct
  response and **not** in the gateway response. The response
  `transform-headers` policy in `policy-classes.yaml` removes them. Its
  `measured_state` recorded "T-07 FAILS AS CONFIGURED" with four header
  names carried as an *unverified hypothesis*; for these three the
  hypothesis is now confirmed, and the note should be updated in place.
- `x-gravitee-request-id` and `x-gravitee-transaction-id` **survive**.

The second group is not a missing entry in a removeHeaders list, and
adding them to one will not help. They are Gravitee's own correlation
headers, emitted by the gateway outside the API's policy chain, so a
response policy cannot reach them — it runs before they are attached.
Suppressing them is a **gateway configuration** change, not an API
definition change, which means it is not expressible in the per-API
definitions this repository generates and would not survive T-12's
"redeploy from code" unless the gateway's own config is in the IaC set.
It currently is not.

This is worth stating plainly because it cuts at a CONOPS claim: the
perimeter cannot fully control its own response surface from the API
definition alone. Two headers that identify the gateway, its request and
its transaction reach every recipient, and §2.3's header-hygiene
language assumes policy is sufficient. T-07 should assert the three it
*can* control and record the two it cannot as a configuration item with
an owner, rather than failing on all five and hiding the distinction.

### The legacy API was not inert, and my retirement advice was wrong

Worth recording separately, because the object that caused B-44 was one
I had explicitly advised keeping. `gravitee/generated/route-family.json`
said to delete the old APIs "AFTER the family imports and T-01 passes,
not before — deleting the old route first removes the only working
comparison." Every clause of that is false:

1. **It blocked the import.** A Gravitee context path is a *prefix*, so
   `/opensharing-demo/` collides with every `/opensharing-demo/<slug>`
   listener in the family. On the first run only the F1 storage proxy
   imported, because `/storage-proxy/` was the single path with no
   collision. The old API did not survive the import — it prevented it.
2. **The "working comparison" never existed.** That API had `flows: 0`
   — no perimeter policies at all — and its upstream was pinned to the
   sharing host of a credential that **expired 2026-10-18**. It could
   not have produced a successful read for any recipient on any day
   after that, and for three days it was an unpoliced pass-through to a
   dead host.
3. **It was actively harmful**, per B-44 above.

The text is retracted in place in the manifest (B-19) with those three
observations attached, rather than edited away: it was specific, it was
mine, and it was the kind of advice that gets followed. The durable fix
is in the tool — `scripts/05_import_gravitee_api.py` now runs a
prefix-aware collision preflight before every import, names the blocking
API and its relation, and will not import over a collision without
`--retire-colliding`. The failure mode that cost this run cannot recur
silently.

### B-46: the catch-all label was accepted as a positive identification

My defect, and T-03 passed on it before it was found. `classify_responder`
has a branch for "round-tripped the edge, vocabulary unrecognised" that
returns `EDGE_POLICY_OR_PROXY_ERROR`. T-03's verdict condition accepted
that label as proof the edge had refused, and its verdict text claimed
the refusal arrived "in the edge's own vocabulary". It had checked only
that the vocabulary was not recognisably *someone else's*.

The tell was visible in the run output and easy to miss: the phase-1 and
phase-3 **200s** were also labelled `EDGE_POLICY_OR_PROXY_ERROR` — "a
policy refusal or a proxy failure", about two successful reads. A label
that a success and a refusal both carry conveys nothing. The classifier
was written for non-2xx responses and never told so.

Two fixes, and the second is the one with teeth:

- `classify_responder` now takes the status and returns `NOT_A_REFUSAL`
  for any 2xx. It must not invent a refusing party when there was no
  refusal.
- A **positive** discriminator, taken from the body T-03 actually
  captured: `Your IP (…) or some proxies whereby your request pass
  through are not allowed to reach this resource.` That identifies
  `ip-filtering` **by name**, so `EDGE_IP_FILTERING_POLICY` is now a
  positive identification of one policy rather than the absence of a
  competitor. T-03's verdict requires it.

The general rule, and it generalises past this repository: **a fallback
verdict must never be admissible as evidence.** B-20 is about vocabulary
too coarse to name a cause; this is the same failure one level up, where
the vocabulary *had* a catch-all and an assertion was allowed to cite it.
Any verdict condition that lists an `UNATTRIBUTED`, `UNKNOWN`, `OTHER` or
`…_ERROR` catch-all among its accepted values is making this mistake.
T-03's finding survived — the refusal was the edge's — but it survived on
a reason the test had not checked, which on another day is how a wrong
result gets recorded as a right one.

### B-47: the local test accommodation made the allow-list refuse nobody

The most consequential finding of the run, and it came out of the
refusal body rather than the refusal. Gravitee's ip-filtering policy
reports the address it compared:

```
Your IP (172.21.0.1) or some proxies whereby your request pass
through are not allowed to reach this resource.
```

`172.21.0.1` is the Docker bridge. And
`scripts/29_gen_gravitee_route_family.py` defined
`LOCAL_TEST_CIDR = 172.21.0.0/16` and **added it to the allow-list of
every recipient whose `ip_access_list_mode` is `APPLIED`**. The observed
client address is inside that CIDR. So the CIDR did not admit the test
client; it admitted the entire bridge network — every client that can
reach the gateway from this host. The allow-list refused nobody, in
precisely the `APPLIED` configuration whose purpose is to refuse.

Three things make this worse than a loose constant.

**It was a near miss on being measured.** T-03 chose `psp7-demo` as its
subject, for an unrelated reason: `t02-iplist` has no reachable 200
control, because its Databricks-side list excludes this operator. Had
T-03 used the recipient whose gateway allow-list is actually `APPLIED`,
it would have reported `ALLOW_LIST_NOT_ENFORCED` and found this on the
first run. The test passed by subject selection, not by the control
working everywhere it is configured.

**It would have shipped.** `scripts/29` is the deployable source of
truth for AC6 and T-12's "redeploy from code". A vacuous allow-list in
the generated artifact is a vacuous allow-list in whatever that artifact
is promoted into, and the generated file *looked* correct: the policy was
enabled, the declared range was present, and one extra CIDR sat beside it
carrying a comment explaining itself.

**The original reasoning was sound and the conclusion was wrong**, which
is the hard kind to catch. The comment said that without the CIDR "every
local result is a network refusal wearing a policy refusal's clothes."
True. But the cure for an unattributable refusal is to **attribute the
refusal** — which is exactly what B-46's positive discriminator now does,
by reading the policy's own message — not to widen the allow-list until
nothing is refused. Widening it produced a policy refusal that could
never fire: the same confusion with the sign flipped, and B-40's lesson
arriving by a third route.

`LOCAL_TEST_CIDR` is now an explicit `--local-test-cidr` flag, **off by
default**. The honest artifact is what gets generated unless someone asks
for the accommodation by name, and asking for it stamps
`control_is_vacuous: true` into the definition's own rationale. The
disabled branch no longer carries the CIDR either: a disabled policy with
a permissive list is one toggle away from this bug, and it is read by
whoever audits the file. With the flag off, a local read through
`t02-iplist`'s route is **expected to be refused** — that is the control
working, not a broken route, and the test that reads it must say so.

The pattern to look for elsewhere in this repository: **any value added
so that a local run would pass.** Each one is a candidate for having
disabled the thing it was meant to let us observe.

### T-03's second measurement: the two allow-lists do not see the same address

Not a defect, but a CONOPS consequence, and now measured rather than
argued. During the phase-2 window — edge allow-list armed, edge returning
403 — the same credential read the same data **directly** and got 200.

That is not a defect in Gravitee, which did exactly what it was told. But
§2.3.2 reads as though the edge allow-list is a control over *access*,
and what it controls is access *through the edge*. §11.7 B-35 argued this
from the topology; `evidence/t03-refusal.json`'s
`edge_is_not_the_only_door` now records it from a measurement.

The addresses compound it. Gravitee compared `172.21.0.1`, a private
address on the container bridge. Databricks compares this host's public
NAT address. Two controls, both called "the IP allow-list", keyed on
observables from different address spaces — so neither "the allow-list"
nor "the allow-listed address" has a single referent in this
architecture. v1.6 should say which of the two is the **control of
record** for address-based refusal. Only the Databricks-side list can
close the direct path, and B-38 / D-8 show that list gates its own
enrolment.

AC2's acceptance text should read "refused at the edge" rather than
"refused".

### B-48: the route table was a documentation allow-list that nothing enforced

The largest finding of Epic 1, and it was found by accident while
diagnosing something smaller.

T-16 was written to measure one thing: whether the explicit deny on route
M3, legacy managed MCP, actually refuses. It returned
`DENY_DOES_NOT_FIRE_THE_EDGE_FORWARDED_THE_REQUEST`. The deny was
expressed as `policy-request-validation` with `{"rules": [], "status":
"403"}` and a comment asserting that an empty rule set "refuses
everything reaching the flow". The policy's own schema, read from this
installation afterwards, makes `rules` required and validates each rule in
turn — so with no rules there is nothing to fail and **everything
passes**. The policy loaded correctly and forwarded the request. AI-4 had
predicted this outcome and predicted the wrong mechanism: it warned that a
policy which *fails to load* would forward. It did not need to fail.

Chasing that produced the real defect, which was never about M3.

Gravitee matches a context path as a **prefix**, and a request whose path
matches no flow selector is **not refused — it is forwarded**, with the
context path stripped and the remainder appended to the endpoint target.
The AI route's target has to be the Databricks workspace root, because
M1's protocol path (`/serving-endpoints/{name}/invocations`) starts there.
Those two facts compose. Measured through the edge:

```
/ai-gateway-demo/api/2.0/serving-endpoints   -> 200
/ai-gateway-demo/api/2.0/clusters/list       -> 200
/ai-gateway-demo/api/2.0/token/list          -> 200
```

The route was an open reverse proxy to the entire Databricks workspace
REST API. The last path enumerates personal access token metadata.

~~**And it was reachable with no credential at all.** This is the part
that inverts the day's other result. The route strips the caller's
`Authorization` and injects the gateway's, which is the mechanism that
answers R12a — so an anonymous caller reached the whole workspace REST API
as the gateway's own identity, which per AI-3 is a PAT carrying a human
operator's full entitlements. R12a's demonstrated capability was what made
the hole worth using. A control and a vulnerability out of one
mechanism.~~

**RETRACTED 2026-10-21, same day, by measurement (B-19 — left standing
above because a severity claim that is quietly deleted cannot be audited,
and because being wrong in this direction is itself the finding.)**

The three 200s above were obtained **with a caller token**. Probed again
with none:

```
/ai-gateway-demo/api/2.0/token/list   anonymous -> 401
   {"error_code":401,"message":"Credential was not sent or was of an
    unsupported type for this API."}
/ai-gateway-demo/api/2.0/token/list   + token   -> 200
```

That 401 is the **upstream's** vocabulary, forwarded through the edge
(B-44). The strip-and-inject steps do not live on the API; they live
inside **M1's flow**, whose selector is `EQUALS` on the single model path.
An unclaimed path never reaches that flow, so nothing is injected and
Databricks refuses the empty `Authorization` itself.

So the defect was a **bypass of the route restriction**, exercised with
the caller's **own** entitlements — not a privilege escalation. Still
serious: §2.3.2 says this route exposes one model path, and it exposed the
workspace REST API, so every consumer-side entitlement claim in the CONOPS
was unenforced at this edge. But a caller already needed a workspace
token, and got no more than that token already carried.

Two things are worth keeping from having got this wrong. First, the
mechanism that makes the overstated version true is **one selector edit
away**: widen M1's `EQUALS` to a `STARTS_WITH` — the obvious change the
first time someone adds a second model path — and the injection applies to
unclaimed paths too, and the retracted paragraph becomes accurate.
Recorded as such in the generator (`corrected_severity_2026_10_21`).
Second, **the overstatement came from reading the artifact instead of the
gateway**: the route's own documentation says it injects a credential, and
I inferred the scope of the injection from the fact of it. The same
inference shape as every other defect in this section.

#### Why no earlier test saw it

The sharing and storage APIs are confined, but **not by the gateway**.
Their endpoint target carries a deep base path, so a stray path is
*appended* to it and the upstream 404s:

```
{"error_code":"ENDPOINT_NOT_FOUND","message":"No API found for
 'GET /opensharing/metastores/48cda780-.../shares'"}
```

That is confinement by URL concatenation — a property of how two strings
join, not a decision anyone made, not fail-closed, and one target edit
away from being gone. The AI route differed only in having no path to hide
behind, so the same missing control became visible there first.

#### The claim that has been retracted

`scripts/29_gen_gravitee_route_family.py`'s `build_catch_all` emitted
route X disabled, with this rationale: an unmatched path "fails closed
because nothing matches it, which is the right OUTCOME reached by accident
rather than by decision." The sentence was doing real work — it is why the
catch-all could be left unbuilt — and it is false. Nothing fails closed.
The claim is now retracted in place in that file (B-19), in the docstring
and in a `retracted_claim` key inside the generated artifact, with the
measurement beside it.

So §2.3.2's route table was a **documentation** allow-list. Every
generator consumes it, and what they emitted were selectors that *match*
listed paths. None of them ever emitted a rule that *refuses unlisted
ones*. A row absent from the table was not absent from the gateway. v1.6
has to say which document is the enforced boundary and which merely
describes it, because the CONOPS currently reads as though they are the
same document.

#### The fix, and its limits

A terminal `resource-filtering` whitelist, last in the flow array,
measured before it was written into the generator. After deploy:
`token/list` 403, `clusters/list` 403, `serving-endpoints` 403,
`mcp/servers` 403 — all `{"message":"You're not allowed to access this
resource","http_status_code":403}` — and M1's model path still 200 with no
caller credential.

Four properties of that fix are load-bearing and each was learned the hard
way:

**The patterns are derived, not restated.** They are read off the
selectors of the flows that forward. An allow-list written out separately
drifts, and the drift is asymmetric: forgetting a live route is a loud
403, while admitting a path no flow claims is silent. B-39 has now cost
five defects in this repository.

~~**It must be LAST.** Flow policies here are cumulative rather than
first-match — verified by running the whitelist at position 0 and watching
M1's injection still happen. So position does not decide *whether* it
runs; it decides whether it runs *before* M3's explicit deny. Evaluated
first, it interrupts the legacy MCP request with an anonymous 403, M3's
mock never executes, the CONOPS reason never reaches the caller, and T-16
cannot attribute the refusal to the decision supposed to have
produced it.~~

**RETRACTED 2026-10-21 (B-19). Array position is not evaluation order.**
Gravitee evaluates flows from the **most generic selector to the most
specific**. The allow-list's selector is `/` `STARTS_WITH`, the most
generic there is, so it is evaluated **first** no matter how late it sits
in the array. Emitted last, it runs first. Proven both ways: with the
array `[M1, M3, X-terminal-allow-list]`, `/api/2.0/mcp/servers` answers in
`resource-filtering`'s words; disable that one flow and nothing else, and
the same path returns M3's marker.

The second half of the retracted paragraph described a consequence
correctly and called it avoidable. It is not avoidable, and it is now
accepted as **AI-9**: the caller receives the allow-list's reasonless 403,
and M3's CONOPS reason never reaches them. The trade was taken
deliberately. The reason-carrier (`mock`) fails **open** — that is
precisely how the original empty-`rules` deny shipped — and the enforcer
(`resource-filtering` whitelist) fails **closed**. When only one can
answer first, it must be the one whose failure mode is refusal. T-16 was
restructured around this rather than against it: M3 is attributed in the
one state where it is reachable (allow-list disabled, M3 still enabled),
which proves the backstop is live configuration and not dead, and the
test's passing verdict now says so by name —
`PERIMETER_CLOSED_M3_IS_THE_BACKSTOP_…`. The CONOPS may not claim the
caller is told *why* the legacy MCP route is closed.

The real rule the retracted one should have been is: **place a flow by its
selector's generality, and read evaluation order off the selectors, never
off the file.** A reviewer reading this generator top to bottom sees M3
before the allow-list and will conclude the opposite of what runs.

**`normalizeRequestPath` and `decodeEncodedSlash` both default to
`false`.** Left off, the policy matches the raw request path while the
upstream resolves a normalised one, so `/api/2.0/./mcp/servers` is a
different string to the filter and the same resource to Databricks. For a
whitelist that mostly fails closed; for a blacklist it is a straight
bypass. Both are set true. This is the difference between filtering the
resource and filtering the spelling.

**A whitelist, not a deny list.** A deny list must anticipate every path
worth protecting across hundreds of REST endpoints and fails open on
everything it forgot. The whitelist's verdict for a forgotten route is a
visible 403 on something someone wanted, not silent reach into something
nobody did.

#### The off-switch nobody would see (AI-10)

Found by accident while trying to make M3 answer first. A step-level
`condition` was added to the allow-list's `resource-filtering` step —
`{!#request.path.contains('/api/2.0/mcp')}` — intending "enforce
everywhere except M3's path, so M3 can answer there."

```
PUT     200
deploy  202
/ai-gateway-demo/api/2.0/token/list  + token  ->  200
```

The condition did not evaluate true, and Gravitee's response to a step
condition that does not evaluate true is to **silently omit the policy**.
No warning on PUT, no warning on deploy, nothing in the response to say a
control had been skipped. A one-line expression, accepted by every API the
platform offers for checking work, turned a default-deny perimeter back
into an open proxy. Reverted immediately; restore verified on both paths.

The rule, which belongs in v1.6 as a configuration constraint and not a
footnote: **no `condition` on any step whose absence fails open.** A
condition is safe on a step that *adds* a refusal and unsafe on a step
that *is* the refusal, because the failure mode of "expression didn't
match" is identical to the failure mode of "policy isn't there" — and
identical, from outside, to there never having been a policy at all. The
same silent negative as §12.9, now reachable by typo.

#### The limits of the fix

Its limits are real. The policy decides on the **request path** and
nothing else: it is not authorisation, says nothing about who the caller
is, and with a `KEY_LESS` plan (AI-1) a 403 from it must never be cited as
an unentitled caller being refused. And **it exists on one API**. The
sharing and storage APIs still forward unmatched paths. Bringing the same
flow to them was deliberately not done in the same change: T-01 and T-03
depend on those APIs, and a whitelist wrong by one pattern turns two
passing tests' positive control into a 403. B-48 stays **open** for the
estate.

#### What caught it, and what would not have

Not a gate, not a review, and not the policy. **The test**, because it
required Gravitee's own vocabulary before calling a refusal a refusal. An
assertion of `status in (401, 403)` would have passed on the upstream's
forwarded 401 and the no-op deny would have shipped as a working control —
and the open proxy behind it would never have been looked for. B-46's
positive-identification rule, written for a different reason three days
earlier, is what made the failure legible.

The generalisation for v1.6, stronger than the one B-46 already carries:
**a perimeter test that never observes the perimeter absent is measuring
its own expectations.** T-16 now disables the allow-list and confirms the
unclaimed paths come back to life, because asserting that a control is
what closed something is not the same as showing it.

One further consequence, caught by `check_secret_hygiene` during the same
change. T-16 snapshots the live API before mutating it, so a crash cannot
leave the perimeter disabled. The live API carries the *filled* credential
property, so that safety snapshot was a verbatim copy of a working
Databricks PAT written into `evidence/` — a safety mechanism that created
a disclosure. The gate found it because it scans the working tree rather
than the git index; the file was untracked, so an index-only check would
have reported clean. The snapshot is now split: redacted into `evidence/`,
full-fidelity into gitignored `_secrets/`, and neither is the restore
source during a run.

---

## 11.8 Coverage gap: 11 of 25 tests have no implementation

Scripts exist, in some form, for T-01 through T-14. **T-15 through T-25
have no code at all.** That is the entire ingress specification (CONOPS
2.4, channels I-1 and I-2, tests T-19 to T-25) and both AI routes (M1
model serving and M2 Unity Gateway MCP, tests T-15 and T-16), plus T-17
(publish and onboard) and T-18 (usage report and cross-tool dashboard).

Measured against the acceptance criteria rather than against test count,
the untested surface is larger than it looks: AC1 alone claims T-01 to
T-04, T-08, T-15, T-16, T-19 to T-21 and T-24 — seven of its eleven
tests are in the unimplemented set.

The test matrix (`docs/12-test-matrix.md`) assigns every one of these to
an epic with a feasibility verdict, so the gap is tracked rather than
discovered late.

**What changed on 2026-10-18, and why it changes the priority here.** The
counts above are unaffected — no code was written — but the *value* of
writing the ingress code rose sharply. Until that date, four of the seven
unimplemented ingress tests were capped at STANDIN or PARTNER, so code
written for them would have exercised a simulation. With a second
metastore and an open-source provider both available, T-19 through T-23
now have real counterparties, which makes the T-19 to T-23 scripts the
highest-return unwritten code in the repository: each one converts
directly into conclusive evidence rather than into a labelled
substitute. T-15, T-16, T-24's upload half and T-25 remain capped by
tier capability or by an unnamed owner, so they stay lower priority
regardless of how much code is written for them.

---

## 11.9 Re-running the probes

The capability probe is the first thing to run after any environment
change — a new workspace, a new token, a tier change.

```bash
cd ~/Documents/awoz-1227-opensharing-demo
python3 scripts/00_check_capabilities.py
```

It checks four things and prints a verdict: PAT/REST reachability, Unity
Catalog visibility, share listing, recipient listing. Note that it has
its own inline `.env` loader using `os.environ.setdefault`, so a
variable already exported in the shell wins over the `.env` value.

The capability probes that are *not* in that script yet — recipient IP
access list, view sharing, the mask/filter refusal, system table access,
AI Gateway availability — should be folded into it during Epic 1 so this
document can be regenerated rather than hand-maintained. That is an
Epic 1 task.
