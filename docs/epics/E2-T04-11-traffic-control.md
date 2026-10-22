# E2 — T04-11: Traffic Control and Serving Configuration (AC2)

| | |
|---|---|
| **Epic** | T04-11 |
| **Acceptance criterion** | AC2 — Traffic Control and Serving Configuration |
| **CONOPS sections** | 2.2, 2.3 (all), 2.3.4, 3.2, 5, 6 |
| **Stories** | 1: Serving design behind the front door · 2: Gravitee policies with Data Tooling · 3: Test results and ARB package |
| **Role** | Build — AI/ML Ops builds and tests it |
| **Target dates** | 10/8 – 10/29 · checkpoints **10/19** configuration tested with Data Tooling, **10/26** test results complete and OD-1 decided |
| **Depends on** | 1636 (Gravitee front door, relationship to Apigee unconfirmed), 1227-E1 (channel model and route table as CaC) |
| **Tests** | T-03, T-05, T-06, T-07, T-08, T-15, T-24 |
| **Decisions in play** | OD-1 (**gates 10/26**), OD-5, OD-8, OD-9 |
| **Risks in play** | R2, R5, R9, R10 |

> **The criterion, verbatim (CONOPS §3.2):** *exposure of Databricks
> endpoints through Gravitee with enforced rate limits, spike arrest and
> request schema validation to protect compute resources.*

---

## E2.0 What this epic actually has to produce

E1 owns the question of *who may see what*. E2 owns the question of
*what the edge does to a request on its way through* — and, critically,
the evidence that the edge trips **before** Databricks does. CONOPS
§2.3.3 states the design intent plainly: *"The Gravitee limit is set
below the Databricks-side limit on the same route so the edge trips
first."* AC2 is not satisfied by a rate limit existing. It is satisfied
by a rate limit demonstrably firing at the gateway while the Databricks
side never sees the burst.

Four deliverables:

1. **One** Gravitee V4 API, generated from the E1 route-table CaC file,
   with the correct upstream target — replacing the two half-correct
   APIs that exist today.
2. **Policy classes A–E** instantiated as reusable configuration, not
   copy-pasted per route, with the starting values from §2.3.3 and the
   tuned values recorded as the T-05 output.
3. **Six refusal and sanitization tests** (T-03, T-05, T-06, T-07, plus
   the edge halves of T-08 and T-24) each producing an evidence record.
4. **The §3.2 capability table, filled in** — seven gateway capabilities
   the design relies on, each currently marked "not yet confirmed for
   the Gravitee version in use", each with a fallback. Turning those
   seven rows from assumptions into observations against CE 4.12.23 is
   the single most useful thing this epic hands the ARB.

A note on the division with E1 and E5. T-03's *refusal* is enforced here
but the *allow-list content* comes from E1's `allow-lists.yaml`. The
correlation ID this epic injects is consumed by E5 (AC5, T-11); E2 owns
putting it on the request, E5 owns proving it ties the three logs
together. Do not re-litigate either boundary inside this epic.

---

## E2.1 Task list

Run them in order. Tasks 2.1 and 2.2 are prerequisites for everything
else and are also the overdue 10/19 checkpoint.

### Task 2.1 — Correct the B-1 diagnosis, then fix the real fault

**Blocker B-1 as written in §11.7 is wrong, and the wrong diagnosis is
more expensive than the fault.** §11.7 blames the 404 on the API
lifecycle never reaching `PUBLISHED` and on a duplicate API fighting
over deployment. Neither is the cause. Re-probed 2026-10-18 09:27 UTC:

```
# Both APIs, via management v2 (B-2 applies — v1 returns [ ]):
a45a3c30… "AWOZ-1227 OpenSharing Perimeter"              /delta-sharing/
          state=STARTED lifecycleState=CREATED deploymentState=DEPLOYED
          flows: perimeter-controls, storage-proxy-download
          target: https://dbc-0c6ebc56-563d.cloud.databricks.com/api/2.0/delta-sharing

97a9f494… "AWOZ-1227 OpenSharing - Metastore 48cda780"   /opensharing-demo/
          state=STARTED lifecycleState=CREATED deploymentState=DEPLOYED
          flows: (none)
          target: https://634cbc18-….opensharing.us-east-2.cloud.databricks.com
                  /api/2.0/opensharing/metastores/48cda780-…
```

Gateway log, both APIs: `ApiManagerImpl - API id[…] has been deployed`.
So the gateway picked up **both**. `lifecycleState: CREATED` governs
*portal publication*, not gateway serving — it is a red herring, and the
baseline doc should stop citing it.

The decisive evidence is the body of the 404:

```json
{"error_code":"ENDPOINT_NOT_FOUND",
 "message":"No API found for 'GET /delta-sharing/shares'",
 "details":[{"@type":"type.googleapis.com/google.rpc.RequestInfo", …}]}
```

That is a **Databricks** error, in Databricks' error envelope, with a
Databricks request id. The gateway proxied the call correctly; the
*upstream* rejected the path. Gravitee's own 404 looks different and is
logged by `NotFoundProcessor` — which does appear in the log, but only
for `/storage-proxy/` (that one is B-3, and it is real).

Meanwhile the "duplicate" API works end to end:

```
GET /opensharing-demo/shares                         → 200
  {"items":[{"name":"awoz1227_demo_share1ashu", …}]}
GET /opensharing-demo/shares/…/all-tables            → 200
  {"items":[{"name":"ashu","schema":"default", …,"accessModes":["url"]}]}
GET /opensharing-demo/shares  (no Authorization)     → 401
```

**The actual fault:** `https://<workspace>.cloud.databricks.com/api/2.0/delta-sharing`
is not the sharing endpoint on this tier. The endpoint in every
credential file is
`https://<uuid>.opensharing.<region>.cloud.databricks.com/api/2.0/opensharing/metastores/<metastore-id>`,
and §2.3.2 is explicit that the target must be *"the endpoint from the
credential file plus the same path"*. The original API was built against
an assumed URL instead of the issued one.

So the two APIs are each half right: one has the policy flows and the
wrong target, the other has the right target and no policy flows. The
fix is to converge them into one, not to pick a winner.

**Deliverable:** a corrected diagnosis written back into
`docs/11-environment-baseline.md` §11.7 (B-1 reclassified: upstream
target error, not a lifecycle or duplication fault, with the 404 body as
evidence); a single consolidated V4 API carrying the `/opensharing-demo`
target and the `perimeter-controls` flow; the redundant API deleted, not
left stopped.

**Verify:** `GET <edge>/shares` with the recipient token returns the
share list **and** the request appears in the Gravitee access log with
the ip-filtering policy evaluated. Management v2 `_search` returns
exactly one API.

**This is the 10/19 checkpoint.** It is already overdue; it is also an
afternoon's work, because the hard part — proving the gateway can proxy
the open protocol at all — is already done.

### Task 2.2 — Make the import idempotent

The duplicate API is itself a defect, independent of B-1. The 23:43
re-import created a second definition rather than updating the first,
which means `scripts/05_import_gravitee_api.py` is not idempotent.

This matters twice over. Here, because an epic whose whole job is
deny-by-default cannot have two definitions of what "default" is. And in
E6, because AC6's T-12 is *"redeploy from code onto a clean target"* —
an import that duplicates on second run fails T-12 by construction. Fix
it here, where it blocks, rather than discovering it in E6.

The correct shape, given B-2: search by **cross-ID or by name** through
`POST /management/v2/environments/DEFAULT/apis/_search`, then `PUT` the
existing id if found and `POST` only if not. Gravitee's cross-ID field
exists precisely for this; use it and set it from the CaC file so the
identity of the API lives in version control rather than in whichever
UUID the server happened to mint.

**Deliverable:** `scripts/05_import_gravitee_api.py` rewritten against
management v2, idempotent by cross-ID, with deploy-after-update; a
`--prune` mode that removes APIs carrying our cross-ID prefix but no
longer in the CaC file.

**Verify:** run the import three times; the API count stays at one and
the revision increments only when the definition actually changed.

### Task 2.3 — Generate the route table into the API definition

E1 Task 1.3 produces `iac/config/route-table.yaml` holding S1–S10, F1,
M1–M3, A1 and X. This task turns that file into V4 flows rather than
hand-maintaining JSON.

Generate, do not transcribe. A route table that exists twice — once as
the CaC source and once as hand-edited JSON — will diverge, and the
divergence will be discovered by a reviewer rather than by a test.

Three design points worth settling before writing the generator.

Flow **selectors** must match on both method and path, because the
protocol distinguishes `GET .../tables/{table}/metadata` (class A) from
`POST .../tables/{table}/query` (class B) on paths that overlap. A
path-only selector silently puts the query route in class A and the
rate-limit evidence for T-05 becomes meaningless.

Route **X** needs to be a real flow, not an absence. §2.3.2 says *"Routes
not listed are denied"* and §3.2's capability table offers *"explicit
catch-all deny route"* as the fallback if deny-by-default is not native.
Build the explicit catch-all regardless — it is the only way the denial
emits the protocol error format (`errorCode`, `message`) that §2.3.2
requires, rather than Gravitee's own 404 shape.

Routes **M3** and **A1** are represented as explicit deny flows with a
comment naming why, not as omissions. §3.1.2's reason for M3 — legacy
managed MCP bypasses Unity AI Gateway grants, policies and guardrails,
and its calls do not appear in the tracing tables — belongs in the
generated artifact where an auditor will find it.

**Deliverable:** `scripts/gen_gravitee_api.py` emitting
`iac/gravitee/api-definition.json` from `route-table.yaml` +
`policy-classes.yaml`; the generated file committed so diffs are
reviewable.

**Verify:** every route id in the YAML appears as a flow; `S8` and `S7`
resolve to different classes; an unlisted path returns the protocol
error format and not a Gravitee 404.

### Task 2.4 — Policy classes A–E as shared configuration

§2.3.3 gives five classes and a set of common policies that apply to
every route. Express the common set once and the per-class deltas once.

Common, per §2.3.3: address allow-list per consumer, bearer presence and
format check, correlation ID added, internal headers removed,
metadata-only logging, deny by default.

Per class, the starting values — and they are starting values, which
§2.3 is explicit about: *"proposals to be tuned in the Section 5 tests;
they are not commitments."* Record them as config, and record the tuned
values as the T-05 output rather than editing history.

| Class | Routes | Rate limit | Spike arrest | Quota/day | Body and validation | Timeout |
|---|---|---|---|---|---|---|
| A | S1–S7 | 60/min | 5/s | 5,000 | no body; path pattern check | 30 s |
| B | S8, S9 | 20/min | 2/s | 1,000 | 16 KB max; JSON schema | 60 s |
| C | S10 | 20/min | 2/s | 1,000 | small body max | 30 s |
| D | F1 | 600/min | 20/s | 50,000 req | GET/HEAD only; range allowed | 300 s |
| E | M1, M2 | 30/min | 3/s | 2,000 | 1 MB JSON; schema per endpoint | 120 s |

Gravitee CE 4.12 has **shared policy groups**, and the gateway log shows
three already deployed in this environment. Use them for the common set
so that a change to header sanitization is one edit rather than fifteen.

Two implementation traps, both already paid for once.

The rate-limit and spike-arrest policies maintain counters in MongoDB
and **build their own connection URI** from discrete properties. Without
`gravitee_ds_mongodb_host`, `_port` and `_dbname` on the **gateway**
service, every request touching one of these policies hangs until
timeout — it does not error, it hangs, which is far harder to diagnose.
`docker-compose.yml` carries the fix; any clean-target rebuild under
T-12 must carry it too.

The per-consumer requirement in §2.3.3 ("Class settings are per
consumer") needs a rate-limit key. §3.2 lists *"rate-limit key from the
Authorization header"* as a needed capability with *"key by source
address"* as the fallback. §2.3.4 explains why this is delicate: the
reference clients send **only** the bearer token and cannot be made to
present a gateway API key. So key on a **hash** of the Authorization
header, never the token itself, and never log the key. If CE cannot
derive a key from a header, fall back to source address and record that
the fallback was taken.

**Deliverable:** `iac/config/policy-classes.yaml`; shared policy groups
for the common set; the Mongo requirement documented inline in the
compose file and in `iac/config/README`.

**Verify:** a class B route rejects a 17 KB body and a class A route on
an overlapping path still accepts a no-body GET; a request touching a
rate-limited route completes in milliseconds, not at timeout.

### Task 2.5 — T-03: valid token from an address not on the allow-list

This one has already passed once, on 2026-10-17 15:40, and the evidence
survives in `_secrets/t03-refusal-evidence.json` — a 403 from the
`ip-filtering` policy with the message
`Your IP (172.21.0.1) ... not allowed`. Two things follow.

It must be **re-run and re-captured** after Task 2.1, because the API it
passed against is the one being retired. A test result against a
retired configuration is not evidence.

And the evidence file must **move out of `_secrets/`**. It contains no
secret; it is in there by accident, and it is the clearest demonstration
of AC2's enforcement that this project has produced. It belongs in
`evidence/` where the ARB package can reference it.

T-03 is also the test that makes R4 (stolen token) tolerable: the token
is valid and the request still fails. Pair it in the evidence record
with E1's T-02, which proves the same thing at the Databricks layer via
the recipient IP access list. Two independent layers, one claim — that
is §6's "layered enforcement" principle with evidence behind it.

**Deliverable:** `tests/t03_address_denied.py`;
`evidence/t03-refusal.json`; `_secrets/t03-refusal-evidence.json`
removed.

**Verify:** 403 from the gateway, logged, with the Databricks side
showing no corresponding request. The second half matters more than the
first — a refusal that still reached Databricks is not a perimeter.

### Task 2.6 — T-05: rate limit, spike arrest, and who trips first

The headline AC2 test. Burst above the configured limit per class and
record the throttle response.

Three assertions, in order of how much the ARB will care.

**The edge trips before Databricks.** Burst a class A route above 60/min
and confirm the Databricks side logged fewer requests than were sent.
This is the actual content of clause 2.5, *"to protect compute
resources"*, and it is the one assertion that cannot be satisfied by
reading configuration.

**The throttle response is recorded as observed.** §3.2 wants 429 with a
retry indication and names *"record the actual response"* as the
fallback; R9 is the risk that CE does not emit `Retry-After`. Capture
the status, headers and body verbatim. If it is a bare 429, say so — the
CONOPS has pre-accepted that outcome, and a fabricated `Retry-After`
would be worse than an honest gap.

**Spike arrest and rate limit are distinguishable.** Two bursts: one
fast and small (trips spike arrest at 5/s, passes the per-minute limit),
one slow and large (passes spike arrest, trips 60/min). If both produce
the same response with no way to tell them apart, that is a finding
worth recording, because operators will need to tell them apart.

Then tune. The §2.3.3 values are proposals; T-05's deliverable includes
the values the test actually supports, written back to
`policy-classes.yaml` with a note on what drove the change.

**Deliverable:** `tests/t05_rate_limit.py` covering classes A, B and D;
`evidence/t05-throttle.json` with verbatim responses; tuned values in
`policy-classes.yaml`.

**Verify:** throttling observed per class; Databricks-side request count
strictly less than the sent count; spike arrest and rate limit
separately attributable or the ambiguity recorded.

### Task 2.7 — T-06: schema validation, body limits, and the error format

Malformed and oversized bodies to the query route (S8, class B) must be
*rejected at the gateway* in the protocol error format.

The schema, from §2.3.3, allows exactly: `predicateHints`,
`jsonPredicateHints`, `limitHint`, `version`, `timestamp`,
`startingVersion`, `endingVersion`. Build it as a real JSON Schema file
in `iac/gravitee/schemas/` and reference it from the flow, so the schema
is reviewable on its own and reusable by E4's push-ingest validation.

Four cases, and the fourth is the one that is usually missed. Oversized
body (>16 KB) rejected. Malformed JSON rejected. Well-formed JSON with
an undeclared field rejected — which requires `additionalProperties:
false`, so set it deliberately and know that this is the choice that
makes the test meaningful. And a **valid** query body accepted, because
a schema that rejects everything passes the first three cases while
breaking the product.

The error format is as important as the rejection. §2.3.2 requires
denials in the protocol's shape (`errorCode`, `message`). Gravitee's
`json-validation` policy emits its own body by default; override it, or
chain a response transformation, so a reference client sees something it
can parse. Confirm what CE 4.12 actually lets you control here and
record it — this is one of the seven §3.2 capability rows.

**Deliverable:** `iac/gravitee/schemas/query-body.schema.json`;
`tests/t06_schema_validation.py` with all four cases;
`evidence/t06-validation.json`.

**Verify:** three rejections and one acceptance; every rejection body
parses as a protocol error with `errorCode` and `message`.

### Task 2.8 — T-07: header sanitization — currently failing

§2.2 step 5 requires Gravitee to remove internal headers (naming
`X-Databricks-Org-Id`) and hostnames from the response. **The working
route does not do this today.** The 200 from `/opensharing-demo/shares`
on 2026-10-18 returned:

```
server: databricks
X-Gravitee-Client-Identifier: fbd57f01…
X-Gravitee-Transaction-Id: c382cd8f-…
X-Gravitee-Request-Id: c382cd8f-…
server-timing: request_id;dur=0;desc="0ea91778-…", client_protocol;…
x-request-id: 0ea91778-…
```

`server: databricks` names the upstream platform. `server-timing` and
`x-request-id` carry upstream request identifiers. The `X-Gravitee-*`
triplet discloses the gateway product and its internal transaction ids.
None of this is catastrophic on its own; all of it is exactly what
clause 2.4's sibling control in §2.2 exists to strip, and all of it
would be found by any competent reviewer in thirty seconds.

Build the strip list as an **allow-list of response headers**, not a
deny-list. A deny-list is a list of the leaks you have already thought
of; the next upstream version will add one you have not. Permit what the
protocol needs (`content-type`, `transfer-encoding`, caching headers,
and for F1 the range and content-length headers) and drop the rest.

Keep one deliberate exception: the correlation ID that E5 depends on.
That header is ours, is documented, and is the mechanism by which AC5's
trace works — so it is in the allow-list, named, with a comment pointing
at §3.5.

**Deliverable:** a `transform-headers` configuration in the common
shared policy group; `iac/config/response-header-allowlist.yaml`;
`tests/t07_header_sanitization.py`; `evidence/t07-headers.json` with
before and after captures.

**Verify:** no `server`, `server-timing`, `x-request-id`,
`X-Databricks-*` or `X-Gravitee-*` header survives; the correlation ID
does; a reference client still parses the response. Include the
**before** capture in the evidence — a sanitization control with no
record of what it removed is unauditable.

### Task 2.9 — T-08 and F1: the storage proxy, and resolving B-3

OD-1(b) is the decision that file downloads are proxied through the
gateway, and §3.2's checkpoint makes **OD-1 due 10/26**. T-08 is what
decides it: download through the proxy succeeds *and* a direct storage
read is refused — or the fallback (storage address limits plus
short-lived credentials) is recorded.

Start by resolving **B-3**, because the path contradiction will waste an
afternoon otherwise. `api-definition.json` declares `/storage-proxy` as
a flow selector *beneath* the `/delta-sharing` listener, making the real
edge path `/delta-sharing/storage-proxy`, while `.env` declares
`http://localhost:8082/storage-proxy`. The gateway log settles which one
is live: `No handler can be found for request /storage-proxy/, returning
NOT_FOUND (404)` — from `NotFoundProcessor`, a genuine Gravitee 404,
unlike B-1's proxied one. Give F1 **its own listener path** so the
OD-1(b) route is independent of the sharing listener's class A policies,
and keep `.env` as the source of truth.

The hard part is not the route, it is the rewrite. §2.3.2 route F1
requires: range requests must pass, the signed query string must be
forwarded unchanged, and URLs in responses must be rewritten to this
route. The last of those is the one §3.2 flags as unconfirmed. The
`all-tables` probe shows `accessModes: ["url"]`, which confirms this
tier vends pre-signed URLs — so there *are* URLs in the response body to
rewrite, and they are in newline-delimited JSON on S8, not in a single
JSON document. A response-body rewrite over NDJSON in CE 4.12 is the
genuine technical risk in this epic.

Sequence it so a failure is informative. Prove the forward path first
(can the gateway relay a signed request to storage, with range, without
breaking the signature?). Only then attempt the body rewrite. If the
forward works and the rewrite does not, OD-1 has a real answer —
proxying is feasible but needs a thin rewrite service — rather than an
undifferentiated "did not work".

**Deliverable:** F1 on its own listener with class D policies; `.env`
and `api-definition.json` reconciled; `tests/t08_storage_proxy.py`
covering proxied download, range request, and direct-storage refusal;
`evidence/t08-proxy.json`; a written OD-1 recommendation with the
observed basis.

**Verify:** a reference client completes a full table read end to end
through the edge with no direct storage reachability. If the rewrite is
infeasible, the evidence record states which half failed and the
fallback is written up rather than implied.

### Task 2.10 — T-15: class E and the serving routes (PROBE, narrowed 2026-10-18)

M1 (model serving) and M2 (Unity Gateway MCP) carry class E limits, and
clause 2.5 requires serving endpoint scaling caps set **above** the
gateway limit so the edge trips first. The original text here said E1
Task 1.9 would probe "whether these assets exist on this tier at all;
the likely answer is no". **That is corrected: they exist.** Unity
Gateway is live with thirteen governed models, so this task has a real
upstream and clause 2.5 becomes testable rather than theoretical.

That makes clause 2.5 the interesting part of this task rather than a
box to tick. "Set the serving cap above the gateway limit so the edge
trips first" is a statement about **precedence between two gateways**,
and it is only meaningful if both can be observed refusing. Build the
class E flows and route definitions from the CaC file as before — they
must stay reviewable and T-12-redeployable — then run T-15 and assert
the Gravitee limit trips first. If the tier allows setting a Unity
Gateway limit as well, invert the pair and capture the error body both
ways: a consumer who trips the edge and a consumer who trips the
upstream should not receive two unrelated error contracts, and nothing
in §5.2 would catch it if they do. Coordinate with E1 Task 1.9 part 3,
which owns the same question from the AI/ML Ops side.

A quota refusal on invocation is still possible and still lands under
A8 — but it must be recorded as *quota*, not as *availability*. That
distinction is the difference between a bounded finding and a
write-off, and the ARB package states it on the page where class E
appears, not in an appendix.

**Deliverable:** class E flows for M1 and M2 and the explicit M3 deny;
`tests/t15_model_route.py` written, possibly `NOT_RUN`; the layering
rule in `policy-classes.yaml` as `databricks_side_limit_must_exceed`.

**Verify:** M3 from the edge returns the protocol error format and not a
proxied response — this half is provable today and closes part of OD-8.

### Task 2.11 — T-24: the edge half of push ingest

T-24 belongs to E4 (AC4, self-service publish) and I-2 is **proposed**
under OD-9, not baselined. E2 owns only the edge enforcement: oversize
refused, wrong content type refused, wrong path refused, overwrite
refused, `GET` on an upload route refused, and a direct Files API call
refused.

The refusals are buildable now, before any landing volume exists,
because five of the six are pure edge concerns. Build them against a
stub upstream and hand E4 a route that already denies correctly. The
sixth — the direct Files API call — is a reachability assertion and
needs no upstream at all.

§3.2 flags *"path rewrite and upstream credential injection"* as an
unconfirmed capability for exactly this route, with *"thin ingest or
proxy service in front of the Databricks API"* as the fallback. Test the
capability here and record the result; E4 should not discover it.

**Deliverable:** class I flows with the six refusals; the capability
result for path rewrite and credential injection recorded;
`tests/t24_push_refusals.py` (edge cases only, E4 owns the allowed
upload).

**Verify:** all six refusals occur at the edge, each with a distinct and
correct status.

### Task 2.12 — Fill in the §3.2 capability table, then build the package

§3.2's seven-row table is the most honest thing in the CONOPS: seven
capabilities the design depends on, each *"not yet confirmed for the
Gravitee version in use"*, each with a fallback. Replacing those seven
"not confirmed" cells with observations against **CE 4.12.23** is this
epic's main contribution to the ARB.

| Capability needed | Used for | Test | Observed on CE 4.12.23 | Fallback taken? |
|---|---|---|---|---|
| Validate the agency JWT | OIDC option (OD-5) | T-09 | *to fill* | |
| Rewrite file URLs; forward signed storage requests incl. range | F1 / OD-1(b) | T-08 | *to fill — Task 2.9* | |
| Rate-limit key from the Authorization header | Per-consumer limits | T-05 | *to fill — Task 2.4* | |
| Return 429 with a retry indication | Throttle behaviour | T-05 | *to fill — Task 2.6* | |
| Deny by default for unlisted routes | Route X | T-02, T-03 | *to fill — Task 2.3* | |
| Path rewrite and upstream credential injection | Push ingest, AI routes | T-15, T-24 | *to fill — Task 2.11* | |
| Client certificate support in reference clients | §2.3.4 | T-09 | *to fill* | |

Two rows will likely stay open. JWT validation is downstream of OD-5,
which is Open (13.2), so the honest entry is "not applicable until OD-5
decides" rather than a result. Client certificate support (R10) is a
property of the *reference clients*, not of Gravitee — so it is tested
by attempting a client-cert handshake from `delta-sharing` and
`python-docx`-era tooling, and §2.3.4 already names the fallback:
the address allow-list plus the recipient IP list carry the binding.

Then assemble Story 3. The package needs: the consolidated route table
and its generator, the policy classes with starting *and* tuned values,
the six evidence records, the filled capability table, and the §6
principles AC2 supports — layered enforcement, tested-not-asserted, and
the compute-protection argument from clause 2.5.

Three things stated on the first page rather than discovered.
**OD-1 is decided by T-08 and due 10/26** — lead with the
recommendation. **T-07 was failing before this epic**, and the before/
after capture is the strongest single piece of evidence in the package;
present it as a found-and-fixed control, not as a clean sheet. And
**B-1 was misdiagnosed for a day** — the corrected diagnosis belongs in
the package's lessons section, because "we built against an assumed
endpoint URL instead of the issued one" is a mistake the production
build can avoid for free.

**Deliverable:** `docs/epics/E2-arb-package.md` with the capability
table filled, evidence references, and the OD-1 recommendation.

**Verify:** every AC2 clause (2.1–2.5) traces to evidence or to a named
gap; all seven capability rows carry an observation or a reason they
cannot yet have one.

---

## E2.2 IaC and CaC deliverables

| Path | Contents |
|---|---|
| `iac/gravitee/api-definition.json` | **Generated** V4 definition — one API, correct target, all flows |
| `iac/gravitee/schemas/query-body.schema.json` | §2.3.3 body schema for S8/S9, `additionalProperties: false` |
| `iac/gravitee/shared-policy-groups/` | Common policy set: allow-list, bearer check, correlation ID, header strip, logging |
| `iac/config/policy-classes.yaml` | Classes A–E: starting values, tuned values, and what changed them |
| `iac/config/response-header-allowlist.yaml` | T-07 allow-list, correlation ID named as the exception |
| `iac/config/gateway-env.yaml` | The Elasticsearch and **MongoDB** discrete properties, with the reason inline |
| `scripts/gen_gravitee_api.py` | Route table + policy classes → API definition |
| `scripts/05_import_gravitee_api.py` | Rewritten: management v2, idempotent by cross-ID, deploy-after-update, `--prune` |

The generated definition is committed. Generated-and-committed gives
reviewable diffs and keeps T-12 honest; generated-and-gitignored means
the thing that actually ran is not in version control.

No secrets in any of these — upstream tokens are `.env` or vault
references per §3.6.

---

## E2.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-01 | BUILD | **E1** | Needs this epic's Task 2.1 to land first |
| T-03 | BUILD | E2 | Passed 10/17; must be re-run post-consolidation |
| T-05 | BUILD | E2 | The headline AC2 test; needs the Mongo keys |
| T-06 | BUILD | E2 | Four cases, including the positive |
| T-07 | BUILD | E2 | **Currently failing**; before/after capture required |
| T-08 | PARTIAL | E2 | Direct-storage refusal not fully testable here |
| T-11 | — | **E5** | E2 injects the correlation ID; E5 proves the trace |
| T-15 | PROBE (narrowed 10/18) | E1 probe, E2 limits | Real upstream now exists; clause 2.5 precedence is testable, not theoretical |
| T-24 | PARTIAL | **E4** | E2 owns the six edge refusals |

---

## E2.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the
following hold:

Exactly one Gravitee API exists, generated from the E1 CaC files, with
the upstream target taken from the issued credential file rather than
assumed; running the import repeatedly does not change that count.
Blocker B-1 is reclassified in the baseline document with the proxied-
404 body as evidence, and B-3 is resolved by giving F1 its own listener.
Policy classes A–E exist as configuration, with the common set in a
shared policy group, and a request touching a rate-limited route returns
promptly rather than hanging. T-03, T-05, T-06 and T-07 pass with
evidence records, and T-07's record carries both the before and after
header captures. T-05 demonstrates the Databricks side receiving fewer
requests than were sent, and the tuned values are written back to
configuration. T-06 rejects three bad bodies and accepts one good one,
all four in the protocol error format where applicable. T-08 produces an
OD-1 recommendation grounded in what the gateway actually did, including
if what it did was fail the body rewrite. The six T-24 edge refusals
work against a stub. Class E flows and the M3 deny exist whether or not
an AI asset was found. All seven §3.2 capability rows carry an
observation or a stated reason they cannot.

---

## E2.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| OD-5 sign-in method | Data Governance decision | 13.2; JWT-validation row stays open |
| 1636 front door and its relation to Apigee | Data Tooling | §3.2 records it unconfirmed |
| The 10/19 "tested with Data Tooling" checkpoint | A Data Tooling environment and a counterpart | §3.2; locally we can only self-test |
| T-08 direct-storage refusal | Storage-account network controls on the tenant | 12.2; PARTIAL verdict |
| ~~T-15 positive~~ | ~~A model serving endpoint on the tier~~ — **removed 10/18**; thirteen governed models are live, only invocation is unproven and that is ours to test | R11 downgraded; ask 9 re-scoped |
| Client certificate support (R10) | Reference client behaviour, then a decision | §2.3.4; fallback already named |
| Production-scale limit values | Real consumer traffic profiles | §2.3 — starting values only |

Each leaves the epic as a dated ask, not as an empty cell in the ARB
package.
