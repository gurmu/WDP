# 12. Test Matrix — T-01 … T-25

Source: CONOPS AWOZ-1227 v1.5 **§5.2 Test Plan** (25 tests), with the
criterion mapping from **§1.5 Acceptance Criteria Map** and the epic
mapping from **§10.1 Traceability Matrix**. Local feasibility verdicts
come from `docs/11-environment-baseline.md`.

The CONOPS evidence rule (§5.1) applies to every row: record test ID,
expected result, actual result, date and an evidence reference; names
and metadata only; never tokens, credential files or data.

---

## 12.1 Feasibility legend

| Verdict | Meaning |
|---|---|
| **BUILD** | Fully buildable and verifiable on this laptop against this workspace. |
| **REBUILD** | Buildable, but the existing implementation is invalid and must be rewritten before the result means anything. |
| **PARTIAL** | The structural half is testable locally; one named dependency keeps it from being a complete proof. The gap is stated, not hidden. |
| **PROBE** | Feasibility unknown until a named capability probe runs. Has a CONOPS-sanctioned fallback if the answer is no. |
| **STANDIN** | Needs an external party the prototype can only simulate; the simulation is explicitly labelled as such. |
| **PARTNER** | Cannot be done solo. Needs a second organisation, a real tool, or an owner who has not been named. |

---

## 12.2 The matrix

| ID | Test (CONOPS §5.2) | Criterion | Epic | Local verdict | What blocks a full proof | Evidence artifact |
|---|---|---|---|---|---|---|
| T-01 | Allowed caller reads entitled data through the gateway (repeats the initial share test) | AC1, AC4 | E1 | **BUILD** | — | `evidence/t01-gateway-read.json` |
| T-02 | Call straight to the Databricks sharing endpoint with a valid token | AC1 | E1 | **BUILD** | Recipient IP access lists work here (11.3), so the refusal is real, not simulated | `evidence/t02-direct-refusal.json` |
| T-03 | Valid token from an address not on the allow-list | AC1, AC2 | E2 | **BUILD** | Already passed once: 403 `ip-filtering`, 2026-10-17T15:40Z | `evidence/t03-refusal.json` |
| T-04 | Request a table or column outside the grant | AC1 | E1 | **REBUILD** | Current build shares the base table, so `internal_notes` is *inside* the grant (11.5). Must be re-specified on the shared-view pattern (11.4) | `evidence/t04-column-denied.json` |
| T-05 | Burst above the rate limit and spike arrest, per class | AC2 | E2 | **BUILD** | Needs the Mongo counter fix already in `docker-compose.yml`, or the policy hangs silently (11.2) | `evidence/t05-throttle.json` |
| T-06 | Malformed or oversized body to a query route | AC2 | E2 | **BUILD** | — | `evidence/t06-schema-reject.json` |
| T-07 | Inspect response headers | AC2 | E2 | **BUILD** | — | `evidence/t07-headers.json` |
| T-08 | Download files through the storage proxy; try a direct storage read | AC1, AC2 | E2 | **PARTIAL** | The proxy forward is testable; the *refusal* of a direct storage read is not — Free Edition storage is Databricks-managed, so we cannot set storage-side egress restrictions. Record the OD-1 fallback instead | `evidence/t08-proxy-download.json` |
| T-09 | Read with the rewritten credential file in each reference client; record certificate and token behaviour | AC4 | E4 | **PARTIAL** | `delta-sharing` (pandas) and Spark are available. Power BI, Tableau and the Java client are not — record as not tested, per §5.1's reference-client list | `evidence/t09-clients.json` |
| T-10 | Rotate a token; revoke a recipient | AC3, AC4 | E3, E4 | **BUILD** | Two-token maximum and overlap behaviour are observable (CONOPS 3.1.1) | `evidence/t10-rotate-revoke.json` |
| T-11 | Trace one egress request using the correlation ID | AC5 | E5 | **PARTIAL** | Gateway → Elasticsearch half is BUILD. The Databricks half depends on `system.access.audit` availability on Free Edition, which is **unconfirmed** (11.6). CONOPS 3.5 already warns the custom header may not reach the audit event; T-11's job is to determine the working join key | `evidence/t11-trace.json` |
| T-12 | Redeploy the configuration from code to a clean target | AC6 | E6 | **BUILD** | The central test of the build target. `docker compose down -v && up -d` + re-import + Terraform apply, then diff | `evidence/t12-redeploy.json` |
| T-13 | PSP7 runs onboarding and a read | AC8 | E8 | **PARTNER** | Needs the CDAO PSP7 team. Session to be booked by 11/3 (CONOPS 3.8, R5). A self-run rehearsal is useful but is not T-13 | — |
| T-14 | Raise a test ticket for an access denial and for a rejected upload | AC9 | E8 | **PARTIAL** | The triage runbook and correlation-ID routing can be walked through on paper. No Service Desk owner exists yet (OD-7, **Open**) | `evidence/t14-triage.json` |
| T-15 | Call a model service through Gravitee as a consumer | AC1, AC2, AC4 | E1, E2 | **BUILD** (was PROBE, was STANDIN-adjacent in expectation) | **Settled 2026-10-18 by probe.** `scripts/08_probe_ai_gateway.py` returned `WORKS`: `databricks-gpt-oss-20b` answered HTTP 200, and `/api/2.0/serving-endpoints` lists 12 endpoints automatably. Availability, authentication and invocation are all proven, so what remains is route-building, not capability. Still carries R12 (gateway-side token injection), which is a build risk shared with other BUILD tests, not a blocker. **Two caveats belong in the evidence record**: the probe used `max_tokens=16` and returned `finish_reason: length` with a *reasoning-only* content block, so the full response shape is not yet captured; and `content` is an **array of typed blocks**, not the classic OpenAI string — see the schema warning in §12.7 | `evidence/t15-model-route.json`, `evidence/capability-baseline-ai.json` |
| T-16 | Call a Unity Gateway MCP server through Gravitee; try a legacy MCP route | AC1, AC4 | E1, E4 | **PROBE** (narrowed) | **Re-scoped 2026-10-18**: the account-console blocker does not apply — an **MCPs tab is present** on the live Unity Gateway surface, alongside Skills and Agents. The remaining question is narrower and genuinely open: whether that tab holds, or permits creating, a *callable* MCP server on this tier. The *negative* half (legacy `/api/2.0/mcp/*` unreachable from the edge, route M3) is BUILD regardless and closes half of OD-8 on its own | `evidence/t16-mcp-route.json` |
| T-17 | Publish a new dataset and onboard a consumer with only the approval as a manual step | AC4 | E4 | **BUILD** | Tests the OD-4 chain end to end and records elapsed time | `evidence/t17-publish-onboard.json` |
| T-18 | Produce the per-consumer usage report and the cross-tool dashboard | AC5 | E5 | **PARTIAL** | Gateway metrics are in Elasticsearch and reportable. Databricks usage/query system tables and the Unity AI Gateway usage tables are unconfirmed on this tier, so "the figures agree" may be provable on one side only | `evidence/t18-usage-report.json` |
| T-19 | Ingress D2D: test provider shares a table with the platform metastore; catalog created; entitled group reads; other group denied; refresh behaviour recorded | AC1, AC3 | E1 | **RUN — `PARTIAL_WITH_NAMED_GAPS`** (was BUILD, was PROBE, was PARTNER) | **Executed 2026-10-20** (`tests/t19_ingress_d2d.py`, 4 runs). Four results, each with its scope. (1) `D2D_SURFACING_ONLY`: with `authentication_type = DATABRICKS` no provider object appears on the consuming metastore — four independent bounded negatives, so the §2.4.1 consumer-side sequence cannot be followed here and the ingress half ran through the open-sharing substitute instead. (2) `DENIAL_A_DEMONSTRATED`: share membership is an enforced boundary — an unshared table in the same provider schema is `TABLE_OR_VIEW_NOT_FOUND` through the consumer catalog. (3) `DENIAL_B_DEMONSTRATED` against a `--fresh-principal` with `UNGRANTED_CONFIRMED`, `groups=none`, a **named** refusal cause (`INSUFFICIENT_PERMISSIONS … does not have USE CATALOG`) and a paired positive control (`READ_SUCCEEDED after 4.6s`) — which retires run 3's `FAIL_ACCESS_CONTROL_LEAK` as our own crash residue, labelled in `prior_runs` rather than deleted (B-19). (4) `REFRESH_IS_TIME_BASED` (see §12.11). Three platform behaviours came out of it: B-27 (HTTP 200 + `state: FAILED` on a denial), B-28 (SCIM entitlements before the SQL API, with an empty-bodied 403), B-29 (one recipient per sharing identifier). **Named gap:** native D2D surfacing, `NOT_RUN_CAPABILITY_NAMED`. Earlier note, still true: **settled 2026-10-18 by probe** (`scripts/09_probe_metastore_identity.py`, `evidence/capability-baseline-d2d.json`). Both gating questions answered yes. (1) `DISTINCT_METASTORES`: primary `48cda780-1dc7-459d-bee0-77abde9af938` vs second account `8875961b-9666-494c-95e2-af6b5b78bd3d`. (2) `PERMITTED`: a recipient with `authentication_type = DATABRICKS` and sharing identifier `aws:us-east-2:8875961b-…` was **created (HTTP 200) and deleted (HTTP 200)** on Free Edition. So D2D is structurally possible *and* tier-permitted, and what remains is share/grant construction — build work, not capability. A10 and R14 are closable; the partner dependency is gone. **See the retraction in §12.9**: an earlier run of this same probe reported `SAME_METASTORE`, which was false | `evidence/t19-ingress-d2d.json`, `evidence/capability-baseline-d2d.json` |
| T-20 | Ingress D2O: import a credential file from the vault; read through the catalog and the connector; record the hosts contacted; attempt a host not on the allow-list | AC1 | E1 | **RUN — `PASS_WITH_SCOPE`** (was BUILD, was STANDIN) | **Executed 2026-10-18** (`tests/t20_ingress_d2o.py`). §2.4.1 step 5 contains two actions in two environments, so the test runs both halves. **Path A, control plane:** `5a IMPORTED (200)`, `5b REFUSED (400 SecurityException)`, `5c CREATED (200)`, `6 GRANTED (200)` → `BLOCKED_BY_LOCAL_TOPOLOGY_ATTRIBUTED`. The block is attributed to the **address class**, not the tier, by probe 14 check 5 reaching `example.com` and getting a real 404 with the upstream body (11.7 B-14). 5c and 6 succeeding over an unreachable provider is defect **D-6**. **Path B, client connector:** the §2.4.1 D2O snippet read through `delta_sharing` under a socket-layer capture, one fresh subprocess per phase so no pooled connection or cached DNS can carry a result across — capture `discovery=LISTED data=READ` (2 hosts), sufficiency with exactly that set `LISTED/READ`, necessity with the provider only `LISTED/FAILED` → `NECESSARY_AND_SUFFICIENT`. Both halves of the necessity result matter: discovery surviving is what attributes the data failure to the storage host rather than to a broken read. **Scope, which travels with the result:** the filter is in-process, so it proves the read *depends* on those hosts, not that a firewall would enforce it; and all seven §2.4.2 roles were worn by one operator, so the sequence and artefacts are evidence while the segregation of duties is not. The captured hosts are local and do **not** transfer — per §2.4.3 the deliverable is the capture *procedure*, which Databricks does not document, and `iac/config/outbound-allow-list.yaml` is generated carrying `non_transferable: true` | `evidence/t20-ingress-d2o.json`, `evidence/capability-baseline-d2o-import.json`, `iac/config/outbound-allow-list.yaml` |
| T-21 | Write to the shared catalog; search repository and logs for the credential file | AC1, AC5 | E1 | **BUILD** | Read-only-by-construction is enforced by Databricks; the secret-scan half ~~would currently fail on `_secrets/` mode 664~~ — **B-4 cleared 2026-10-18**, and the scan is now a reusable five-axis assertion (`scripts/check_secret_hygiene.py`) rather than an ad-hoc grep, so T-21's second half has a standing green baseline to re-run against | `evidence/t21-readonly-nosecrets.json`, `evidence/secret-hygiene.json` |
| T-22 | Land a good load, a bad-schema load and an empty load | AC3, AC5 | E4 | **BUILD** | Landing, validation, quarantine and tagging are all local work (CONOPS 2.4.4) | `evidence/t22-landing-quarantine.json` |
| T-23 | Rotate the provider credential; drop the catalog and provider | AC3, AC4 | E4 | **BUILD** (was STANDIN) | **Reclassified 2026-10-18**: the operator controls the OSS provider's token configuration, so issuing a replacement token, overlapping the old one and expiring it are real provider-side actions. Dropping the catalog and provider object is Databricks-side and was never the blocked half | `evidence/t23-provider-rotate.json` |
| T-24 | Push through the gateway: allowed upload; oversize, wrong type, wrong path, overwrite, GET and direct Files API call | AC1, AC2 | E2, E4 | **PARTIAL** | The six *refusals* are pure gateway policy and are BUILD. The successful upload needs a service principal with `WRITE VOLUME` — unconfirmed on Free Edition — and content scanning has no named owner (OD-9, **Open**). Carries R12 | `evidence/t24-push-ingest.json` |
| T-25 | Trace one ingress request (pull and push) | AC5 | E5 | **PARTIAL** | Same join-key unknown as T-11, plus it depends on T-20/T-24 standing up first. CONOPS notes dependency 1694-E4, which does not exist yet | `evidence/t25-ingress-trace.json` |

---

## 12.3 Count by verdict

Counts as of **2026-10-18**, after the second metastore (`glovashu`) and
the open-source OpenSharing provider closed the two capability holes.
The "was" column is the position before them, kept because the delta is
itself the argument for the topology.

| Verdict | Tests | Count | Was |
|---|---|---|---|
| BUILD | T-01, T-02, T-03, T-05, T-06, T-07, T-10, T-12, **T-15**, T-17, **T-19**, T-20, T-21, T-22, T-23 | **15** | 11 |
| REBUILD | T-04 | 1 | 1 |
| PARTIAL | T-08, T-09, T-11, T-14, T-18, T-24, T-25 | 7 | 7 |
| PROBE | T-16 | **1** | 2 |
| STANDIN | — | **0** | 2 |
| PARTNER | T-13 | **1** | 2 |

This taxonomy grades whether a test *can* be made conclusive in this
topology, not whether it has been run. **T-20 is the first of the BUILD
set actually executed end to end** (verdict `PASS_WITH_SCOPE`, row
above); the rest are classified as buildable and not yet exercised. Once
more than a handful have run, execution status needs its own column, or
"BUILD" will be read as "done" by exactly the audience this matrix is
written for.

> **That column now exists: §12.10, which is authoritative over this
> section.** The paragraph above was written as a warning and then came
> true inside this document — see the retraction in §12.4. Two of
> twenty-five tests have been run (T-19 and T-20). The counts in this
> section describe **feasibility only**.

Sixteen of twenty-five tests can be made genuinely conclusive here, and
seventeen if T-16's remaining MCP question resolves positively. Seven
more produce a real partial result with a named gap. One depends on a
probe. **One cannot be done solo at all**, and it is the one that is
irreducible by definition rather than by circumstance: T-13 is *the CDAO
PSP7 team* running onboarding, so no amount of local capability can
produce it.

The move from eleven to sixteen conclusive tests was not achieved by
relaxing any standard. Every one of the five came from a capability that
was *assumed* unavailable and turned out, when probed, to be available:
model serving (T-15), a second metastore (T-19), and an operator-run
open-protocol provider (T-20, T-21's rebaseline, T-23). The pattern is
consistent enough to be worth stating as a lesson for the client
engagement: **tier limits that were never tested are not findings.**

Two features of that distribution matter more than the headline number.
**The STANDIN category is empty** — nothing in the matrix now rests on a
substitute pretending to be something else, which was the weakest kind
of evidence this project produced. And **PARTNER has fallen to one**,
which converts the answer to "how much of the milestone can one person
de-risk before the partner teams engage?" from *most of egress* to
*everything except another organisation's own judgement, four tier
capabilities, and a document*.

---

## 12.4 Coverage by acceptance criterion

| AC | Epic | Tests claimed (CONOPS 1.5) | Conclusive locally | Needs a partner or probe |
|---|---|---|---|---|
| AC1 | T04-10 | T-01, T-02, T-03, T-04, T-08, T-15, T-16, T-19, T-20, T-21, T-24 | T-01, T-02, T-03, T-04 (after rebuild), **T-15**, **T-19**, **T-20**, T-21 | T-08, T-16, T-24 |
| AC2 | T04-11 | T-03, T-05, T-06, T-07, T-08, T-15, T-24 | T-03, T-05, T-06, T-07, **T-15** | T-08, T-24 |
| AC3 | 1227-E3 | T-10, T-19, T-22, T-23 | T-10, **T-19**, T-22, **T-23** | — *(no partner or probe dependency. **Not** the same as conclusive: see the retraction below and §12.10)* |
| AC4 | T04-13 | T-09, T-10, T-13, T-15, T-16, T-17, T-23 | T-10, **T-15**, T-17, **T-23** | T-09, T-13, T-16 |
| AC5 | 1227-E5 | T-11, T-18, T-21, T-22, T-25 | T-21, T-22 | T-11, T-18, T-25 |
| AC6 | 1227-E6 | T-12 | T-12 | — |
| AC7 | T04-14 | review (ARB packages) | — | 1694-G2 template missing |
| AC8 | T04-15 | T-13 | — | PSP7 |
| AC9 | T04-15 Story 4 | T-14 | — | Service Desk owner (OD-7) |

> **RETRACTED 2026-10-20.** The paragraph that stood here read: "**AC3
> joined AC6 as fully conclusive on 2026-10-18**, when the D2D probe
> settled T-19 … of the nine acceptance criteria, two can now be closed
> out end to end on a laptop with no partner, no paid tier and no client
> environment." It is labelled rather than deleted (B-19).
>
> It confused **conclusive-in-principle with executed**. The
> "Conclusive locally" column grades whether a test *can* be made
> conclusive in this topology — §12.3 says so in as many words — and
> this paragraph then read the column as a completion claim. On the
> evidence actually on disk: **AC3's T-10, T-22 and T-23 have never
> run**, and T-19 has run to `PARTIAL_WITH_NAMED_GAPS`, which is not a
> pass. **AC6's T-12 has never run at all.** Neither criterion was
> closed out.
>
> This is the failure mode §12.3 predicted in writing — *"'BUILD' will
> be read as 'done' by exactly the audience this matrix is written
> for"* — and the first reader to do it was this document. Execution
> status now has its own axis in **§12.10**.

What can honestly be said about AC3 and AC6:

**AC3** has no partner dependency and no tier dependency. All four of
its tests are buildable here; one has run with named gaps and three have
not run. That is a strong position, and it is not a closure.

**AC6** remains the strongest argument for front-loading E6 — its single
test is conclusive *in principle* and its output makes every other epic
cheaper to rebuild — but T-12 has not been executed, so AC6 rests on an
argument rather than on evidence. Until the clean-target redeploy runs,
the ARB package has nothing to put in the AC6 row except the plan.

AC1 still carries the most exposure — eleven tests and the broadest
requirement phrases — but its position has changed materially. Eight of
its tests are now conclusive rather than four, T-19 moved from
*impossible* through *one probe away* to **BUILD**, and the CONOPS
traceability matrix (§10.1) rests clauses 1.1 through 1.5 on exactly
these tests. The remaining AC1 gaps are down to three: one tier
capability (T-16), one storage-side refusal that Databricks-managed
storage will never permit (T-08), and one service principal (T-24). The ARB package
should state those four plainly; they are capability limits of the
environment, not unfinished work.

**AC3 and AC4 are the quiet winners** of the new topology. AC3 goes from
two of four conclusive to three of four, and AC4 from two of seven to
three of seven, because T-23 — rotating a provider credential and
dropping the catalog and provider — stopped being a stand-in once the
operator owned a real provider's token configuration. Credential
rotation is the control that DSA reviewers ask about first, so proving it
end to end against a live provider is worth more than its single row
suggests.

---

## 12.5 Current implementation status

Against the existing tree, before the rebuild:

| Range | State |
|---|---|
| T-01 … T-14 | Covered in some form by `scripts/01`–`07` and `tests/run_verification_session.py`. T-04 is invalid (11.5). The verification-session script is stale: its docstring says "Section 6.3 … seven steps" where v1.5 §5.3 defines **eight** |
| T-15 … T-25 | **No code at all.** All of ingress (I-1, I-2) and both AI routes |

`docker-compose.yml` also references `tests/test_t11_trace_correlation.py`,
which does not exist. The rebuild's one-module-per-test convention
(`tests/t01_*.py` … `tests/t25_*.py`) exists to make this kind of drift
impossible to miss.

"Covered in some form" is weaker than it reads, and §12.10 is where that
is spelled out: covered is not run, the coverage described above belongs
to the tree being **replaced**, and no evidence file exists for any of
T-01 … T-14. Modules written under the rebuild to date are
`tests/t19_ingress_d2d.py` and `tests/t20_ingress_d2o.py`, which are
also the only two that have produced evidence.

---

## 12.6 Mapping to the §5.3 client verification session

CONOPS §5.3 defines **eight** steps. This is what the client actually
watches, so it is the real acceptance bar.

| Step | What is shown | AC | Tests behind it | Locally demonstrable? |
|---|---|---|---|---|
| 1 | Publish a test dataset as a share | AC4 | T-17 | Yes |
| 2 | Register and approve a consumer through the portal, tied to a DSA reference | AC3, AC4 | T-10, T-17 | Yes, with the Gravitee portal standing in for OD-10 |
| 3 | Issue the credential file with the endpoint rewritten to the gateway address | AC4 | T-09 | Yes — this is the OD-4 pattern, the single most reusable trick in the prototype |
| 4 | Read through the gateway showing only entitled columns; call one model service or MCP server | AC1, AC4 | T-01, T-15, T-16 | Read: yes. AI call: **PROBE** |
| 5 | Show the refusals: burst, malformed request, direct call to Databricks, column outside the grant | AC1, AC2 | T-05, T-06, T-02, T-04 | Yes, once T-04 is rebuilt on the view pattern |
| 6 | Ingest: pull a share into a read-only catalog and land it with validation; push a file; show a rejected upload | AC1, AC3, AC5 | T-20, T-22, T-24 | Mostly — pull now runs against a real provider (OSS D2O, and `glovashu` for D2D); only the push upload's service principal is outstanding |
| 7 | Trace one egress and one ingress request across gateway log and Databricks audit event | AC5 | T-11, T-25 | Partly — gateway side yes, Databricks audit side unconfirmed |
| 8 | Revoke the consumer and show access fails; redeploy the configuration from code | AC3, AC6 | T-10, T-12 | Yes |

Five of eight steps are fully demonstrable today, and step 5 becomes the
sixth as soon as T-04 is rebuilt.

Step 6 moved on 2026-10-18. It used to be the weakest step in the
session, because the pull half had no provider behind it at all. Now the
pull is real on both channels — the OSS reference server for D2O, the
`glovashu` metastore for D2D — and the only thing left incomplete is the
service principal the push half wants. That is a permissions question,
not a missing-party question, so step 6 is now better evidenced than
step 7 and is a candidate for the seventh fully demonstrable step rather
than a known hole.

Step 7 is now the single place where the prototype genuinely stops being
able to stand in for the real environment: the gateway side of the trace
works, the Databricks audit side is unconfirmed on Free Edition, and
1694-E4 — the correlation-ID contract the CONOPS itself calls the
biggest unknown — has no owner. Of the two dependencies this section
used to lean on, 1694-E4 is still live and A10/R14 is not.

---

## 12.7 Findings from the AI Gateway probe (2026-10-18)

`scripts/08_probe_ai_gateway.py` settled T-15 and produced three
side-findings that change work in other epics. They are recorded here
because each one would otherwise be discovered late, during route
building, when it is more expensive.

**1. The model response shape is not the classic OpenAI contract, and
this threatens the gateway's body-schema policy.** The successful call
returned `choices[0].message.content` as an **array of typed blocks**
beginning with a `reasoning` block, not a string:

```
"content": [{"type": "reasoning", "summary": [{"type": "summary_text", ...}]}]
```

Any Gravitee request/response body-schema validation written against
`content: string` will reject valid upstream responses. E2 owns the
schema policies and must write them against the observed shape, not the
assumed one. This is the same class of error as blocker B-1 — an API
definition built on an assumed contract that 404s against the real one —
and it is worth noting that the prototype has now caught that same
mistake twice on two different protocols.

**2. The call was truncated, so the full shape is still uncaptured.**
`finish_reason` came back as `length` with `max_tokens=16`: the
reasoning block consumed the entire budget before any answer text was
emitted. The probe proves the path, not the payload. Re-run with
`max_tokens` of at least 512 before writing any schema, and record the
complete response in the evidence file. Reasoning tokens also bill
against quota, which matters for the class E limit values E2 picks.

**3. The console and the API disagree on inventory: 13 versus 12.** The
Unity Gateway page lists thirteen entries; `/api/2.0/serving-endpoints`
returns twelve. The difference is `databricks-genie`, which the console
shows as **Workspace**-located with a `databricks-product: genie` tag
while the other twelve are `system.ai`. Genie is a different object
type that appears on the same governed surface. Two consequences: the
IaC in E6 must target serving endpoints and cannot assume the console
list maps one-to-one, and the §3.1 access matrix has no row for whatever
Genie is, which reinforces the v1.6 point that E-3's surface is wider
than "model serving and MCP".

**4. The legacy MCP API is absent, which makes route M3's evidence
subtler than it looks.** Both `/api/2.0/mcp/servers` and
`/api/2.1/unity-catalog/mcp-servers` returned `404 ENDPOINT_NOT_FOUND`
to an authenticated workspace token — not `403`. M3 must prove the
legacy managed MCP path is unreachable *from the Gravitee edge*, but if
the upstream has no such API, a 404 at the edge proves nothing: it is
indistinguishable from the upstream's own 404 passing through. **M3's
evidence must therefore be a Gravitee-generated refusal** — the deny
route returning the gateway's own error format, demonstrably produced at
the edge and never forwarded. The existing verify step in E1 Task 1.9
already says "protocol error format from the edge, not a proxied
response"; this finding is why that wording has to be enforced literally
rather than treated as a formality.

The MCPs tab exists in the console, so T-16's positive half is not
closed by these 404s either — the tab is likely backed by a path the
probe did not guess. T-16 stays **PROBE** pending a look at the tab
itself.

---

## 12.8 Finding from the Task 1.1 credential merge (2026-10-18)

Repairing the OD-4 bypass exposed a hole in the route table that the
bypass had been masking.

`icebergEndpoint` now rewrites to `<gateway-edge>/iceberg`. **The §2.3.2
route table has no iceberg route.** S1–S10 cover the sharing protocol,
F1 covers file download, M1–M3 cover model and MCP, A1 is the admin
route, and X is deny-all. Nothing matches `/iceberg`.

That is the correct outcome and should be stated as a deliberate
decision rather than left as an accident, because the two failure modes
are opposites:

| | Before the fix | After the fix |
|---|---|---|
| Client reads `icebergEndpoint` | Reaches Databricks directly | Hits Gravitee, matches no route, falls to deny-all X |
| Security property | **Fail open** — silent perimeter bypass | **Fail closed** — refused at the edge |
| Visibility | None; nothing logged at the gateway | Refusal appears in the gateway log |

So the repair does not merely close the hole, it converts an invisible
bypass into a logged refusal. That is worth a line in the evidence
record, because "the control failed safely" is a stronger ARB claim than
"the control was configured".

**Two decisions this forces, both for E2 and both currently unmade.**
Either the iceberg path is a supported egress route and needs a row in
the route table with a policy class, or it is deliberately not exposed
and needs an explicit deny row like M3 rather than relying on the
catch-all. M3 sets the precedent: §3.1.2 does not leave legacy MCP to
the deny-all, it names it. The iceberg path deserves the same treatment,
whichever way it goes.

**For v1.6:** §3.4.1's step 4 wording drives this. A document that says
"replaces *the endpoint*" produces exactly one rewritten field and
exactly one route to plan for. Correcting it to "every endpoint field"
(register item 3) also obliges §2.3.2 to carry a route — or an explicit
refusal — for each one.

---

## 12.9 A withdrawn reading, and three holes it exposed

On 2026-10-18 the D2D probe was run twice and returned opposite
verdicts. The first, `SAME_METASTORE`, was wrong. It is recorded here
rather than quietly replaced, because an evidence pack that shows which
readings were withdrawn is harder to dismiss than one that shows only
survivors — and because the failure mode generalises.

### What happened

The second workspace's host and token were written into `.env.example`
instead of `.env`. The probe reads only `.env`, found no second
credential, and **fell through to a single-workspace fallback path
without saying so**. In that path it looked for a catalog named
`workspace` — a name every Databricks workspace has — matched the
*primary* workspace's own catalog, read its metastore ID, and reported
it as the far side. The verdict was an artefact of a catalog name.

The correct reading, taken once the credential was in the right file:

| | Metastore ID |
|---|---|
| Primary (`dbc-0c6ebc56-563d`) | `48cda780-1dc7-459d-bee0-77abde9af938` |
| Second account (`dbc-519df5ad-574f`) | `8875961b-9666-494c-95e2-af6b5b78bd3d` |

Both in `aws:us-east-2`. This corrects a working assumption recorded
earlier in this exercise: a Free Edition metastore is provisioned **per
account per region**, not per region. Two accounts in the same region
get two metastores, which is why D2D is testable here at all.

### Three defects, one shape

The probe was written specifically to avoid collapsing distinguishable
verdicts, and it collapsed two anyway. Alongside it, the secret hygiene
check reported "clean" on three separate occasions while live
credentials sat in scanned-looking files. All four defects share one
shape: **a silent negative**. A check that cannot see a thing reports
the same output as a check that looked and found nothing.

| Defect | Why it was silent | Guard added |
|---|---|---|
| Fallback path chosen without a credential | Mode switch was implicit | `mode` recorded in the evidence file; ambiguous catalog names now return `INVALID_PROBE` rather than a verdict |
| `.env` and `.env.example` never scanned | `Path(".env").suffix` is `''`; `Path(".env.example").suffix` is `.example` — a suffix allow-list skips both | Scan matches on filename prefix, not just suffix; `.env` is a declared sanctioned store, excluded deliberately and mode-checked instead |
| Fine-grained GitHub PAT never matched | `gh[pousr]_[A-Za-z0-9]{36,}` cannot match `github_pat_…`, which has a different prefix and **contains underscores** | Explicit `github_pat_` pattern, plus a shape-based backstop on any `*_TOKEN`/`*_SECRET`/`*_PASSWORD` key assigned a long non-placeholder value |
| Nothing enforced the check before a commit | It ran only when someone remembered | `scripts/hooks/pre-commit`, tracked in-repo and installed by `scripts/hooks/install.sh`, blocks the commit on failure |

The hook is tracked rather than left in `.git/hooks/` on purpose:
`.git/hooks` is not version-controlled, so a control that lives only
there does not survive a fresh clone and would silently fail **AC6 /
T-12's "redeploy from code"** — reproducing the config but not the
control. The patterns now have a nine-case assertion covering both
directions, including values that must *not* fire (`<placeholder>`,
empty, `GRAVITEE_MGMT_PASSWORD=admin`), because a scanner that flags
everything gets switched off within a week.

### The shape at four more levels, from T-20 (2026-10-18)

T-20 produced four further instances, and they are worth listing
together because they sit at four different levels of the stack, each
one guarding the level above it. The
pattern is not a coding mistake that better review would catch; it
recurs wherever something reports an outcome it was not in a position to
observe.

| Level | Instance | Guard |
|---|---|---|
| **Procedure** — the CONOPS itself | §2.4.1's D2O column creates a catalog *and grants* over a provider the control plane has already refused to reach. A step that cannot verify its own precondition produces the same green ticket as a step that verified it (defect **D-6**) | Promote `SHOW SHARES IN PROVIDER` into the D2O column as a required gate — one command, and the only point in §2.4.1 where the credential file's endpoint is proven reachable |
| **Evidence** — the record of the run | `scrub()` appended its redaction marker once per pass, three times over one URL. Nothing leaked, but the marker count asserted three removals where there was one — a record saying more than was measured (**B-16**) | Idempotent pattern, plus `assert_scrub_contract()` run in the parent and every child before any write, graded against the gate's own `TOKEN_PATTERNS` and verified able to fail against four broken scrubbers |
| **Control** — the gate that guards the record | The gate's new placeholder exemption would have skipped three checks per run while printing the same "clean" as a run that skipped none (**B-13**) | Every exemption printed with its file and value, and the exempted count reported on the same line as the scanned count |
| **Test of the control** — one level further down | The scrubber contract asserted that gate patterns stop matching after scrubbing, without ever checking they matched **before**. A softened fixture, or a later weakening of the gate's own patterns, would have printed `VERIFIED` while measuring nothing (**B-17**) | A vacuity guard: the fixture must trip ≥2 gate patterns or the run refuses, and the labels it tripped are recorded in the evidence rather than summarised as a pass |

Two of these are worth dwelling on, because each is the *inverse* of the
failure one would expect to guard against.

The risk in a redaction function is normally that it removes too little.
A scrubber that removes **too much** passes every secret-detection check
ever written and silently destroys the finding the test exists to
produce. Hence the contract asserts the storage host *survives*
scrubbing, not merely that the signature does not.

And the fourth row is the shape appearing inside the function written to
prevent it, which is the most useful instance in the set. Its fixture
has to look exactly like a live credential, because its whole purpose is
to be something the gate would flag — so it cannot be softened to quiet
the scanner, and it cannot be hidden from the scanner either, since
splitting a literal is the technique used to smuggle a real credential
past one. The resolution generalises: **a stand-in for a credential must
be constructed so its falsity can be recomputed, not asserted.** The
fixture's signature is derived from a seed published beside it, so any
reviewer can verify in one line that it is synthetic. A hard-coded hex
blob cannot be told from a real signature by reading it; a derivation
can.

### What to carry into the client engagement

This is a reusable argument rather than housekeeping. A control that
has only ever been observed passing has not been observed working; it
has to be shown refusing something before a green result from it means
anything. The hook was verified in both directions — a planted decoy
token blocks the commit, its removal permits it — and that two-way
verification, not the clean run, is the evidence. The same standard
applies to every gateway refusal this prototype will claim: §12.7's
point that a 404 at the edge is indistinguishable from an upstream 404
is this identical defect wearing a different hat.

---

## 12.10 Execution status, as its own axis

§12.3 predicted this section in writing: *"Once more than a handful have
run, execution status needs its own column, or 'BUILD' will be read as
'done' by exactly the audience this matrix is written for."* The
prediction came true faster than expected, and the first reader to
misread it was this document — §12.4 claimed two criteria had been
"closed out end to end" when the tests under them had never been
executed. That claim is retracted above. This section exists so the
mistake cannot be made again by reading the matrix correctly.

**The two axes are independent, and neither implies the other.**

| Axis | Question it answers | Where it lives |
|---|---|---|
| Feasibility (`BUILD`, `REBUILD`, `PARTIAL`, `PROBE`, `PARTNER`) | *Can* this test be made conclusive in this topology, by one operator, without a partner organisation? | §12.1, §12.2, §12.3 |
| Execution | Has it been **run**, and what did the run return? | This section, and the `verdict` key of its evidence file |

A `BUILD` verdict is a statement about the topology. It is not a result.
The evidence file is the only thing that is a result, and the honest
summary of the repository is that **two of twenty-five tests have been
executed.**

| Test | Execution | Verdict returned | Evidence file |
|---|---|---|---|
| T-19 | **RUN** | `PARTIAL_WITH_NAMED_GAPS` | `evidence/t19-ingress-d2d.json` |
| T-20 | **RUN** | `PASS_WITH_SCOPE` | `evidence/t20-ingress-d2o.json` |
| T-01, T-02, T-03, T-04, T-05, T-06, T-07, T-08, T-09, T-10, T-11, T-12, T-13, T-14, T-15, T-16, T-17, T-18, T-21, T-22, T-23, T-24, T-25 | NOT_RUN | — | none exists |

Three qualifications on that table, each of which would otherwise be
read more generously than it deserves.

**T-03 is NOT_RUN despite §12.2 recording a pass.** That row says
"already passed once: 403 `ip-filtering`", and it did — under the
pre-rebuild tree, against a configuration that no longer exists in this
repository. There is no `evidence/t03-*.json`. A pass whose artifact
cannot be produced is a memory, not evidence, and the rebuild has to
re-earn it. The same reasoning retires the §12.5 claim that T-01 … T-14
are "covered in some form" by the old scripts: covered is not run, and
the old coverage is the thing being replaced.

**The eleven `evidence/capability-baseline-*.json` and probe files are
not test executions.** They are probes — `scripts/1x`–`scripts/2x` —
that establish what the platform *can* do, which is how five tests moved
out of `STANDIN`/`PROBE`/`PARTNER` in §12.3. A probe answers "is this
capability available?"; a test answers "does the control work?". Filing
probe output under a test ID would be the §12.9 defect again: a thing
that was never checked producing the same green line as a thing that
was.

**Neither of the two runs returned a clean pass, and both say so in
their own verdict.** T-19 is `PARTIAL_WITH_NAMED_GAPS` because native
D2D surfacing is `NOT_RUN_CAPABILITY_NAMED` behind four independent
bounded negatives (B-21), with open sharing standing in as an
*evidenced* substitute ingress path rather than a workaround. T-20 is
`PASS_WITH_SCOPE` because the Databricks-native control-plane read was
blocked by local topology, attributed by measurement rather than
assumed, and because its hostnames do not transfer to a client
environment — only the procedure does. A verdict vocabulary that could
only say PASS or FAIL would have had to round both of these to something
untrue in one direction or the other, which is B-20: **ours before
theirs**, a coarse vocabulary fails toward blaming the far side.

What this means for the corporate conversation is narrower and stronger
than "AC3 and AC6 are closed". It is: *the hardest capability questions
in the milestone — can ingress be done at all without the partner
organisation, and can the recipient-side firewall be derived from
evidence rather than from Databricks documentation that does not publish
it — are answered yes, with artifacts.* That is a defensible claim. The
closure claim was not.

---

## 12.11 `REFRESH_IS_TIME_BASED` — and the bound it is honest about

T-19's refresh step returned `REFRESH_OBJECT_LATENCY_EXCEEDS_BOUND`: a
newly shared object was **not** readable through the consumer's existing
catalog within 170.8s over twelve polls, while a *previously* shared
object that had been added after that catalog was created **was**
readable. Those two observations together rule out the explanation that
would have mattered most — that the consumer's catalog is a snapshot
taken at creation time and a re-import is required. It is not. The
catalog does refresh.

That left one question, which `scripts/21_probe_refresh_trigger.py`
exists to answer: does the object appear through the passage of **time**,
or through a consumer-side **provider update**? The answer is
`REFRESH_IS_TIME_BASED`. The probe read the object as PRESENT before it
performed any mutation at all, so its phase 2 (watch) and phase 3
(provider update) both recorded `NOT_RUN_ANSWER_ALREADY_IN_HAND`. No
re-import, no provider update, no catalog recreate. **The consumer
waits.**

Two alternative explanations were excluded by earlier evidence rather
than by assumption, and the probe records which evidence did it:
warehouse-side caching, excluded because T-19's object-metadata check
used the tables API — no warehouse in the path — and that API also
reported the object absent; and the creation-time snapshot, excluded by
comparing `share.added_at` against `catalog.created_at` on the standing
object.

### The bracket, and why the file carries two numbers

The object appeared inside a window nobody watched. That window, not the
30s poll interval, is the resolution of the result:

| Bound | Value | How it was obtained |
|---|---|---|
| Lower (observed ABSENT) | **170.8s** | T-19's object-visibility step, 12 polls after the add |
| Upper (observed PRESENT) | **1044s** | the first probe run's PRESENT read, at a share-membership age of 17.4 minutes |
| Unobserved gap | ~873s | no observation exists inside it |

So the only statement the repository supports is **"later than 170.8s
and no later than 1044s"**. Anything more precise is invented. What is
safe to put in a runbook is the floor, and it is the useful half anyway:
*a consumer who polls for three minutes and raises a defect is raising a
false one.* Tightening the upper end means re-running the probe against
a fresh object with a watch window that covers the gap — and note that a
re-run is **looser** by construction unless it starts from a new object,
because the object keeps ageing while nobody is looking at it.

#### B-30: the carry-forward aggregator quoted the wrong end

`evidence/t19-refresh-trigger.json` records
`tightest_upper_bound_across_runs: 1978.0`, and its `conops_implication`
prose quotes 1978.0s as the upper bound. Both are from the **second**
run. The first run — present in the same file under `prior_runs` — read
the object as PRESENT at `age_minutes_at_read: 17.4`, i.e. 1044s, which
is a materially tighter bound, but stored `upper_bound_seconds: null`,
so the aggregation that was written to carry the best bound across runs
had nothing to compare and carried the worse one. The aggregator's own
`aggregation_means` note explains exactly why this must not happen —
"a re-run of this probe has a LOOSER upper bound than its first run by
construction" — and then it happened, because the defect was in what the
first run *recorded*, not in the comparison logic.

Per B-19 the number is **labelled, not deleted**: the evidence file
keeps 1978.0s with this correction recorded here and in §11.7, and the
table above is the figure to quote. The lesson is the generalisable one:
a carry-forward is only as good as the fields the earlier run wrote, so
the run that produces a bound must record it in the field the aggregator
reads, not merely in prose or in a derivable timestamp.

### What changes in the CONOPS

§2.4.1 currently describes ingress as a provisioning sequence and says
nothing about what the consumer does after the provider adds an object.
It needs a **timing expectation**, not a re-provision step: the newly
shared object becomes readable through the existing catalog on its own,
later than three minutes, and a consumer-side runbook that treats a
three-minute absence as a failure will generate false defects against
the provider. §2.4.4's troubleshooting path needs the same sentence from
the other side — "object missing from the consumer's catalog" has a wait
as its first remedy, not a re-import, and the re-import that an operator
would reach for first is both unnecessary and the thing that would
destroy the evidence of what actually fixed it.
