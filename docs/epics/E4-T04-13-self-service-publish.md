# E4 — T04-13: Self-Service API/MCP and Data Publishing (AC4)

| | |
|---|---|
| **Epic** | T04-13 |
| **Acceptance criterion** | AC4 — Self-Service API/MCP and Data Publishing |
| **CONOPS sections** | 3.4, 3.4.1, 3.4.2, 2.4.5, 2.4.4, 2.4.6, 6 |
| **Stories** | 1: Federated publish pattern with Data Eng (§3.4) · 2: Self-registration and dev portal flow (§3.4.2) · 3: ARB package (§6) |
| **Role** | Build — AI/ML Ops builds and tests it |
| **Target dates** | 10/16 – 11/5 · checkpoint **11/2–11/3** credential provisioning and IaC/CaC working in test environment |
| **Depends on** | 1227-E2 |
| **Tests** | T-09, T-10, T-13, T-15, T-16, T-17, T-23, T-22, T-24 |
| **Decisions in play** | OD-4 (proposed), OD-10 (open) |
| **Risks in play** | R5, R7, R10, R12 |

> **The criterion, verbatim (CONOPS §3.4, §4.3):** *federate ability to publish
> Databricks datasets through OpenSharing and standard Databricks APIs/MCPs;
> external consumers seamlessly request access, e.g., Gravitee API developer
> portal.*

---

## E4.0 What this epic actually has to produce

AC4 is the story of how data owners publish datasets and how consumers request
access without calling Databricks directly. Four things have to work in concert:
a publish pipeline that creates per-tier views and registers them; a developer
portal where consumers self-register and data owners approve; a credential
provisioning process that rewrites the endpoint so reference clients hit the
gateway instead of Databricks; and the push-ingest landing flow that takes
incoming data and validates it before it reaches curated stores.

The credential-rewrite step (OD-4) is the single most reusable pattern in the
prototype. The provisioning process, not the consumer, retrieves the activation
link, downloads the credential file once, replaces the endpoint with the
gateway edge URL, leaves the bearer token unchanged, and delivers the rewritten
file through the authenticated portal. The activation link is never given to the
consumer, and on rotation the process repeats steps 3–5.

The publish pipeline must create a per-tier VIEW, not apply masks and filters
(CONOPS §3.4 step 2). Section 11.4 proved that masks and filters are refused
on any OpenSharing-shared table, at every tier. This is a document defect (D-1)
that the pipeline must work around by creating a view. The view is what carries
the DSA reference and the tier in its `COMMENT`, and what gets added to the
share. The base table is never shared.

Everything else in AC4's test list (T-13, T-15, T-16) is either partner-owned
or conditional on AI-route availability; AC4 owns the provisioning chain,
the publish pipeline, the landing/validation/quarantine sequence, the push-route
policies and refusals, and the portal registration that stands in for OD-10.

---

## E4.1 Task list

Each task is independently verifiable. Run them in order. **PARTNER** or
**DEFERRED** tasks are not skipped quietly — they produce a written gap
with an owner.

### Task 4.1 — Reconcile the divergent credential-rewrite script

Blocker B-4 (Epic 1 Task 1.1). `_secrets/rewrite_credential.py` is a divergent
untracked copy of `scripts/04_rewrite_credential.py`, modified *later* than the
tracked one. The two implement the OD-4 pattern differently: the tracked version
loads `GRAVITEE_GATEWAY_EDGE_URL` from `.env`, handles an optional
`icebergEndpoint` field, and uses environment defaults; the divergent version
hard-codes `GATEWAY_BASE` and takes command-line arguments. Neither is wrong,
but they cannot both exist, and the .env-driven version aligns with the
canonical deployment pattern.

**Deliverable:** `scripts/04_rewrite_credential.py` as the single source of
truth, implementing OD-4 steps 3–5; the divergent copy deleted from `_secrets/`;
confirmation that the script handles the raw credential format correctly.

**Verify:** `python3 scripts/04_rewrite_credential.py` with a test credential
file produces a rewritten file with the endpoint replaced and the bearer token
and all other fields untouched; the script cleans up after itself and produces
the expected output message pointing to the test that uses the rewritten file.

### Task 4.2 — Build the OD-4 credential provisioning process, six steps complete

This is the core deliverable of the epic. The pattern from CONOPS §3.4.1
replaces the risk (R7) that a consumer receives the raw Databricks endpoint.
Build the full chain: recipient creation with IP access list and DSA comment,
activation-link retrieval, credential-file download, endpoint rewrite, delivery
through the portal, and rotation (steps 3–5 repeating). Integrate Task 1.5
recipient setup (from E1) with this flow.

The path-prefix verification is critical. CONOPS §3.4.1 says "confirm in
testing that the path prefix the gateway exposes matches what the client builds
from the endpoint". Blocker B-3 records a real case: `gravitee/api-definition.json`
declares `/storage-proxy` as a flow selector beneath the `/delta-sharing` listener,
so the real edge path is `/delta-sharing/storage-proxy`, not `/storage-proxy`.
A credential rewritten to `/storage-proxy` would cause clients to fail with a
404 at the path-prefix step.

**Deliverable:** `scripts/05_credential_provisioning.py` implementing the six
steps (create recipient, get activation link from Databricks SDK, retrieve and
rewrite the credential file, deliver via portal); `tests/t09_reference_client.py`
covering multiple clients with the rewritten file; the path-prefix assertion
built into the test.

**Verify:** T-09 passes with both `delta-sharing` (pandas) and Spark,
recording which reference clients are unavailable and why. The path-prefix
assertion catches any mismatch between what the client builds and what the
gateway advertises. The activation link is never logged or committed.

### Task 4.3 — Build the publish pipeline with per-tier views

CONOPS §3.4 step 2 says the pipeline "applies masks and filters for the tier".
That is defect D-1. The working pattern: the pipeline creates a per-tier VIEW
that selects only the entitled columns (and, with a `WHERE` clause, only the
entitled rows), adds it to the share, and leaves the base table untouched.
Every view carries a `COMMENT` with its DSA reference and tier.

The pipeline is data-owner-initiated but executed by Data Eng and approved by
Data Governance. It picks up the tier and DSA template from a configuration
map (OD-3 input, or a placeholder), places the asset in the Unity Catalog
schema, creates the view, and adds it to the purpose share.

**Deliverable:** `scripts/06_publish_pipeline.py` taking table name, tier,
DSA reference and template as parameters, creating the view with the comment,
adding it to the share, and recording the operation in a manifest;
`iac/config/tier-templates.yaml` with tier definitions and their DSA templates;
Terraform in `iac/databricks/` for the views and the share assignment.

**Verify:** the view is created with the correct column set; the base table is
not added to the share; the view carries the DSA reference and tier in its
`COMMENT`; a recipient reading the share sees the entitled columns only.

### Task 4.4 — Build the developer portal registration flow (OD-10 stand-in)

OD-10 is Open and owned by Data Tooling. The local Gravitee developer portal
already runs at `localhost:8085`. Use it as the stand-in for the registration
flow, implementing the CONOPS §3.4.2 table: self-service register, gated approval,
automated creation of recipient/route/credential, self-service read.

A consumer self-registers with a purpose and a DSA template reference. Data
Governance (simulated locally) approves, linking the registration to a UC
recipient and a DSA reference. The provisioning process (from Task 4.2) then
runs automatically, creating the recipient, rewriting the credential, and
returning it through the portal.

**Deliverable:** Gravitee developer portal integration script
`scripts/07_portal_registration.py` that ingests registration requests,
validates the DSA template, triggers the approval flow, and on approval runs
the credential provisioning; a written simulation of the approval step;
evidence of registration → approval → credential issuance in the local portal.

**Verify:** a self-service registration can be performed in the Gravitee portal;
approval can be simulated by advancing a status field; the credential is
available in the portal after approval; the credential works with a reference
client.

### Task 4.5 — T-09 rebuilt: reference clients with the rewritten credential

T-09 is PARTIAL in the current environment. `delta-sharing` (pandas) and Spark
are available. Power BI, Tableau and the Java client are not — record those as
NOT_RUN with the reason.

This task is T-09 done completely for the available clients: import the
rewritten credential from Task 4.2, confirm that each available client reads
through the gateway edge URL with the rewritten endpoint, and record the client
behavior around certificates and token presentation.

**Deliverable:** `tests/t09_reference_clients.py` with sub-tests for each
available client; evidence record with PASS for Spark and pandas, NOT_RUN for
unavailable clients with the reason.

**Verify:** Spark reads through the rewritten credential file successfully;
pandas reads successfully; unavailable clients are listed with the reason,
not silently omitted.

### Task 4.6 — T-10: rotate and revoke the recipient token

Recipient token lifetime, overlap and revocation are determined by OD-5, which
is Open and owned by Data Governance. CONOPS §3.1.1 states that a recipient
holds at most two tokens (active plus rotated) and a token is valid for at most
one year. Task 4.2's credential provisioning implements rotation by repeating
steps 3–5 with a new activation link.

Build the rotation and revocation test. Rotate a recipient token, create a
second token, confirm both work in overlap, then revoke one and confirm it no
longer works. Record the overlap behaviour.

**Deliverable:** `tests/t10_rotate_revoke.py` creating a test recipient with
two tokens, reading with both, revoking one, and confirming the revocation.

**Verify:** both tokens work in overlap; after revocation, the old token is
refused by Databricks.

### Task 4.7 — T-17: publish a new dataset and onboard a consumer end to end

This is the full story: a data owner publishes a dataset through the pipeline
(Task 4.3), a consumer registers through the portal (Task 4.4), Data Governance
approves, the provisioning process issues the credential (Task 4.2), and the
consumer reads through the gateway with the rewritten file (Task 4.5). Record
the elapsed time from registration to first successful read.

**Deliverable:** `tests/t17_publish_onboard.py` orchestrating all four steps
and recording elapsed time in the evidence.

**Verify:** the end-to-end flow completes; elapsed time is recorded; T-17 is
BUILD (fully demonstrable locally).

### Task 4.8 — T-22: landing, validation, quarantine and tagging

CONOPS §2.4.4 defines the landing workflow for ingress data: land in a schema
owned by the data owner, validate columns and types against the agreed schema,
confirm row count is above zero and within tolerance, record table version and
load time, check freshness, quarantine failures, and tag successful loads with
tier, owner and DSA reference.

Land a good load, a bad-schema load (columns missing or wrong type), and an
empty load. Confirm that good loads are tagged and queryable, and bad or empty
loads are moved to quarantine and a notification is raised.

**Deliverable:** `scripts/08_landing_validation.py` that applies the checks
and tags and quarantines as needed; `tests/t22_landing_quarantine.py` covering
the three cases; evidence record.

**Verify:** good loads are queryable with tier/owner/DSA tags; bad and empty
loads are in quarantine, not visible to consumers; a notification is raised
for quarantine.

### Task 4.9 — T-24: push-ingest route and the six refusals

CONOPS §2.4.5 defines the push-ingest route I-2: `PUT /ingest/{producer}/{file}`
maps to the Files API path of a landing volume. The gateway enforces six
refusals: oversize (gateway limit < 100 MB), wrong content type, wrong path
pattern (traversal or encoded forms), overwrite forced false (no `overwrite=true`),
GET/LIST/DELETE (PUT only), and direct Files API calls with the producer
credential.

The successful-upload path is PARTIAL: it needs a service principal with
`WRITE VOLUME` on the landing volume, which is unconfirmed on Free Edition.
Build the six refusals (all pure gateway policy) and document the unconfirmed
dependency. Also note that content scanning (CONOPS §2.4.5) is required and
is a platform security capability with no named owner (OD-9, Open) — uploads
are accepted in the test environment only until the owner is named.

**Deliverable:** `iac/config/policy-class-i.yaml` with the route definition,
rate limits (10/min), spike arrest (1/s), quota (500/day), body limits,
content types and path pattern; `tests/t24_push_refusals.py` covering each of
the six refusal cases; a written note on the service-principal unconfirmed
dependency and the content-scanning owner gap.

**Verify:** all six refusals are observed; error codes and messages match the
gateway policy; the path-pattern validator rejects traversal (`../`) and
encoded forms (`%2e%2e`); a PUT with `overwrite=true` is rejected; GET/LIST/DELETE
return 405 (method not allowed).

### Task 4.10 — R12 and token refresh: can the gateway inject and refresh the upstream service principal token?

Risk R12 states that the gateway cannot inject or refresh the upstream service
principal token for push ingest. CONOPS §2.4.5 notes that "Databricks OAuth
tokens for a service principal are short-lived, so the gateway secret must be
refreshed by a small scheduled function." Whether the gateway can do this is
unverified.

This is an engineering test, not a partner dependency. If the gateway can
inject the token (via policy or request-enrichment), the flow is
producer-facing → gateway → Databricks. If it cannot, a thin ingest service in
front of the Files API replaces the direct route. The producer-facing contract
does not change, but the implementation shifts.

**Deliverable:** a test that attempts to set an upstream service principal token
in a push request and observe whether it reaches Databricks; a written
conclusion on whether the gateway can inject it; if not, an outline of the
thin-ingest alternative (not implemented, because a service principal is
unconfirmed on this tier anyway).

**Verify:** test output shows whether token injection is possible; the
conclusion and fallback outline are documented.

### Task 4.11 — Story 3: Assemble the E4 ARB package

Pull together the three stories: the publish pipeline (Task 4.3), the portal
registration (Task 4.4), and the credential provisioning (Task 4.2). Include
the test evidence from Tasks 4.5–4.10, the O-4 reference implementation
(Tasks 4.1–4.2), the defect-D-1 correction (per-tier views instead of masks),
the landing/validation flow (Task 4.8), the push-route policies and refusals
(Task 4.9), and the R12 token-refresh finding.

Two things must appear prominently. **OD-10 is Open**, so the portal section
of the package is explicitly labeled as a stand-in; the Gravitee portal proof
of concept is a real data point for the primary option. **Defect D-1 and the
per-tier-view correction**: the package carries the 11.4 finding as a
correction to the CONOPS §3.4 step 2, since AC4 clause 4.1 currently rests on
a mechanism that does not exist on Free Edition (and, per 11.4, does not exist
at any tier for OpenSharing-shared tables).

**Deliverable:** `docs/epics/E4-arb-package.md` with evidence references,
gaps and asks.

**Verify:** every AC4 clause (4.1–4.4) traces to evidence or to a named gap;
T-13 (user test with PSP7) is recorded as PARTNER with the dependency named.

### Task 4.12 — Checkpoint 11/2–11/3: credential provisioning and IaC/CaC working in test environment

All credential provisioning steps (Tasks 4.1–4.2), the publish pipeline
(Task 4.3) and its Terraform, the portal registration simulation (Task 4.4),
and the push-route refusals (Task 4.9) are working locally. Run all of
Tasks 4.1–4.10 to this point, collect evidence, and produce a sign-off request.

**Deliverable:** confirmation that the six-step OD-4 provisioning process
works end to end, that the publish pipeline creates the per-tier views and
tags them correctly, that the push-route policies are enforced, and that IaC
regenerates the configuration from code (T-12 for E4's IaC contributions).

**Verify:** the checkpoint criteria are met; a sign-off request is sent to
Data Eng by 11/2–11/3 per the CONOPS schedule.

---

## E4.2 IaC and CaC deliverables

| Path | Contents |
|---|---|
| `iac/config/tier-templates.yaml` | Tier definitions and their DSA templates; data-owner-facing reference |
| `iac/config/policy-class-i.yaml` | Push-ingest route I-2, rate limits, spike arrest, quota, validation rules |
| `iac/databricks/publish-views.tf` | Per-tier views, with DSA and tier comments; one view per (table, tier) pair |
| `iac/databricks/publish-share.tf` | Purpose shares carrying views only; base tables never added |
| `iac/config/path-pattern-rules.yaml` | Path traversal and encoding rejection patterns for I-2 validation |
| `scripts/04_rewrite_credential.py` | OD-4 steps 3–4: fetch and rewrite the credential file (canonical version) |
| `scripts/05_credential_provisioning.py` | OD-4 full six-step chain: recipient creation, link retrieval, credential rewrite, delivery |
| `scripts/06_publish_pipeline.py` | CONOPS §3.4: table nomination, tier selection, view creation, share assignment |
| `scripts/07_portal_registration.py` | Developer portal integration: self-register, approve, trigger provisioning |
| `scripts/08_landing_validation.py` | CONOPS §2.4.4: landing, validation, quarantine, tagging |

Secrets appear in none of these, only as `.env` or vault references (§3.6).

---

## E4.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-09 | PARTIAL | E4 | `delta-sharing` and Spark available; Power BI, Tableau, Java not available — record as NOT_RUN |
| T-10 | BUILD | E4 (co-own with E3) | Two-token overlap and revocation observable |
| T-13 | PARTNER | E8 | Needs PSP7; belongs to AC8 |
| T-15 | PROBE (narrowed 10/18) | E4 (co-own with E2) | Availability **confirmed**; only invocation open. A8 now covers quota refusal only |
| T-16 | PROBE (narrowed 10/18) | E4 (co-own with E2) | MCPs tab **present**; open half is a callable server. M3 negative is BUILD |
| T-17 | BUILD | E4 | Publish and onboard end to end; record elapsed time |
| T-22 | BUILD | E4 (co-own with E3) | Landing, validation, quarantine, tagging |
| T-23 | BUILD | E4 (co-own with E5) | Live open-source provider; reclassified 2026-10-18 |
| T-24 | PARTIAL | E4 (co-own with E2) | Six refusals BUILD; successful upload needs service principal (unconfirmed) and content-scanning owner (OD-9, Open) |

---

## E4.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the following hold:

The divergent credential-rewrite script is reconciled and the canonical version
is in `scripts/04_rewrite_credential.py`. The six-step OD-4 provisioning process
is complete and tested, with the path-prefix assertion catching any mismatch
between client-side path building and gateway edge paths. The publish pipeline
creates per-tier views (not masks or filters), each carrying a DSA reference
and tier in its `COMMENT`, and adds them to purpose shares while leaving the
base table untouched. The developer portal registration flow is built and tested
against the Gravitee stand-in, demonstrating the self-service → approval →
credential-issuance path. T-09 passes for available reference clients (Spark
and pandas) and records NOT_RUN for unavailable ones. T-10 demonstrates token
rotation and revocation working correctly. T-17 passes end to end with elapsed
time recorded. T-22 validates and quarantines correctly. T-24's six refusals
all pass, and the unconfirmed service-principal dependency is documented.
The R12 token-refresh question is answered or documented as unanswerable on
this tier. The ARB package traces all four AC4 clauses to evidence or to a gap,
and leads with defect D-1's correction (per-tier views) and OD-10's open status
(Gravitee stand-in).

---

## E4.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| OD-4 sign-off | Data Eng confirmation of the six-step pattern | Tasks 4.1–4.2; ready for confirmation |
| OD-10 developer portal selection | Data Tooling decision (Gravitee vs. Backstage) | Task 4.4; Gravitee stand-in working |
| T-13 user test with PSP7 | PSP7 team availability and booking | Task 4.11; needs 11/3 confirmation |
| ~~T-15 model-service call~~ | ~~Model serving on the client tier~~ — **self-served 10/18**; the surface is live and Task 1.9 exercises it | A8 now covers quota refusal only |
| ~~T-16 positive (Unity Gateway MCP)~~ | ~~MCP beta enabled~~ — the MCPs tab is present with no account-admin gate; what remains is whether a *callable* server exists on this tier, which is ours to probe | E1 Task 1.9 part 4; M3 negative is BUILD |
| T-23 provider credential rotation | ~~T-20 stand-in provider~~ — **no longer a dependency**; the OSS provider is ours to rotate against | Task 4.9; T-23 is now BUILD |
| T-24 successful upload | Service principal with WRITE VOLUME (unconfirmed on Free Edition) and content-scanning owner | Tasks 4.9–4.10; risk R12; OD-9 open |
| R12 token refresh in production | Gateway policy or thin-ingest service decision | Task 4.10; testable locally if service principal is available |
| OD-9 content-scanning owner | Security + Data Governance assignment | Task 4.9; uploads in test environment until named |

Each of these should leave the epic as a dated ask, not as an empty cell in
the ARB package.
