# E5 — 1227-E5: Auditability and Observability (AC5)

| | |
|---|---|
| **Epic** | 1227-E5 |
| **Acceptance criterion** | AC5 — Auditability and Observability |
| **CONOPS sections** | 3.5, 5 |
| **Stories** | 1: Logging/metrics requirements (§3.5) · 2: Integrate into CONOPS (§3.5) · 3: Trace-compliance check (§3.5, 5) |
| **Role** | Integrate — Data Tooling owns telemetry and logging implementation; AI/ML Ops integrates the requirements and runs the trace check |
| **Target dates** | 10/16 – 11/5 · checkpoint **10/28** infrastructure and logging requirements collected; **11/5** sign-off request |
| **Depends on** | 1694-E4 (correlation-ID propagation contract, **does not exist yet**) |
| **Tests** | T-11, T-18, T-21, T-22, T-25 |
| **Decisions in play** | OD-4, OD-5, OD-9 |
| **Risks in play** | R1, R12, R13 |

> **The criterion, verbatim (CONOPS §3.5):** *Auditability and Observability: end-to-end telemetry, access logs, query metrics across tools; trace compliance; track usage.*

---

## E5.0 What this epic actually has to produce

AC5 mandates end-to-end observability across five telemetry sources, a monthly per-consumer usage report, and the ability to trace a single request through every system that touched it. The test that proves traceability — T-11 for egress, T-25 for ingress — depends on a correlation-ID propagation contract (1694-E4) that does not yet exist. The epic's central engineering question is therefore not "how do we trace?", but rather "what fields and join keys allow us to stitch the evidence together once the contract is signed?" That answer must come from T-11's execution and becomes the standard for T-25.

Three deliverables in dependency order:

1. **The telemetry infrastructure**, matching the five sources (§3.5 table): gateway access logs into Elasticsearch, Databricks audit and query system tables confirmed discoverable, storage access logging, and ingest job records. This is the foundation — traces exist only if all five are live.

2. **The trace field list and join-key schema**, proven against a live egress request (T-11). The join key is the critical unknown, because Databricks' audit event may not carry the gateway's custom correlation-ID header. Fallback is recipient + share + table + time window + gateway request ID, but the test determines what actually works on this tier.

3. **The per-consumer monthly usage report** (T-18), cross-referenced to the observability dashboard, with one consumer and one month of data used to verify that gateway metrics, Databricks query history, and (if available on Free Edition) Unity AI Gateway usage tables agree on the same request counts and bytes.

Everything else in AC5 — the logging rule, the usage-tracking scope, the DSA audit obligation support — lives in the configuration and evidence rules set by §10.4 and §10.5, not in new code.

---

## E5.1 Task list

Each task is independently verifiable. Run them in order. **PARTNER** or **DEFERRED** tasks are not skipped quietly — they produce a written gap with an owner.

### Task 5.1 — Probe Databricks-side audit-table availability on Free Edition

Blocker for the entire trace design. The CONOPS §3.5 join-key section states "Databricks may not copy a custom header into its audit event (unverified)", and indeed, testing with a custom header shows it does not. But `system.access.audit` may or may not be available on Free Edition, since account-level audit delivery configuration normally sits in the account console, which Free Edition does not have (11.6). The system-table route may be the only available one, if it exists.

**Deliverable:** a script that attempts to read `system.access.audit` and `system.query.audit` and reports whether they exist, how many rows each holds, what fields are populated, and whether a share-related query event is present with the recipient name and share ID.

**Verify:** the script runs without authentication errors and reports conclusively whether the tables are accessible. If they are not, document the error code so T-11 and T-25 can be bounded properly.

### Task 5.2 — Instantiate the telemetry sources configuration file

CONOPS §3.5 lists six sources, each with what it records and where it lands. Make it a versioned CaC file so the tracing queries and the evidence schema can resolve against one source of truth.

**Deliverable:** `iac/config/telemetry-sources.yaml` with per-source: id, name, system, what it records (field list), destination, real-time or batch, reachability status (confirmed working, unconfirmed, blocked), and notes.

**Verify:** all six sources from §3.5 appear exactly once; the field lists match the CONOPS table; reachability status is honest (confirmed by a test or by an error message, never by assumption).

### Task 5.3 — Collect the trace field list and join-key schema

The CONOPS defines trace compliance (§3.5) as the presence of nine fields in every relevant source: consumer, recipient, share or asset, route, decision, time, status, bytes, correlation ID, DSA reference. Those are the *required* fields. The join key is the *optional* fields that tie events together across sources — and the CONOPS cannot answer that question because 1694-E4 does not exist yet.

**Deliverable:** `iac/config/trace-fields.yaml` with two sections: *required* (nine fields, per §3.5) and *join-key* (TBD, to be determined by T-11). Include for each field: system of origin, data type, schema path (e.g., `gateway.access_log.correlation_id`), and whether it is populated in practice.

**Verify:** the required fields match §3.5 verbatim; the join-key section carries a placeholder note that T-11 will fill it; the file is used by the T-11 evidence script to report which fields were found in each source.

### Task 5.4 — Build T-11: the egress trace check, gateway half

T-11 is PARTIAL: the gateway side is fully buildable, the Databricks side depends on Task 5.1. The gateway half traces a request from the Gravitee access log into Elasticsearch and confirms it has all nine required fields.

This task carries a critical configuration trap from 11.2: the gateway's Elasticsearch config key is `ds.elastic.host` / `ds.elastic.port`, not `analytics.elasticsearch.endpoints[0]`. The latter is silently ignored and leaves the service pointed at localhost:9200, which is empty, making T-11 look impossible when it is only misconfigured. Call this out explicitly in the test's docstring and in the evidence record if this was the issue.

**Deliverable:** `tests/t11_trace_egress.py` that creates a request to the gateway (via any route; E-1 ingress is sufficient), captures the correlation ID from the response, waits for it to flush to Elasticsearch, queries Elasticsearch for the event, and reports whether all nine required fields are present. The script must check the gateway's Elasticsearch config and error clearly if it is wrong.

**Verify:** the test executes and produces an evidence record with either (a) all nine fields found, with the join key determined and recommended for T-25, or (b) a subset found, listing which are missing and why, or (c) "Elasticsearch is misconfigured at ds.elastic.host / ds.elastic.port" — which is a real output, not a failure, because it is actionable.

### Task 5.5 — Probe and document Databricks audit-side trace capability

Continuation of Task 5.1, with emphasis on what a trace actually looks like once T-11 determines the join key.

**Deliverable:** if Task 5.1 succeeded, a script that queries `system.access.audit` or `system.query.audit` with the join key determined by T-11 and reports the matching event. If Task 5.1 found the tables unavailable, a written analysis of what T-11 and T-25 can prove and what they cannot (one-sided trace, limited to the gateway side).

**Verify:** the script either (a) produces a Databricks audit event matching the gateway event by the join key, with all required fields present, or (b) reports that no match was found, which means the join key is wrong and T-11 must try again with a different key, or (c) reports that the audit tables do not exist and T-11 is a gateway-side-only trace, which is a valid outcome (see 11.6 and CONOPS A8).

### Task 5.6 — Build and verify the observability dashboard definition for gateway metrics

T-18 requires a cross-tool dashboard with gateway latency and throttles beside Databricks query history and (if available) Unity AI Gateway usage. The gateway metrics half is fully buildable — Elasticsearch holds the access logs with latency and policy-denial counts.

**Deliverable:** `iac/dashboards/gateway-metrics.json` (or yaml/hcl in your dashboard tool of choice) defining: gateway request rate per consumer and route, gateway latency p50/p99 per consumer, throttle and spike-arrest denials per consumer, request-routing decision distribution (pass/deny/rate-limit). Include documentation of the Elasticsearch query that populates each panel.

**Verify:** the dashboard renders in the local Elasticsearch instance without errors; all panels show data if there is test traffic in Elasticsearch from previous test runs.

### Task 5.7 — Build T-18: the per-consumer monthly usage report, gateway half

T-18 is PARTIAL: gateway metrics are observable in Elasticsearch; Databricks usage and query history tables and Unity AI Gateway usage tables are unconfirmed on Free Edition (11.6). Build the gateway half — query Elasticsearch for counts, bytes and denials per consumer over a calendar month.

**Deliverable:** `tests/t18_usage_report.py` that generates a per-consumer report: total requests, total bytes downloaded, tables read, denials, throttles, and ingest volumes (if available in Elasticsearch). Include a month selector and a consumer selector. Document what figures are available only from the gateway and what would require Databricks system tables.

**Verify:** the report executes and produces one consumer's one month of data; the numbers are non-zero if there is test traffic; the report clearly labels which figures come from the gateway and which are "pending Databricks system table confirmation".

### Task 5.8 — Ingest job records: landing, validation, quarantine, tagging (co-owned with E4)

T-22 and T-24 require evidence that landing jobs record their status, validation failures land in quarantine, and outputs are tagged with DSA tier. This is the I-1/I-2 observability.

**PARTNER.** E4 owns the publish pipeline and landing logic. E5 defines the ingest-job record schema and the quarantine-event schema. Coordinate on the evidence format: counts, validation outcome, quarantine event timestamp, DSA tier tag.

**Deliverable:** `iac/config/ingest-job-record-schema.yaml` with fields: job ID, source (I-1 or I-2), counts (rows attempted, accepted, rejected), validation outcome (pass/fail), quarantine event (if any), DSA tier applied, timestamp. Cross-referenced from `docs/epics/E4-T04-13-self-service-publish.md`.

**Verify:** the schema is used by E4's landing pipeline; T-22 and T-24 produce records matching the schema; quarantine counts are nonzero if there are quarantine events.

### Task 5.9 — Assemble the Story 3 trace-compliance-check evidence

The three stories (1: logging/metrics requirements, 2: integrate into CONOPS, 3: trace-compliance check) culminate in a single verification that a request can be traced end-to-end. Story 3's evidence is T-11 and T-25 both producing records in the evidence schema (§10.4).

**Deliverable:** `evidence/t11-trace-egress.json` and `evidence/t25-trace-ingress.json` (once E1 and E4 are far enough along), each recording: test ID, expected (nine required fields in all sources, join key confirmed), actual (what was found, what was not), result (PASS, PARTIAL, or the reason for NOT_RUN), timestamp.

**Verify:** both evidence records are committed; if either is PARTIAL, the notes explain what was blocked by which dependency (Databricks audit-table availability, T-20/T-24 standing up, 1694-E4 contract).

### Task 5.10 — Checkpoint 10/28: infrastructure and logging requirements collected

The first checkpoint of E5 (10/28, before the 11/5 sign-off request) is that Elasticsearch is flowing, the telemetry sources are confirmed reachable or documented as unavailable, and the five configuration files (telemetry-sources.yaml, trace-fields.yaml, ingest-job-record-schema.yaml, the dashboard definition, and the usage-report schema) are in place.

**Deliverable:** a summary document, `docs/epics/E5-infrastructure-checkpoint.md`, reporting: Elasticsearch connectivity (yes/no), `system.access.audit` availability (confirmed/unavailable/untested), `system.query.audit` availability (confirmed/unavailable/untested), reachability of cloud storage access logging (yes/no), ingest-job-record integration point with E4 named and dated.

**Verify:** the summary is honest and specific; no rows say "pending further investigation" without a date and owner.

### Task 5.11 — Sign-off request for 1227-E5

Checkpoint **11/5**: gather T-11 and T-25 evidence, the observability dashboard proof-of-concept, the per-consumer usage report (partial if needed), and the configuration files into a single package. Request sign-off from AI/ML Ops (trace compliance verified) and Data Tooling (logging and metrics instrumentation).

**Deliverable:** `docs/epics/E5-arb-evidence.md` with sections: telemetry sources (confirmed reachable, gaps documented), trace field list (required vs. join key, join key determined or TBD), T-11 and T-25 results (evidence records with verdict), cross-tool dashboard screenshot, per-consumer monthly report sample, ingest-job observability schema, and a list of what cannot be closed locally and why (Databricks audit tables if unavailable, 1694-E4 contract if it arrives late, etc.).

**Verify:** every AC5 clause traces to evidence or to a named gap; no clause traces to nothing or to an assumption.

---

## E5.2 IaC and CaC deliverables

| Path | Contents |
|---|---|
| `iac/config/telemetry-sources.yaml` | Five/six sources, what each records, destination, reachability status |
| `iac/config/trace-fields.yaml` | Required nine fields per §3.5, join-key schema (TBD by T-11) |
| `iac/config/ingest-job-record-schema.yaml` | Job ID, source, counts, validation outcome, quarantine event, DSA tier, timestamp |
| `iac/dashboards/gateway-metrics.json` | Gateway latency, throttles, denials, request rate per consumer and route |
| `iac/dashboards/usage-report-schema.yaml` | Monthly per-consumer report: requests, bytes, tables, denials, throttles, ingest volumes |
| `docs/epics/E5-infrastructure-checkpoint.md` | 10/28 status: Elasticsearch reachability, audit-table availability, storage logging, ingest integration |
| `docs/epics/E5-arb-evidence.md` | 11/5 sign-off request: traces, dashboard, reports, and gaps |

Secrets appear in none of these, only as `.env` or vault references (§3.6).

---

## E5.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-11 | PARTIAL | E5 | Gateway half is BUILD; Databricks audit half is PARTIAL (depends on Task 5.1 outcome) |
| T-18 | PARTIAL | E5 | Gateway metrics are BUILD; Databricks system tables and Unity AI Gateway usage tables are unconfirmed on Free Edition (11.6) |
| T-21 | BUILD | **E1** | Write-read refusal and secret-scan; E5 re-verifies the secret-scan half |
| T-22 | BUILD | **E4** | Landing, validation, quarantine, tagging; E5 defines the job-record schema |
| T-25 | PARTIAL | E5 | Same join-key unknown as T-11; depends on T-20, T-24 standing up first; dependency 1694-E4 does not exist yet |

---

## E5.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the following hold:

Elasticsearch is confirmed live and receiving gateway access logs, with a clear error message if the `ds.elastic.host` / `ds.elastic.port` configuration is wrong. The telemetry sources configuration file lists all five sources, marks each as confirmed, unconfirmed, or unreachable, and gates no test on an assumption. The trace field list captures the nine required fields and carries a join-key placeholder or a confirmed join key from T-11. T-11 passes with evidence showing all nine fields (or documents which are missing and why). T-18 produces a monthly per-consumer usage report with the gateway side fully represented and the Databricks side marked as confirmed or unconfirmed. T-21 and T-22 pass with evidence. T-25 has a record that is either a result (if the join key worked and T-20/T-24 are ready) or a named dependency (1694-E4, T-20, T-24). The ingest-job-record schema is specified and cross-referenced from E4. The 10/28 checkpoint report is dated and specific. The ARB evidence package on 11/5 traces all five AC5 clauses (telemetry, access logs, query metrics, trace compliance, usage tracking) to evidence or to a gap, and notes prominently what cannot close locally and why.

---

## E5.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| 1694-E4 correlation-ID propagation contract | Data Tooling specification | 3.5 "single biggest unknown"; gates the true join key for T-11 and T-25 |
| `system.access.audit` and `system.query.audit` availability on Free Edition | Databricks confirmation or a probe on the real tier | 11.6; T-11 and T-25 cannot join Databricks-side events if these tables do not exist |
| T-25 ingress tracing | T-20 and T-24 standing up first | 12.2; 1694-E4 contract. |
| Unity AI Gateway usage and inference tables on Free Edition | Databricks confirmation or a probe on the real tier | 11.6; T-18 cross-tool dashboard is one-sided without them |
| Ingest-job-record schema integration into E4's landing pipeline | E4 commitment and implementation | Task 5.8; the schema is specified but lives as a sibling definition until E4 consumes it |

Each of these should leave the epic as a dated ask, not as an empty cell in the ARB package.
