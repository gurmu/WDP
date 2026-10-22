# E8 — T04-15: User Testing (AC8) and Customer Support (AC9)

| | |
|---|---|
| **Epic** | T04-15 |
| **Acceptance criteria** | AC8 — User Testing; AC9 — Customer Support |
| **CONOPS sections** | 3.8, 3.9, 5.3, 5.4 |
| **Stories** | 1: Engage PSP7 via Binod and Dave (§3.8, 5); 2: Run egress validation, live and recorded (§5); 3: Incorporate feedback (§5); 4 (proposed, AC9): Support and triage workflow (§3.9) |
| **Role** | Build — coordinates the PSP7 run and builds the triage runbook |
| **Target dates** | 10/30 – 11/20 · checkpoint **11/2 to 11/3** PSP7 session booked; **11/18 to 11/20** wrap-up, handoff, sign-off |
| **Depends on** | 1694-E6 (not yet assigned to this milestone), PSP7 introduction (Dave/Binod), OD-7 Service Desk owner (Open) |
| **Tests** | T-13 (PSP7 egress run, AC8); T-14 (support triage on paper, AC9) |
| **Decisions in play** | OD-7 (placement of AC9 and Service Desk owner, **Open**) |
| **Risks in play** | R5 (PSP7 availability late in weeks 5–7), R13 (ADVANASD-814427 details not incorporated), R1 |

> **AC8, verbatim (CONOPS §3.8):** *User Testing: at least one use case; recommend CDAO PSP7 team's egress use cases.*

> **AC9, verbatim (CONOPS §3.9):** *Customer Support: Service Desk workflows, triaging, etc. for positive customer experience in the future.*

---

## E8.0 What this epic actually has to produce

AC8 and AC9 are distinct in kind. AC8 is a live test that cannot be done solo — it requires a partner consumer (PSP7) to read shared data through the gateway in a real egress scenario and to report the experience. AC9 is a documented workflow that *can* be written now regardless of the Service Desk owner's start date, because the runbook is a document rather than an integration.

The epic delivers in two parts. **AC8 verification through PSP7:** a three-week engagement across the 10/30–11/20 window, starting with selection-criteria screening and a fallback use case, culminating in a live session where PSP7 runs the eight-step client verification procedure (§5.3) and provides feedback on the egress experience. Feedback flows into the egress design (§3.8), the client test matrix (§12), and the support runbook. The session is booked by 11/3, runs in the window 11/3–11/13, and is complete with post-session sign-off by 11/20.

**AC9 preparation through triage runbook:** seven ticket categories covering the most common support scenarios. The runbook is organized as one page per category, each with typical cause, first-line diagnosis using the correlation ID, and escalation path. A triage record format holds party, share or route, timestamp and correlation ID — the minimum needed to route a ticket and for support staff to gather context. The runbook is validated on paper in T-14, and after the PSP7 run, updated with real feedback and handed off to the Service Desk owner (OD-7, currently Open). AC9 has no epic yet — Section 1.5 of the CONOPS flags this, and Binod is the decision owner. This epic assumes AC9 lands as Story 4 under T04-15, but the runbook is built regardless.

The eight-step client verification procedure is the core of AC8. Section 5.3 lists them: *"The session follows eight steps."* This epic rebuilds `tests/run_verification_session.py` against that list, because the script is stale twice over — it says "seven steps" and cites Section 6.3, which in v1.5 is neither the right count nor the right section (§11.7 B-5).

The count is worth stating carefully, because **the CONOPS contradicts itself and the script may have been right once**. §5.3 says eight steps and lists eight. But §3.8 says *"Run: the seven-step client verification session (Section 5.3)"* — pointing at the same section while naming a different count. §5.3 is the one that enumerates, so eight is authoritative and §3.8 is the stale cross-reference. This is a new document defect for v1.6 (recorded as **D-5** in docs/10 §10.7), and it is the kind of thing worth catching before a client reads §3.8, counts seven, and asks which step was dropped. A self-run rehearsal of the eight steps against the local stack is valuable for shortening the real session and for identifying technical gaps early. But a self-run rehearsal is explicitly not T-13: the true test is the PSP7 consumer reading real data with their own client in their own environment, using a case from their egress use-case portfolio.

---

## E8.1 Task list

Each task is independently verifiable. Run them in order. **PARTNER** or **DEFERRED** tasks are not skipped quietly — they produce a written gap with an owner.

### Task 8.1 — Rebuild `run_verification_session.py` against the eight-step procedure

The existing script at `tests/run_verification_session.py` is stale. Its docstring references "Section 6.3" (the old document structure) and lists "seven steps" when both CONOPS §3.8 and §5.3 specify eight. The eight steps are:

1. Publish a test dataset as a share (AC4)
2. Register and approve a consumer through the portal, tied to a DSA reference (AC3, AC4)
3. Issue the credential file with the endpoint rewritten to the gateway address (AC4)
4. Read the data through the gateway with a standard client, showing only entitled columns; call one model service or MCP server through the gateway (AC1, AC4)
5. Show the refusals: burst above the limit, malformed request, direct call to Databricks, column outside the grant (AC1, AC2)
6. Ingest: pull a test share into the read-only catalog and land it with validation; push a file through the gateway; show a rejected upload (AC1, AC3, AC5)
7. Trace one egress and one ingress request across the gateway log and the Databricks audit event (AC5)
8. Revoke the consumer and show access fails; redeploy the configuration from code (AC3, AC6)

Rebuild the script to walk these eight steps in order, with a per-step PASS/FAIL/NOT_RUN evidence record following the shape in `docs/10` §10.4. For steps that depend on external components or on prior epics (E2 for the gateway, E5 for the trace correlation), mark the record `NOT_RUN` with the dependency stated, never silence or fake a result.

This is the local rehearsal harness and the template for the PSP7 session flow.

**Deliverable:** `tests/run_verification_session.py` rebuilt against eight steps with per-step evidence records; a timestamped evidence log at `evidence/verification-session-rehearsal.json`.

**Verify:** each step either returns a PASS record with evidence, or a NOT_RUN record with the dependency named; no step is silently skipped.

### Task 8.2 — Build the step-by-step readiness assessment

Not all eight steps are equally buildable today. Per `docs/12` §12.6, five steps are fully demonstrable, step 5 becomes the sixth once T-04 is rebuilt on the view pattern, and steps 6 and 7 are where the prototype stops being able to stand in.

Blocker B-1 is **not** the obstacle it appeared to be on 10/17. As reclassified on 10/18 (§11.7), the gateway proxies the open protocol correctly and returns a real share list; the 404 was an upstream target error on a second, policy-free API definition. So steps 3, 4 and 5 are not blocked from starting — what they need is E2 Task 2.1 to converge the two definitions so the rehearsal runs against a route that carries the perimeter policies. Rehearse the steps now against the working route; re-run them against the consolidated one.

Build a readiness table, one row per step, with columns: Step number and title; Current status (BUILD, PARTIAL, DEFERRED, or BLOCKED); Blocker or dependency if any; What the local rehearsal can demonstrate; What the PSP7 run will add. This table is the foundation for the 11/2–11/3 checkpoint: it answers "are we ready to book the PSP7 session, or do we need to land some fixes first?"

**Deliverable:** `docs/epics/E8-readiness-table.md` with the assessment.

**Verify:** the table matches the status of each epic that provides steps: the E2 Task 2.1 consolidation is listed as the dependency for steps 3–5 (not B-1 as originally diagnosed), T-04's rebuild requirement for step 5, step 6's unconfirmed service principal and push upload for the ingress half, step 7's unconfirmed `system.access.audit` for the Databricks half.

### Task 8.3 — Define the PSP7 selection criteria and build the checklist

Section 3.8 and Section 5.1 of the CONOPS define PSP7 criteria. A PSP7 candidate must match all of the following: an egress scenario in their use case; a non-sensitive test dataset; a named technical contact; a consuming client from the reference list (Section 5.1); availability inside the 11/3–11/13 window; and alignment with ADVANASD-814427 reference request (pending details, A9/R13).

Build a single-page checklist that Binod and Dave use to screen candidates. For each criterion, list the question, the expected answer, and the placeholder for the reference. Record the date screened, the outcome (approved/rejected), and the contact name.

For the approved candidate, capture: contact name, organization, email, phone; use case title and description; dataset name and sensitivity classification; preferred session date and timezone; and technical contact's Databricks role and PAT/token availability.

**Deliverable:** `docs/epics/E8-psp7-selection-checklist.md` with the criteria and the outcome record.

**Verify:** all four criteria from §3.8 appear in the checklist; one approved candidate is recorded with full contact details by 11/2.

### Task 8.4 — Identify the fallback use case

Risk R5 calls for a fallback use case if the approved PSP7 candidate becomes unavailable inside the 11/3–11/13 window. The fallback is a second candidate screened against the same criteria and held in reserve, or an internal use case (a synthetic egress scenario run within the platform team with a volunteer consumer).

The fallback does not reduce the real test — a PSP7 consumer from the CDAO reference list is the preferred outcome — but it ensures the session runs on schedule if the primary candidate's availability slips.

**Deliverable:** a documented fallback candidate (external or internal) screened against the same criteria and recorded with the outcome in the same checklist file.

**Verify:** the fallback candidate record is present, dated, and captured by 11/2.

### Task 8.5 — Gather the eight-step test data and prepare the rehearsal environment

The PSP7 session will run against a real test dataset provided by the consumer. Before PSP7 arrives, the rehearsal must run against the same data — or at minimum, against data with the same shape. Coordinate with the approved PSP7 candidate to obtain the dataset name, column list, and sensitivity classification. Create a synthetic twin if necessary.

Stage the dataset as a share (step 1 of the procedure), create a recipient and issue a rewritten credential file (steps 2–3), and run a local read to confirm the data and the credential file work (step 4).

This is the "fast path to confirmation": before the 11/3 booking, you will have proven to the PSP7 contact that their data is in the right shape, that the platform understands the structure, and that the credential rewrite works. This builds confidence and shortens the real session.

**Deliverable:** the test dataset staged as a share; a recipient created and a rewritten credential file issued; a successful local read recorded.

**Verify:** the dataset is reachable through the gateway at the endpoint in the rewritten credential file; the column list in the share matches the consumer's expectations.

### Task 8.6 — Write the AC8 acceptance-test procedure and evidence record template

AC8 succeeds when the PSP7 consumer reads shared data through the gateway, the request is traceable end to end, and feedback is recorded and incorporated (T-13, §3.8). Write a one-page procedure that the PSP7 technical contact and the platform team (Dave/Binod + AI/ML Ops) will follow during the live session:

- Session start: confirm the PSP7 contact has the rewritten credential file and can reach the gateway endpoint address
- Steps 1–8: follow the procedure above; a platform team member guides and records evidence
- Per-step checkpoints: does this step pass (green), partially pass (yellow), or fail (red)? Does the consumer have a question or observation?
- Feedback capture: after each step, record what worked, what was confusing, what is unexpected
- Session end: thank the consumer, agree on feedback-incorporation timeline, document follow-up actions

Prepare an evidence-record template in JSON format holding: timestamp, step number, step name, expected result, actual result, PASS/FAIL/PARTIAL, consumer feedback, and platform notes.

**Deliverable:** `docs/epics/E8-psp7-session-procedure.md` and `evidence/t13-psp7-evidence-template.json`.

**Verify:** the procedure names the eight steps; the template matches the shape in `docs/10` §10.4.

### Task 8.7 — Create the triage record schema and the seven-category runbook

AC9 requires triage workflows and runbook documentation. A triage record is the minimal ticket metadata: party (consumer or producer name), share or route name, timestamp, and correlation ID. The correlation ID is the join key across the gateway log and the Databricks audit event (when the audit is available), so it is the single fact that allows first-line support to gather context without asking for tokens or credential files.

Build the schema as a JSON structure (or a Terraform variable) and document it in one line: what each field is, why it is present, and what it indexes.

Then write the seven-category runbook, one page per category:

| Ticket category | Typical cause | First-line action | Escalate to |
|---|---|---|---|
| Registration or onboarding | Portal error or approval pending | Check approval status and guide the party | Data Eng; Data Governance for approvals |
| Access denied | Expired token, address not allowed, or no entitlement | Check recipient status, token expiry, IP list and grants using the correlation ID | Data Governance (entitlement); Data Eng (recipient) |
| Throttled | Rate limit or quota exceeded | Check the party's usage, advise retry, changes only through a change request | Data Tooling |
| Credential rotation or lost file | Rotation due, file lost | Reissue through the provisioning process (CONOPS §3.4.1) after approval | Data Eng |
| Data question | Missing or stale data, failed ingest | Check the publish or ingest job status and quarantine | Data Eng; data owner |
| Upload rejected (push ingest) | Size, type or path rule | Check the gateway decision for the correlation ID, guide the producer | Data Tooling |
| Suspected misuse | Unusual usage in logs | Revoke at once and notify security | Data Governance; security |

For each category: state the typical cause in one sentence; list the three to four first-line checks a support person can do without escalation (always using the correlation ID as the join key); name the escalation team(s) and what they will need from support; and provide one worked example (a fictional ticket) showing the diagnosis flow.

One critical rule: support staff never ask for tokens or credential files. All context comes from the triage record, the correlation ID, and the gateway/Databricks logs.

**Deliverable:** `docs/epics/E8-triage-schema.md` and `docs/epics/E8-support-runbook.md` (seven pages, one per category).

**Verify:** the triage schema includes party, share or route, timestamp and correlation ID; each runbook page is self-contained and includes a worked example.

### Task 8.8 — Validate the runbook against T-14 on paper

T-14 is a paper test: raise a fictional access-denial ticket and a fictional rejected-upload ticket, and walk them through the triage procedure. The ticket categories are "Access denied" and "Upload rejected (push ingest)".

For each ticket: write a short scenario (e.g., "Consumer received a 403 Forbidden when trying to read the share; the error message says 'ip_filtering'. The timestamp is 2026-10-30T14:22:34Z. The correlation ID is ABC123."). Then, using only the runbook and the triage schema, walk through the first-line actions:

- Access denied: check recipient status, token expiry, IP list and grants using the correlation ID. What do you ask for from the consumer? What do you check in the logs?
- Upload rejected: check the gateway decision for the correlation ID. What does the rejection reason tell you? What does the producer need to do?

Document the diagnosis flow for each ticket, the questions asked, and the decision to escalate or resolve locally. This proves the runbook is usable.

**Deliverable:** `evidence/t14-triage-paper-test.json` with the two scenarios, the diagnosis steps, and the outcomes.

**Verify:** each ticket can be triaged using only the runbook and the correlation ID, without asking for tokens or credential files.

### Task 8.9 — Create the feedback incorporation plan

Story 3 of the epic incorporates feedback from the PSP7 run into the egress design, the client test matrix and the support runbook. Feedback does not land in a black box — it lands in a log, it is prioritized, and it flows into the next action.

Create a feedback log in JSON format with columns: timestamp, category (design/testing/support/usability), feedback text, priority (P1–P4), affected component (e.g., gateway credential-rewrite, client verification step 4), and action item (who does what by when). Populate the log with a few mock entries showing the shape.

In the PSP7 session, the platform team captures feedback in this log after each step. After the session, feedback is reviewed, prioritized, and tracked to closure before 11/20. Items that cannot close before 11/20 (e.g., requests to add MCP support) are marked as future work.

**Deliverable:** `evidence/feedback-log.json` with the schema and mock entries; a summary of how feedback flows: from the session → the log → the design/test/runbook updates → the 11/18–11/20 wrap-up report.

**Verify:** the log schema matches the evidence format in `docs/10`; at least three categories of feedback are represented in the mock entries.

### Task 8.10 — Prepare the 11/2–11/3 checkpoint: PSP7 session readiness

By 11/2–11/3, the following must be in place to book the session:

- The approved PSP7 candidate is screened and confirmed (Task 8.3)
- The fallback candidate is identified (Task 8.4)
- The test data is staged and the credential file works (Task 8.5)
- The session procedure and evidence template are ready (Task 8.6)
- The triage runbook is written (Tasks 8.7–8.8)
- The readiness assessment shows what can and cannot be demonstrated (Task 8.2)

Binod books the session with the PSP7 contact, targeting a date inside 11/3–11/13 and confirming the technical contact's availability, timezone, and preferred session time. The session will run for four to six hours, with a thirty-minute break halfway through.

Send the PSP7 contact: the session procedure (one page), the rewritten credential file for their test dataset (already prepared), and the expected steps. Ask them to review and confirm they are ready.

**Deliverable:** a confirmation email from the PSP7 contact dated by 11/3, with the session date and time locked in.

**Verify:** the confirmation is in the project archive; the date is inside 11/3–11/13.

### Task 8.11 — Run the PSP7 session and capture feedback

**PARTNER.** Binod and Dave run the session with the approved PSP7 candidate on the booked date. The platform team (AI/ML Ops, Data Tooling representative if needed) is present as guides and evidence collectors. The session runs the eight steps against the PSP7 consumer's test data and their own client. After each step, feedback is captured in the feedback log and on the evidence record.

This cannot be done solo or simulated. The value is in the real consumer reading real data through the real gateway and reporting what works and what is confusing.

If the session is successful, it closes T-13 with the evidence log showing all eight steps in the PSP7 environment.

**Deliverable:** `evidence/t13-psp7-session-evidence.json` with evidence records for all eight steps; `evidence/feedback-log.json` updated with PSP7 feedback.

**Verify:** the evidence log includes at least four steps with PASS records; feedback is recorded for at least three steps; the consumer's name and the session date are in the evidence.

### Task 8.12 — Wrap-up, incorporate feedback, and hand off (11/18–11/20 checkpoint)

By 11/20, complete the following:

- Review all feedback from the PSP7 session and prioritize it (P1 must-fix, P2 design input, P3 future)
- Update the egress design (§3.8 notes) with design-category feedback
- Update the client test matrix (`docs/12`) with any new test insights or gaps
- Update the support runbook with feedback-category items and any new scenarios discovered during the session
- Close the triage record schema and sign off on it
- Run a final cross-epic consistency check: does E6 (IaC/CaC) deployment cover AC9's runbook pages and the triage schema? Do the Evidence records in E1–E7 follow the same shape and naming?
- Prepare the 11/20 status report: T04-15 complete, AC8 proven in the PSP7 session, AC9 ready for handoff to the Service Desk owner (OD-7)

The handoff to the Service Desk owner includes: the complete runbook, the triage schema, the feedback log from the PSP7 run, and a sign-off request for OD-7 to confirm the workflow and service levels.

Jira stories (Story 1–4) are marked complete and the status is reported to the roadmap owner.

**Deliverable:** updated `docs/12-test-matrix.md` (AC8 and AC9 rows); updated support runbook with PSP7 feedback; `evidence/e8-11-20-status-report.md` with sign-off requests for T04-14 and T04-15; email to the Service Desk owner with the runbook and a request to confirm placement of AC9 and to agree on service levels.

**Verify:** the status report is dated 11/20; it names at least one P1 fix incorporated and at least one P2 design input noted; the Service Desk owner's reply is archived.

---

## E8.2 IaC and CaC deliverables

This epic is predominantly documentation and test harness. The infrastructure is minimal: the triage schema, the feedback log, and the verification-session script are the delivered code artifacts.

| Path | Contents |
|---|---|
| `tests/run_verification_session.py` | Eight-step client verification procedure with per-step evidence records |
| `docs/epics/E8-readiness-table.md` | Step-by-step buildability and dependencies |
| `docs/epics/E8-psp7-selection-checklist.md` | PSP7 screening criteria and approved candidate record |
| `docs/epics/E8-psp7-session-procedure.md` | Live session walkthrough for the PSP7 team |
| `docs/epics/E8-triage-schema.md` | Triage record format and field definitions |
| `docs/epics/E8-support-runbook.md` | Seven-category support workflow, one page per category |
| `evidence/t13-psp7-evidence-template.json` | Per-step evidence record schema for the session |
| `evidence/feedback-log.json` | Feedback capture log with priority and action tracking |

IaC deployment (E6) validates that these files are deployed and accessible to the support team, but E8 does not own infrastructure — it owns documentation and the bridge between the PSP7 consumer and the support organization.

---

## E8.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-13 | PARTNER | E8 | PSP7 egress run, booked by 11/3, runs 11/3–11/13; not simulable solo |
| T-14 | PARTIAL | E8 | Triage runbook and correlation-ID routing proven on paper; no Service Desk owner (OD-7 Open) |

---

## E8.4 Exit criteria

The epic is done when all of the following hold:

The eight-step client verification script is rebuilt against CONOPS §5.3 and includes per-step evidence records for the local rehearsal, with NOT_RUN records stating dependencies where the gateway or earlier epics are not ready. The PSP7 selection checklist screens at least one candidate against the four criteria from §3.8 and a fallback is identified. The test data is staged and a rewritten credential file is confirmed working by 11/2. The session procedure and evidence template are ready. The seven-category triage runbook is written, one page per category, with worked examples and first-line actions that use only the triage record and correlation ID, never tokens. The runbook is validated on paper in T-14. The feedback log is created and the incorporation plan is documented. The PSP7 session is booked by 11/3 with a confirmed date inside 11/3–11/13. After the session (by 11/20), feedback is incorporated into the design, test matrix and runbook. The support runbook is handed off to the Service Desk owner with a sign-off request for OD-7. Stories 1–4 are closed and the 11/20 status report is signed off.

---

## E8.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| T-13 PSP7 egress run | CDAO PSP7 team availability, session booked and run | §3.8, R5; PARTNER |
| OD-7 placement of AC9 | Binod decision and Service Desk owner assignment | §3.9, §8 (roles) |
| Service levels and SLA agreement | Service Desk owner acceptance and governance alignment | §3.9, OD-7 |
| ADVANASD-814427 reference request details | Data Governance / procurement to supply | §3.8, A9, R13 |
| Steps 6–7 dependencies | Service principal for push upload, `system.access.audit` availability, and E2 Task 2.1's consolidated policy-bearing route | §5.3, §12.6 |

Each of these should leave the epic as a dated ask with an owner, not as silence or an empty cell in the runbook.
