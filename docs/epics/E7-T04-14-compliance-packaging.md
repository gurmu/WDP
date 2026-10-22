# E7 — T04-14: EA / Change-Request Compliance Packaging (AC7)

| | |
|---|---|
| **Epic** | T04-14 |
| **Acceptance criterion** | AC7 — Security and Compliance |
| **CONOPS sections** | 3.7, 6, 9.3 |
| **Stories** | 1: Map to EA/CR standards (§3.7) · 2: Apply ARB template (§3.7, §6) · 3: Final review with Data Governance (§3.7) |
| **Role** | Build — AI/ML Ops as integrator; Data Governance supplies the standards and template |
| **Target dates** | 10/30 – 11/20 · checkpoint **11/18–11/20** final ARB review-ready |
| **Depends on** | 1694-G2 (ARB template, not yet supplied), EA/CR standards (to be supplied by Data Governance) |
| **Tests** | Review (ARB packages); no test IDs |
| **Decisions in play** | OD-5 (gates the sign-in model), OD-1, OD-6, OD-8, OD-9 |
| **Risks in play** | R1, R2, R3, R4, R13, R14 |

> **The criterion, verbatim (CONOPS §3.7):** *WDP Enterprise Architecture and Change Request standards; artifacts to obtain approval to deploy in the future.*

---

## E7.0 What this epic actually has to produce

AC7's output is not a test result. It is a **compliance package** — an evidence pack and a mapping to EA/CR standards that will support an approval decision for future deployment. The prototype cannot write the package in final form because the ARB template (1694-G2) and the EA/CR standards themselves have not been supplied. What it can do, and what this epic therefore must do, is assemble everything the template will need: the evidence records from all other epics, a mapping of the design against the (as-yet-unknown) EA standard clauses, a residual-risk statement that does not hide or minimize, and a faithful artifact index. When the template arrives, applying it is then a matter of inserting the pieces rather than a rewrite.

The single most important work here is **scope discipline**. Per docs/12 §12.3 (recounted 2026-10-18), 15 of 25 tests are conclusive locally — 14 BUILD plus 1 REBUILD — 7 are partial with named gaps, 2 are probes, **none are stand-ins**, and 1 needs a partner. The direction of that change matters for how this epic writes: the package is stronger than first assessed, and the honest statement is now a short list of specific capability limits rather than a broad disclaimer about absent counterparties. An ARB package that claims coverage it does not have is worse than one that states the gaps — and the converse also holds, so a package that under-claims coverage it genuinely has is a disservice to the approval decision. Every ARB justification claim in §6 of the CONOPS must be either backed by an evidence record or explicitly downgraded — no claims without evidence, and no silence about what the local build cannot prove.

Three additional facts that shape the work:

**First, this epic is blocked on 1694-G2.** The checkpoint at 10/22 for "applying the ARB template" has already passed (it is now 10/18) with no template in hand. The honest position: we cannot apply a template that does not exist. What we can do is build a template-agnostic artifact index and claims register, so that when the real template lands, filling it is mechanical.

**Second, the local environment cannot fully prove three of the Section 6 principles**: Infrastructure decoupling (blocker B-1; the edge currently returns 404), Read-only by construction (T-21 passes but its secret-scan half currently fails on mode-664 files; Task 1.1 of E1 fixes this), and Token misuse risk reduction (R4 residual risk; strengthened by working recipient IP access lists but not eliminated). These must be stated honestly in the ARB package rather than claimed without qualification.

**Third, the prototype has revealed four document defects** (docs/10 §10.7) that the ARB package must carry rather than hide: D-1 (masks and row filters are refused on OpenSharing-shared tables, so AC1's granular-access claim cannot be met as written); D-2 (T-04 as built proves nothing, fixed by E1 Task 1.7); D-3 (recipient IP access lists DO work, so R4/R7 mitigations are stronger than documented); D-4 (the F1 storage-proxy edge path contradiction in CONOPS §2.3.2). The ARB is the place to carry them.

---

## E7.1 Task list

Each task is independently verifiable and ordered so dependencies between epics are explicit. **PARTNER** and **DEFERRED** tasks are not skipped — they produce a written gap with an owner.

### Task 7.1 — Build the claims and evidence register

The CONOPS §6 names seven principles and asserts them without proof. This task builds a table mapping each principle to the test evidence that supports it, and marking each piece of evidence as conclusive, partial, probe, standin or partner-dependent. The output is a register that will fill the evidence-mapping section of the ARB package.

The seven principles are: (1) No provider-side replication, (2) Infrastructure decoupling, (3) Read-only by construction, (4) Least privilege on ingress, (5) Token misuse risk reduction, (6) Layered enforcement, (7) Tested, not asserted.

**Deliverable:** `docs/epics/E7-claims-and-evidence-register.md` with the seven principles and for each one: the verbatim principle text from §6, the evidence test IDs that support it (T-01, T-02, T-03, etc.), the local verdict for each test (BUILD, REBUILD, PARTIAL, PROBE, STANDIN, PARTNER), and a one-line statement of what is proven and what is not. Do not invent evidence; map only to tests that exist in the test matrix. For principle (2), state plainly that blocker B-1 leaves Infrastructure decoupling unproven locally.

**Verify:** every one of the seven principles has at least one evidence mapping; no principle claims full proof if any of its supporting tests are PARTIAL, PROBE, STANDIN or PARTNER; the register is accurate against §12 of docs/12.

### Task 7.2 — Build the artifact index

AC7 requires an artifact checklist. The CONOPS §3.7 table lists eleven artifacts; this epic owns the master index that tracks their status as other epics complete.

**Deliverable:** `docs/epics/E7-artifact-index.md` with a table: Artifact / Source / Owner / Status / Evidence reference. Sources are CONOPS sections and epic playbook tasks. Owners are teams (AI/ML Ops, Data Governance, Data Eng, Data Tooling). Status values are: Draft, Planned, In Progress, Ready for Review, Complete. Evidence references point to the artifact location, the test evidence backing it, or the decision/risk document where the gap is noted.

The eleven artifacts:
1. CONOPS (This document, AI/ML Ops, Draft v1.5)
2. Architecture and data-flow diagrams (Figures 1 to 3 and architecture diagram package, AI/ML Ops, Draft)
3. Interface and route inventory (§2.3.2 and §2.4.5, AI/ML Ops + Data Tooling, Draft)
4. Security control mapping to the EA standard (§2, §3.1, §3.2, §6, AI/ML Ops + Data Governance, Needs the standard)
5. UC access matrix (§3.1, Data Governance, Draft)
6. DSA references and templates (§3.3, Data Governance, Owner drafts)
7. Test evidence pack (§5, recorded session, AI/ML Ops, Planned)
8. IaC repository and deployment record (§3.6, Data Eng, Planned)
9. Logging, monitoring and sustainment requirements (§3.5 and §3.6, Data Tooling + Data Eng, Planned)
10. Risk register with residual risks (§9.3, AI/ML Ops, Draft)
11. Change Request package using the ARB template (§6, AI/ML Ops + Data Governance, Planned)

**Verify:** all eleven artifacts appear exactly once; every entry has an owner and a status; the index can be built now without the template, and filled as epics complete.

### Task 7.3 — Build the control-to-EA mapping table (template-agnostic)

Data Governance will supply the EA standard clauses. When they arrive, this epic must map the design's security controls to them. Since the standard is not yet known, build the control inventory now: every control mentioned in CONOPS §2, §3 and §6, with its mechanism, its CONOPS section, and empty slots for the EA clause number and CR section number once the standards arrive.

**Deliverable:** `docs/epics/E7-control-inventory.md` with a table: Control / Mechanism / CONOPS section / EA clause (TBD) / CR section (TBD) / Evidence test. Controls include: recipient IP access list, Unity Catalog entitlements, view-based column and row scope, token lifetime and rotation, share isolation, gateway rate limiting and schema validation, read-only enforcement on egress, write-only isolation on ingress, logging and correlation ID tagging, data residency and encryption at rest (if mentioned). Fill the first four columns now; leave EA and CR columns empty for Data Governance to fill.

**Deliverable:** brief prose guidance on how to use this table once the standards arrive: map each EA clause to one or more controls; verify that every clause has evidence; and then populate CR section numbers as the change request is structured.

**Verify:** every security mechanism mentioned in CONOPS §6's seven principles has a row; the table is self-contained and does not require the ARB template to be useful.

### Task 7.4 — Assemble the residual-risk statement

The CONOPS §9.3 risk register lists fourteen risks. Three of them carry residual risk that the ARB must accept: R2 (gateway does not cover the data plane; Databricks-managed storage cannot be restricted here, so a valid token plus storage reachability is a real bypass; docs/13 §13.4 confirms it), R4 (static bearer token theft; mitigated but not eliminated by address binding and lifetime controls; docs/13 confirms recipient IP lists work, making this risk materially lower than designed but still residual), R14 (**largely retired on 2026-10-18** — both ingress channels now have real providers, so what the ARB is asked to accept is no longer "ingress was never exercised" but the narrower point that the outbound host list captured locally does not transfer to the client environment; the *method* of capture is what the package evidences).

**Deliverable:** `docs/epics/E7-residual-risks.md` with a table: Risk ID / Risk statement / Mitigation in this design / Local proof / Residual risk statement / ARB action. Rows for R2, R4, R14. The residual risk statement must be specific: not "accepted" or "noted", but "this control works here" (R4's IP list, per 11.3), "this cannot be proven locally" (R2's storage-side refusal, per docs/12 T-08), and for R14 **not** "this depends on an external party" — that framing expired on 2026-10-18 — but "ingress was exercised end to end against real providers on both channels; what does not transfer is the captured outbound host list, so the evidence is the capture procedure" (per docs/13 A10, now confirmed). Each row cites its evidence and acknowledges where the prototype cannot prove the mitigation.

**Verify:** the ARB reviewer can read this statement and understand exactly what has been proven, what cannot be proven locally, and what decision to make. No claims without evidence, and no silence about gaps.

### Task 7.5 — Assemble the defect log

CONOPS v1.5 contains four document defects discovered during the prototype build (docs/10 §10.7). These must be carried in the ARB package so the next revision can correct them. The defects are not design failures; they are cases where the document promises something that the platform does not support, or contradicts itself.

**Deliverable:** `docs/epics/E7-document-defects.md` with a table: Defect ID / CONOPS clause / What the CONOPS says / What is actually true / Evidence / Consequence. Rows for D-1 (masks/filters refused on OpenSharing tables), D-2 (T-04 invalid), D-3 (recipient IP lists work, contradicting the README), D-4 (F1 storage-proxy path contradiction). Each defect cites the evidence section where it was discovered and what the CONOPS revision needs to say instead.

**Verify:** the ARB reviewer understands that these are not hidden problems but documented findings that the ARB needs to account for in its approval scope.

### Task 7.6 — Decision OD-11: view-based granular access

Finding D-1 (Task 7.5) forces a design choice the CONOPS never considered, because it assumed both options were available. The CONOPS §3.1 promises granular access by "a view, **or** column masks and row filters". The masks and filters option does not exist on OpenSharing tables. Therefore, **every entitlement scope — column and row — must be expressed as a view**, the base table is never added to a share, and §3.1 / §2.3.1 / §3.4 need correction in v1.6.

This is not a design failing; views are a standard pattern and they work locally (docs/11 §11.4, §11.3). But it is a decision the CONOPS did not explicitly make, and it must be stated as such.

**Deliverable:** a dated memo recording the decision: owner (AI/ML Ops + Data Governance), effective date (10/18, the date the mask/filter error was discovered), evidence (docs/11 §11.4), scope (all entitlement views in the Databricks IaC, §3.1 / §2.3.1 / §3.4 in the next CONOPS revision). File it in `docs/13-decisions-and-risks.md` as OD-11, to be added to the open decisions table in the next revision.

**Verify:** OD-11 is dated and linked in the ARB package so the approver knows it is a recent discovery, not an original design choice.

### Task 7.7 — Section 4 IL5 documentation package

CONOPS §4 describes the "Dual-Environment Strategy (IL2 Baseline, IL5 Future Readiness)". The IL5 column of the table is explicitly documentation-for-the-future and not part of this IL2 build. However, it is ARB material because it shows the growth path and the decisions the ARB is deferring.

**Deliverable:** `docs/epics/E7-il5-future-readiness.md` with a summary of §4's IL5 column: network boundary, identity and authentication, gateway enforcement, storage access, ingress. State that these are requirements the ARB must review for future deployment but that are **not** being tested or built now. Cite CONOPS §4 as the source. This is not a gap or a defect; it is an explicit scope boundary.

**Verify:** the ARB reviewer can see the full technical scope the design is prepared for, even though only the IL2 column is being deployed now.

### Task 7.8 — Assemble the test evidence pack (DEFERRED)

AC7's verification method is review of the ARB packages. The packages need test evidence from all other epics. This task cannot finish until E1, E2, E4, E5 and E6 have produced their evidence records.

**Deliverable:** `evidence/arb-test-evidence-pack.json` (or multiple files, one per epic) with every test result from the test matrix (§5.2 of the CONOPS), including all metadata: test ID, expected result, actual result, timestamp, evidence reference, notes. One record per test, in test-ID order. Include tests marked NOT_RUN, PARTIAL, PROBE, STANDIN with their reasons. No tokens, credential files or data — metadata and decision information only.

**Deliverable:** `docs/epics/E7-test-evidence-cross-reference.md` with a table: Test ID / AC / Epic / Local verdict / Evidence file / Status. Cross-reference the evidence pack to the test matrix so the ARB reviewer can navigate from the principles (§6) to the tests (§5.2) to the evidence.

**Verify:** DEFERRED until all tests are run. Mark as **PARTNER** work owned by: E1 (T-01, T-02, T-04, T-21), E2 (T-03, T-05, T-06, T-07), E4 (T-09, T-17, T-22), E5 (T-10, T-21, T-22), E6 (T-12). Tests marked NOT_RUN or BLOCKED are included, not omitted.

### Task 7.9 — Assemble the IaC artifact bundle (PARTNER)

Data Eng and E6 own the IaC deployment record and the versioned Terraform/CaC files. This epic catalogs what they produce.

**Deliverable:** `docs/epics/E7-iac-artifact-manifest.md` citing the sources in the `iac/` tree: Terraform for Databricks objects, JSON definitions for Gravitee, CaC files for policy classes and allow-lists. Index them by CONOPS section (channel definitions §2.1, route table §2.3.2, token policy §3.1.1, ingress hosts §2.4.3, logging §3.5, deployment §3.6). Each entry: IaC file path, what it creates, CONOPS section, deploy verification step.

**Verify:** PARTNER work. E6 provides the files; E7 indexes them. The manifest is complete and deployable from the list without consulting the playbooks.

### Task 7.10 — Final compliance review checklist

Days before the ARB review, AI/ML Ops and Data Governance run through a checklist to ensure nothing was missed: evidence pack complete, all test results linked, all defects acknowledged, all residual risks stated, all open decisions called out, the control-to-EA mapping filled in, and the artifact index current.

**Deliverable:** `docs/epics/E7-arb-readiness-checklist.md` with a markdown checklist: claims register has all seven principles [ ], each principle has evidence [ ], all partial/probe/standin/partner tests have gap statements [ ], residual risks (R2, R4, R14) are stated [ ], document defects (D-1 through D-4) are carried [ ], OD-5 status is disclosed [ ], OD-11 is recorded [ ], IL5 future-readiness is documented [ ], all eleven artifacts have status [ ], test evidence pack is present [ ], IaC manifest is current [ ], EA/CR standard mapping is populated [ ], template application date is set [ ]. Run it once a week starting week 5 (11/5) so gaps surface early.

**Verify:** the checklist runs green. If any item fails, the gap is raised as an ask to the owner, dated and tracked.

---

## E7.2 IaC and CaC deliverables

AC7 is a compliance documentation epic, not an infrastructure epic. This epic produces **documents and registers**, not code or infrastructure:

- Claims and evidence register (Task 7.1)
- Artifact index (Task 7.2)
- Control-to-EA mapping table (Task 7.3)
- Residual-risk statement (Task 7.4)
- Document defects log (Task 7.5)
- Recorded decision OD-11 (Task 7.6)
- IL5 future-readiness documentation (Task 7.7)
- Test evidence pack and cross-reference (Task 7.8)
- IaC artifact manifest (Task 7.9)
- ARB readiness checklist (Task 7.10)

There is no infrastructure code here because the design's infrastructure is owned by E1 through E6. This epic's role is to **assemble and index** what those epics produce, map it against unknown EA/CR standards, and present it for review.

---

## E7.3 Tests owned or co-owned

AC7 is verified by **review**, not by test. The CONOPS §1.5 (Acceptance Criteria Map) explicitly lists AC7's verification method as "Review (ARB packages)". There are no test IDs.

The evidence backing each of the seven Section 6 principles comes from other epics' tests. The claims and evidence register (Task 7.1) maps each principle to its test evidence:

| Principle | Supporting tests | Local verdict | Gap |
|---|---|---|---|
| No provider-side replication | T-01 (read through gateway), T-04 (base table unreachable) | BUILD | — |
| Infrastructure decoupling | T-02 (refusal at Databricks), T-03 (IP-filtering) | BUILD; partly proven already | Gateway proxies the open protocol correctly (§11.7, B-1 reclassified 10/18); full proof once E2 Task 2.1 consolidates the two API definitions |
| Read-only by construction | T-21 (write refused) | BUILD; secret-scan half fails locally | E1 Task 1.1 fixes mode-664 files |
| Least privilege on ingress | T-20 (outbound allow-list), T-24 (ingress refusals) | **BUILD** + PARTIAL | T-20 reclassified 10/18 — a real open-protocol provider, so the allow-list is capture-derived rather than assumed; T-24 still missing a service principal, though its six refusals are provable |
| Token misuse risk reduction | T-02 (IP access list), T-10 (token rotation) | BUILD + verified at 11.3 | Residual risk R4 remains; mitigated stronger than documented |
| Layered enforcement | T-03 (gateway), T-04 (UC enforcement), T-21 (read-only) | BUILD | — |
| Tested, not asserted | All of the above; T-01 through T-25 collectively | 16 conclusive, 7 partial, 1 probe, 0 standin, 1 partner (recounted 2026-10-18, after the T-15 and T-19 probes passed) | Gaps stated in each category; no silent failures. The one partner is T-13 (PSP7), which is the only test that cannot be run honestly without a second organisation |

The output is not a test result. The output is an **evidence map** that the ARB reviewer can use to trace each principle to the test or tests that support it, and to see immediately which ones are fully proven locally and which carry stated gaps.

---

## E7.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the following hold:

The claims and evidence register maps all seven Section 6 principles to test evidence, with local verdicts (conclusive, partial, probe, standin, partner) and honest gap statements. The artifact index lists all eleven artifacts with owner, source, status and evidence reference. The control-to-EA mapping table is built and ready for the standards to arrive; the EA and CR columns will be filled by Data Governance but the control inventory is complete. The residual-risk statement covers R2, R4 and R14 with local proof for what is proven and named gaps for what cannot be proven here. The document defects log carries all four defects (D-1, D-2, D-3, D-4) with evidence and consequence. Decision OD-11 is recorded, dated and referenced. The IL5 future-readiness documentation is written. The test evidence pack is assembled from all other epics, with tests marked NOT_RUN including their reason. The IaC manifest indexes what Data Eng produces. The ARB readiness checklist is in place and runs green. When the 1694-G2 template arrives, the gaps between the template structure and this evidence pack are bridged by a straightforward mapping, not by a rewrite. The package is review-ready for Data Governance and the ARB by 11/20.

---

## E7.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| 1694-G2 ARB template | Data Governance supplies the shared template structure | 13.7; blocks applying the template |
| EA and CR standards themselves | Data Governance supplies the standard clause lists | 13.7; required for control mapping |
| Final compliance review | Data Governance performs the ARB review | 13.3 ask 1; gates the approval |
| Test evidence pack completion | All other epics (E1, E2, E4, E5, E6) complete their tests | 12.2, 12.3. **Shorter than first assessed**: T-20 and T-23 became BUILD on 10/18 and T-19 moved to a local probe, so the irreducible set is T-08 (storage-side refusal on Databricks-managed storage), T-24's upload half (service principal, scanning owner) and T-11/T-25 (the 1694-E4 join key). **T-15/T-16 left this list on 10/18** — they were listed as tier capability, and the tier turned out to have the capability; only invocation is open and that is testable here. Two of the five irreducible items dissolved in one day, which is itself worth stating in the package: this register distinguishes *tested and unavailable* from *assumed unavailable*, and the second category has repeatedly proved wrong |
| Full Infrastructure decoupling proof | E2 Task 2.1 consolidates the two API definitions onto the issued credential endpoint | 11.7 (B-1 reclassified, not a broken gateway); the principle is partly proven already |
| E1 Task 1.1 completion (Read-only secret-scan proof) | E1 fixes mode-664 secret files | 11.7; unblocks T-21's full pass |
| Data Eng IaC deployment record | Data Eng provides the versioned IaC history and deployment log | 13.7; E7 indexes it |
| Data Tooling logging requirements implementation | Data Tooling configures Elasticsearch and custom headers | 13.7; E7 documents the requirement |

Each of these should leave the epic as a dated ask or a dependency note, not as silence.
