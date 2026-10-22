# E3 — 1227-E3: Data Governance Policies / Sharing Agreements (DSA) (AC3)

| | |
|---|---|
| **Epic** | 1227-E3 |
| **Acceptance criterion** | AC3 — Data Governance: data sharing policies/agreements considerations that streamline a user's ability to serve and consume WDP data externally |
| **CONOPS sections** | 3.3, 7, 10; lifecycle 2.5, landing/revocation 2.4.4 |
| **Stories** | 1: DSA input from Data Governance (§3.3) · 2: Integrate into CONOPS (§3.3) · 3: Review-ready check (§7, §10) |
| **Role** | Integrate — Data Governance owns the DSA instrument and templates; AI/ML Ops integrates its considerations into the CONOPS and maps each to a technical control |
| **Target dates** | 10/8 – 11/5 · checkpoints **10/20** DSA section drafted, **10/26** reviewed with Data Governance, **10/28** final, **11/5** sign-off request |
| **Depends on** | 1694-G1 (UC access model inputs), also carries OD-5 (bearer-token sign-in decision, **Open**, owned by Data Governance) and OD-11 (new, view-based granular access) |
| **Tests** | T-10 (token rotation, revoke), T-19 (D2D ingress, partner-dependent), T-22 (land good/bad-schema/empty loads, validation/quarantine), T-23 (rotate provider credential, drop catalog and provider, partner-dependent) |
| **Decisions in play** | OD-5 (**Open**, gates token lifetime/rotation/revocation/approver), OD-6 (**Proposed**, Data Governance and ARB confirm), OD-9 (**Open**, content scanning owner), **OD-11 (new, proposed)** — granular access is view-based, not masks/filters |
| **Risks in play** | R1 (1694-G1 not confirmed), R13 (ADVANASD-814427 and AWOZ-1361 details not incorporated) |

> **The criterion, verbatim (CONOPS §3.3):** *Data Governance: data sharing policies/agreements considerations that streamline a user's ability to serve and consume WDP data externally.*

---

## E3.0 What this epic actually has to produce

AC3 is not about authoring a Data Sharing Agreement. That is Data Governance's job, and it sits outside a laptop prototype. AC3 is about integrating the **shape** of a DSA into the platform so that:

1. Every DSA clause maps to a technical control the platform enforces.
2. A user requesting access fits their request into pre-approved templates, not custom agreements.
3. The DSA reference itself rides on every artifact — recipient, share, view, landed table — so it is auditable forever.

The prototype cannot write the agreement, but it **can** build the control-mapping scaffolding, the tier-and-template data structures, the DSA-reference plumbing, and the enforcement points. It can also capture what Data Governance must supply so the real platform knows what to wait for.

The heart of this work is **Task 3.2**: the seven DSA considerations (purpose limitation, permitted consumers/providers, handling, retention, revocation, audit, incident) are mapped to technical controls in §3.3 (CONOPS), and this epic materializes each mapping in code, config and tests. The DSA reference itself becomes a `COMMENT` on every recipient, share, view and landed table — this is the one genuinely enforceable control a prototype can build and test.

---

## E3.1 Task list

Each task is independently verifiable. Run them in order. **PARTNER** or **DEFERRED** tasks are not skipped — they produce a written gap with an owner.

### Task 3.1 — Understand the DSA surface and the streamlining proposal

Read CONOPS §3.3 in full, including the seven-row table mapping DSA considerations to technical controls. The streamlining proposal (last paragraph of §3.3) says: pre-approved templates per data tier and direction; one review and approval triggers automated issuance; only out-of-template requests follow the full process.

Document locally what Data Governance must supply so this can work: the DSA templates themselves (the legal agreements, one per tier per direction), the tier list (how is "PII", "Confidential", etc. defined), the approver roles and review time targets. Record these as **inputs required** rather than as gaps — we know what to ask for.

**Deliverable:** a one-page summary in `docs/epics/E3-streamlining-inputs.md` listing template names, tier labels and approver roles needed from Data Governance, with a note that the templates are owned by Data Governance and not built here.

**Verify:** E3.2 can cite this document and say "these are the things we asked for".

### Task 3.2 — Map DSA considerations to technical controls and build the governance inventory

This is the spine of the epic. CONOPS §3.3 lists seven DSA considerations and maps each to a technical control and a CONOPS section. Build a Terraform + config set that makes each mapping real in the prototype.

Create `iac/config/dsa-tiers.yaml` with a tier definition structure:

```yaml
dsa-tiers:
  - name: public
    label: "Public / No restriction"
    purpose_control: "share_isolation"
    consumers_control: "recipient_list"
    retention_days: 90
    revocation_control: "recipient_drop"

  - name: confidential
    label: "Confidential / Restricted"
    purpose_control: "share_isolation"
    consumers_control: "recipient_list_plus_ip_allow"
    retention_days: 30
    revocation_control: "recipient_drop_plus_vault"
```

Create `iac/config/governance-inventory.yaml` as the master ledger of every provider, share, catalog, owner, tier, DSA reference, review date and (for D2O) credential expiry. Every share creation task updates this inventory. This becomes the operational registry for the §5.3 client verification session and for audits.

Create Terraform in `iac/databricks/` that attaches the DSA reference as a `COMMENT` to every share, recipient, view and (in E4) every landed table. The `COMMENT` must carry both the DSA identifier and the tier, so a reader knows immediately what governance applies.

**Deliverable:** `iac/config/dsa-tiers.yaml`, `iac/config/governance-inventory.yaml`, and Terraform that writes DSA/tier comments on shares, recipients and views.

**Verify:** every share in the workspace has a `COMMENT` containing its DSA reference and tier; `DESCRIBE RECIPIENT` echoes a DSA comment; every view has a comment with format `"DSA: <id>, tier: <tier>"`.

### Task 3.3 — Build the credential rotation and revocation pattern

OD-5 decides token lifetime, rotation schedule and revocation triggers — it is **Open** and owned by Data Governance. This task builds **both branches** of OD-5 (bearer token and OIDC federation) far enough that the decision becomes a substitution rather than a redesign.

Bearer token branch (the branch Free Edition supports and the one every reference client in §2.3.4 sends): a recipient holds at most two tokens (active plus rotated); a token is valid at most one year; the activation link yields a credential file once; rotating before use replaces the link; revocation removes the token from the vault.

Create `iac/config/token-policy.yaml` with values that OD-5 will fill in: `max_tokens_per_recipient`, `token_lifetime_days`, `overlap_days`, `revocation_triggers`. Mark it as `status: proposed, awaiting OD-5`.

Create Terraform in `iac/databricks/recipients.tf` that creates recipients with the two-token constraint baked in: use SDK calls to list tokens on each recipient, assert count ≤ 2, and document the code point where a third token would be refused by the platform itself.

For the OIDC federation branch: add a comment block in the Terraform showing what the OIDC issuer, client ID, and scope claims would be, using the OAuth 2.0 Client Credentials flow that CONOPS §3.1.1 would require.

**Deliverable:** `iac/config/token-policy.yaml` (bearer branch filled in, OIDC branch as a template); Terraform assertions in `recipients.tf` enforcing the two-token maximum; comments describing the OIDC branch; T-10 test code for token rotation and revocation.

**Verify:** a second token on a recipient is creatable and readable; a third token fails; rotating a recipient updates its credential file link and the old token remains valid for the overlap period; revoking removes the token from the vault and subsequent calls with it are refused.

### Task 3.4 — T-22 and T-23: landing with tier/owner/DSA tags

**T-22 (Ingress D2O, landing and validation) — BUILD.** A job reads from a remote D2O provider catalog, validates the schema against the agreed contract, and lands the table in the local workspace with validation checks. CONOPS §2.4.4 lists the checks: columns and types match, row count is above zero and within tolerance, freshness is acceptable. Every landed table carries tags: `dsa_ref`, `data_tier`, `data_owner`, `load_time`, `table_version`.

Create `iac/databricks/ingress-landing.tf` that defines a landing schema, landing jobs and validation rules. Create `scripts/22_land_table.py` that reads a share, validates, lands, and tags the table. Create a quarantine flow: if validation fails, move the load to a quarantine table and raise a ticket.

**T-23 (Provider credential rotation and revocation) — BUILD** (reclassified from STANDIN on 2026-10-18). The open-source OpenSharing server is a real provider whose token configuration this operator controls, so rotation is a genuine provider-side action rather than a simulation: issue a replacement token, overlap it with the old one, let the old one expire, and observe what the recipient side does across the boundary. That last part is the reason this matters more than its single row suggests — credential rotation with overlap is the control a DSA reviewer asks about first, and until now it could only be described.

Create `scripts/23_rotate_revoke_provider.py` showing the full cycle: new credential to the vault, provider object updated, old credential expiring after the overlap window, then the catalog and provider dropped with the DSA retention rule applied to any landed copies. Exercise the two halves under their proper hats and say so in the evidence record — the provider hat issues and expires the token, the credential custodian hat vaults the replacement, and neither is the data owner.

Record one behaviour that only a live rotation reveals: whether an in-flight read survives the old token's expiry or fails mid-query. The CONOPS specifies an overlap period but not what happens to work already running, and that is exactly the kind of detail v1.6 can carry because this exercise produced it.

**Deliverable:** landing schema and job Terraform, `scripts/22_land_table.py`, validation/quarantine logic, T-22 test evidence; `scripts/23_rotate_revoke_provider.py` runnable end to end; evidence records for both tests.

**Verify:** T-22: a good load lands with correct tags; a bad-schema load lands in quarantine with a ticket; an empty load is rejected. T-23: all three phases observed against the live provider — rotate, overlap, drop — with the overlap window's effect on an in-flight read recorded rather than assumed.

### Task 3.5 — Review and finalize the §3.3 integration section

Checkpoint **10/26**: Review-ready with Data Governance. Take the control mappings from Task 3.2, the token policy from Task 3.3, the landing and revocation work from Task 3.4, and write a coherent CONOPS §3.3 integration section that says:

1. Here are the seven DSA considerations (table, copied from CONOPS).
2. Here is how each maps to a technical control the platform enforces.
3. Here is the streaming proposal: templates, tiers, approver roles, review time.
4. Here are the inputs we asked Data Governance for (from Task 3.1).
5. Here are the checkpoints: 10/28 final, 11/5 sign-off.

This is **not** the DSA itself — that is owned by Data Governance. This is the integration that says "when Data Governance gives us the templates and tier definitions, we will automatically enforce these controls."

**Deliverable:** `docs/epics/E3-integration-section.md` ready for §3.3 revision in CONOPS v1.6.

**Verify:** every AC3 clause traces to either a completed control or a named input from Data Governance.

### Task 3.6 — Handle OD-5 as an open decision with both branches built

OD-5 (sign-in method, token lifetime, rotation, revocation, approver) is **Open** and gates the 10/23 checkpoint. This task does **not** decide it — that is Data Governance's role. This task builds both branches far enough that the decision is now a one-line Terraform change.

Bearer-token branch: already in Task 3.3, fully buildable and tested on Free Edition.

OIDC federation branch: in Task 3.3 as a Terraform template showing the client ID, issuer, and scope claims needed, and a code comment explaining where the substitution would go.

Produce a document `docs/epics/E3-OD5-both-branches.md` that says: "If Data Governance chooses bearer token, we activate branch A (values already in `token-policy.yaml`). If OIDC, we activate branch B (Terraform template at line XYZ of `recipients.tf`). The infrastructure is ready for either. Data Governance's decision is a commit, not a redesign."

**Deliverable:** `docs/epics/E3-OD5-both-branches.md` with both branches buildable and the cost of deciding stated.

**Verify:** a reader can see that the prototype is not waiting for OD-5 to be decided — both paths are built and ready.

### Task 3.7 — Confirm OD-11 and update the view-based entitlement rule

OD-11 is new (proposed by this prototype, evidence in docs/11-environment-baseline.md §11.4). It says: **granular access on shared data is view-based only. Column masks and row filters are refused on any table in an OpenSharing share, at every tier.** This finding corrects CONOPS §3.1, §2.3.1 and §3.4.

This epic depends on the E1 finding, so Task 3.7 is a read-through and acceptance task, not a build task. Read 11.4 in full. Understand that the DSA-driven "handling and downstream use" control (Task 3.2's mapping) now rests on a **view** per entitled purpose, not on masks and filters that do not exist.

Update `docs/epics/E3-integration-section.md` (from Task 3.5) to state: "The 'handling and downstream use' control is enforced by sharing a view that selects only the entitled columns (and, with a `WHERE` clause, only the entitled rows). The base table is never added to a share. See §11.4 for the technical finding that makes this necessary."

**Deliverable:** acceptance of OD-11 in the integration section; a note that CONOPS v1.6 must strike the "or apply column masks and row filters" language from §3.1, §2.3.1 and §3.4.

**Verify:** the integration section correctly describes the view-based pattern and cites the evidence.

### Task 3.8 — Sign-off and close

Checkpoint **11/5**: sign-off request for 1227-E3. Pull together:

- Task 3.1 inputs summary
- Task 3.2 control mappings and governance inventory
- Task 3.3 token policy and rotation/revocation tests
- Task 3.4 landing and validation tests
- Task 3.5 integration section (ready for CONOPS v1.6)
- Task 3.6 OD-5 both-branches document
- Task 3.7 OD-11 acceptance

Assemble a **Story 3 review-ready document**: `docs/epics/E3-arb-package.md` that says:

1. What Data Governance must supply (inputs summary).
2. What the prototype built (control mappings, tier/template scaffolding, DSA-reference plumbing).
3. What it cannot deliver (the DSA agreements themselves, owned by Data Governance).
4. What depends on what (OD-5, OD-11, 1694-G1).
5. The evidence for T-10, T-22 and T-23 — all three now conclusive, T-23 having moved from STANDIN to BUILD on 2026-10-18 once a real provider existed. T-19 is the only AC3 test still gated, and only on the two Epic 1 Task 1.2 capability probes rather than on a partner.

State explicitly: "This epic does **not** deliver the Data Sharing Agreement. It delivers the governance-control mapping, the platform enforcement points, and the data structures that will carry DSA references forever. Data Governance owns the agreement; AI/ML Ops owns the technical implementation of its clauses."

**Deliverable:** `docs/epics/E3-arb-package.md` with all gaps and dependencies stated.

**Verify:** every AC3 clause traces to evidence or to a named input awaiting Data Governance; no clause traces to a gap that is hidden.

---

## E3.2 IaC and CaC deliverables

| Path | Contents |
|---|---|
| `iac/config/dsa-tiers.yaml` | Data tier definitions (purpose, consumers, retention, revocation controls) |
| `iac/config/token-policy.yaml` | Token lifetime, rotation, overlap, revocation triggers — values pending OD-5 |
| `iac/config/governance-inventory.yaml` | Master ledger: provider, share, catalog, owner, tier, DSA reference, review date, credential expiry for D2O |
| `iac/databricks/recipients.tf` | Recipients with DSA comments and two-token constraint assertion |
| `iac/databricks/shares.tf` | Shares with DSA/tier comments |
| `iac/databricks/views.tf` | Views with DSA/tier comments (from E1, updated for governance tag) |
| `iac/databricks/ingress-landing.tf` | Landing schema, jobs, validation rules, quarantine flow |
| `docs/epics/E3-streamlining-inputs.md` | What Data Governance must supply (templates, tiers, approvers, review time) |
| `docs/epics/E3-OD5-both-branches.md` | Bearer token and OIDC federation branches, both built and ready |
| `docs/epics/E3-integration-section.md` | CONOPS §3.3 integration section, ready for v1.6 revision |

Secrets appear in none of these, only as vault or `.env` references (§3.6).

---

## E3.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-10 | BUILD | E3 | Token rotation (two-token max, overlap) and revocation; carrier tests for AC3 |
| T-19 | **BUILD** (probes passed 10/18) | E1 | D2D ingress; the second-account metastore `8875961b-…` supplies the far side. Both Task 1.2 probes passed: distinct metastores, and a `DATABRICKS`-auth recipient accepted. E3 owns the DSA/lifecycle part |
| T-22 | BUILD | E3 | Landing with validation, quarantine, tier/owner/DSA tags; schema and row-count checks |
| T-23 | BUILD | E3 | Provider credential rotation and revocation, against the live open-source provider |

---

## E3.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the following hold:

Data Governance has supplied (or the absence has been formally noted with a date) the DSA templates, the tier list, the approver roles and review time targets. The control mappings from §3.3 are implemented in code: shares, recipients and views carry DSA comments; the governance inventory is versioned and current; the token-policy config is filled for the bearer-token branch and templated for OIDC. T-10 passes with evidence of rotation and revocation. T-22 passes with good loads landing correctly and bad/empty loads quarantined. T-23 passes against the live open-source provider, with all three lifecycle phases (rotate, overlap, drop) observed and the overlap window's effect on an in-flight read recorded. OD-5 is addressed as an open decision with both branches buildable and the cost of deciding stated clearly. OD-11 is accepted, and the integration section correctly describes the view-based granular-access pattern. The §3.3 integration section is review-ready with Data Governance and ready for CONOPS v1.6 incorporation. Every AC3 clause (purpose limitation, permitted consumers/providers, handling, retention, revocation, audit, incident) traces to a technical control or to a named input awaiting Data Governance, never to silence.

---

## E3.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| The Data Sharing Agreement itself | Data Governance authorship and legal review | Owned by Data Governance, sits outside the prototype |
| OD-5 decision (token lifetime, rotation, revocation, approver, sign-in method) | Data Governance decision | 13.2; gates the 10/23 package; both branches are built here |
| 1694-G1 UC access model inputs | Data Governance input | Assumption A1; access matrix stays provisional (E1) |
| ~~T-19 D2D ingress~~ | ~~A second metastore or an external provider~~ — **self-served and confirmed 2026-10-18**: a second account yields a distinct metastore and the tier accepts a `DATABRICKS`-auth recipient. No probe outstanding | A10 confirmed, R14 retired |
| ~~T-23 provider rotation against a real provider~~ | ~~T-20 stand-in provider (D2O) or external D2D provider~~ — **self-served**; we own the OSS provider and can rotate its token on demand | Now BUILD, no external party |
| ADVANASD-814427 and AWOZ-1361 incorporation | Binod and Data Governance | R13; requested by 10/23 |

Each of these should leave the epic as a dated ask, not as an empty cell in the ARB package.
