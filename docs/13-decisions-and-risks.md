# 13. Decisions, Risks, Assumptions and Dependencies

Source: CONOPS AWOZ-1227 v1.5 **§9** (9.1 assumptions, 9.2 dependencies,
9.3 risk register, 9.4 decisions). This document adds, for each item,
what the prototype can actually settle and what it cannot — so that a
governance decision is never mistaken for an engineering one, and an
engineering unknown is never left waiting on a meeting.

---

## 13.1 Open decisions (OD-1 … OD-10)

### Status summary

Three of ten decisions are **Decided** (all on 10/12). Three are
**Proposed**. **Four remain Open**, and one of those gates a checkpoint
that is five days away.

| ID | Decision | CONOPS status | Owner / forum | Can the prototype settle it? |
|---|---|---|---|---|
| OD-1 | Data-plane control: proxy storage URLs through the gateway (option b) | Decided 10/12; proven in T-08, fallback recorded | AI/ML Ops + Data Tooling | **Partly.** The proxy forward is testable; the direct-storage refusal is not, because Free Edition storage is Databricks-managed. We can prove half and record the fallback. |
| OD-2 | Models and volumes stay conditional on tenant support | Decided 10/12 | AI/ML Ops | **Yes, informatively.** The Epic 1 probe tells us what this tenant supports, which is one data point toward the condition. |
| OD-3 | AWS with Unity Catalog E2; IL2 commercial, IL5 GovCloud | Decided 10/12; Gov region to confirm | AI/ML Ops | **No.** Gov region availability is unknowable from here. |
| OD-4 | Credential file issuance with endpoint rewrite (§3.4.1) | **Proposed**; confirm and test | Data Eng + AI/ML Ops | **Yes — this is the prototype's strongest contribution.** The six-step rewrite pattern is fully buildable and testable here (T-09, T-17). We can hand Data Eng a working reference implementation rather than a proposal. |
| OD-5 | Recipient sign-in: bearer token with lifetime and rotation, or OIDC federation (§3.1.1) | **Open** | Data Governance | **No — and this is the schedule problem.** See 13.2. |
| OD-6 | Gateway covers D2O and push; D2D and pull ingest sit outside with their own controls | **Proposed** | Data Governance + ARB confirm | **Supporting evidence only.** We can demonstrate *why* a gateway cannot front a D2D connection, which is the technical basis of the proposal. |
| OD-7 | Placement of AC9 (epic or story) and the Service Desk contact | **Open** | Binod | **No.** But the runbook AC9 needs can be written now regardless of where the story lands (Epic 8). |
| OD-8 | Unity AI Gateway governs model services and Unity Gateway MCP behind Gravitee; legacy MCP not exposed | **Proposed**; tests T-15, T-16 | AI/ML Ops + Data Tooling; Binod confirms | **Upgraded 2026-10-18 — now largely exercisable.** The *negative* half (route M3 unreachable from the edge) was always provable locally. The positive half is no longer a question of whether the gateway exists: it is live here with thirteen governed models and an MCPs tab, so OD-8's premise is confirmed rather than assumed. A **new sub-question** falls out of that and has no owner yet: OD-8 proposes the layering but does not say **which gateway is authoritative when both can refuse**. Gravitee and Unity Gateway each enforce limits and permissions, so E-3 has two refusal points and no stated precedence or common error contract. That belongs to AI/ML Ops and is *proposable* here — a recommendation with evidence, not a decision. |
| OD-9 | Ingress scope: I-1 pull baseline, I-2 push proposed; owner of content scanning | **Open** | Binod, Data Governance, Security | **Partly.** The I-2 route policies and all six refusal paths are buildable (T-24), which makes the proposal concrete. The content-scanning owner is a staffing decision. |
| OD-10 | Developer portal: Gravitee portal (primary) or Backstage | **Open** | Data Tooling | **Supporting evidence only.** The Gravitee portal is already running at `localhost:8085`; using it for the §5.3 step 2 registration demo is a real data point for the primary option. |

### 13.2 OD-5 is the critical path item

OD-5 decides the recipient sign-in method, token lifetime, rotation
schedule and overlap, revocation triggers, and who approves issuance.
It is **Open**, owned by Data Governance, and CONOPS §3.1.1 lists five
sub-decisions under it.

It gates more than it looks. Checkpoint **10/23 — "T04-10 package
review-ready"** cannot honestly be review-ready without it, because
AC1's sign-in model is OD-5. Epic 1's exit criteria, the §3.4.1
credential issuance pattern (which is also the *rotation* path), T-10's
overlap behaviour, and R4's residual-risk statement all read differently
depending on the answer.

The prototype cannot decide it. What it can do, and what Epic 1
therefore specifies, is build the **bearer-token branch** completely —
because that branch is what Free Edition supports and what every
reference client in §2.3.4 actually sends — while recording precisely
what would change under OIDC federation. Then the decision is a
substitution rather than a redesign.

The platform facts the decision needs are already confirmed from
documentation and should be restated in the ask: a recipient token is
valid at most one year; a recipient holds at most two tokens (active
plus rotated); the activation link yields the credential file once, and
rotating before use replaces the link.

### 13.3 Decisions this prototype can convert

Worth stating separately, because it is the clearest expression of the
prototype's value:

| From | To | How |
|---|---|---|
| OD-4 "Proposed; confirm and test" | Tested, with a reference implementation | Build the six-step rewrite; prove a reference client reads through the gateway edge URL with the rewritten file (T-09, T-17) |
| OD-8 half-open | Negative half closed | Prove route M3 (legacy MCP) is unreachable from the edge |
| OD-9 "Open" on the technical shape | Concrete and demonstrated | Build the class-I push route and all six refusals (T-24) |
| OD-1 "Decided, to be proven" | Half-proven, fallback recorded | T-08 proxy forward works; direct-read refusal recorded as untestable here |

And the one it adds: **a new decision the CONOPS does not yet have.**
The mask/filter finding (11.4) forces a choice the document never
considered, because it assumed both options were available.

> **OD-11 (proposed, new): granular access on shared data is
> view-based.** Column masks and row filters are refused on any table in
> an OpenSharing share
> (`ROW_COLUMN_SECURITY_NOT_SUPPORTED_WITH_TABLE_IN_DELTA_SHARING`), at
> every tier. Therefore every entitlement scope — column and row — is
> expressed as a view, the base table is never added to a share, and
> §3.1 / §2.3.1 / §3.4 are corrected in v1.6. Owner: AI/ML Ops with Data
> Governance. Evidence: 11.4.

This belongs in the §9.4 table in the next revision, not as a footnote.

---

## 13.4 Risk register (R1 … R14)

CONOPS §9.3, with the local position on each. "Local status" means what
this prototype has done to the risk — reduced it, confirmed it, or left
it untouched.

| ID | Risk | CONOPS mitigation | Local status |
|---|---|---|---|
| R1 | Upstream inputs (1636, 1694-G1) not confirmed, delaying T04-10 and T04-11 | Named contacts and dated commitments; escalate via scrum master and Binod | **Untouched.** Organisational. The prototype does reduce the *cost* of a delay: when the inputs land, the build is already standing. |
| R2 | Gateway does not cover the data plane, so valid token + storage reachability bypasses the perimeter | T-08 on 10/19; fallback of storage limits plus short-lived credentials; decide 10/26 | **Partly confirmed.** Locally we cannot restrict Databricks-managed storage, so the bypass is *real* in this environment. That is itself evidence for OD-1's fallback branch. |
| R3 | Model and volume sharing unavailable over open sharing | Confirm in OD-2; scope ARB claims to tables if unconfirmed | **Tends to confirm.** Asset coverage here is tables and views; CONOPS 2.7 already treats models/volumes as conditional. Keep ARB claims at tables and views. |
| R4 | Static bearer token theft | Address binding, lifetime and rotation or OIDC, SIEM alerting; residual risk accepted by ARB | **Reduced and verified.** Recipient IP access lists work (11.3), so address binding is a real control, not an aspiration. Residual risk still stands. |
| R5 | PSP7 availability late in weeks 5–7 | Book by 11/3; identify a fallback use case | **Untouched.** Needs Binod and Dave. A self-run rehearsal of the §5.3 eight steps shortens the real session, which is the only hedge available. |
| R6 | Week-4 compression: six epics overlap 10/23–10/29 | Daily plan sequencing; early sign-off requests; early read of test results | **Live and material.** For a one-person build the practical mitigation is front-loading E1, E2 and E6 (see 10.6). |
| R7 | Credential file issued unchanged exposes the Databricks endpoint | Provisioning with endpoint rewrite (OD-4); recipient IP list limited to gateway egress | **Substantially reduced.** Both halves are buildable and verified available here. This risk is the one the prototype can most nearly close. |
| R8 | Client-side access or permissions do not allow share, recipient, catalog or gateway changes | Confirm workspace, roles and approvals with Data Eng and Binod | **Answered for *this* workspace.** Shares, recipients, views, IP lists and SQL all work on Free Edition (11.3). Says nothing about the client workspace, but removes the "is this even possible" doubt. |
| R9 | Gateway capabilities missing in the Gravitee version in use (JWT validation, URL rewrite, signed-request forwarding, 429 behaviour) | Test early (10/19); record each gap with its fallback (§3.2) | **Being actively tested, with new findings.** Version in use is CE 4.12.23. Two non-obvious configuration traps found (11.2) and one live 404 blocker (B-1). The §3.2 capability table is the right instrument; E2 fills it in with observed results. |
| R10 | Reference clients cannot present a client certificate or a second credential | Rely on address allow-list and recipient IP list; OIDC if available; record in T-09 | **Partly testable.** `delta-sharing`/pandas and Spark only; Power BI, Tableau and Java are unavailable locally, so their rows in T-09 stay "not tested". |
| R11 | Unity AI Gateway / Unity Gateway MCP features beta, disabled, or unavailable in Gov | Confirm in the workspace first; record tests as not run; scope ARB claims | **Downgraded 2026-10-18 — the first clause does not describe this tier.** Console inspection shows Unity Gateway live at `/ml/ai-gateway` with thirteen governed models in `system.ai` and a Models / Providers / **MCPs** / Skills / Agents surface. Nothing is hidden behind the account console this tier lacks. T-15/T-16 are no longer expected to be A8 write-offs. **What survives is the Gov clause alone**, and it survives undiminished: this workspace is commercial-region Free Edition and can say nothing whatever about GovCloud/IL5 availability, which is where the CONOPS actually needs the answer. Narrower, not closed. |
| R12 | Gateway cannot inject or refresh the upstream service principal token, or rewrite the path, for push ingest and AI routes | Thin ingest or proxy service in front of the Databricks API; same consumer contract | **Testable and important.** The gateway *can* rewrite paths and set headers; whether it can refresh a short-lived Databricks OAuth token on a schedule is the real question, and it is a local engineering test, not a partner dependency. E4 covers it. |
| R13 | Details of ADVANASD-814427 and AWOZ-1361 not yet incorporated | Request from Binod; map the design onto them before 10/23 | **Untouched.** Information request. Note that 10/23 is in five days. |
| R14 | No test provider available for ingress tests, or recipient-side outbound hosts cannot be allow-listed | Create a stand-in provider (A10); build the allow-list from the T-20 capture | **Retired on its first clause, 2026-10-18.** Both halves of the first clause now have real, *probe-confirmed* providers: a second-account metastore for D2D (verified distinct, recipient creation permitted) and an open-source OpenSharing server for D2O. The mitigation is no longer a stand-in, and as of 10/18 it is no longer conditional either. What survives is the *second* clause, narrowed: the T-20 capture proves the allow-list **method**, but the hosts it yields are local and do not transfer, so the client-side host list remains an open question for Data Eng. |

### 13.5 Risks the prototype materially reduces

R4, R7, R8 and R9 all move. R7 moves furthest: the endpoint-exposure
risk has two mitigations (endpoint rewrite, recipient IP list) and both
are proven available and buildable here, so it can be presented to the
ARB as mitigated-and-demonstrated rather than mitigated-by-design.

**R14 has since moved the furthest of any risk in the register**, and in
the good direction. As first assessed it was *confirmed* — no ingress
provider existed, and D2D was impossible. The 10/18 topology change
retired it almost entirely: a second metastore and an open-source
provider mean the ingress tests have real counterparties rather than
substitutes, and A10 stops being an assumption. The residue is narrow
and should be stated as such — the captured outbound host list is
environment-specific, so what transfers to the client is the capture
procedure, not its output.

R2 still moves in the other direction: the prototype *confirms* it
rather than reducing it. That is still progress — a confirmed risk
with a known fallback beats an open question — but it should be reported
as confirmation, not mitigation.

---

## 13.6 Assumptions (A1 … A10) in local terms

| ID | CONOPS assumption | Local reality |
|---|---|---|
| A1 | Data Governance provides UC access model inputs (1694-G1); requested, not confirmed | Not available. Epic 1 uses the §3.1 starting access matrix as a placeholder and labels it as such. |
| A2 | Upstream dependencies (1636, 1694 items) delivered in time | Not available. Every dependency is stubbed locally; see 13.7. |
| A3 | Schedule skips Columbus Day, Veterans Day, Thanksgiving, Christmas | Accepted as given. |
| A4 | Production and IL5 outside this milestone, follow ARB approval | Holds. §4's IL5 column is documentation only. |
| A5 | Client workspace and Gravitee test environment available with rights to create shares, recipients, catalogs, service principals, and configure the gateway; NIPR access expected week of 10/19 | **Substituted.** Free Edition workspace + local Gravitee CE. Shares, recipients, catalogs and gateway config confirmed working; **service principals unconfirmed** on this tier, which matters for T-24 and the E-3 upstream identity. |
| A6 | A non-sensitive test dataset is available | Holds. `awoz1227_demo.opensharing_test.test_dataset`, synthetic. |
| A7 | PSP7 provides a technical contact and a client | Not available. T-13 is PARTNER. |
| A8 | Unity AI Gateway features enabled for T-15/T-16; if not, record as not run and note the gap | **Confirmed and unused, 2026-10-18.** The probe returned HTTP 200 from `databricks-gpt-oss-20b`, so the assumption holds and the escape hatch was not needed: T-15 is BUILD, not a write-off. A8 now covers exactly two residues — the Gov-region half of R11, which this environment can never test, and T-16's positive half, where the MCP API paths 404 while the console shows an MCPs tab. Worth recording *why* this matters: A8 was drafted as the safety net for the whole AI route, and the route turned out not to need it. An ARB package that still leans on A8 for T-15 would be understating its own evidence. |
| A9 | Details of ADVANASD-814427 and artifacts of AWOZ-1361 are supplied | Not supplied. Nothing in this prototype assumes them, per the CONOPS instruction. |
| A10 | A test provider for ingress can be created | **Confirmed 2026-10-18, both mechanisms.** D2O: an open-source OpenSharing server with Delta tables versioned in GitHub — a real provider, not a stand-in. D2D: a second Databricks account yielding metastore `8875961b-9666-494c-95e2-af6b5b78bd3d`, distinct from the primary `48cda780-…` in the same region, with a `DATABRICKS`-auth recipient created and deleted successfully on Free Edition. **Both Task 1.2 probes passed, so the qualifier is gone**: this assumption is now confirmed unconditionally and is the largest single change to the local position. |

---

## 13.7 Dependencies (§9.2) and their local substitutes

| Dependency | What it supplies | Local substitute |
|---|---|---|
| 1636 | The front door that serving routes sit behind | Gravitee CE gateway on `:8082`. Relationship to Apigee is unconfirmed in the CONOPS and unmodelled here. |
| 1694-G1 | UC access model inputs | §3.1 starting access matrix, used as a placeholder |
| 1694-G2 | ARB template | **None.** Epic 7 is blocked on this; we assemble the evidence pack that will fill it. |
| 1694-E4 | Correlation-ID propagation contract | **None, and the CONOPS says so.** §3.5 calls the correlation ID "the single biggest unknown". Locally we mint a custom header at the gateway and let T-11 discover what survives. |
| 1694-S3 | IaC/CaC tooling from Data Eng | Databricks Terraform provider + versioned Gravitee JSON + CaC files in `iac/`. This is the self-build fallback CONOPS §1.4 explicitly permits. |
| 1694-E6 | Input to T04-15 | None. |
| 1227-E1, 1227-E2 | INC17 milestone inputs (mapping to be confirmed) | None; mapping unknown. |
| Client Databricks + Gravitee test env access | The real test environment | Free Edition + local Docker |
| PSP7 introduction | The AC8 user test | None |
| Data Governance decisions (OD-5) and review slots | Sign-in and token policy | None; build both branches |
| Data Eng decision on OD-4 | Credential issuance pattern | **We build it and hand it over** |
| Service Desk contact (OD-7) | AC9 owner and service levels | None; write the runbook anyway |
| Test provider for ingress | T-19 to T-23 | **Self-served, 2026-10-18.** A second metastore (`glovashu`) covers D2D; a GitHub-hosted OSS reference provider covers D2O. No stand-in remains. |
| Content scanning owner (OD-9) | Upload inspection | None; uploads stay test-environment-only, exactly as §2.4.5 requires |

---

## 13.8 The asks this prototype generates

Items that need a person, not a commit. Each is worth raising with a
date attached, since several are already inside their checkpoint window.

| # | Ask | To | Why now |
|---|---|---|---|
| 1 | Decide OD-5 (sign-in method, token lifetime, rotation, overlap, revocation triggers, approver) | Data Governance | Gates the 10/23 T04-10 package; five sub-decisions in §3.1.1 |
| 2 | Accept OD-11 and correct §3.1, §2.3.1 and §3.4 in v1.6 | AI/ML Ops + Data Governance | The current text promises granular access by a mechanism that does not exist (11.4) |
| 3 | Confirm OD-4 and take the reference implementation | Data Eng | It is built and tested; confirmation is now cheap |
| 4 | Supply 1694-G2 (ARB template) | Data Governance | Epic 7 cannot start without it; T04-14 opens 10/30 |
| 5 | Name the correlation-ID propagation contract owner (1694-E4) | Data Tooling | §3.5 calls it the biggest unknown; T-11 and T-25 both rest on it |
| 6 | Name the Service Desk owner and settle OD-7 | Binod | AC9 has no epic; T-14 has no routing target |
| 7 | Name the content-scanning owner (OD-9) and decide I-2 scope | Binod, Data Governance, Security | **Dated 10/21** by the roadmap — "ingress specification reviewed, OD-9 decided". T-24's successful-upload path is gated on it, and §2.4.5 confines uploads to the test environment until the owner is named |
| 8 | Supply ADVANASD-814427 and AWOZ-1361 details (R13) | Binod | §9.3 sets "before 10/23" |
| 9 | ~~Confirm whether the client workspace tier supports model serving, Unity Gateway MCP~~ **and service principals** | Data Eng | **Re-scoped 2026-10-18.** The model-serving and MCP clauses are self-served — both surfaces are live here, so T-15/T-16 are real tests rather than A8 write-offs. Only the **service-principal clause** still needs Data Eng, and it still gates T-24's upload half. One third of the ask survives |
| 9a | Confirm Unity Gateway availability **in GovCloud / at IL5** | Data Eng + AI/ML Ops | New, and the half of R11 that local work cannot touch. A commercial-region workspace proves nothing about Gov. Raise with ask 9 so the two are not confused |
| ~~10~~ | ~~Provide a second metastore or an external provider for D2D ingress (A10, R14)~~ | ~~Data Eng~~ | **Withdrawn 2026-10-18 — self-served.** The `glovashu` metastore and an open-source OpenSharing server supply both counterparties, so this is no longer an ask. What replaces it is narrower and belongs to Data Eng at client-side time: confirm the **outbound host list** for the real provider endpoints, since the T-20 capture yields the procedure but only local hosts |
