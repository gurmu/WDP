# E1 — T04-10: Perimeter Security and Data-Access Model (AC1)

| | |
|---|---|
| **Epic** | T04-10 |
| **Acceptance criterion** | AC1 — Perimeter Security and Data Access |
| **CONOPS sections** | 2 (all), 3.1, 3.1.1, 3.1.2, 6 |
| **Stories** | 1: OpenSharing ingress/egress flow (§2) · 2: UC access model with Data Governance (§3.1) · 3: ARB package (§6) |
| **Role** | Build — AI/ML Ops builds and tests it |
| **Target dates** | 10/1 – 10/29 · checkpoint **10/23** package review-ready |
| **Depends on** | 1694-G1 (UC access model inputs, not confirmed), 1636 (front door) |
| **Tests** | T-01, T-02, T-03, T-04, T-08, T-15, T-16, T-19, T-20, T-21, T-24 |
| **Decisions in play** | OD-5 (**Open**, gates the package), OD-6, OD-8, OD-9, OD-11 (new) |
| **Risks in play** | R4, R7, R8, R11, R14 |

> **The criterion, verbatim (CONOPS §3.1):** *mechanisms to scale
> OpenSharing for secure ingress/egress via API, MCP, etc.; granular
> access via Unity Catalog and Unity AI Gateway; incorporate Gravitee
> where appropriate.*

---

## ▸ The verdicts live in the closure record

**[`E1-closure-record.md`](E1-closure-record.md) is the authoritative
statement of what this epic measured.** This file is the *plan*; that
file is the *result*, and where the two disagree the closure record wins,
because it carries evidence references and this file carries intentions.

As of **2026-10-22**: 11 of 12 tasks complete, Task 1.12 (the ARB
package) deferred by instruction pending the corporate 1694-G2 template.
Twelve tests run — eight pass, one passes with a `CANNOT_SEE` sub-check,
one is honestly partial, **two fail**.

Go straight to these if you read nothing else:

| | |
|---|---|
| **§3.1** | **B-48** — the route table was a documentation allow-list that nothing enforced. Gravitee *forwards* an unmatched path rather than refusing it |
| **§3.2** | **B-32c** — a *narrowed* view predicate did not reach the live consumer within 600s while every provider-side check reported the reduction in force. The one finding with a disclosure behind it |
| **§3.7** | **M2** — §2.3.2's MCP path shape is wrong, and this route answers HTTP 200 carrying a JSON-RPC error, so a status-code health check calls a broken MCP service healthy |
| **§4** | The credential time-box, discharged — including a rotation that is **refused precisely when it is most needed** |
| **§6** | The honest list of what E1 does not know |
| **§7** | Five recommendations for the corporate discussion, all measurements rather than opinions |

A reader who arrives at the task list below and stops there will see what
was planned, not what happened: several tasks read COMPLETE while
carrying findings that change the CONOPS.

---

## E1.0 What this epic actually has to produce

AC1 is the broadest criterion in the milestone and the one with the most
tests (eleven). It is tempting to read it as "build the gateway", but
the gateway is AC2. AC1 is about the **access model**: who can reach
what, by which channel, under which Unity Catalog grant, and what
happens at each boundary when they shouldn't.

Four deliverables, in dependency order:

1. **The channel model**, instantiated rather than described — five
   channels (E-1, E-2, E-3, I-1, I-2) each with its named control point,
   its Databricks-side control and its tests.
2. **A view-based entitlement model** in Unity Catalog, which after
   finding 11.4 is the *only* mechanism available for column and row
   scope.
3. **Databricks-side perimeter controls** — recipient IP access lists,
   verified working on this tier.
4. **An honest AI-asset position** for routes M1/M2 and route M3, from a
   real probe rather than from documentation.

Everything else in AC1's test list (T-08, T-24) is enforced at the
gateway and belongs to E2 and E4; AC1 only owns the Databricks-side half
and the model that says why the split is where it is.

---

## E1.1 Task list

Each task is independently verifiable. Run them in order. **PARTNER** or
**DEFERRED** tasks are not skipped quietly — they produce a written gap
with an owner.

### Task 1.1 — Fix the secret-hygiene violations and lock in the rule

Blocker B-4. `_secrets/raw-credential1.json` and
`gateway-credential1.json` are mode 664 with live bearer tokens, and
`_secrets/rewrite_credential.py` is a divergent copy of
`scripts/04_rewrite_credential.py` modified *later* than the tracked
one — code living in a secrets directory.

This is first because CONOPS §1.4 and §2.4.3 make custody a hard rule,
because T-21's second half is a secret scan that would currently fail,
and because the divergent script is a correctness hazard — we would
otherwise spend Epic 4 debugging the wrong file.

**Deliverable:** everything under `_secrets/` at mode 0600; the stray
script reconciled into `scripts/` or deleted; a reusable hygiene check
that asserts it.

**Verify:** no file under `_secrets/` has group or other permissions;
`git status` shows nothing from `_secrets/` as tracked or staged.

### Task 1.2 — Extend the capability probe into a generated baseline

`scripts/00_check_capabilities.py` checks four things. Section 11 records
nine more that were probed by hand and then lost to shell history. Those
hand probes are the evidence behind the most valuable findings in this
project, and they are currently unreproducible.

**Deliverable:** `scripts/00_check_capabilities.py` extended to probe,
and emit as JSON: PAT/REST, Unity Catalog, share listing, recipient
listing, **recipient IP access list support** (create a throwaway
recipient with a documentation CIDR, read it back, delete it), **view
sharing**, **the mask/filter refusal** (assert the specific error code),
warehouse availability and start behaviour, `system.access.audit`
reachability, model-serving endpoint listing, and Unity Gateway MCP
service listing.

Two design notes. The probe must clean up after itself — the throwaway
recipient gets deleted whether the probe passes or fails. And the
mask/filter check is an *assertion that it fails with the expected error
code*, not a check that it works; a future Databricks release that
changes this behaviour should make the probe go red so we notice.

Use `203.0.113.0/24` (RFC 5737 documentation range) for throwaway CIDRs,
never a real address.

**Deliverable:** `evidence/capability-baseline.json`, and
`docs/11-environment-baseline.md` §11.3/§11.6 regenerable from it rather
than hand-maintained.

**Verify:** the JSON matches the tables in §11.3 and §11.6; re-running
the probe twice leaves no residue in the workspace.

### Task 1.3 — Instantiate the channel model as configuration

CONOPS §2.1's five-channel table is the spine of AC1, and it is
currently prose in a Word document. Make it a versioned CaC file so the
route table (§2.3.2), the policy classes (§2.3.3) and the ingress
controls (§2.4.6) all resolve against one source.

**Deliverable:** `iac/config/channels.yaml` holding, per channel: id,
direction, mechanism, whether Gravitee fronts it, the Databricks-side
control, status, and the test IDs. Plus `iac/config/route-table.yaml`
with the §2.3.2 routes S1–S10, F1, M1–M3, A1, X — each with method,
protocol path, target, policy class and exposure decision.

Record M3 and A1 explicitly as **not exposed**. A route table that only
lists what is allowed cannot express deny-by-default; one that names the
deliberately-excluded routes can, and route X ("everything else, denied
in the protocol error format") then has something to be the complement
of.

**Verify:** every channel in §2.1 and every route in §2.3.2 appears
exactly once; E2 can generate the Gravitee flows from these files
without consulting the docx.

### Task 1.4 — Build the view-based entitlement model

This is the heart of the epic and the task that finding 11.4 rewrote.

The pattern, which replaces the CONOPS §3.1 "or apply column masks and
row filters" clause:

```
awoz1227_demo.opensharing_test.test_dataset      base table, NEVER shared
awoz1227_demo.opensharing_test.v_entitled_t2     view: entitled columns only
awoz1227_demo.opensharing_test.v_entitled_t2_us  view: + row scope via WHERE
```

The share carries views only. `internal_notes` — and anything else
outside the grant — is excluded by never appearing in the view's select
list, so there is no mask to misconfigure and nothing to fail open.

Three rules to enforce in code, not by convention. The base table is
never added to a share, and a check asserts it. Every view carries a
`COMMENT` with its DSA reference and its tier, because §3.3's
purpose-limitation control is "the DSA reference is carried on every
recipient" and a view without one cannot be audited. And the share
itself gets one share per purpose, per §3.1's share-isolation rule — not
one share with everything in it.

**Deliverable:** the views created; the existing share corrected to drop
the base table and carry the view; Terraform in
`iac/databricks/` for catalog, schema, views, share and share objects.

**Verify:** share metadata lists the view and **not** the base table; a
recipient reading the share sees no `internal_notes` column at all (not
a masked one — absent); the base table is not reachable through the
share.

This task closes defect D-1 and D-2 and makes T-04 meaningful.

### Task 1.5 — Recipients, DSA references and IP access lists

One recipient per consuming agency or use case (§3.1 share isolation).
Each created with its DSA reference in the `COMMENT`, its token lifetime
per OD-5 — and since OD-5 is Open, with the **lifetime as a config
value** in `iac/config/` rather than a literal, so the decision is a
one-line change — and an IP access list limited to the gateway egress
addresses.

The IP access list is the control that makes T-02 real. With it, a
stolen token used from anywhere but the gateway fails at Databricks even
if the gateway is bypassed entirely. §11.3 confirms it works on this
tier, and R7/R4 both lean on it.

The existing recipient `psp7-demo-recipient` has no IP access list. It
either gets one or gets replaced.

**Deliverable:** recipient(s) with DSA comment and IP access list;
Terraform for recipients, grants and IP lists;
`iac/config/allow-lists.yaml` holding the gateway egress CIDRs as the
single source of truth.

**Verify:** `DESCRIBE RECIPIENT` echoes the IP list; the DSA reference
is present; `GRANT SELECT ON SHARE` is to the recipient and to nothing
else.

### Task 1.6 — T-01 and T-02: the read, and the refusal

T-01 repeats the original share read, now through the gateway. T-02 is
its negative: the same valid token used straight against the Databricks
sharing endpoint, which must be refused.

T-01 depends on E2 Task 2.1, which converges the two competing Gravitee
API definitions into the single policy-bearing route. The gateway is not
broken — one definition already proxies the open protocol correctly and
returns a real share list (see `docs/11` §11.7, where B-1 was
reclassified on 2026-10-18 as an upstream target error on the *second*
definition). Sequence T-01 accordingly: build the test now, run it
against the consolidated route so the evidence records a single
deterministic path rather than whichever definition happened to win.
T-02 is independent of the gateway and runnable immediately — in fact it
is more honest when run first, because it proves the Databricks-side
control standing alone.

**Deliverable:** `tests/t01_gateway_read.py`, `tests/t02_direct_refusal.py`,
evidence records.

**Verify:** T-01 returns rows and the entitled column set; T-02 is
refused by the IP access list, not merely by a network error, and the
evidence record captures which.

### Task 1.7 — T-04 rebuilt: column outside the grant

Now meaningful. Three assertions: the column is absent from the share's
table metadata; a client request naming it fails; and a request for the
base table (outside the share) is refused.

Assert on the *absence of the column in metadata*, not just on a failed
query. A query can fail for a dozen uninteresting reasons; metadata
absence is the thing AC1 clause 1.3 actually claims.

**Deliverable:** `tests/t04_column_denied.py`, evidence record,
retirement of the invalid `scripts/02_create_share.py` behaviour.

### Task 1.8 — T-21: read-only by construction, and no leaked credentials

Two halves. Attempt a write against the shared catalog — it must fail,
because §6's "read-only by construction" principle is an ARB
justification and needs evidence. Then scan the repository and logs for
credential-file content.

The scan must look for the *shape* of a credential (a `bearerToken`
field, an `endpoint` + token pair) rather than for a specific secret
value, so it stays useful after rotation and so the test itself never
contains a token.

**Deliverable:** `tests/t21_readonly_nosecrets.py`, evidence record.

**Verify:** write refused; scan clean (which requires Task 1.1 to have
been done).

### Task 1.9 — Exercise the AI routes (rewritten 2026-10-18)

**This task was written expecting to fail, and that expectation is now
wrong.** The original text read: "Free Edition has no account console,
and §3.1.2 notes some Unity Gateway MCP servers need an account admin
to enable the beta. The likely outcome is *not available*." Console
inspection on 10/18 shows Unity Gateway live at `/ml/ai-gateway` with
thirteen governed models in `system.ai` and tabs for Models, Providers,
**MCPs**, Skills and Agents. Routes M1 and M2 have a real surface to
target, so this task changes from "probe, then write down a gap" into
"exercise the routes, and probe only what is genuinely still unknown".

Run it in four parts.

**Part 1 — Settle invocation (the only real unknown on M1).** Every
model reads 0 tokens over a 7-day window, so nothing here has ever been
called and a Free Edition workspace may still refuse inference on quota.
Call one small model directly, outside Gravitee, before building any
route. Use `databricks-gpt-oss-20b` or `databricks-gemma-3-12b` rather
than the 120B — if a quota exists, the small model is likeliest to clear
it. A 200 makes T-15 BUILD. A 402/429 keeps it PROBE and lands under A8
honestly, which is a *quota* finding, not an availability finding, and
the evidence record must say which.

**Part 2 — Build M1 through Gravitee.** This is where R12 gets tested
for real: the gateway must inject the upstream credential, because the
consumer must never hold a Databricks token. Same pattern as OD-4 on the
sharing side. Record whether Gravitee's injected header survives to the
model endpoint.

**Part 3 — The precedence question (new, and the most valuable part).**
With Gravitee and Unity Gateway both able to refuse and both able to
rate-limit, E-3 has **two enforcement points and no stated precedence**.
Set a Gravitee class E limit deliberately lower than the Unity Gateway
limit and burst it; then, if the tier allows setting a Unity Gateway
limit, invert the pair and burst again. Record both error shapes
verbatim. The CONOPS has no test for this and OD-8 does not resolve it.
Two unrelated error contracts reaching one consumer is a defect worth
finding here rather than at the client. Output is a *proposed*
recommendation for AI/ML Ops, never a decision.

**Part 4 — M2 and M3.** Open the MCPs tab and record what it contains
and whether a callable server can be created on this tier; that is the
remaining open half of T-16. M3 is unchanged and still BUILD: legacy
managed MCP at `/api/2.0/mcp/*` must not be reachable from the edge,
because §3.1.2 is unambiguous that those endpoints bypass Unity Gateway
grants, policies and guardrails and never reach the tracing tables.

**Opportunistic, fifteen minutes, stop if it does not yield.** The
console tracks tokens per model over a rolling window and the page
banner claims lineage through Unity Catalog. If that accounting is
queryable from SQL, it may give T-11 a second join key to try on the AI
routes — not a solution to 1694-E4, but a lead Epic 5 would otherwise
not have. Report rows or report nothing; do not infer.

**Deliverable:** `scripts/probe_ai_gateway.py` results in
`evidence/capability-baseline.json`; `tests/t15_model_route.py`;
`tests/t16_mcp_route.py` covering at least the M3 negative; the two
error-shape captures from Part 3; a written note on R11's surviving Gov
clause.

**Verify:** M3 returns the protocol error format from the edge, not a
proxied response. T-15 records an actual HTTP status from a real call —
`NOT_RUN` is no longer an acceptable outcome for *availability*, only
for quota, and the record must distinguish the two.

### Task 1.10 — Ingress I-1: build what is possible, document the rest

**Rewritten 2026-10-18.** Both halves of this task were previously
capped — T-20 at STANDIN, T-19 at PARTNER — because no external provider
existed. Both now have real counterparties, so this task changes from
"build what is possible, document the rest" into a task that can finish.

**T-20 (D2O pull) — BUILD.** An open-source OpenSharing server holding
Delta tables versioned in GitHub is a genuine open-protocol provider,
so the full eight-step §2.4.1 D2O sequence is runnable: the provider
issues the token and credential file, the custodian vaults it, the
provider is imported, a catalog is created from the share, groups are
granted, and the read is validated through the connector. The
**host capture** remains the most valuable half — §2.4.3 says plainly
that Databricks does not publish recipient-side firewall requirements,
so the allow-list must come from an observed capture. State the
limitation in the evidence record: the captured hosts are local, so what
transfers to the client environment is the *procedure*, not the list.

**T-19 (D2D pull) — BUILD, both gates passed 2026-10-18.** A second
Databricks account supplies the far side, so this was never a partner
dependency, and Task 1.2's two capability probes have now cleared it:

| Gate | Result | Evidence |
|---|---|---|
| Is the far side a genuinely distinct *metastore*? | **Yes.** `48cda780-1dc7-459d-bee0-77abde9af938` vs `8875961b-9666-494c-95e2-af6b5b78bd3d`, both `aws:us-east-2` | `evidence/capability-baseline-d2d.json` |
| Does this tier permit `authentication_type = DATABRICKS`? | **Yes.** Recipient created HTTP 200 against `aws:us-east-2:8875961b-…`, deleted HTTP 200 | same |

Two notes carry forward. The identity check was taken through
`/api/2.1/unity-catalog/metastore_summary` rather than
`SELECT CURRENT_METASTORE()` as originally written here, because the REST
path needs no running compute — on Free Edition that matters, and it
makes the probe scriptable for T-12 replay. And the probe's *first* run
returned the opposite verdict, `SAME_METASTORE`, from a fallback path
that matched on a catalog name every workspace has; see §12.9. The
retraction is deliberately preserved.

So the gate language below no longer applies to T-19, but keep it for
the method: *if either probe had failed, mark `NOT_RUN` with the
specific capability named — and do not simulate a metastore and call it
T-19.* That rule is what makes the BUILD verdict worth anything.

The remaining T-19 work is construction, not capability: identifier
exchange, provider-side recipient and share grant, `SHOW PROVIDERS`,
`SHOW SHARES IN PROVIDER`, `CREATE CATALOG … USING SHARE`, group grants,
the entitled read, the denied read for a non-entitled group, and the
refresh behaviour.

**One extra deliverable, new and worth the detour.** With `glovashu`
available, channel **E-2** (egress D2D) is testable for the first time.
§2.1 gives E-2 the status *"Documented; tested if a test recipient
exists"* and §5.2 assigns it **no numbered test at all** — a structural
gap in the CONOPS, since §2.1 states every channel has one set of tests.
Reverse the T-19 roles (this workspace as provider, `glovashu` as
recipient) and record the result as a proposed new test for v1.6, with
the OD-6 claim examined directly: confirm that D2D has no gateway
interception point and that its assurance rests wholly on share grants,
the recipient identifier and audit.

**Deliverable:** `tests/t20_ingress_d2o.py` with host capture;
`iac/config/outbound-allow-list.yaml` generated from the capture;
`tests/t19_ingress_d2d.py` runnable, gated on the Task 1.2 probes;
`tests/e2_egress_d2d.py` as the proposed v1.6 test; the §2.4.1 role
table (requester, approver, metastore admin, credential custodian,
catalog owner, security approver) recorded with the hat each was worn
under.

**Verify:** the allow-list file is derived from captured hosts, with the
capture attached as evidence and its non-transferability stated; T-19
records either a real result or the specific tier capability that
refused it; the E-2 result is written up as a v1.6 test proposal rather
than filed against an existing test ID.

### Task 1.11 — The §3.1 access matrix, marked as provisional

§3.1's starting access matrix (external recipient, internal consumer
group, data owner, sharing admin, ingest job identity, gateway upstream
identity) is explicitly "for Data Governance to confirm (input
1694-G1)". That input has not arrived (A1).

Implement it as written, in Terraform, and label it provisional in the
file itself. A matrix that is implemented and labelled gives Data
Governance something concrete to react to, which is a faster route to
1694-G1 than waiting.

Note the one row that cannot be implemented locally: the gateway
upstream identity needs a service principal, and service principal
support on Free Edition is **unconfirmed** (A5 substitution note). Flag
it rather than assume it.

**Deliverable:** `iac/databricks/access-matrix.tf` with group grants;
`iac/config/access-matrix.yaml` as the readable source, marked
`status: provisional, awaiting 1694-G1`.

### Task 1.12 — Assemble the Story 3 ARB package

Checkpoint 10/23: "T04-10 package review-ready, including the ingress
specification."

Pull together: the channel model (Task 1.3), the entitlement model and
its correction (Task 1.4), the perimeter controls (Task 1.5), the test
evidence from Tasks 1.6–1.10, the provisional access matrix (Task 1.11),
and the §6 ARB justification principles that AC1 supports — no
provider-side replication, infrastructure decoupling, read-only by
construction, least privilege on ingress, token-misuse reduction,
layered enforcement, tested-not-asserted.

Two things must appear prominently rather than in a footnote. **OD-5 is
Open**, so the sign-in and token-policy section of the package is a
placeholder with both branches described — say so on the first page
rather than letting a reviewer discover it. And **OD-11 / defect D-1**:
the package should carry the mask/filter finding as a correction to the
CONOPS, since AC1 clause 1.3 currently rests on a mechanism that does
not exist.

**Deliverable:** `docs/epics/E1-arb-package.md` with evidence
references, gaps and asks.

**Verify:** every AC1 clause (1.1–1.5) traces to evidence or to a named
gap; no clause traces to nothing.

---

## E1.2 IaC and CaC deliverables

| Path | Contents |
|---|---|
| `iac/databricks/catalog.tf` | Catalog, schema |
| `iac/databricks/views.tf` | Entitlement views, with DSA/tier comments |
| `iac/databricks/share.tf` | Share per purpose; share objects = views only |
| `iac/databricks/recipients.tf` | Recipients, DSA comments, IP access lists, share grants |
| `iac/databricks/access-matrix.tf` | Group grants per §3.1, provisional |
| `iac/config/channels.yaml` | §2.1 five-channel model |
| `iac/config/route-table.yaml` | §2.3.2 routes incl. not-exposed M3, A1, X |
| `iac/config/allow-lists.yaml` | Gateway egress CIDRs (recipient IP lists) |
| `iac/config/outbound-allow-list.yaml` | Ingress hosts, generated from the T-20 capture |
| `iac/config/access-matrix.yaml` | Readable access matrix, `status: provisional` |

`iac/config/token-policy.yaml` is **not** an E1 deliverable — **E3 Task
3.3** creates it. E1 only consumes it, in Task 1.12, where OD-5's open
status has to appear prominently in the ARB package.

Secrets appear in none of these, only as `.env` or vault references
(§3.6).

---

## E1.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-01 | BUILD | E1 | Run against E2 Task 2.1's consolidated route |
| T-02 | BUILD | E1 | Independent of the gateway; run first |
| T-03 | BUILD | **E2** | AC1+AC2; enforced at the edge |
| T-04 | REBUILD | E1 | Task 1.7; was invalid |
| T-08 | PARTIAL | **E2** | Storage-side refusal untestable here |
| T-15 | **BUILD** (settled 10/18) | E1 probe, E2 limits | Probe returned HTTP 200. Capability closed; route-building remains. Mind the response shape — §12.7 |
| T-16 | PROBE | E1 | MCP API paths 404 while the console shows an MCPs tab; the positive half is genuinely open. M3 negative half is BUILD, but its evidence must be a *gateway-generated* refusal — §12.7 item 4 |
| T-19 | **BUILD** | E1 | Second-account metastore `8875961b-…`; both Task 1.2 probes passed 10/18 |
| T-20 | BUILD | E1 | Real OSS provider; host capture is the valuable half |
| E-2 | proposed test | E1 | Egress D2D, untested and unnumbered in v1.5 |
| T-21 | BUILD | E1 | Depends on Task 1.1 |
| T-24 | PARTIAL | **E4** | Push ingest; refusals buildable |

---

## E1.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the
following hold:

Secret hygiene is clean and asserted by a check, not by inspection. The
capability baseline is machine-generated and reproducible, and §11 can
be rebuilt from it. The channel model and route table exist as
versioned config that E2 consumes. No share anywhere contains a base
table; every share object is a view carrying a DSA reference. Every
recipient has a DSA reference and an IP access list. T-02, T-04 and
T-21 pass with evidence records. T-01 passes once the edge is up. T-16's
M3 negative passes. T-15, T-16 positive, T-19 and T-20 each have a
record that is either a result or a named dependency — never silence.
The provisional access matrix is implemented and labelled. The ARB
package traces all five AC1 clauses to evidence or to a gap, and leads
with OD-5's open status and the OD-11 correction.

**Status against those criteria, 2026-10-22: all met except the ARB
package, which is deferred by instruction.** See
[`E1-closure-record.md`](E1-closure-record.md) §1 for the per-task
verdicts and §5 for what the deferral costs the 10/23 checkpoint.

**One criterion above needs re-reading in light of what was measured.**
"No share anywhere contains a base table; every share object is a view"
is satisfied — and B-32c (closure record §3.2) showed that is not
sufficient on its own. A view is the right container, but *editing* one
is not a working way to reduce what a live consumer can read: a narrowed
predicate did not reach the consumer inside 600s while the provider's
catalog, the applier and the model's own conformance rule all reported
the reduction in force. An exit criterion phrased as "every share object
is a view" tests the **shape** of the entitlement model and says nothing
about whether a **change** to it takes effect. For E2 the criterion
should be the second thing.

---

## E1.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| OD-5 sign-in and token policy | Data Governance decision | 13.2; gates the 10/23 package |
| 1694-G1 UC access model | Data Governance input | A1; matrix stays provisional |
| ~~T-19 D2D ingress~~ | ~~A second metastore or an external provider~~ — **removed 2026-10-18.** This row no longer belongs in a "cannot close" table: `glovashu` supplies the counterparty, and the two remaining questions are capability probes this epic runs itself in Task 1.2 | A10 confirmed, R14 largely retired, ask 10 withdrawn |
| Client-side outbound host list for ingress | Data Eng, at client-environment time | Task 1.10 captures the *procedure*; the hosts it yields are local and do not transfer. This is what survives of R14 |
| ~~T-15 / T-16 positive~~ | ~~Model serving + Unity Gateway MCP on the tenant~~ — **removed 10/18**, both surfaces are live here and Task 1.9 now exercises them | R11 downgraded; ask 9 re-scoped |
| Unity Gateway availability in GovCloud / at IL5 | Data Eng + AI/ML Ops | R11's surviving clause; **ask 9a**. A commercial-region workspace cannot answer it |
| Gateway upstream identity row | Service principal support confirmation | A5, ask 9 |
| 1636 front-door relationship to Apigee | Data Tooling | §3.2 notes it unconfirmed |

Each of these should leave the epic as a dated ask, not as an empty cell
in the ARB package.
