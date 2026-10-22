# 10. Implementation Manual — AWOZ-1227 OpenSharing + Gravitee Prototype

Reference CONOPS: **AWOZ-1227 v1.5** (`CONOPS_AWOZ-1227_v1.5.docx`,
sections 1–10). Plan window 10/1/2026 – 11/20/2026. This manual is the
entry point; read it before any epic playbook.

| Document | Purpose |
|---|---|
| `docs/10-implementation-manual.md` | This file. Scope, layout, conventions, sequence, working method. |
| `docs/11-environment-baseline.md` | Verified environment facts, Free Edition capability matrix, open blockers. **Read second.** |
| `docs/12-test-matrix.md` | T-01 … T-25 mapped to epic, AC, artifact, feasibility, evidence. |
| `docs/13-decisions-and-risks.md` | OD-1 … OD-10 and R1 … R14 with local status and what the prototype can actually settle. |
| `docs/epics/E*.md` | One playbook per epic, in roadmap order. Tasks, IaC deliverables, tests, exit criteria. |
| `docs/00-services-setup-guide.md` | Pre-existing: accounts, services, cost reality check. |

---

## 10.1 What this prototype is for

Three things, in priority order.

**Reduce the unknowns before the real build.** CONOPS v1.5 carries ten
open decisions, fourteen risks and a long list of "capabilities not yet
confirmed for the Gravitee version in use" (3.2). A laptop prototype
cannot decide the governance items, but it can convert a surprising
number of the technical ones from "unverified" to "verified, with the
error message attached". Section 11.4 is the model: the CONOPS claim
that column masks and row filters give granular access on shared tables
is **false**, and now we know that before the client verification
session rather than during it.

**Produce the IaC/CaC artifacts AC6 requires.** Every epic step emits
versioned config — Terraform for Databricks objects, JSON definitions
for Gravitee, plain config files for policy-class values and allow-lists.
T-12 ("redeploy the configuration from code to a clean target, same
configuration, no manual steps") is then a real test rather than a
gesture. This is the "Prototype + IaC artifacts" build target.

**Make the undeliverable parts visible.** AC7 needs an ARB template that
does not exist yet (1694-G2). AC8 needs a second party (PSP7). AC9 has
no epic at all (OD-7). T-19 to T-23 need an ingress provider that one
Free Edition workspace cannot supply. The honest output for those is a
documented gap with an owner and a dated ask — not a script that
pretends.

**Explicitly out of scope**, following CONOPS 1.4: production and IL5
deployment, authorship of the DSA instrument, the real agency CIDR
ranges, and anything involving real client data. The test-data rule is
absolute: non-sensitive synthetic data only, and evidence records carry
names and metadata only, never tokens, credential files or data.

---

## 10.2 How we work through this

The division of labour is fixed:

> I write the guidance, the commands and the code for one step at a
> time. You run it in your environment and report what actually
> happened. When a step is done you ask for the next one. We do not skip
> ahead.

For each step I will give you the goal tied to its CONOPS clause, the
exact files to create or change, the commands to run, the observable
result that counts as success, and the evidence artifact to keep. When
reality disagrees with the CONOPS — and it already has twice — we record
the disagreement as a document defect for v1.6 rather than quietly
working around it.

Epics are worked in roadmap order (10.5). Within an epic, tasks are
ordered so that each one is independently verifiable; a task that cannot
be verified locally is marked **PARTNER** or **DEFERRED** with the
reason and the owner, and we move past it rather than faking it.

---

## 10.3 Repository layout

The rebuild is clean-slate in structure: documentation and IaC are new,
and the `scripts/` and `tests/` trees are rewritten per epic rather than
patched. The existing scripts stay in place as reference until their
replacement is built and verified.

```
awoz-1227-opensharing-demo/
├── CONOPS_AWOZ-1227_v1.5.docx    the reference document
├── README.md                      orientation; rebuilt against v1.5
├── docker-compose.yml             Gravitee CE 4 + Mongo + Elasticsearch
├── .env                           live values, gitignored
├── .env.example                   template
├── requirements.txt
│
├── docs/                          ── documentation (this set)
│   ├── 00-services-setup-guide.md
│   ├── 10-implementation-manual.md
│   ├── 11-environment-baseline.md
│   ├── 12-test-matrix.md
│   ├── 13-decisions-and-risks.md
│   └── epics/E1…E8-*.md
│
├── iac/                           ── AC6 deliverables, versioned
│   ├── databricks/                Terraform: catalogs, schemas, views,
│   │                              shares, recipients, grants, IP lists
│   ├── gravitee/                  V4 API definitions, plans, policy sets
│   └── config/                    CaC: policy-class values, allow-lists,
│                                  route templates, DSA tier map
│
├── scripts/                       ── build and operate steps
├── tests/                         ── one module per test ID, T-01…T-25
├── evidence/                      ── metadata-only test evidence (committed)
└── _secrets/                      ── tokens, credential files (gitignored, 0600)
```

Two rules about the last two directories. `evidence/` **is** committed:
it holds test ID, expected result, actual result, timestamp and an
evidence reference, and nothing else — this is the CONOPS 5.1 evidence
rule. `_secrets/` is **never** committed, every file in it is mode
`0600`, and no code lives there. Section 11.7 B-4 records the current
violations of both rules and Epic 1 fixes them.

---

## 10.4 Conventions

**Naming.** Databricks objects are prefixed `awoz1227_`. Shares are
named by purpose (`awoz1227_<purpose>_share`), recipients by consumer
(`awoz1227_<consumer>_recipient`), entitlement views
`v_<purpose>_<tier>`. Every share and every recipient carries a
`COMMENT` holding its DSA reference — that is the CONOPS 3.3 control
that makes a DSA clause enforceable, and it is cheap, so it is never
skipped.

**Granular access is view-based.** Per Section 11.4, never add a base
table to a share. Create a view selecting only entitled columns and
rows, add the view. This is non-negotiable and is the single most
important convention in the build.

**Test IDs are first-class.** One module per test: `tests/t01_*.py`
through `tests/t25_*.py`. Each writes a record to `evidence/` in a
single shape:

```json
{
  "test_id": "T-03",
  "criterion": ["AC1", "AC2"],
  "expected": "Refused at the gateway and logged",
  "actual": "403 ip-filtering; message 'Your IP (…) not allowed'",
  "result": "PASS",
  "timestamp": "2026-10-17T15:40:00Z",
  "evidence_ref": "evidence/t03-refusal.json",
  "notes": ""
}
```

Permitted `result` values are `PASS`, `FAIL`, `PARTIAL`, `NOT_RUN` and
`BLOCKED`. `NOT_RUN` requires a reason and is exactly what CONOPS A8
anticipates for the AI Gateway tests if the features are not enabled.

**IaC/CaC is written at the same time as the thing it builds**, not
retrofitted. A step that creates a share by SDK call and does not also
produce the Terraform for it is not finished. Secrets appear in IaC only
as vault/`.env` references (CONOPS 3.6, "references to vault entries
only; no secret in the repository").

**Gravitee management calls use the v2 API.** V4 API definitions are
invisible on v1 (Section 11.7 B-2).

**Edge limits sit below Databricks-side limits**, so the edge trips
first (CONOPS 2.3.3, 3.1.2). Whenever a limit is set, record both
numbers and which one is lower.

**Logging is metadata only.** Tokens, credential files and response
bodies are never logged, never written to evidence, never pasted into a
ticket or into this chat (CONOPS 3.5 logging rule, 2.4.3 custody).

---

## 10.5 Epic sequence

Roadmap order from CONOPS 1.6 / 7, with each epic's local build posture.

| # | Epic | AC | CONOPS dates | Role | Playbook | Local posture |
|---|---|---|---|---|---|---|
| E1 | T04-10 Perimeter security and data-access model | AC1 | 10/1 – 10/29 | Build | `epics/E1-T04-10-perimeter-and-access.md` | Mostly buildable. View-based entitlement, recipient IP lists, channel map. AI-route probe may come back unavailable. |
| E2 | T04-11 Traffic control and serving configuration | AC2 | 10/8 – 10/29 | Build | `epics/E2-T04-11-traffic-control.md` | Fully buildable locally, and holds blocker B-1 — now reclassified as an upstream target error, not a broken gateway. Checkpoint 10/19 is already due. T-07 is currently failing. |
| E3 | 1227-E3 Data governance / DSA | AC3 | 10/8 – 11/5 | Integrate | `epics/E3-1227-E3-data-governance.md` | Partner-owned. We build the control-mapping and the tier/template scaffolding, not the DSA. |
| E4 | T04-13 Self-service API/MCP and data publishing | AC4 | 10/16 – 11/5 | Build | `epics/E4-T04-13-self-service-publish.md` | Buildable: OD-4 credential rewrite, publish pipeline, portal registration. |
| E5 | 1227-E5 Auditability and observability | AC5 | 10/16 – 11/5 | Integrate | `epics/E5-1227-E5-audit-observability.md` | Partly buildable. Elasticsearch is the SIEM stand-in; the Databricks audit join key is the big unknown. |
| E6 | 1227-E6 Infrastructure and deployment (IaC/CaC) | AC6 | 10/23 – 11/13 | Integrate | `epics/E6-1227-E6-iac-cac.md` | Buildable and central to the build target. T-12 against a clean target. |
| E7 | T04-14 EA / Change-Request compliance packaging | AC7 | 10/30 – 11/20 | Build | `epics/E7-T04-14-compliance-packaging.md` | Blocked on 1694-G2 (ARB template). We assemble the evidence pack that will fill it. |
| E8 | T04-15 User testing (AC8) and customer support (AC9) | AC8, AC9 | 10/30 – 11/20 | Build | `epics/E8-T04-15-user-testing-support.md` | AC8 needs PSP7. AC9 is buildable as a runbook and has no epic yet (OD-7). |

Ingress (CONOPS 2.4, channels I-1 and I-2, tests T-19 to T-25) is not an
epic of its own. It is split across E1 (the channel model and controls),
E4 (landing and the push route) and E5 (ingress tracing, T-25), which is
how the CONOPS allocates it. The test matrix is where you see the whole
ingress picture in one place.

---

## 10.6 Schedule reality as of 10/18

Taking the CONOPS roadmap at face value, today is day 18 of a 51-day
plan. Four things matter:

Checkpoint **10/19 — "Gravitee configuration tested with Data Tooling
(T04-11)"** is tomorrow. Blocker B-1 is the first task of E2 and
arguably the first task of the whole rebuild — but it is a much smaller
job than it looked on 10/17. **B-1 was reclassified on 10/18** (11.7):
the gateway is not broken, it proxies the open protocol correctly and
returns a real share list on `/opensharing-demo/`. The 404 is an
*upstream target error* on the other API, which was built against an
assumed Databricks URL instead of the endpoint in the issued credential
file. Converging the two APIs into one is an afternoon, not a week.

**Any statement elsewhere in this document set that the gateway
"returns 404 on every route" predates that reclassification.** Where it
appears — E1 §E1.3, E6 §E6.0, E7 §E7.0 and its claims register, E8
§E8.0 — read it as "the policy-bearing route 404s; the correctly
targeted route works". It upgrades E7's *infrastructure decoupling*
principle from unprovable to partly proven.

Checkpoint **10/21 (proposed) — "Ingress specification (Section 2.4)
reviewed with Binod and Data Governance; OD-9 decided"** is in three
days and is the one checkpoint that is *entirely* a review, with no
build task of ours gating it. It matters more than its proposed status
suggests, for two reasons. OD-9 decides whether channel I-2 (push
through the gateway) is in scope at all, so until it lands, E2 Task 2.11
and E4's push work are building against a proposed channel. And OD-9's
second half — the owner of upload content scanning — has no candidate
named anywhere in the CONOPS; §2.4.5 says plainly that until it is
named, uploads are accepted in the test environment only. What we can
bring to that review is the class-I route with its six refusals
demonstrated against a stub, which converts "is push feasible" from a
discussion into a demonstration. The ask is dated in §13.8.

Checkpoint **10/23 — "T04-10 package review-ready, including the ingress
specification"** depends on OD-5 (recipient sign-in and token policy),
which is **Open** and owned by Data Governance. The prototype cannot
settle it. What it can do is build both branches far enough that the
decision is cheap whenever it lands, and say so in the package.

**R6, week-4 compression**: six epics overlap in 10/23–10/29. The
mitigation in the CONOPS is "daily plan sequencing; early sign-off
requests; early read of test results". For a one-person prototype the
practical version is to front-load E1, E2 and E6, because E6's IaC makes
every later epic cheaper to rebuild, and because E1 and E2 carry the two
nearest checkpoints.

---

## 10.7 Where the CONOPS and reality already disagree

These go into v1.6 as document defects. They are not local
idiosyncrasies.

| # | CONOPS text | Reality | Detail |
|---|---|---|---|
| D-1 | 3.1, 2.3.1, 3.4: granular access via "a view, **or** column masks and row filters" | Masks and filters are refused outright on any OpenSharing-shared table, at every tier. The remaining limb — the view — is now built and measured, so the defect is a correction to make, not an open question | 11.4; `evidence/entitlement-model.json`; D-1 note below |
| D-2 | AC1 1.3 is proven by T-04 | T-04 as built proves nothing; the column it tests is inside the grant. The replacement mechanism exists; the replacement **test** does not yet | 11.5; D-2 note below; E1 Task 1.7 |
| D-3 | 3.1 "Defense in depth: recipient IP access list" assumed to need a higher tier | Works on Free Edition; README's "Partial" is wrong | 11.3 |
| D-4 | 2.3.2 F1 route at its own edge path | As defined, F1 sits under the sharing listener, so the real path is `/delta-sharing/storage-proxy` | 11.7 B-3 |
| D-5 | 3.8 refers to "the **seven**-step client verification session (Section 5.3)" | 5.3 says "The session follows **eight** steps" and enumerates eight | 5.3, 3.8; E8 |
| D-7 | 3.1 "one recipient per consuming agency or use case", stated once, for all channels | The sentence has **two answers**. Per *use case* it is available on D2O and refused on D2D, because the uniqueness key differs by authentication type. Both halves are measured | 11.7 B-29; `evidence/recipient-model.json` rule 7; D-7 note below |
| D-6 | 2.4.1 step 5, D2O column: "Import the provider from the file … then create a catalog from the share" | The D2D column confirms first (`SHOW PROVIDERS`, `SHOW SHARES IN PROVIDER`); the D2O column does not, and the platform does not enforce the ordering. Import returns 200 without contacting the endpoint, so a catalog **and its grants** are created over an unreachable provider and fail at the consumer's first query | 2.4.1; 11.7 B-14; T-20 |
| D-8 | 3.4.1 orders onboarding: create the recipient, apply the IP access list, **then** deliver the activation link | Step 3 happens **inside the perimeter step 2 just built**. The activation endpoint is itself gated by the recipient's own allow-list: 403 for the allow-listed recipient, 200 for the one without a list, same client, same run, links minted in the same second. The credential cannot be collected from an excluded address, and the CONOPS never says so | 11.7 B-38; `evidence/credential-activation.json`; D-8 note below |
| D-9 | 2.3.2 describes channel E-1 as **one** gateway route with one upstream target, serving all recipients | The sharing endpoint hostname is **per-recipient**, and the platform validates the host↔recipient binding: `400 BAD_REQUEST: Request URL hostname '634cbc18-…' does not match with the recipient id 'aa8b5b00-…'`. A single fixed upstream is wrong for every recipient but one. Either E-1 is per-recipient by nature (and §3.4's onboarding portal must provision a route), or the edge holds a token→host directory, which is the secret-handling surface OD-4 exists to avoid | 11.7 B-42; D-9 note below; T-01 |

### D-9: §2.3.2's single E-1 route cannot exist, because the host is part of the credential

§2.3.2 draws channel E-1 as one Gravitee API with one upstream target and
a plan per recipient. The target is the problem. Each recipient's
credential file carries its own endpoint hostname — `aa8b5b00-…`,
`a7066515-…`, `13ad6c00-…` for the three recipients this repository has
created — and the host is not cosmetic routing. The platform checks it
against the bearer token and refuses the mismatch by name:

```
400 BAD_REQUEST: Request URL hostname '634cbc18-...' does not match
with the recipient id 'aa8b5b00-...'
```

So "one route, many plans" fails on contact. Whichever host the route is
pinned to, every other recipient's token is refused at that host, and the
refusal is correct.

Three ways out, and the CONOPS has to pick one rather than leaving §2.3.2
as drawn.

**One route per recipient.** Buildable today, and it is what the E2 Task
2.1 consolidation will generate. The cost lands on §3.4: a self-service
onboarding portal that creates a recipient now also has to create a
gateway route, so AC4 becomes a deployment step rather than a form
submission. That is a real change to the acceptance criterion's shape,
not just its wording.

**Dynamic upstream resolution.** One route survives, and the gateway
resolves recipient → host at request time. As first written this meant
resolving **token** → recipient → host, which requires the edge to hold a
directory mapping live bearer tokens to hosts — a credential store in the
one component the architecture most wants to keep free of them. OD-4
exists precisely to keep secret custody off the gateway.

*Refined 2026-10-21, and this option is less dead than it first looked.*
The recipient can be selected by **URL slug** rather than by token:
`/opensharing-demo/<slug>/<protocol-path>`, where the slug is a recipient
*name*. A name is not a credential, so the directory the edge holds maps
`slug → host` and contains no secrets at all, and OD-4's objection does
not reach it. The build this repository now runs takes the slug from the
path for exactly this reason — see `route-table.yaml`'s
`what_the_slug_is_not`.

Two costs remain, smaller but real. The slug becomes part of the endpoint
the recipient is handed, so §2.3.2's "edge path equals protocol path" is
no longer true — §3.4.1's promise survives, because the client is handed
the full endpoint and never assembles it. And the edge gains a mapping
that must stay in step with the recipient set, which is an IaC artifact
either way. The practical distance between this option and the first is
therefore shorter than the original framing suggested: both are generated
from `recipients.yaml`, and the real question is whether the generated
artifact is three API definitions or one definition plus a table.

**Declare E-1 per-recipient by nature.** Costs nothing to implement,
because it is what the platform already does. It costs a paragraph in
§2.3.2 and an honest step in §3.4.1.

The recommendation for v1.6 is the third, implemented as the first: say
that E-1 is a route family rather than a route, and generate the family
from `iac/config/recipients.yaml` plus the credential files so that
adding a recipient and adding its route are one versioned change. That is
what AC6 and T-12 ask for anyway — "redeploy from code" — and it removes
the hand-merge of the two live Gravitee definitions that Task 1.6
originally assumed.

Two build consequences follow immediately. **T-01 must be built and
reported per recipient**, reading each endpoint from that recipient's own
credential file; a single-endpoint T-01 would pass or fail for reasons
that have nothing to do with the gateway. And the consolidated definition
is **generated, not merged**: API 1 contributes the right kind of target,
API 2 contributes the perimeter policies, and neither contributes its
host.

One thing the platform got right, and E5 should copy it. The error names
both halves of the mismatch — the hostname received and the recipient the
token belongs to — so the caller can locate the fault without guessing.
That is the opposite of the failure mode in 11.7 B-20, where a verdict
vocabulary too coarse to name the cause defaults to blaming the nearest
component. E5's error contract should require both halves of any
binding failure to appear in the message.

**Status: MEASURED, not inferred (2026-10-21).** D-9 was first written
from an error seen in passing. T-01 phase 2 now tests it deliberately,
and it is the only assertion in this repository whose *expected* result
is a 400: `psp7-demo`'s credential against `psp7-t2-us`'s route, with its
own route as the same-run control, one variable. Control 200, crossed
400, and the refusal named both halves —
`BINDING_ENFORCED_AND_THE_ERROR_NAMES_BOTH_HALVES`. The probe was built
so that a 200 would have **falsified** D-9 and handed §2.3.2 its
single-route model back, which is why it is a probe and not a footnote.
It did not. Evidence: `evidence/t01-gateway-read.json`, `binding_probe`.

### D-8: §3.4.1 delivers the credential inside the perimeter it just built

§3.4.1's three steps are in the wrong order for a reason the section
never mentions. Create the recipient, apply the IP access list, deliver
the activation link: by step 3 the recipient is already behind the
perimeter, and the activation endpoint honours that perimeter. The
measurement is in `evidence/credential-activation.json`:
`awoz1227-t02-iplist-recipient` got 403 on the non-consuming activation
*info* endpoint while `psp7-demo-recipient` got 200, same client, same
process, links minted seconds apart. The only difference between the two
recipients is that one carries a list and one does not.

So the onboarding procedure as written has a step that cannot be
performed by the party it is written for. A consuming agency whose
analysts sit outside the allow-listed range — which is the normal case,
because the range is chosen to admit the gateway, not the analyst's
laptop — receives a link it cannot exchange, and the refusal it sees is
a bare 403 that looks identical to a bad link, a revoked recipient and a
missing grant (§11.7 B-20).

v1.6 has to say which of three things is intended, and none of them is
free:

- **Collect from inside the range.** The link is exchanged by whoever
  operates the allowed egress — the gateway host, or an operator on it —
  and the credential is then handed to the agency by some other channel.
  That other channel needs naming, because it now carries a bearer token.
- **Widen for enrolment.** The list is widened for a stated window,
  the agency exchanges, the list is restored. That is an approval, a
  window and a record, not a footnote, and whoever widens it must also
  re-read the list afterwards to prove the restore happened (§11.7 B-23).
- **Apply the list after enrolment.** Reorder the steps so the perimeter
  lands on an already-credentialed recipient. Cheapest to write and the
  worst to defend: there is then an interval in which the recipient is
  reachable from anywhere, and the CONOPS would be describing a control
  that is deliberately absent at the one moment a credential is in
  flight.

`scripts/28_activate_credential.py --widen-ip-list` implements the
second option, and implements it as a *measurement* rather than a
convenience: it records the list as declared, widens, re-reads, retries
the non-consuming endpoint, and restores and re-reads in a `finally`.
That turns an accidental 403 into an attributed observation, which is
the only form in which it is worth anything — see §11.7 B-33b on why the
before-picture is what makes a later absence attributable.

One scope caveat belongs in the v1.6 text with the finding, because
without it the finding will be over-read. This is an observation about
the **activation** endpoint, not the **data** endpoint. They are
different services that happen to consult the same control, and whether
the data plane enforces the list is T-02's question, measured
separately by `tests/t02_ip_access_list.py`. Reporting D-8 as "the IP
access list is enforced" would be exactly the §12.4 error: a verdict
promoted past what was measured.

### D-7: §3.1's isolation rule, and why one sentence is the problem

§3.1 asks for "one recipient per consuming agency **or use case**". Both
halves of that are now measured, and they disagree.

On the **D2D** channel a recipient carries a sharing identifier — the
consuming metastore — and that identifier is the uniqueness key. A
second recipient for a metastore that already has one is refused with
`RECIPIENT_ALREADY_EXISTS ... with the same sharing identifier`, and the
message names the *other* recipient rather than the one being created
(§11.7 B-29). So two use cases that land in the same consuming metastore
cannot have two recipients, and per-use-case isolation has to be carried
on **shares** instead.

On the **D2O** channel a TOKEN recipient has no sharing identifier, so
the key does not bind. Task 1.5 created a second and then a third TOKEN
recipient for the same logical consumer and all three coexist
(`evidence/recipient-model.json`, rule 7:
`ISOLATION_RULE_DIFFERS_BY_CHANNEL_MEASURED`, three recipients listed).
Per-use-case isolation is available, and `iac/config/recipients.yaml`
expresses it that way — two purposes, two recipients, two shares.

The defect is not that either behaviour is wrong; both are reasonable
platform designs. The defect is that the CONOPS states the control once,
channel-agnostically, which is the worst available shape for it.
Whoever implements the D2D half will read a sentence that promises
per-use-case recipients, build it, and receive an error naming an object
they never touched. v1.6 needs the rule split by channel, with the D2D
row saying plainly that isolation lives on shares there and that the
error message points at the wrong object.

Worth noting what this measurement cost: nothing extra. Rule 7 reads the
authentication types that rule 1 already collected, so the second answer
came out of applying the configuration rather than out of another probe.

### D-1 after E1 Task 1.4: the surviving limb is measured, provider-side

§11.4 killed two of the three mechanisms the CONOPS offers. Task 1.4
built the third and ran it, so D-1 is no longer "the CONOPS offers
something that does not work" — it is "the CONOPS offers three things,
one works, and the sentence has to be rewritten to say so."

What the run holds (`evidence/entitlement-model.json`): both views exist
with explicit select lists (rule 2 `EXPLICIT_SELECT_LIST`), the stored
definition is character-identical to the one in
`iac/config/entitlements.yaml` (rule 2b `EXACT`), the withheld column
set matches the config (rule 3 `EXACT_MATCH`), each view carries its DSA
reference in its comment (rule 4 `DSA_REF_CARRIED`), the base table is
in **no** share across all four shares on the metastore (rule 1
`BASE_TABLE_IN_NO_SHARE`), and the row scope is a measured ratio rather
than an assertion — 50 rows through `v_entitled_t2`, 16 through
`v_entitled_t2_us` (rule 5 `ROW_SCOPE_MEASURED`). Apply outcome is
`APPLIED` with both views `UPDATED` via `ALTER VIEW`, which is the part
that matters for AC6: the model is not merely creatable on a blank
metastore, it is **reproducible** against one that already holds it. The
first version of the applier was not, and said nothing about it (11.7
B-32).

The bound: every one of those rules is a provider-side observation. The
verdict says `..._PROVIDER_SIDE` for that reason. Nothing here shows a
consumer reading the view through a share on a live credential, so the
claim this evidence supports is *the provider can express the
entitlement and hold it across a redeploy* — not *the recipient sees
only the entitled columns and rows*. Writing the second sentence from
this evidence would be the §12.4 error again.

### D-2 after E1 Task 1.4: half-closed, and the open half is named

D-2 is precisely that missing second sentence. The mechanism now exists;
the test that would prove the consumer's view of it does not. T-04 as
built asks whether a withheld column is invisible, while granting the
recipient the table that contains it, so it would report the same
`not found` whether the mechanism worked or the grant was simply
mis-read — a silent negative of the kind §12.9 catalogues.

The rebuilt T-04 belongs to E1 Task 1.7 and has a shape fixed by this
evidence: share only `v_entitled_t2` / `v_entitled_t2_us`, activate a
recipient credential, and assert from the **consumer** side that
`internal_notes` is absent from the schema, that selecting it fails, and
that the row count is 16 and not 50. The 50/16 split is doing real work
there — it is the discriminator that makes a row-scope failure visible
instead of plausible. Until that runs, D-2 stays open and AC1 1.3 stays
unproven, whatever the provider-side verdict says.

### D-6 in full, because it is the one with a remediation

§2.4.1's two columns do not ask for the same amount of proof. The D2D
column reads *"Confirm the provider with `SHOW PROVIDERS` and `SHOW
SHARES IN PROVIDER`, then create a catalog from the share."* The D2O
column reads *"Import the provider from the file …, then create a
catalog from the share."* The confirming call is in one column and
absent from the other.

Before T-20 ran, that asymmetry had two readings. If the platform
refuses to create a catalog over a provider it cannot reach, the
omission is a documentation tidiness issue and nothing more. If it does
not refuse, the D2O procedure as written produces a broken deliverable
that looks complete at every step.

It does not refuse. T-20 recorded `5a IMPORTED (200)`,
`5b REFUSED (400, SecurityException)`, then **`5c CREATED (200)`** and
**`6 GRANTED (200)`**. The catalog exists, carries `USE CATALOG`,
`USE SCHEMA` and `SELECT`, and appears in the consuming team's
namespace. Every ticket closes green. The failure surfaces at the
requester's first `SELECT`, by which point the operator who imported the
credential, the governance approver, and the security approver who
cleared the allow-list entry have all signed off and moved on.

This is the §12.9 silent-negative shape at procedure level rather than
code level: **a step that cannot verify its own precondition reports the
same output as a step that verified it and passed.**

Remediation for v1.6, which is small: promote the confirming call into
the D2O column as a **required gate**, worded so the operator stops
rather than continues — `SHOW SHARES IN PROVIDER <name>` must return at
least one share before step 5's second half is attempted. It costs one
command. It converts a failure found by the consumer into a failure
found by the operator who can still fix it, and it is the only point in
§2.4.1 where the endpoint inside the credential file is proven reachable
at all.

Keep this table growing. A prototype whose only output is "it worked on
my laptop" is worth far less than one that returns a short list of
things the design document gets wrong.

---

## 10.8 Starting conditions

Before Epic 1, confirm you can get a clean result from all five:

```bash
cd ~/Documents/awoz-1227-opensharing-demo
pip install -r requirements.txt --break-system-packages

python3 scripts/00_check_capabilities.py          # 4 x ok:true + provider verdict
docker compose ps                                 # 6 services up
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8083/management/v2/environments/DEFAULT/apis/_search
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:8082/delta-sharing/shares
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOK" \
     http://localhost:8082/opensharing-demo/shares
```

The fourth is expected to be **404** and the fifth **200**. That pair
*is* blocker B-1 in one line: the same gateway, two APIs, one with the
wrong upstream target. If the fifth returns 200 with a share list, the
gateway is healthy and E2 Task 2.1 is a merge rather than a repair.
Everything else should be green before
we start.
