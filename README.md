# AWOZ-1227 — OpenSharing + Gravitee: end-to-end CONOPS validation

A single-operator but **fully closed-loop** implementation of the ingress
and egress paths specified in **CONOPS AWOZ-1227 v1.5** (*OpenSharing and
Gravitee API Gateway Integration*, INC17 / Milestone AWOZ-1227), built
across two Databricks metastores, an open-source OpenSharing provider,
and a local Gravitee APIM 4 CE stack.

Three things are being produced at once, deliberately.

A **working prototype**, so that claims about the design rest on observed
behaviour rather than on documentation. The **versioned IaC and CaC
artifacts** that AC6 (1227-E6) and its test T-12, *"redeploy from code
onto a clean target"*, require — anything proven by hand that does not
end up in `iac/` has not really been proven, because it cannot be
rebuilt. And **the evidence base for CONOPS v1.6**: every correction,
confirmed assumption, closed risk and exercised decision this build
produces is written back into the document, so that what is eventually
delivered to the client is a specification that has been run rather than
reviewed.

That third output is the reason this exercise is worth doing at full
depth. A CONOPS that has been executed end to end — including the parts
that fail — is a different instrument from one that has been circulated
for comment.

**Start here:** [`docs/10-implementation-manual.md`](docs/10-implementation-manual.md).
It is the entry point, the document index, and the statement of working
method. Read it before running anything.

## What changed on 10/18: the test topology closed

Until now the prototype had two holes that no amount of local work could
fill, and they were the two that mattered most, because between them
they made **all of ingress** and **one whole egress channel**
unevidenced:

- **No second metastore.** Databricks-to-Databricks sharing is
  metastore-to-metastore, so one Free Edition workspace cannot play both
  parties. This blocked T-19 outright, and §2.1 leaves channel **E-2**
  at *"Documented; tested if a test recipient exists"* — no test
  recipient, no tested channel.
- **No external open-protocol provider.** The D2O ingress path needs
  somebody *else* running an OpenSharing server. Without one, T-20 and
  T-23 could only be described.

Both are now closed, with a second Unity Catalog metastore
(**`glovashu`**, its own token) standing in as the partner Databricks
organisation, and an **open-source OpenSharing server** holding
Delta tables versioned in GitHub standing in as the open-protocol
provider.

The consequence is larger than three test verdicts. The platform can now
be **provider and recipient at the same time, by both mechanisms**, which
is what the CONOPS actually specifies and what no previous iteration
could demonstrate:

| Channel | Mechanism | Who plays the far side | Status before | Status now |
|---|---|---|---|---|
| **E-1** egress D2O | Open-protocol client reads our share through Gravitee | `delta-sharing` client | Baseline, working | Working |
| **E-2** egress D2D | A Databricks consumer reads our share via its own metastore | **second-account metastore** (`8875961b-…`) | *Documented only* — and with **no numbered test in §5.2** | **Confirmed exercisable**; proposed test for v1.6 |
| **E-3** egress API/MCP | External app calls model service or MCP server | — | Probe | Probe (unchanged) |
| **I-1** ingress pull, D2D | We read a share published by another Databricks org | **second-account metastore** (`8875961b-…`) | Not simulable | **Confirmed testable** (T-19, BUILD) |
| **I-1** ingress pull, D2O | We read a share from an open-protocol server | **OSS server + GitHub** | Stand-in only | Real provider (T-20, T-23) |
| **I-2** ingress push | Producer uploads through the gateway | local producer client | Proposed (OD-9) | Proposed; refusals testable |

**D2D on Free Edition is now confirmed, both ways** (2026-10-18, Epic 1
Task 1.2). The two accounts resolve to genuinely distinct metastores —
`48cda780-…` and `8875961b-…`, both in `aws:us-east-2`, which establishes
that a Free Edition metastore is provisioned per *account* per region
rather than per region — and this tier **does** permit a recipient with
`authentication_type = DATABRICKS`: one was created and deleted cleanly
against the sharing identifier `aws:us-east-2:8875961b-…`. T-19 is
therefore **BUILD**, and AC3 becomes the second acceptance criterion
after AC6 that closes end to end with no partner and no paid tier. The
first run of that probe returned the opposite verdict and was withdrawn;
the retraction and the four defects it exposed are documented in
`docs/12-test-matrix.md` §12.9, which is worth reading as a method note
rather than an erratum.

One caveat remains, stated here rather than discovered later. The
**outbound host list**
captured from the OSS provider in T-20 proves the *method* for building
an allow-list, which §2.4.3 says Databricks does not document, but the
captured hosts themselves are local and do not transfer to the client
environment. The procedure is the deliverable there, not the list.

## The four-party topology

What runs locally is no longer a prototype of one side of a boundary. It
is both sides of two boundaries:

```
          ┌──────────────────── the platform (WDP stand-in) ────────────────────┐
          │  Databricks workspace A — metastore 48cda780…                       │
          │  catalogs, schemas, entitlement views, shares, recipients,          │
          │  landing volume, read-only shared catalogs from providers           │
          └───────┬───────────────────────────────────────────────┬─────────────┘
                  │                                               │
     egress E-1/E-3│  (Gravitee fronts it)         ingress I-1 pull│ (outbound; Gravitee cannot front it)
                  │                                               │
          ┌───────▼─────────────────┐                   ┌─────────▼──────────────┐
          │  Gravitee APIM 4 CE     │                   │  providers             │
          │  routes S1–S10, F1,     │                   │  • glovashu metastore  │ D2D
          │  M1–M3, A1, deny-all X  │                   │  • OSS OpenSharing     │ D2O
          │  policy classes A–E, I  │                   │    server + GitHub     │
          └───────┬─────────────────┘                   └────────────────────────┘
                  │                                               ▲
   consumers      │                                  egress E-2   │ (outside the gateway, per OD-6)
   • delta-sharing client  ◄───────────────────────────────────────┘
   • push producer (I-2) ──► PUT /ingest/{producer}/{file} ──► landing volume
```

The asymmetry in that picture is the whole design, and the next section
is about why it is not a flaw.

GitHub carries three distinct loads here, and only the first is obvious.
It versions `iac/`, which is what makes T-12 *"redeploy from code onto a
clean target"* a real test rather than a hypothetical one. It holds the
OSS provider's Delta tables and server configuration, so the external
provider is itself reproducible — clone the repository and the far side
of the ingress boundary exists again. And it is the artifact that proves
the **Infrastructure decoupling** principle in §6: a configuration that
can be rebuilt from a repository onto different infrastructure is the
evidence for that claim, which E7 previously had to argue rather than
show.

One design note on the OSS provider, because it decides whether T-08's
storage-side half is demonstrable. The reference OpenSharing server
hands clients **pre-signed URLs** for the data plane, exactly as
Databricks does, and pre-signed URLs are what make storage part of the
perimeter. If the server will serve Delta tables from a local filesystem
path, the simple setup is enough for T-19/T-20's control-plane
behaviour; if it requires object storage for pre-signed URLs, the
compose stack grows an S3-compatible store (MinIO). The second shape is
worth preferring **even if the first works**, because owning the storage
is the only way to demonstrate a storage-side refusal — the half of T-08
that Databricks-managed storage will never let us test. That is a
genuine evidence gain, and it is the kind of thing this topology makes
available for the first time.

## One person, many hats — and the line the method must not cross

This build is run by one person wearing every role the CONOPS names:
CONOPS owner and AI/ML Ops, Data Governance approver, metastore admin,
catalog owner, credential custodian, security approver, Data Tooling,
the external provider, the push producer, and the consuming team. That
is what makes an end-to-end run possible at all. It is also the thing
most likely to be challenged when this reaches the corporate side, so
the method has to be explicit about what wearing a hat can and cannot
produce.

Three tiers, and every artifact in `evidence/` belongs to exactly one:

**Exercisable — produces evidence.** Process steps genuinely under this
operator's control: requesting and approving a share against a DSA
reference, exchanging sharing identifiers, vaulting a credential file,
creating catalogs and granting to groups, rotating and revoking,
capturing outbound hosts, deploying from code and tearing down. Wearing
two hats across a handoff does not weaken the result, because what is
being tested is whether the *mechanism* works and whether the
*procedure* is complete enough to follow. These produce `PASS` or `FAIL`
records and they are the backbone of the v1.6 evidence base.

**Proposable — produces a recommendation, never a decision.** Decisions
whose real owner sits in another team: OD-5 (sign-in and token policy,
Data Governance), OD-6 (D2D outside the gateway), OD-9 (push scope and
the content-scanning owner), OD-4 (credential issuance, Data Eng). Here
the operator builds **both branches**, runs them, records the trade-off
with measurements attached, and brings a recommendation labelled
**proposed**. A decision exercised locally is evidence *for* a decision;
it is not the decision. Keeping that label honest is what makes the
recommendation persuasive rather than presumptuous — the leadership
conversation is "here is what each branch costs, measured", not "I
decided this already".

**Irreducible — stays open, and becomes a dated ask.** Things no hat can
manufacture. The CDAO PSP7 team's independent judgement, which is why
**T-13 remains PARTNER**: a self-run rehearsal of the onboarding
walkthrough is useful preparation and is *not* T-13, because the test is
defined as another organisation's people succeeding or failing at it.
The ARB template (1694-G2). The correlation-ID propagation contract
across systems this operator does not own (1694-E4). Real agency address
ranges. A named security owner for upload content scanning. IL5
accreditation. These are listed with dates in §13.8, and the point of
closing everything else is that **this list is what leadership is asked
to resolve** — a short list of genuine external dependencies, rather
than a long list that mixes them with things that were merely not done.

That distinction — exercisable, proposable, irreducible — is the single
most useful thing to carry into the corporate discussion, because it
answers the first question that will be asked: *how much of this is
real?*

## Both directions, and why they are not symmetrical

The CONOPS covers **egress** (the platform is the provider; external
consumers read shares) and **ingress** (the platform is the recipient,
or receives a push). These are not mirror images, and the asymmetry is
the most important thing to understand before reading the route table,
because it decides where each control can physically live.

**Egress — channels E-1, E-2, E-3.** Gravitee fronts E-1 and E-3. The
consumer's client reads a credential file whose endpoint has been
rewritten to the gateway edge (OD-4), so every discovery, query and
credential-vending call lands on a policy-bearing route: S1–S10 for the
sharing protocol, F1 for file download, M1–M3 for model and MCP
services, A1, and a deny-all X. One caveat is structural — the protocol
sends recipients **directly to storage** for the data plane, so
storage-side controls are part of the perimeter and the proxied-download
decision (OD-1(b)) has to be proven, not assumed (T-08). **E-2 is
deliberately outside the gateway** (OD-6): a Databricks consumer reading
through its own metastore has no interception point, so its controls are
share grants, the recipient metastore identifier and audit. That is a
defensible design, but it means E-2's assurance rests entirely on
Databricks-side controls — which is precisely why it needs a test of its
own, and why the absence of one in §5.2 matters.

**Ingress by pull — channel I-1, the baseline.** Gravitee fronts nothing
here, and *cannot*: the platform opens the connection itself, and a
reverse proxy cannot front an outbound call. The control moves to the
outbound side — an allow-list covering the approved provider endpoint
and the storage hosts serving pre-signed URLs — plus a read-only shared
catalog and Unity Catalog grants by group. What makes this real work
rather than a config line: **Databricks does not publish the
recipient-side firewall requirements**, so the allow-list must be
*discovered* by capturing the hosts actually contacted (T-20) rather
than written from documentation (§2.4.3). D2D exchanges no secret at
all; D2O puts a credential file in the vault under a named custodian who
has no need to read the data.

**Ingress by push — channel I-2, proposed (OD-9).** Same rule as egress:
the only public surface is the gateway, and the producer never holds a
Databricks credential. One route, `PUT /ingest/{producer}/{file}`, under
**policy class I** — 10 per minute, 1 per second, 500 uploads a day, a
100 MB starting cap, content types allow-listed, path patterns rejecting
traversal and encoded forms, `overwrite=false` forced, and PUT only so
there is no read-back. The gateway holds the sole upstream credential: a
service principal with write access to one landing volume and no read
access to curated data.

Two things about I-2 are unverified rather than merely unbuilt. Whether
the gateway can inject **and refresh** a short-lived Databricks OAuth
token while rewriting the path is risk **R12**, and the CONOPS names its
own fallback — a thin ingest service in front of the Files API, with the
producer-facing contract unchanged. The new topology helps here: the
token-injection-and-refresh mechanism can be exercised against the OSS
provider as upstream even if Free Edition withholds a service principal,
which separates "the gateway cannot do this" from "this tier will not
let us try". And content scanning is a platform security capability with
no named owner, the open half of **OD-9**; until it is named, §2.4.5
confines uploads to the test environment.

After landing, both pull and push converge on the same obligations
(§2.4.4): zero-copy read in place, a landing copy only where retention
or transformation requires it, schema, count and freshness validation
with failed loads quarantined where consumers never see them, refresh at
the agreed cadence, and rotation and revocation that drop the catalog
and the provider object together.

## Honest coverage: 25 tests, 16 conclusive, zero stand-ins

This is the number that matters, and it is the reason the test matrix
exists as its own document. Of the twenty-five tests in CONOPS §5.2:

| Verdict | Was | Now | Meaning |
|---|---|---|---|
| BUILD | 11 | **15** | Buildable and conclusive in this environment |
| REBUILD | 1 | 1 | Exists but proves nothing as written (T-04) |
| PARTIAL | 7 | 7 | One half provable, the other needs tenant or partner capability |
| PROBE | 2 | **1** | Depends on an unconfirmed feature; probe first (T-16 only) |
| STANDIN | 2 | **0** | — |
| PARTNER | 2 | **1** | Needs another organisation; cannot be simulated honestly |

Five verdicts moved, and the shape of the change matters more than the
count. **T-15 goes PROBE → BUILD**, settled by a probe that ran the same
day: a model service answered HTTP 200 through an automatable endpoint
list, so what remains on it is route-building rather than capability.
**T-20 and T-23 go STANDIN → BUILD**: a real open-protocol
provider now exists, so importing a credential file from the vault,
reading through the connector, capturing the hosts contacted and
rotating the provider's token are all genuine operations rather than
substitutes. **T-19 goes PARTNER → PROBE → BUILD** in a single day: it was never
blocked on another organisation, only on two local capability questions,
and the probe answered both yes — distinct metastores, and a
`DATABRICKS`-auth recipient accepted on Free Edition. **The STANDIN
category is now empty**, and the single remaining PARTNER is T-13, which
is irreducible by definition rather than by circumstance.

Of the seven ingress tests T-19 to T-25, **five are now conclusive
here** — T-19, T-20, T-21, T-22 and T-23 — where previously only two
were. That is the single biggest evidence gain available to this
project, and it lands on the direction the CONOPS was weakest in.

One pattern runs through all five moved verdicts and is worth carrying
into the corporate discussion on its own: every one of them was blocked
by an assumed tier limitation that turned out, when actually probed, not
to exist. Model serving, a second metastore, and an operator-run
open-protocol provider were all written off before being tested. The
lesson generalises past this milestone — **an untested tier limit is not
a finding** — and it is the reason this prototype probes before it
classifies.

**AC1 is still the criterion with the most exposure** — eleven tests and
the broadest requirement phrases — but it is no longer the case that six
of them need something unavailable. Its two AI-route probes improved on
the same day for an unrelated reason: see *The AI surface* below. What
is left on AC1 is one storage-side refusal it cannot stage and one
upload permission, which is a far narrower exposure than the test count
suggests. Per-criterion detail is in §12.4, with per-test reasoning in
§12.3.

## What this environment still cannot evidence

Shortening this list is the point of the exercise, so it is worth
keeping it visible and exact:

| Gap | Blocks | Why it cannot be closed here |
|---|---|---|
| ~~Model serving and Unity Gateway MCP on Free Edition~~ | ~~T-15, T-16~~ | **Removed 2026-10-18 — the surface exists on this workspace.** See *The AI surface* below. What remains is one invocation, not a tier limit, so this is no longer a gap of this kind |
| Service principal with `WRITE VOLUME` | T-24's successful upload | Tier capability, unconfirmed. The six *refusals* are buildable now |
| Correlation-ID propagation contract (1694-E4) | T-11, T-25 (PARTIAL) | A contract across systems this operator does not own. §3.5 calls it the biggest unknown |
| `system.access.audit` reachability | the Databricks half of tracing | Tier capability, to be probed |
| ARB template (1694-G2) | all of E7 | Not yet supplied; T04-14 opens 10/30 |
| CDAO PSP7's own run | T-13 (PARTNER) | Another organisation's independent judgement |
| Named content-scanning owner | T-24, OD-9 | A security capability with an owner, not a gateway policy |
| Real agency address ranges | production allow-lists | Out of scope per §1.2; documentation CIDRs stand in |
| IL5 posture | §3.6's six rows | Out of scope; requirements are *collected* in E6 and handed on |

Everything on that list is either a tier capability, a document, or
another organisation's judgement. None of it is work that was simply
skipped, and that is the claim this README is trying to be able to make
honestly.

## The AI surface: present, and wider than the CONOPS describes

**Confirmed by console inspection, 2026-10-18.** The Unity Gateway page
is live on this workspace at `/ml/ai-gateway`. Thirteen models are
registered and governed — `gpt-oss-120b`, `gpt-oss-20b`,
`qwen3-next-80b-a3b-instruct`, `llama-4-maverick`,
`meta-llama-3-3-70b-instruct`, `gemma-3-12b`, the `gte-large-en` and
`bge-large-en` embedding models among them — all located in `system.ai`
except `databricks-genie`, which is workspace-located. The page carries
five tabs: **Models, Providers, MCPs, Skills, Agents**, a `+ Model`
button for registering external providers, and a per-model
**Configuration** column.

This changes the AI routes from the weakest part of the local position
to one of the better-evidenced ones, and it changes four things in the
document set.

**R11 was wrong about this tier, and A8 is no longer the expected
outcome.** R11 reads "Unity AI Gateway / Unity Gateway MCP features
beta, disabled, or unavailable" and the local note said *likely to
bite*, expecting T-15 and T-16 to land as `NOT_RUN` under the A8 escape
hatch. The gateway is neither absent nor hidden behind an account
console this tier does not have. A8 stays in the register as a genuine
fallback — it is good drafting and it still covers the Gov-region half
of R11, which this environment cannot speak to at all — but the
*expected* path is now a pass.

**Then the probe ran, and invocation is confirmed too.**
`scripts/08_probe_ai_gateway.py` returned `WORKS`:
`/api/2.0/serving-endpoints` lists twelve endpoints to an automation
token, and `databricks-gpt-oss-20b` answered **HTTP 200**. That settles
T-15, which becomes **BUILD** — the remaining work is route-building,
not capability. It also settles something the console could not: the
surface is *automatable*, not merely governable by hand, which is what
AC6's "redeploy from code" needs on the AI routes.

**T-16 stays PROBE, and the reason is worth keeping.** Both guessed MCP
paths returned `404 ENDPOINT_NOT_FOUND` to an authenticated token. That
is not a refusal and not a permission error — the API simply is not
there — while the console plainly shows an MCPs tab. The honest reading
is that the tab is backed by a path the probe did not guess, so the
question is open rather than answered either way.

**Three things in the probe output matter more than the pass**, and all
three are recorded in §12.7 because each would otherwise surface late,
during route building, when it costs more:

- The response shape is **not** the classic OpenAI contract.
  `choices[0].message.content` came back as an array of typed blocks
  beginning with a `reasoning` block, not a string. Any gateway
  body-schema written against `content: string` will reject valid
  responses — the same class of mistake as blocker B-1, now caught
  twice on two different protocols.
- The call was **truncated**: `finish_reason: length` at
  `max_tokens=16`, with reasoning consuming the whole budget before any
  answer text. The path is proven; the payload is not yet captured.
  Reasoning tokens also bill against quota, which bears on the class E
  limit values.
- Console and API **disagree on inventory**, 13 against 12. The extra
  console row is `databricks-genie`, workspace-located rather than
  `system.ai` — a different object type sharing the same governed
  surface, with no row anywhere in the §3.1 access matrix.

**The real finding is architectural: there are two gateways in the E-3
path.** Unity Gateway is not a passive model registry. The per-model
Configuration column and the token accounting mean it is itself a policy
enforcement point — permissions, usage limits, and the guardrails
§3.1.2 refers to. Channel E-3 therefore runs consumer → Gravitee →
Unity Gateway → model, with **two independent places a request can be
refused and two independent places it can be rate-limited**. OD-8
already proposes this layering, and §3.1.2 already gives the reason the
legacy `/api/2.0/mcp/*` route must stay closed — it bypasses Unity
Gateway grants, policies and guardrails, and its calls never reach the
tracing tables. What neither §5.2 nor OD-8 supplies is a test for
**which gateway refuses first, and what the consumer sees when they
disagree**. A consumer who trips Gravitee's class E limit and a consumer
who trips a Unity Gateway token limit should not receive two unrelated
error shapes, and right now nothing in the CONOPS says they won't. That
question belongs to AI/ML Ops, it is answerable here, and it is the
strongest single contribution this workspace can make to v1.6.

**The surface is wider than the CONOPS's model of it.** §2.1 describes
E-3 as the API/MCP channel, and §3.1.2 discusses model serving and MCP.
The console shows **Skills** and **Agents** as first-class governed
objects alongside them, and an *Agent Integrations* panel described as
managing access for coding agents. None of those three appear in the
five-channel model. That is not a defect in v1.5 — the platform moved —
but a v1.6 that still describes E-3 as "model serving and MCP" will be
describing a narrower surface than the one the client is actually
required to govern, and the access matrix in §3.1 will have no row for
two object types that carry real entitlement.

**One opportunistic lead on the audit problem.** The banner on this page
states that model services now live in Unity Catalog with permissions,
lineage and cross-workspace governance, and the page tracks tokens
per model over a rolling window. If that accounting is queryable, the
AI routes may have a usage record that the Delta Sharing routes do not
— which would not solve 1694-E4's correlation-ID contract, but could
give T-11 a *second* join key to try on at least one channel. Worth
fifteen minutes in Task 1.9 before it is written off; not a claim until
a query returns rows.

## Feeding CONOPS v1.6

The build's second output is a correction register. These are the
document changes this work has already earned, each with evidence
behind it rather than an opinion:

| # | v1.6 change | Basis |
|---|---|---|
| 1 | **Granular access on shared data is view-based only.** §3.1, §2.3.1 and §3.4 offer "a view, **or** column masks and row filters"; masks and filters are refused outright on any OpenSharing-shared table, at every tier | Live refusal with error code; §11.4, OD-11 |
| 2 | **Correct the sharing endpoint host form.** The issued endpoint is `https://<uuid>.opensharing.<region>.cloud.databricks.com/api/2.0/opensharing/metastores/<id>`, not a `delta-sharing` path on the workspace host. An API definition built on the assumed form 404s | B-1 reclassification, §11.7 |
| 3 | **§3.4.1 step 4 must rewrite *every* endpoint field, not "the endpoint".** A credential file also carries `icebergEndpoint`; leaving it unrewritten lets a client bypass the gateway entirely — the exact failure OD-4 exists to prevent | Found in the live credential files; detail in the Epic 1 handover |
| 4 | **Recipient IP access lists work on Free Edition.** The assumption that they need a higher tier was wrong, and a "Partial" verdict rested on it | §11.3 |
| 5 | **Add a test for channel E-2.** §2.1 says every channel has "one set of tests"; E-2 has none in §5.2, and its status is conditional on a test recipient that now exists | §2.1, §5.2 gap |
| 6 | **Resolve the step-count contradiction.** §3.8 says the client verification session has seven steps; §5.3 enumerates eight | Defect D-5, §10.7 |
| 7 | **Correct F1's path.** As defined, F1 sits under the sharing listener, so its real path is not an independent edge path | Defect D-4, blocker B-3 |
| 8 | **Document the outbound allow-list *procedure*.** Since Databricks does not publish recipient-side firewall requirements, v1.6 should carry the capture method as a reusable step | §2.4.3, T-20 |
| 9 | **Carry the two Gravitee configuration traps as deployment notes.** Discrete Elasticsearch host/port properties, and gateway-side Mongo properties without which rate-limit and spike-arrest requests hang until timeout | Both diagnosed live; see *Running it* |
| 10 | **Close A10 and R14.** A test provider for ingress is no longer an assumption — both a second metastore and an open-protocol server exist | This topology |
| 11 | **Add a test for gateway precedence on E-3.** With Gravitee and Unity Gateway both able to refuse and both able to rate-limit, §5.2 needs a test for which refuses first and whether the consumer sees one coherent error contract or two | Two enforcement points, confirmed; OD-8 names the layering but no test covers it |
| 12 | **Widen E-3 beyond "model serving and MCP".** Skills and Agents are governed objects on the same surface, with an agent-integration path for coding agents. §2.1, §3.1.2 and the §3.1 access matrix each need rows they do not have | Console inspection, 10/18 |
| 13 | **Downgrade R11 and re-scope ask 9.** R11's "beta, disabled or unavailable" does not describe this tier; what survives is the Gov-region question alone. Ask 9's model-serving and MCP clauses are self-served, leaving only the service-principal clause | Probe, 10/18 |
| 14 | **Specify the model response contract.** `choices[0].message.content` is an array of typed blocks including `reasoning`, not a string. A gateway body-schema written against the assumed OpenAI shape rejects valid responses — the same failure mode as B-1, on a second protocol | Live 200 response; §12.7 |
| 15 | **State that reasoning tokens bill against the class E budget.** §2.3 picks limit values; a reasoning model can spend an entire token budget before emitting any answer text, which changes what a sensible limit is | `finish_reason: length` at `max_tokens=16` |
| 16 | **Give §2.3.2 a row per rewritten endpoint.** Correcting step 4 to "every endpoint field" means every rewritten field needs a route or an explicit deny. Today `/iceberg` has neither and survives only on the deny-all — safe, but by accident rather than by decision. M3 is the precedent for naming a refusal instead of inheriting one | §12.8 |

Items 1 through 4 are corrections of statements that are currently
wrong. Items 5 through 7 are internal inconsistencies. Items 8 and 9 are
knowledge the document does not yet carry and that cost real debugging
time to acquire. Items 11 and 12 are different in kind and are the most
valuable of the thirteen: they are not corrections of v1.5 but places
where the **platform has moved since v1.5 was written**, and a document
that governs an AI surface has to track that surface or it silently
under-scopes the thing it is meant to control. That is exactly the
material that makes a v1.6 stronger than a v1.5 at delivery.

## Current state

The Gravitee stack is up and **proxying the open protocol correctly** —
a recipient token against the edge returns a real share list. Blocker
B-1 was reclassified on 2026-10-18: the 404 that looked like a broken
gateway is an *upstream target error* on a second API definition built
against an assumed Databricks URL rather than the endpoint issued in the
credential file. See §11.7; converging the two API definitions into one
is the first task of Epic 2.

**Response header sanitization is currently failing.** The working route
returns `server: databricks`, `server-timing`, `x-request-id` and three
`X-Gravitee-*` headers. T-07 is a found-and-fixed control, not a clean
sheet (E2 Task 2.8).

**On the ingress side there is no code yet.** Everything from T-15 to
T-25 — both ingress channels and both AI routes — is unimplemented, and
the previous iteration's scripts stop at egress (§12.5). What has
changed is that this is now a queue of buildable work rather than a list
of unavailable capabilities.

**There is no git repository yet**, which is both a gap and the reason
T-12 has never been meaningful: `.gitignore` exists but nothing is
versioned, so "redeploy from code" has no code to redeploy from. This is
the first item in the Epic 1 handover, ahead of the secret-hygiene fixes
it interacts with.

## Repository layout

```
docs/                   The documentation set above
docs/epics/             One playbook per epic, E1 to E8
iac/databricks/         Terraform: catalog, schema, views, shares, recipients,
                        grants (egress) and landing volume, ingest jobs,
                        provider objects, read-only shared catalogs (ingress)
iac/gravitee/           Generated V4 API definition, body schemas, shared policy groups
iac/config/             CaC: channels (E-1..E-3, I-1, I-2), route table incl. the
                        class-I ingest route, policy classes, egress allow-lists,
                        the generated outbound allow-list, token policy
provider/               The open-protocol provider: server config, Delta table
                        artifacts, and its compose service — the far side of I-1
scripts/                Provisioning and probe scripts, including
                        08_probe_ai_gateway.py — settles whether the AI
                        Gateway invokes, and separates quota refusal from
                        unavailability so the two are never conflated
tests/                  One file per test, each emitting an evidence record
evidence/               Evidence records and captures — committed
_secrets/               Credential files and tokens — mode 0600, never committed
```

`.env` and `_secrets/` are gitignored. Secrets appear in IaC only as
`.env` or vault references, per §3.6. The second workspace's token is a
second set of credentials under the same rule — `glovashu` is a party to
the test, not an exception to the custody policy.

## Running it

Do not run the old script sequence end to end; several scripts predate
the findings above and are being rebuilt epic by epic. `docs/10` §10.8
gives the five commands that establish starting conditions, including
the one-line reproduction of blocker B-1.

```bash
pip install -r requirements.txt --break-system-packages
docker compose up -d
cp .env.example .env     # fill in both workspaces and the provider
python3 scripts/00_check_capabilities.py
```

Two Gravitee configuration traps are already fixed in
`docker-compose.yml` and must survive any clean-target rebuild under
T-12. Elasticsearch needs the discrete `gravitee_ds_elastic_host` and
`_port` properties, because `analytics.elasticsearch.endpoints[0]` is
not a key in this schema, is silently ignored, and leaves services
pointed at `localhost:9200`. And the gateway needs
`gravitee_ds_mongodb_host`, `_port` and `_dbname`, because the
rate-limit and spike-arrest policies build their own Mongo URI —
without them, every request touching one of those policies **hangs
until timeout** rather than erroring, which is considerably harder to
diagnose.

## Scope

In scope: the OpenSharing, Gravitee and Unity Catalog path for egress
and ingress, built and tested across two metastores and an open-protocol
provider, with the IaC and CaC artifacts to redeploy it, an honest
account of which of the nine acceptance criteria this environment can
and cannot evidence, and the correction register for CONOPS v1.6.

Out of scope, and correctly so per CONOPS §1.2: the client's Databricks
test environment, real agency address ranges, the DSA instrument itself,
the ARB template (dependency 1694-G2, not yet supplied), IL5 and
production. What needs a person rather than a commit is listed as dated
asks in §13.8 — and the aim of this build is that the list stays short
and every item on it is genuinely external.
