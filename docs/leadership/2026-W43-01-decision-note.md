# 2026-W43 · Note 01 — Decision note

**For:** ARB · Data Governance · the CONOPS owner's peer group
**From:** AWOZ-1227 prototype, E1 (T04-10, AC1)
**Cut:** 2026-10-22 · **Read time:** ~10 minutes

---

## The ask, up front

Five corrections to CONOPS v1.5, four of which are documentation and
**one of which is a disclosure**. Plus two decisions that this prototype
cannot make and should not be left holding.

Each item below is a measurement, not a preference. Each names the
evidence file, so any of them can be disagreed with on the facts.

---

## 1. A view edit is not a revocation mechanism — and §3.4.1 implies it is

**This is the one item on this page with a security consequence.**

The entitlement model works by sharing *views* rather than base tables,
with a row predicate controlling what a recipient sees. That design is
sound and E1 confirms it. What E1 also measured is what happens when you
**narrow** that predicate to take rows away from a recipient:

| | Provider's own catalog | The live consumer |
|---|---|---|
| Predicate as shipped | 16 rows | 16 rows |
| Predicate narrowed | **8 rows** | **16 rows**, held for 600 seconds across 19 reads |
| Predicate restored | 16 rows | 16 rows |

The eight rows that were just taken out of scope **remained readable by
the recipient** for the full ten-minute observation window. And nothing
on our side looked wrong while that was true: the catalog reported the
narrow definition, the applier reported `APPLIED`, and the entitlement
model's own conformance rule reported `EXACT`. **Every check we have said
the reduction was in force. It was not.**

**Why this was nearly missed.** The same experiment run in the *widening*
direction fails too, but harmlessly — a stale consumer then sees *less*
than it is entitled to, which is an operational complaint a consumer
would report. The security-relevant direction is narrowing, and it only
got measured because the two directions were treated as two different
questions rather than one with the sign flipped.

**What we need from v1.6:**

- §2.4.1 to carry a stated propagation expectation for entitlement
  **reductions**, not just for new shares.
- §3.4.1's revocation path to act at the **share boundary** — remove the
  grant, or rotate the recipient's credential — because that is the only
  reduction this prototype has measured as taking effect immediately.
- The operational rule stated plainly: *a view edit changes what is
  shared going forward; it is not how you take access away from someone
  now.*

**The honest bound:** 600 seconds is a **floor, not a ceiling.** We
measured that the change had not arrived within ten minutes. Whether it
arrives at twenty, or at all, is unmeasured. A related measurement puts
the likely mechanism in the same place: a newly shared object was
unreadable at 170 seconds and readable 7.7 hours later. So the honest
reading is *"slow by an unknown amount"* — which is still unacceptable
for a revocation path, and is why the recommendation is to not use one.

*Evidence: `evidence/b32c-change-propagation-narrow.json`,
`evidence/b32c-change-propagation.json`. Closure record §3.2.*

---

## 2. Say which document is the enforced boundary and which merely describes it

CONOPS §2.3.2 contains a route table. It currently reads as though it is
both the description of the perimeter and the perimeter itself. It is
only the first, and E1's largest finding is what that costs.

Gravitee **forwards** a request matching no flow selector; it does not
refuse it. Every generator we had emitted rules that *match* the listed
paths, and none ever emitted a rule that *refuses the unlisted ones*. A
row absent from the table was not absent from the gateway. With the AI
route's upstream target at the workspace root, three paths §2.3.2 never
exposed answered 200.

Fixed on that route, by a terminal allow-list whose patterns are derived
from the forwarding flows' own selectors rather than restated. **Still
open for the sharing and storage APIs**, deliberately — two passing
tests depend on those APIs, and an allow-list wrong by one pattern turns
their positive control into a refusal. That work is queued with those
tests as the regression check.

**What we need from v1.6:** one sentence per table saying whether it is
enforced or descriptive, and for the enforced ones, what enforces them.

*Closure record §3.1.*

---

## 3. Strike the mask / row-filter alternative from §3.1, §2.3.1 and §3.4

Three sections offer "a view, **or** column masks and row filters". The
second option does not exist at **any** Databricks tier. The platform
refuses it in both directions — a table in an OpenSharing share cannot
carry row/column security, and a table carrying it cannot be added to
such a share:

```
INVALID_PARAMETER_VALUE.ROW_COLUMN_SECURITY_NOT_SUPPORTED_WITH_TABLE_IN_DELTA_SHARING
```

AC1 clause 1.3 currently rests on a mechanism that does not exist. The
entitlement model is view-based only, and v1.6 should say so with that
error as the evidence rather than leaving a choice nobody can take.

*Closure record §3.5.*

---

## 4. Remove the claim that the caller is told why the legacy MCP route is closed

A small correction with a deliberate trade-off behind it. Two things can
answer a request on that route: a policy that carries the CONOPS reason,
and a policy that enforces the refusal. Only one can answer first, and we
chose the enforcer — because the reason-carrier fails **open** and the
enforcer fails **closed**, and when those conflict the one whose failure
mode is refusal has to win.

The consequence is that a caller gets a **reasonless 403**. That is the
right behaviour and the wrong documentation. v1.6 should describe what
happens.

*Closure record §3.3.*

---

## 5. Correct §2.3.2's MCP path shape — and decide how MCP routes are health-checked

Two things, found while resolving a method ambiguity that had been
blocking M2.

**The path shape is wrong.** It is not
`/ai-gateway/mcp-services/{mcp-name}` but
`/ai-gateway/mcp-services/{catalog}.{schema}.{leaf}` — the server states
the shape in its own error message. This is not cosmetic: it means MCP
authorization is scoped **per Unity Catalog object**, so the allow-list
question is "which `catalog.schema.leaf` may be invoked", not "which
service may be invoked". That is a materially larger and more granular
list than §2.3.2 implies, and it needs to be designed rather than
inherited.

**And this route answers HTTP 200 carrying a JSON-RPC error.** Any
gateway health check that asserts on status code will therefore report a
**broken MCP service as healthy**. That is item 2's false negative
relocated into monitoring — the place where nothing in this epic would
have caught it. v1.6 should state that MCP route health must be asserted
on the JSON-RPC envelope, not the HTTP status.

*Evidence: `evidence/m2-mcp-methods.json`. Closure record §3.7.*

---

## Two decisions that are not ours

| | What is needed | What it is blocking |
|---|---|---|
| **OD-5** — sign-in and token policy | A Data Governance decision | **It gates the ARB package.** The package can be assembled with both branches described, but it cannot be closed |
| **1694-G1** — UC access model inputs | A Data Governance input | The access matrix is built, labelled `status: provisional`, and will stay provisional. The ask is written in the config itself as three specific questions, so it is answerable without a meeting |

Neither is late through inaction here. Both should leave E1 as **dated
asks** rather than as empty cells in a package.

---

## And one open build item worth naming to the ARB

**R12 is two questions and only one is answered.** Can the gateway inject
an upstream credential? *Yes* — confirmed and measured. Can it do so
**without a long-lived secret**? *Unbuilt.* Today the injected credential
is a personal access token carrying a human operator's full entitlements.

This is the highest open item in the access matrix. It belongs on the
**first page** of the ARB package, not inside it. And a related
measurement bounds how it can be fixed on this tier: **no credential can
be minted for a non-human principal here** — three endpoints, three 404s
— so a service-principal-based answer needs a capability confirmation
before it needs a design.

---

## The procedural recommendation

Everything above was found the same way, and it was not by review, not by
a gate, and not by policy.

**Require every control to have a run in which it was observed absent.**

Both of this week's findings came from that habit alone. The route-table
finding surfaced because a test refused to accept `status in (401, 403)`
as evidence of a refusal and insisted on the platform's own vocabulary —
without that, an upstream's forwarded 401 would have been scored as our
perimeter working, and a no-op deny would have shipped as a live control
with an open proxy behind it. The propagation finding surfaced because
the narrowing direction was run as its own experiment.

The corollary, worth stating because it governs how this week looks on a
dashboard: **E1's two red rows exist because things were measured that
could have been left as tidy caveats.** A checkpoint that rewards colour
over verdicts will reliably produce the caveats instead. The closure
record is written as a verdict per task and per test for that reason, and
it says `CANNOT_SEE` wherever the honest answer is that nothing looked.

---

*Full detail: `docs/epics/E1-closure-record.md`. §3 is the findings, §6
is the honest list of what E1 does not know, §7 is these
recommendations with their evidence.*
