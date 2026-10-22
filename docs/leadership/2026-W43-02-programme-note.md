# 2026-W43 · Note 02 — Programme note

**For:** milestone leadership · programme management
**Milestone:** AWOZ-1227 / INC17 · **Epic:** E1 — T04-10 (AC1)
**Cut:** 2026-10-22 · **Checkpoint:** 10/23

---

## Status

**E1 is closed except for one task that is deferred by instruction.**

| | |
|---|---|
| Tasks | **11 of 12 complete.** Task 1.12 (the Story 3 ARB package) deferred pending the corporate 1694-G2 template |
| Tests | **12 run.** 8 pass, 1 passes with a `CANNOT_SEE` sub-check, 1 honestly partial, **2 fail** |
| Gates | **All green.** `CAC_CONFIG_CONSISTENT` (356 checks, 0 failed) · secret hygiene Clean. Pyflakes reports **14 style warnings** in nine scripts untouched by E1's closure work — unused locals and placeholder-less f-strings, no logic defects; listed in note 03 §6 rather than claimed clean |
| Target window | 10/1 – 10/29. Checkpoint 10/23 |

Nothing in E1 is outstanding for want of work. Task 1.12 is outstanding
for want of a corporate template, which is a deliberate decision
explained below.

---

## What the 10/23 checkpoint will actually show, and what it will not

The checkpoint reads *"T04-10 package review-ready, including the ingress
specification."* It will not be met on its own terms, because **the
package itself is deferred.**

**Why deferred rather than late.** The ARB package is assembled from the
same evidence whatever shape it takes. Assembling it now against a guessed
structure means assembling it twice — once now, once again when the
corporate 1694-G2 template arrives — and the second pass is where
transcription errors enter. The instruction was to wait for the template
so the evidence is shaped once.

**What substitutes for it.** `docs/epics/E1-closure-record.md` plus the
`evidence/` directory. Every AC1 clause traces to a verdict or to a named
gap, which is Task 1.12's own verify condition — *"no clause traces to
nothing"* — satisfied without the document. A reviewer can be walked
through the closure record on 10/23 and get everything the package would
have given them except its cover sheet.

**What must appear prominently in the package when it is assembled** —
and these are easy to bury:

- **OD-5 is Open** and it gates the package. The sign-in and token-policy
  section is a placeholder with both branches described.
- **The mask/row-filter correction** (AC1 clause 1.3 rests on a mechanism
  that does not exist at any tier) belongs as a *correction to the
  CONOPS*, not as an implementation note.
- **R12b is unbuilt** and is the highest open item in the access matrix.
  First page, not inside.
- **The propagation finding** — a view edit is not a revocation
  mechanism. New this week; see note 01 §1.

---

## The two failing tests, and why they are the week's best outcome

This needs stating plainly because the metric moved the wrong way: **test
count went from 9 to 12, and failures went from 0 to 2.**

Both failures are the same finding measured twice — a changed view
definition not reaching a live consumer, once by widening the entitlement
and once by narrowing it. Last week that finding did not exist. In its
place was a line in the closure record describing Task 1.4 as *"complete
with one named gap"*, and the gap was *"the predicate has not been
widened"*. The task table read **COMPLETE**.

Running the experiment turned one tidy caveat into two red rows and one
CONOPS correction with a disclosure behind it. **That is the trade we
want made every time**, and it is worth saying out loud at programme
level, because the incentive runs the other way: nobody is rewarded for
converting a caveat into a failure, and a checkpoint reported in colours
rather than verdicts actively punishes it.

The closure record is structured to make this difficult to lose — a
verdict per task and per test, with `CANNOT_SEE` recorded wherever a
check could not observe the thing it names, rather than rounded to a
pass or a fail. A checkpoint that cannot distinguish *"measured and
passing"* from *"nobody looked"* is the same defect this epic spent its
last three days finding in its own tests.

---

## What moved this week

| | |
|---|---|
| **Task 1.10 closed** | Its outstanding deliverable — the internal egress channel test — is written and passing. It gave the access matrix's single most important deny row (*the internal consumer must not hold SELECT on the base table*) a probe that was itself proven to work: the row reads clean, a deliberate control grant makes it read violated, the revoke makes it read clean again |
| **Task 1.9 closed** | The MCP method ambiguity that was blocking it is resolved by measurement rather than recorded as unknown. Two larger corrections fell out of the probe (note 01 §5) |
| **B-32c measured** | In both directions. Failed in both. This is the week's substantive finding |
| **The credential time-box discharged** | The positive control for two tests was 84 minutes from expiry. It was exercised inside the window, then rotated and re-verified. Three further findings came out of doing it — including that **rotation with the configured overlap is refused precisely when it is most needed** |
| **The §6.3 session script fixed** | The script that implements the *client* verification session **crashed at step 1** on an SDK rename, so six of seven steps produced no verdict. Two of its nine rows were PASS rows that measured nothing — they pointed at another program's output. It now reads **6 of 9**, which is the first honest number it has produced. Not an E1 deliverable, but it is the artifact with an audience |
| **Access matrix coverage corrected** | The deny-row count was reported as 5 tested of 14. It is now 5 tested clean, 2 tested with a named residual gap, 7 with no test at all. The old count folded "tested with a gap" into "untested", which both understated the evidence and made it indistinguishable from rows nobody had looked at |

---

## Risks and carried items

| | Status |
|---|---|
| **OD-5** (sign-in / token policy) | **Open.** Data Governance decision. Gates the ARB package. Not ours |
| **1694-G1** (UC access model inputs) | **Awaiting input.** The access matrix is built and labelled provisional; the ask is written into the config as three specific questions |
| **1694-G2** (ARB template) | **Awaiting.** Blocks Task 1.12 and E7's packaging, by instruction |
| **B-48 for the estate** | **Open work**, queued. The sharing and storage APIs still forward unmatched paths. Sequenced *after* the credential work because two passing tests depend on those APIs and would be the first casualties of a wrong pattern |
| **R12b** | **Unbuilt.** Compounded by a measured platform limit: no credential can be minted for a non-human principal on this tier |
| **T-12 / AC6** | `NOT_RUN`. All generated Terraform is `PLAN_ONLY_NOT_APPLIED` — AC6's clean target does not exist in this topology |
| **Separation of duty** | 7 of 14 deny rows have no test, because this prototype has **one operator wearing every corporate hat**. Structural, not an oversight; it is what E8's external party is for |
| **Arm's-length counterparty** | The D2D counterparty is a real second account but not a separate organisation. Only T-13 can produce that |

---

## Where E2 picks up

E1's findings hand E2 three things that are more useful than a clean
hand-off would have been.

**The estate-wide allow-list work**, with the pattern already written and
proven on one route, and with two named platform facts that will
otherwise cost a day each: array position is **not** evaluation order
(Gravitee evaluates flows most-generic-selector-first, so a reviewer
reading a generator top to bottom concludes the opposite of what runs),
and a step-level condition that does not evaluate true causes the policy
to be **silently omitted** — PUT 200, deploy 202, no warning. One line of
that reopened a path that was supposed to be closed.

**A corrected exit criterion.** E1's own criterion *"every share object
is a view"* is satisfied, and B-32c showed it is not sufficient: it tests
the **shape** of the entitlement model and says nothing about whether a
**change** to it takes effect. E2's criteria should test the second
thing.

**A rule about configuration**, generalised from the condition defect:
no `condition` on any policy step whose absence fails open. A condition
is safe on a step that *adds* a refusal and unsafe on a step that *is*
the refusal — because "the expression didn't match" is indistinguishable
from "the policy isn't there" and from "there was never a policy".

---

## Ask of leadership this week

1. **Accept the deferral of Task 1.12** and the closure record plus
   evidence directory as what the 10/23 checkpoint reviews.
2. **Route OD-5 to Data Governance with a date.** It is the only item
   that blocks a package rather than a task.
3. **Read note 01 §1 before the next CONOPS working session.** The
   revocation finding changes a sentence in §3.4.1 that is currently
   load-bearing.
