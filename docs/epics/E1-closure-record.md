# E1 — T04-10 closure record

| | |
|---|---|
| **Epic** | 1227-E1 / T04-10 — Perimeter Security and Data-Access Model |
| **Acceptance criterion** | AC1 |
| **Checkpoint** | 10/23 — package review-ready |
| **This record written** | 2026-10-21 |
| **Last updated** | 2026-10-22 — Tasks 1.9 and 1.10 closed, B-32c closed with a negative answer, §4's time-box discharged |
| **Status** | **CLOSED EXCEPT FOR THE DEFERRED TASK.** 11 of 12 tasks complete; 1 (Task 1.12, the ARB package) deferred by instruction pending the corporate 1694-G2 template |
| **Written by** | the prototype operator, wearing every corporate hat except E8's |

This record exists so that the 10/23 checkpoint is met by a **verdict per
task and per test**, not by a status colour. Where the honest verdict is
`CANNOT_SEE` it says so, because a checkpoint that cannot distinguish
"measured and passing" from "not looked at" is the same defect this epic
spent three days finding in its own tests (§12.9, the silent negative).

Two conventions carried from the test suite:

- **`CANNOT_SEE`** means the check could not observe the thing it names.
  It is not a failure and it is not a pass. It is the absence of a
  measurement, recorded rather than rounded.
- **A retracted claim is labelled in place, never deleted** (B-19). This
  record therefore names what was claimed and withdrawn, because a
  closure record that shows only the final position cannot be audited.

---

## 1. Task verdicts

| Task | What it had to produce | Verdict | Evidence |
|---|---|---|---|
| **1.1** | Fix the secret-hygiene violations; lock in the rule | **COMPLETE** | `evidence/secret-hygiene.json` — Clean, 6 checks. Gate runs on every session |
| **1.2** | Extend the capability probe into a generated baseline | **COMPLETE** | 5 `capability-baseline-*.json`. Assumption A10 confirmed **unconditionally** — both D2O and D2D probes passed |
| **1.3** | Instantiate the channel model as configuration | **COMPLETE** | `iac/config/channels.yaml` + 4 siblings; `scripts/22` → 356 checks, 0 failed, `CAC_CONFIG_CONSISTENT` |
| **1.4** | Build the view-based entitlement model | **COMPLETE; THE NAMED GAP IS NOW A MEASURED FINDING** | `evidence/entitlement-model.json`; `iac/config/entitlements.yaml`. **B-32c closed 2026-10-22, with a negative answer** — a changed view definition does *not* reach a live consumer inside 600s, in **either** direction. `evidence/b32c-change-propagation.json` (widening), `b32c-change-propagation-narrow.json` (narrowing). See §3.2 |
| **1.5** | Recipients, DSA references, IP access lists | **COMPLETE — TIME-BOXED** | `evidence/recipient-model.json`, `credential-activation.json`. See §4 |
| **1.6** | T-01 and T-02: the read, and the refusal | **COMPLETE WITH ONE `CANNOT_SEE`** | `evidence/t01-report.json` 3/4, `t02-report.json` 1/1. See §2 |
| **1.7** | T-04 rebuilt: column outside the grant | **COMPLETE** | `COLUMN_AND_ROW_SCOPE_PROVEN_FROM_THE_CONSUMER_SIDE`. Closes D-2, EKI-1, RKI-1 |
| **1.8** | T-21: read-only by construction, no leaked credentials | **COMPLETE** | `READ_ONLY_AND_NO_LEAK_BOTH_MEASURED`. Carries its own retraction (B-40) |
| **1.9** | Exercise the AI routes | **COMPLETE** | T-15 and T-16 both pass. M2 is still ungenerated (AI-5), but **OD-8's second half is closed by measurement**, not left open: `scripts/32_probe_m2_mcp_methods.py` → `POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER`, `evidence/m2-mcp-methods.json`. See §3.7 |
| **1.10** | Ingress I-1: build what is possible, document the rest | **COMPLETE** | T-19 `PARTIAL_WITH_NAMED_GAPS`, T-20 `PASS_WITH_SCOPE`, and the outstanding deliverable `tests/e2_egress_d2d.py` is now written and **passing** — `E2_SCOPE_ENFORCED_AND_DENY_ROW_CLEAN_CONSUMER_IDENTITY_NOT_OBSERVABLE`, `evidence/e2-egress-d2d.json` |
| **1.11** | The §3.1 access matrix, marked provisional | **COMPLETE 2026-10-21, extended 2026-10-22** | `iac/config/access-matrix.yaml`, `iac/databricks/access-matrix.tf`, `evidence/access-matrix.json`. Now carries E-2's measured results and a **three-way** deny-row count (see §3.8) |
| **1.12** | Assemble the Story 3 ARB package | **DEFERRED BY INSTRUCTION** | Awaiting the corporate 1694-G2 template. See §5 |

**So: eleven tasks complete and one deferred by instruction.** Nothing in
E1 is now outstanding for want of work; Task 1.12 is outstanding for want
of a corporate template.

The two items this record previously carried as open work — **Task 1.10's
missing test** and **B-32c** — are both closed, but they closed in
opposite ways and the difference is the point. 1.10's test was written
and **passes**. B-32c was measured and **failed**, which is why it is now
a finding in §3.2 rather than a gap in this table. A gap is something
nobody has looked at; this is something that was looked at and is broken.
Converting the first into the second is progress even though the colour
got worse.

---

## 2. Test verdicts

| Test | Verdict | Passing | Note |
|---|---|---|---|
| **T-01** | `GATEWAY_READ_FAITHFUL` ×2, `BINDING_ENFORCED_AND_THE_ERROR_NAMES_BOTH_HALVES` | **3 of 4** | The fourth is `CANNOT_SEE_RECIPIENT_IP_LIST_EXCLUDES_THIS_CLIENT` — the recipient IP access list does not admit the client this test runs from, so the positive control cannot be exercised from here. **Not a failure; an unexercised control.** |
| **T-02** | `ENFORCED_MECHANISM_PROVEN` | 1 of 1 | Both phases settled as expected |
| **T-03** | `REFUSED_AT_THE_EDGE_AND_REVERSIBLE` | 1 of 1 | Refusal attributed to a named policy, and reversed |
| **T-04** | `COLUMN_AND_ROW_SCOPE_PROVEN_FROM_THE_CONSUMER_SIDE` | pass | Rebuilt after D-2 |
| **T-15** | `R12A_CONFIRMED_INJECTION_REPLACES_AND_IS_SCOPED` | 1 of 1 | R12**a** confirmed. R12**b** unbuilt — see §3 |
| **T-16** | `PERIMETER_CLOSED_M3_IS_THE_BACKSTOP_SUBJECT_ABSENT_UPSTREAM` | 1 of 1 | Passes as of 2026-10-21 after two retractions. See §3 |
| **T-19** | `PARTIAL_WITH_NAMED_GAPS` | partial | Native D2D surfacing `NOT_RUN` against a **named platform capability**, with three bounded negatives behind it. Substitute ingress works |
| **T-20** | `PASS_WITH_SCOPE` | pass | D2O pull end to end; outbound allow-list shown necessary **and** sufficient |
| **T-21** | `READ_ONLY_AND_NO_LEAK_BOTH_MEASURED` | pass | Carries a retracted verdict in its own evidence file |
| **E-2** | `E2_SCOPE_ENFORCED_AND_DENY_ROW_CLEAN_CONSUMER_IDENTITY_NOT_OBSERVABLE` | **1 of 1** | **New 2026-10-22.** The internal egress channel. Checks its own probe *before* its finding: the base-table deny row reads CLEAN, a deliberate control grant makes it read VIOLATED naming the principal, the revoke makes it read CLEAN again. A deny row that only ever reads CLEAN is indistinguishable from one nothing is looking at |
| **B-32c** (widening) | `B32C_CONFIRMED_PROVIDER_MOVED_CONSUMER_DID_NOT_WITHIN_600S` | **0 of 1 — FAILS** | **New 2026-10-22.** Provider 16 → 33, consumer held 16 across 18 polls / 600s |
| **B-32c** (narrowing) | `B32C_NARROWING_DID_NOT_REACH_THE_CONSUMER_REVOKED_ROWS_STILL_READABLE_AFTER_600S` | **0 of 1 — FAILS** | **New 2026-10-22.** Provider 16 → 8, consumer held 16 across 19 polls / 600s. **This is the security-relevant direction.** See §3.2 |
| **M2 method probe** | `POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER` | n/a — a probe, not a test | **New 2026-10-22.** Closes OD-8's second half. `scripts/32_probe_m2_mcp_methods.py` |
| **T-08, T-24** | out of scope for E1 | — | Gateway-enforced; belong to E2 and E4 |
| **T-12** | `NOT_RUN` | — | AC6's clean target does not exist in this topology. All generated Terraform is `PLAN_ONLY_NOT_APPLIED` |
| **§6.3 session** | `SESSION_RUNS_6_OF_9_ONE_RED_TWO_NOT_RUN_HERE` | **not an E1 test** | **New 2026-10-22, found by E1's verification pass.** `tests/run_verification_session.py` — the CONOPS §6.3 *client* verification session. **Crashed at step 1** on an SDK rename, so six steps produced no verdict at all. Two of its nine rows were PASS rows that had measured nothing. It read 8 of 9 before any of this, and that was the least true of the three numbers. Counted separately because it is not E1's deliverable — it is what a client would be shown. See §3.9 |

**Twelve tests run. Eight pass outright, one passes with a `CANNOT_SEE`
sub-check, one is honestly partial, and two fail** — the two B-32c
directions, which are the same defect measured twice. No test in this
epic passes on a catch-all verdict (B-46). The §6.3 session is **not**
in those twelve; it is a neighbouring artifact E1's verification pass
happened to run, and §3.9 records what that cost.

**The two failures are reported as failures on purpose.** B-32c could
have been left as the "named gap" it was in this record yesterday, and
the task table would still have read COMPLETE WITH ONE NAMED GAP. Running
it turned a tidy caveat into two red rows. That trade is the right one
every time: a CONOPS cannot state a propagation expectation it has never
measured, and the measurement is bad news.

---

## 3. What E1 found, in the order it matters

### 3.1 B-48 — the route table was a documentation allow-list that nothing enforced

The largest finding of the epic, found by accident while diagnosing
something smaller. Gravitee **forwards** a request matching no flow
selector; it does not refuse it. With the AI route's target at the
Databricks workspace root, that made the route a reverse proxy to the
whole workspace REST API on paths §2.3.2 never exposed:

```
/ai-gateway-demo/api/2.0/token/list       + caller token -> 200
/ai-gateway-demo/api/2.0/clusters/list    + caller token -> 200
/ai-gateway-demo/api/2.0/serving-endpoints + caller token -> 200
```

§2.3.2's route table is consumed by every generator, and what they
emitted were selectors that **match** listed paths. None ever emitted a
rule that **refuses unlisted ones**. A row absent from the table was not
absent from the gateway.

**Fixed on this API** by a terminal `resource-filtering` whitelist whose
patterns are *derived from the forwarding flows' own selectors*, not
restated. Verified both directions by T-16: all three paths 403 with the
allow-list on, all three 200 again with it off and nothing else changed.

**Open for the estate.** The sharing and storage APIs still forward
unmatched paths, confined only by their endpoint target carrying a deep
base path — confinement by string concatenation, one target edit from
being gone. Bringing the same flow to them was deliberately not done in
the same change, because T-01 and T-03 depend on those APIs and a
whitelist wrong by one pattern turns two passing tests' positive control
into a 403.

**Two claims I made about this finding and withdrew the same day**,
recorded here because the CONOPS discussion will be stronger for them:

1. I wrote that the paths were reachable **with no credential at all**,
   as the gateway's injected identity. Measured: anonymous gets the
   upstream's 401. The strip-and-inject steps live inside M1's flow,
   whose selector is `EQUALS` on the single model path, so an unclaimed
   path never reaches them. It was a **bypass of the route restriction
   with the caller's own entitlements** — not a privilege escalation.
   Still serious, and **one selector edit** (widen `EQUALS` to
   `STARTS_WITH` when someone adds a second model path) from the
   overstated version becoming true.
2. I wrote that the allow-list flow **must be last**. Array position is
   not evaluation order: Gravitee evaluates flows from the **most generic
   selector to the most specific**, so a `/` `STARTS_WITH` flow emitted
   last runs **first**. Proven both ways.

### 3.2 B-32c — a reduced entitlement does not reach the consumer, and every provider-side check says it did

The finding with the shortest path to a real disclosure, and the one that
changed most between being a caveat and being measured.

`ALTER VIEW ... AS` on a shared view returns success, and the provider's
own catalog immediately reports the new definition. The live Delta
Sharing consumer keeps resolving the **previous** definition. Measured in
both directions, 30-second polls, 600-second budget, config restored
byte-identical afterwards:

| Direction | Predicate | Provider | Consumer |
|---|---|---|---|
| Widening | `region = 'us-east'` → `region IN ('us-east','us-west')` | 16 → **33** | 16 → **16** (18 polls) |
| Narrowing | `region = 'us-east'` → `region = 'us-east' AND record_id % 2 = 0` | 16 → **8** | 16 → **16** (19 polls) |

**Why both directions had to be run.** Widening and narrowing are not one
experiment with the sign flipped. A stale consumer under a widened
predicate sees *less* than it is entitled to — wrong, but an operational
complaint, and the kind of thing a consumer reports. A stale consumer
under a **narrowed** predicate keeps reading the eight rows that were
just taken out of scope, and nobody reports it, because nothing on the
provider side looks wrong: the catalog shows the narrow definition, the
applier reports `APPLIED`, and the model's own rule 2b reports `EXACT`.
**The entitlement reduction is believed to be in force by every check
that exists, and it is not in force.**

Had only the widening run been done, this would have gone into the record
as a latency annoyance. The narrowing run is what makes it a security
finding, and it exists only because the directions were asked about
separately.

**What this does not say.** 600s is a **floor, not a ceiling.** The
change had not arrived within ten minutes; whether it arrives at twenty
is unmeasured, and the verdict labels carry the wait for exactly that
reason (B-46). T-19 separately measured a newly-shared object unreadable
at 170.8s and readable 7.7h later, so the same cache is the likely
mechanism and the honest reading is "slow by an unknown amount", not
"never".

**It also carries its own retraction** (B-19). The first version of this
test read the consumer **once**, immediately after the applier returned,
and recorded 16 against a provider-side 33. That reading cannot tell
"never propagates" from "propagates in four minutes", and it is this
repository's own recurring defect turned on its own test. The
single-sample claim is retracted in place inside
`evidence/b32c-change-propagation.json` under
`what_this_does_not_prove.propagation_latency`.

**What v1.6 owes this.** §2.4.1 needs a stated propagation expectation
for entitlement **reductions** specifically, and §3.4.1 needs a
revocation path that does not run through a view definition. Removing the
recipient's grant or rotating its credential acts at the share boundary,
and is the only reduction this prototype has measured as immediate.
Editing a view is not a revocation mechanism on the evidence available.

### 3.3 AI-9 — the enforcer answers, so the caller is not told why

A consequence of §3.1's second retraction, and now an accepted trade-off
rather than a defect. The terminal allow-list is reached before M3's
explicit deny, so a caller on the legacy MCP path receives the
allow-list's **reasonless 403** and M3's CONOPS reason never arrives.

The trade was taken deliberately: the reason-carrier (`mock`) fails
**open** — that is exactly how the original empty-`rules` deny shipped —
and the enforcer (`resource-filtering` whitelist) fails **closed**. When
only one can answer first it must be the one whose failure mode is
refusal. T-16 attributes M3 in the one state where it is reachable, which
proves the backstop is live configuration rather than dead, and its
passing verdict says so by name.

**The CONOPS may not claim the caller is told why the legacy MCP route is
closed.** v1.6 needs that sentence changed.

### 3.4 AI-10 — a one-line expression that silently disables a control

A step-level `condition` that does not evaluate true causes Gravitee to
**silently omit the policy** — `PUT 200`, `deploy 202`, no warning
anywhere. Found by accident while trying to make M3 answer first: a
condition on the allow-list step reopened `/api/2.0/token/list` to 200.
Reverted; restore verified on both paths.

**Rule for v1.6, as a configuration constraint:** no `condition` on any
step whose absence fails open. A condition is safe on a step that *adds*
a refusal and unsafe on a step that *is* the refusal, because "expression
didn't match" is indistinguishable from "policy isn't there" and from
"there was never a policy".

### 3.5 D-1 / D-2 — AC1 clause 1.3 rested on a mechanism that does not exist

§3.1, §2.3.1 and §3.4 all offer "a view, **or** column masks and row
filters". The second half is impossible at **every** tier:

```
INVALID_PARAMETER_VALUE.ROW_COLUMN_SECURITY_NOT_SUPPORTED_WITH_TABLE_IN_DELTA_SHARING
```

A table in an OpenSharing share cannot carry row/column security, and a
table that carries it cannot be added to such a share. The clause should
be **struck** from v1.6 with that error as the evidence. The entitlement
model is view-based only.

### 3.6 R12 is two questions, and only one is answered

- **R12a** — can the gateway inject an upstream credential? **CONFIRMED**
  and measured by T-15, scoped to M1's flow.
- **R12b** — without a long-lived secret? **UNBUILT.** The injected
  credential is today a personal access token carrying a human
  operator's full entitlements (AI-3).

This is the **highest open item** in the access matrix and should be on
the first page of the ARB package, not in it.

### 3.7 OD-8's second half, closed by measurement — and a health check that cannot see a broken MCP service

§2.3.2 gives M2's method as "MCP", which is a protocol and not an HTTP
method, so the open question was whether a POST-only selector would
silently drop the streamable-HTTP event stream. That question is now
answered rather than deferred: `scripts/32_probe_m2_mcp_methods.py`
returns `POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER`. GET is
refused **405 both with and without `text/event-stream` in Accept**, so
the refusal is not content negotiation; POST reaches a dispatcher and
answers with a JSON-RPC envelope. A POST-only selector is correct here.

Two things fell out of the probe that matter more than the method
question did:

1. **The path shape in §2.3.2 is wrong.** It is not
   `/ai-gateway/mcp-services/{mcp-name}` but
   `/ai-gateway/mcp-services/{catalog}.{schema}.{leaf}` — the server
   states the shape in its own error. M2's authorization scope is
   therefore **per Unity Catalog object**, and the allow-list question is
   "which `catalog.schema.leaf` may be invoked", not "which service".
   That is a different and much larger allow-list than the CONOPS
   currently implies.
2. **HTTP 200 can carry a JSON-RPC error.** The malformed-name probe
   returns status 200 with an error body. Any gateway health check on
   this route that asserts on status code will therefore **report a
   broken MCP service as healthy** — §3.1's defect relocated into
   monitoring, where nothing in this epic would have caught it.

The probe also refuses to follow redirects on purpose. An earlier ad-hoc
check of the base path returned 200 only because `urllib` follows
redirects by default, so that 200 described a **different URL** than the
one asked about — the same mislabel, found in my own tooling, and
recorded in the evidence under `base_path_is_not_the_probe`.

### 3.8 Three states, not two — the deny-row count

E-2 gave the access matrix's most important deny row a verified probe,
and the matrix generator still reported the coverage as unchanged. The
count was `tested_by present AND no gap`, which put a row with a proven
probe and a named residual gap in the same bucket as a row nobody had
ever looked at.

Fixed to count three states. The matrix now reports **14 deny rows: 5
tested with no residual gap, 2 tested with a named gap, 7 with no test at
all** — where it previously said 5 tested and 9 not. The old sentence
"9 of 14 deny rows have no test, and they are the separation-of-duty
rows" was false in both halves once E-2 existed.

This is small, and it is the same defect as B-20 and B-46 in a third
place: **a vocabulary too coarse to name the state will name the nearest
one, and the nearest one is usually the worse one.** Folded upward the
count overstates coverage; folded downward it discards the only
internal-channel evidence E1 produced. Neither is reportable.

### 3.9 The §6.3 client verification session did not run, and two of its PASS rows had measured nothing

Found during E1's own verification pass on 2026-10-22, by running
`tests/run_verification_session.py` — the script that implements CONOPS
**§6.3, the client verification session**. It is not E1's deliverable;
it is what a client would be shown. It had **four** defects, and the
order they were found in is the point.

**It crashed at step 1.** `databricks-sdk` 0.153.0 renamed
`SharesAPI.list` to `list_shares` and removed the old name, so step 1
raised `AttributeError` and steps 2–7 never ran. A crash is not a
failure: a failure names a cause for one step, a crash produces **no
verdict for six**. `RecipientsAPI.list` was *not* renamed in the same
release, which is why the very next line still worked and the breakage
looked like a one-off rather than a version skew. Resolved by name so
the script runs on either SDK.

**Step 3 passed on a retired path.** It asserted
`rewritten_credential.endpoint == GRAVITEE_GATEWAY_EDGE_URL` and
reported PASS, while step 4 read that same endpoint and got
`404 ENDPOINT_NOT_FOUND`. Both sides of step 3's equality came from the
same stale source — the rewriter and the env var both still say
`/delta-sharing`, which `route-table.yaml` records as **retired**. A
comparison between two values of common origin is self-consistent
whatever the truth is: this is **B-40** — *the control must be the same
path as the subject* — in a new place. The step whose whole purpose was
to catch endpoint drift **certified** it. Step 3 now resolves the live
path from `gravitee/generated/route-family.json`
(`/opensharing-demo/psp7-demo`) and **FAILS**, correctly: the credential
rewriter does emit a retired endpoint. That fix is E2 Task 2.1's
consolidation, and it is now a red row rather than a green one.

**Step 4 named the base table.** `...#awoz1227-psp7-demo-share.`
`opensharing_test.test_dataset` — and E1's entitlement model makes every
share object a **view**, so the base table is deliberately absent. The
platform answered `RESOURCE_DOES_NOT_EXIST`, which reads exactly like a
broken share and was in fact a **correct refusal of a name this
repository's own design forbids**. The shared object is now discovered
from the share rather than named in the test, and step 4 **passes on a
real measurement**: 50 rows from `opensharing_test.v_entitled_t2`
through `/opensharing-demo/psp7-demo`, `internal_notes` absent.

**T-06 passed because the route did not exist.** Its assertion was
`status >= 400`, so the retired path's `404 ENDPOINT_NOT_FOUND` — nothing
having looked at the body at all — scored as *"the edge rejected the
malformed request"*. **B-44** again: an edge refusal and an upstream
refusal forwarded through the edge are the same status code with
opposite remedies. The assertion is now `400 from the edge`, with
`CANNOT_SEE_NO_ROUTE_AT_THIS_PATH` and
`CANNOT_SEE_REFUSED_BEFORE_VALIDATION_{401,403}` as distinct verdicts.
It still passes, now on a measured 400.

**And steps 6 and 7 were PASS rows that measured nothing** — recorded
`passed=True` with an actual of *"see that other program's output"*.
That is the **third inversion** written directly into a test: a report
describing an intention as an outcome. Two of nine rows in the evidence
log a client would be shown were of this kind. They now record
`NOT_RUN_HERE` and do not count as passes.

The session reads **6 of 9** — one real red row (step 3's retired
endpoint) and two honest `NOT_RUN_HERE`s. It read 8 of 9 before any of
this, and that number was the least true of the three.

*Evidence: `_secrets/verification-session-evidence.json` (gitignored —
it carries a bearer token). Script: `tests/run_verification_session.py`.*

---

### 3.10 What caught all of this, and what would not have

Not a gate, not a review, not the policy. **The tests**, because they
required the platform's own vocabulary before calling a refusal a
refusal. An assertion of `status in (401, 403)` would have passed on the
upstream's forwarded 401, and the no-op deny would have shipped as a
working control with an open proxy behind it.

The generalisation for v1.6, and the single most transferable thing this
epic produced: **a perimeter test that never observes the perimeter
absent is measuring the wrong thing.** Every control in this epic now has
a run in which it was switched off and seen to stop working.

---

## 4. Time-boxed: DISCHARGED 2026-10-22 07:40 UTC

**Resolved. The text of the original time-box is kept below unaltered
(B-19), because what it got wrong is instructive.**

What was done, in order, with 84 minutes left on the clock:

1. **T-01 and T-03 were re-run inside the window** (06:59Z) — so the
   positive control was exercised on the original credential before it
   could expire. T-01 3/4, T-03 1/1.
2. **The credential was then rotated and re-activated**, so the control
   survives past the deadline rather than being spent by it. New
   credential live to **2026-10-23T07:37:24Z**. T-01 and T-03 were re-run
   *again* on the rotated credential — T-01 `GATEWAY_READ_FAITHFUL_WHERE_OBSERVABLE`
   3/4, T-03 `REFUSED_AT_THE_EDGE_AND_REVERSIBLE` 1/1. Re-running after
   the rotation is the point: a rotation that writes a credential file is
   not evidence that the credential works.

**Three things the paragraph below got wrong, all of them worth more than
the deadline it was warning about:**

- **The remedy named a script that does not exist.**
  `scripts/23_rotate_revoke_provider.py` is not in the repository;
  `scripts/23` is `23_gen_outbound_allow_list.py`, and rotation lives in
  `scripts/27_build_recipient_model.py --rotate-token NAME`. A closure
  record that points at a non-existent remedy is worse than one that
  points at none, because the reader stops looking.
- **Rotation with the configured overlap is refused precisely when it is
  needed.** `POST /recipients/{name}/rotate-token` with the configured
  24h overlap returned **HTTP 400 `INVALID_PARAMETER_VALUE`, "Cannot
  extend the token expiration time"** — because an overlap of 24h on a
  token with 84 minutes left is an *extension* request, and extension is
  refused. The same call with `--rotate-overlap-seconds 3600` returned
  **200 `ROTATED`**: one variable changed, opposite outcomes. So **the
  configured overlap is unusable in the final 24h of a credential's
  life**, which is exactly the window in which somebody notices. The
  operational rule is: rotate before `expiry − overlap`, or shorten the
  overlap and accept a harder cutover. §3.4.1 has to say this.
  `--rotate-overlap-seconds` was added for it, which also makes RKI-2's
  `expire=0` compromise path *reachable* — still unexercised, now not
  unreachable.
- **Two console lines were lossy where the evidence was sound.** The
  first rotation attempt printed `ROTATE_FAILED` and nothing else; the
  cause (`404 RECIPIENT_DOES_NOT_EXIST` — the recipient is
  `psp7-demo-recipient`, with no `awoz1227-` prefix) was in the evidence
  file and not on screen, which reads as a platform refusal rather than a
  typo. Separately, rule 4 has **always** measured
  `psp7-demo-recipient: LIFETIME_DIFFERS_SET_AT_BIRTH` — a 24h token
  window against a configured 7d — and the console printed only state and
  token count, so three recipients that differ read as three that agree.
  Anyone planning from the terminal would have assumed a week of
  credential life on a recipient that has one day. Both lines now print
  the cause. **Note what this is not:** it is *not* a platform-wide 24h
  cap. The other two recipients measure `LIFETIME_AS_CONFIGURED` at 7d.
  The mechanism was right and the summary was lossy — and the first
  reading of it, which blamed the tier, was wrong.

---

### 4.1 The original time-box, as written on 2026-10-21 — RETRACTED, kept for audit

> ## 4. Time-boxed: act before 2026-10-22 08:59 UTC

> `awoz1227-psp7-demo-recipient`'s Delta Sharing credential expires
> **2026-10-22T08:59:42Z** and it is the **positive control** for T-01 and
> T-03 — the thing that proves those tests can see a success as well as a
> refusal. After expiry both tests lose the ability to distinguish "refused
> by the control" from "refused because the credential is dead", which is
> B-44's shape exactly.
>
> Either re-run T-01 and T-03 before it expires, or rotate the credential
> (`scripts/23_rotate_revoke_provider.py` exercises the full cycle).
> `awoz1227-psp7-t2-us-recipient` expires 2026-10-28 and is not urgent.

The B-44 reasoning in that paragraph was right and is the reason the
rotation was done rather than just noted. The recipient **name** in it is
also wrong — there is no `awoz1227-` prefix — which is how the first
rotation attempt earned its 404.

**The new clock:** the rotated `psp7-demo-recipient` credential expires
**2026-10-23T07:37:24Z** (24h, not 7d — see above).
`awoz1227-psp7-t2-us-recipient` expires **2026-10-28** and is the
credential B-32c and T-04 read through, so it is the one that matters for
re-running the propagation measurement. Neither is urgent for the
checkpoint; both are urgent for anyone re-running this suite later, and
the remedy is `scripts/27_build_recipient_model.py --rotate-token NAME
--rotate-overlap-seconds N` followed by `scripts/28_activate_credential.py
--recipient NAME --activate --also-rewrite --force` and **then** a re-run
of T-01 and T-03.

---

## 5. Why 1.12 is deferred, and what that costs the checkpoint

The 10/23 checkpoint reads "T04-10 package review-ready, including the
ingress specification." The **ARB package itself** (Task 1.12, and
E7's packaging) is deferred **by instruction** until the corporate
1694-G2 template exists, so that the evidence is assembled once into the
right shape rather than twice.

What that costs: the checkpoint cannot be reported as met on its own
terms. What substitutes for it is **this record plus the evidence
directory** — every AC1 clause traces to a verdict or a named gap, which
is Task 1.12's own verify condition ("no clause traces to nothing")
satisfied without the document.

Two things must appear **prominently** in the package when it is
assembled, not in a footnote: **OD-5 is Open**, so the sign-in and
token-policy section is a placeholder with both branches described; and
**OD-11 / D-1**, the mask/filter finding, as a correction to the CONOPS
rather than an implementation note.

---

## 6. The honest list of what E1 does not know

| | |
|---|---|
| **OD-5** | Open, and it gates the package. B-34a's third sub-question is still unanswered |
| **OD-8** | ~~Half open~~ **CLOSED 2026-10-22** by `scripts/32`. The original entry read: *"M2 ungenerated (AI-5): §2.3.2 gives M2's method as 'MCP', a protocol not an HTTP method, and a POST-only selector would silently drop the streamable-HTTP event stream."* Measured: there is **no event stream on this tier**, GET is 405 regardless of Accept, POST-only is correct. **M2 is still ungenerated (AI-5)** — that part stands; what is closed is the method question that blocked generating it. See §3.7 |
| **B-48** | Open for the estate — the sharing and storage APIs |
| **B-32c** | ~~`v_entitled_t2_us`'s predicate not widened~~ **CLOSED 2026-10-22, and it FAILED.** Moved out of this list because it is no longer something E1 does not know; it is something E1 measured and reported. See §3.2. What remains unknown is the **ceiling**: 600s is a floor, and how long propagation actually takes — or whether it completes at all — is unmeasured |
| **R12b** | Unbuilt |
| **T-12** | `NOT_RUN`. All Terraform is `PLAN_ONLY_NOT_APPLIED` |
| **Separation of duty** | **7** of the access matrix's 14 deny rows have no test at all; **2** have a test with a named residual gap; **5** are tested clean. The 7 are the separation-of-duty rows, untestable where one operator wears every hat. The previous entry read *"9 of 14 have no test… the 5 that are tested all belong to the external recipient"* — **both halves became false when E-2 shipped**, since one of the newly-covered rows is the internal base-table row. See §3.8 |
| **Internal channel** | E-2 proves the view boundary and the base-table deny row from the **operator's** identity, because this tier exposes no second human principal. **Consumer identity is not observable** — the test says so in its own verdict rather than implying coverage it does not have |
| **Credential lifetime** | `psp7-demo-recipient` carries a **24h** token window against a configured 7d, measured as `LIFETIME_DIFFERS_SET_AT_BIRTH`. This is a birth property of that one recipient, **not** a tier cap — the other two measure 7d as configured |
| **Rotation overlap** | The configured 24h overlap **cannot be used** in a credential's final 24h (HTTP 400, "Cannot extend the token expiration time"). RKI-2's `expire=0` compromise path is now reachable via `--rotate-overlap-seconds` but **still unexercised** — no run has yet proven a hard cutover works |
| **Service principals** | **Partially answered.** UC accepts a service principal by `applicationId` (E-2's control grant did exactly that, and was observed to move the probe), but **no credential can be minted for a non-human principal** on this tier — three endpoints, three 404s. UC principals are also **account-level**, so a workspace group returns `404 PRINCIPAL_DOES_NOT_EXIST`: that measurement *confirms* the matrix's `implementable: false` instead of inferring it. Note the near-miss — workspace groups **are** creatable here, so a row built on one would have looked fine and been invisible to UC |
| **Account-level objects** | 4 of 6 matrix principals are account groups or service principals; this tier exposes no account console and no account-level API |
| **Arm's-length counterparty** | The D2D counterparty is a real second account but not a separate organisation. T-13 is still the only thing that can produce that |

---

## 7. For the corporate discussion

Three recommendations that are measurements rather than opinions:

1. **Strike the mask/row-filter alternative from §3.1, §2.3.1 and §3.4**,
   with the platform's own error as the evidence. AC1 clause 1.3 currently
   rests on a mechanism that does not exist at any tier.
2. **Record T-19's native D2D confirming calls as `NOT_RUN` against a
   named platform capability**, with open sharing as the *evidenced
   substitute ingress path* rather than a workaround. That converts a dead
   end into a decision the ARB can actually take: accept the open-protocol
   path for D2D ingress, or escalate the surfacing gap to Databricks.
   §2.4.1 also needs a **timing expectation** — a newly shared object was
   not readable within 170.8s, while one shared earlier was readable 7.7h
   later, so a consumer who polls for three minutes and concludes the
   share is wrong will raise a false defect.
3. **Say which document is the enforced boundary and which merely
   describes it.** The CONOPS currently reads as though §2.3.2's route
   table is both. B-48 is what happens when it is not.
4. **Stop treating a view edit as a revocation mechanism.** B-32c
   measured a *narrowed* predicate failing to reach a live consumer for
   600s while every provider-side check reported the reduction in force.
   §2.4.1 needs a stated propagation expectation for reductions, and
   §3.4.1's revocation path needs to run through the share boundary —
   removing the grant or rotating the credential — which is the only
   reduction this prototype has measured as immediate. This is the one
   recommendation here with a disclosure behind it rather than a
   documentation error.
5. **Correct §2.3.2's MCP path shape, and say how MCP routes are
   health-checked.** The path is
   `/ai-gateway/mcp-services/{catalog}.{schema}.{leaf}`, so M2's
   authorization scope is per Unity Catalog object and the allow-list is
   a list of UC names rather than of services. And because this route
   answers **HTTP 200 carrying a JSON-RPC error**, any status-code health
   check reports a broken MCP service as healthy — the same
   false-negative shape as B-48, relocated into monitoring.

### 7.1 One procedural recommendation, separate from the five above

**Require every control to have a run in which it was observed absent,
and require every count to have three states where two would hide one.**
Both of E1's final two days of findings came from that one habit rather
than from new tooling: B-32c only became a security finding when the
*narrowing* direction was run separately from the widening one, and the
deny-row coverage only became accurate when "tested with a named gap"
stopped being folded into "untested". E1's two red rows exist because
things were measured that could have been left as tidy caveats, and a
checkpoint that rewards colour over verdicts will reliably produce the
caveats instead.
