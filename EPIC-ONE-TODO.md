# Epic One — what is left, in the order to do it

**Read `docs/epics/E1-closure-record.md` first.** That is the verdict
record: a result per task and per test, with `CANNOT_SEE` where that is
the honest answer. This file is only the work queue.

**Epic 1 status as of 2026-10-22: CLOSED except for the deferred task.**
Eleven of twelve tasks complete; Task 1.12 (the ARB package) deferred by
instruction pending the corporate 1694-G2 template. Twelve tests run;
eight pass outright, one passes with one `CANNOT_SEE` sub-check, one is
honestly partial, and **two fail** — the two B-32c directions, which are
the same defect measured twice and are reported as failures on purpose
(closure record §3.2).

**Nothing in §1 below is outstanding any more.** It is kept, struck
through, because the order in which those four items closed is part of
the record: two closed by passing, one closed by *failing*, and one
closed by measuring the thing that was blocking it. §3 and §4 are still
live work, and they belong to the estate and to E2 rather than to E1's
closure.

---

## 0. ~~BEFORE 2026-10-22 08:59 UTC~~ — DISCHARGED 07:40 UTC

**Done, and it produced three findings of its own.** Full account in
closure record §4. In short:

- T-01 and T-03 were re-run **inside** the window (06:59Z), so the
  positive control was exercised before it could expire.
- The credential was then **rotated and re-activated**, and T-01/T-03
  re-run *again* on the rotated credential — because a rotation that
  writes a credential file is not evidence that the credential works.
  New expiry **2026-10-23T07:37:24Z**.

**What this item got wrong, which matters more than the deadline:**

1. `scripts/23_rotate_revoke_provider.py` **does not exist.** `scripts/23`
   is `23_gen_outbound_allow_list.py`. Rotation is
   `scripts/27_build_recipient_model.py --rotate-token NAME`. A work
   queue that names a non-existent remedy stops the reader looking.
2. The recipient is **`psp7-demo-recipient`**, with no `awoz1227-`
   prefix. The name above earned a 404.
3. **Rotation with the configured 24h overlap is refused in a
   credential's final 24h** — HTTP 400, *"Cannot extend the token
   expiration time"* — because the overlap request becomes an extension
   request. `--rotate-overlap-seconds 3600` on the same call returned
   200 `ROTATED`: one variable, opposite outcomes. The overlap is
   unusable exactly when somebody notices the credential is expiring.

The working procedure, for next time:

```bash
python3 scripts/27_build_recipient_model.py \
    --rotate-token psp7-demo-recipient --rotate-overlap-seconds 3600
python3 scripts/28_activate_credential.py \
    --recipient psp7-demo-recipient --activate --also-rewrite --force
python3 tests/t01_gateway_read.py && python3 tests/t03_ip_refusal.py
```

**The next clock:** `awoz1227-psp7-t2-us-recipient` expires
**2026-10-28**, and it is the credential B-32c and T-04 read through, so
it is the one that gates re-running the propagation measurement.

---

## 1. ~~To close Epic 1~~ — ALL FOUR CLOSED 2026-10-22

Kept rather than deleted, because *how* each closed is the useful part.

### 1.1 ~~Task 1.10's outstanding deliverable~~ — `tests/e2_egress_d2d.py` — **WRITTEN, PASSES**

`E2_SCOPE_ENFORCED_AND_DENY_ROW_CLEAN_CONSUMER_IDENTITY_NOT_OBSERVABLE`,
1/1, `evidence/e2-egress-d2d.json`.

It was shaped as asked — name the control, probe it, switch it off and
watch the probe change — and the verdict ladder checks the **probe before
the finding**, so a blind probe cannot report a clean deny row:

```
base-table deny row reads CLEAN
  -> deliberate control grant to a service principal  -> 200
  -> deny row now reads VIOLATED, naming 73bc845e-...
  -> revoke                                           -> 200
  -> deny row reads CLEAN again, base table left clean
```

The verdict names its own limit: **consumer identity is not observable**
on this tier, because there is no second human principal to read as. That
is stated rather than implied, which is why the matrix counts this row as
*tested with a named gap* and not as *tested* — see §3.8 of the closure
record, where the counting itself had to be fixed.

### 1.2 ~~Close B-32c~~ — **MEASURED, AND IT FAILED**

Done in **both** directions, 30s polls, 600s budget, config restored
byte-identical afterwards (`git diff` empty, all 68 comments intact):

| Direction | Provider | Consumer |
|---|---|---|
| Widening `region = 'us-east'` → `IN ('us-east','us-west')` | 16 → **33** | 16 → **16** (18 polls) |
| Narrowing → `region = 'us-east' AND record_id % 2 = 0` | 16 → **8** | 16 → **16** (19 polls) |

The item above asked only for a **widening**. Widening alone would have
gone into the record as a latency annoyance — the consumer seeing *less*
than it is entitled to is an operational complaint. The **narrowing**
direction is the one the CONOPS depends on, and it is a disclosure: the
consumer keeps reading the eight rows just taken out of scope, while the
provider's catalog, the applier and the model's own rule 2b all report
the reduction in force. **Two directions, not one, is what turned this
from a caveat into a finding.** Closure record §3.2.

Also note what the first run of that test got wrong, retracted in place
inside its own evidence: it read the consumer **once**, which cannot tell
"never propagates" from "propagates in four minutes". 600s is a **floor**,
not a ceiling.

### 1.3 ~~Decide M2~~ — **CLOSED BY MEASUREMENT, not by recording `NOT_RUN`**

`scripts/32_probe_m2_mcp_methods.py` →
`POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER`. GET is **405 with
and without `text/event-stream` in Accept**, so the refusal is not
content negotiation; POST reaches a dispatcher. A POST-only selector is
correct here. **M2 is still ungenerated (AI-5)** — what closed is the
method ambiguity that blocked generating it.

Two larger things fell out of the probe: §2.3.2's path shape is wrong (it
is `{catalog}.{schema}.{leaf}`, so M2's scope is per-UC-object), and this
route answers **HTTP 200 carrying a JSON-RPC error**, so a status-code
health check reports a broken MCP service as healthy. Closure record
§3.7.

### 1.4 ~~Cross-link the closure record from the epic file~~ — **DONE**

`docs/epics/E1-T04-10-perimeter-and-access.md` now opens with a pointer
to the closure record, a six-row index of the findings worth reading
first, and a note that the plan file loses to the verdict file wherever
they disagree. E1.4's exit criteria also now carry B-32c's correction:
"every share object is a view" tests the **shape** of the entitlement
model and says nothing about whether a **change** to it takes effect.

---

## 2. Deferred by instruction (do not do these yet)

| Item | Why deferred |
|---|---|
| **Task 1.12 — the Story 3 ARB package** | Awaiting the corporate **1694-G2** template, so the evidence is assembled once into the right shape rather than twice. §5 of the closure record explains what that costs the 10/23 checkpoint and what substitutes for it |
| **E7's package** | Same reason |
| **Task 1.11's confirmation** | `iac/config/access-matrix.yaml` is **built** and labelled `status: provisional, awaiting 1694-G1`. The task is complete; what is waiting is Data Governance's answer, which is not ours to produce. The file's `provisional_because.what_is_being_asked` field is the ask, written as three specific questions |

---

## 3. Open for the estate — B-48, the epic's largest finding

**Bring the terminal allow-list to `scripts/29`'s APIs.**

The sharing and storage APIs still **forward** any path matching no flow
selector. They are confined only by their endpoint target carrying a deep
base path, so a stray path is *appended* and the upstream 404s — that is
confinement by string concatenation, not a decision anyone made, not
fail-closed, and **one target edit away from being gone**.

Deliberately not done in the same change as the AI route's fix: **T-01
and T-03 depend on those APIs**, and a whitelist wrong by one pattern
turns two passing tests' positive control into a 403. So do it *after*
§0 above, with those two tests as the regression check.

The pattern to copy is `terminal_allow_list()` in
`scripts/30_gen_gravitee_ai_route.py`. Copy the **function**, not the
patterns — it derives them from the forwarding flows' own selectors.
Restating them is B-39, which has now cost **six** defects in this
repository.

**Two platform facts to keep in front of you while doing it:**

1. **Array position is not evaluation order.** Gravitee evaluates flows
   from the **most generic selector to the most specific**, so a `/`
   `STARTS_WITH` flow emitted last runs **first**. A reviewer reading the
   generator top to bottom will conclude the opposite of what runs.
2. **No `condition` on any step whose absence fails open** (AI-10). A
   step condition that does not evaluate true causes Gravitee to
   **silently omit the policy** — PUT 200, deploy 202, no warning. One
   line reopened `/api/2.0/token/list` to 200 while every API the
   platform offers for checking work reported success.

---

## 4. Housekeeping, in descending order of how much it would cost to skip

1. **Retire the legacy `/delta-sharing/` API**
   (`a45a3c30-1f35-4d86-9a3c-301f359d869d`). Still `STARTED`, and its
   target is wrong in **both** host and path (B-42: a target wrong in
   the path answers, and answers wrongly). `route-table.yaml` already
   marks the listener RETIRED, so the live object and the config
   disagree.
2. **AI-6's durable fix** — move the policy-classes readers into
   `scripts/lib/policy_classes.py`. Three scripts currently each parse
   `policy-classes.yaml` their own way. B-39 again.
3. **Add CAC checks for `policy-classes.yaml`.** It is the one config
   file `scripts/22` does not validate, so it is the one that can drift
   silently.
4. **Sweep the repo for B-47 candidates** — *any value added so that a
   local run would pass is a candidate for having disabled the thing it
   was meant to observe.* This is the general form of the step-condition
   defect and almost certainly has other instances.
5. **The rate-limit precedence burst** — set Gravitee's limit below, then
   above, the platform's, and attribute the refuser **from the response
   body** rather than from the status code.
6. `iac/gravitee/schemas/query-body.schema.json` is missing (PC-1, RF-2).
7. S10's path unconfirmed (PC-2).
8. Live leftovers to clean: `awoz1227_p18_*`, `awoz1227_p19_*`,
   `awoz1227_t19_*`, `awoz1227_demo_*ashu`.
9. Reconcile the git author `temariapp@gmail.com` with the Databricks
   principal `temari.app@gmail.com` — E7 needs them to agree.
10. Probe 21's `conops_implication` still quotes **1978.0s**; the
    measured figure is **1044s** (B-30). Correct it in place.
11. `datetime.utcnow()` DeprecationWarning in `tests/t03_ip_refusal.py`.

---

## 5. Five things to carry into the v1.6 CONOPS

Not tasks — the sentences the evidence supports, so they are not
reconstructed from memory later.

1. **Strike the mask/row-filter alternative** from §3.1, §2.3.1 and §3.4.
   A table in an OpenSharing share cannot carry row/column security at
   **any** tier; the platform refuses it with
   `ROW_COLUMN_SECURITY_NOT_SUPPORTED_WITH_TABLE_IN_DELTA_SHARING`. AC1
   clause 1.3 currently rests on a mechanism that does not exist.
2. **Say which document is the enforced boundary and which merely
   describes it.** §2.3.2's route table reads as both. B-48 is what
   happens when it is not: every generator emitted selectors that *match*
   listed paths, and none ever emitted a rule that *refuses unlisted
   ones*.
3. **Remove any claim that the caller is told why the legacy MCP route is
   closed** (AI-9). The enforcer answers first and carries no reason. The
   trade is deliberate — the reason-carrier fails *open*, the enforcer
   fails *closed* — but the CONOPS currently describes the other outcome.
4. **Stop treating a view edit as a revocation mechanism**, and state a
   propagation expectation for entitlement **reductions** in §2.4.1. A
   narrowed predicate did not reach a live consumer within 600s while
   every provider-side check reported the reduction in force (B-32c).
   §3.4.1's revocation path has to act at the **share boundary** —
   removing the grant or rotating the credential — which is the only
   reduction this prototype has measured as immediate. This is the only
   item in this list with a disclosure behind it rather than a
   documentation error.
5. **Correct §2.3.2's MCP path shape, and say how MCP routes are
   health-checked.** The path is
   `/ai-gateway/mcp-services/{catalog}.{schema}.{leaf}`, so M2's
   authorization scope is **per Unity Catalog object** and the allow-list
   is a list of UC names, not of services — a different and much larger
   list than the CONOPS implies. And because the route answers **HTTP 200
   carrying a JSON-RPC error**, any status-code health check calls a
   broken MCP service healthy: B-48's false negative, relocated into
   monitoring, where nothing in this epic would have caught it.

Two smaller sentences the evidence also supports, for §3.4.1: the
configured rotation overlap is **unusable in a credential's final 24h**
(the platform refuses it as an extension), and a token's lifetime is a
**birth property** — one recipient here carries 24h against a configured
7d, and a bound that only catches excess cannot see a shortfall.

And the one generalisation worth more than any of them: **a perimeter
test that never observes the perimeter absent is measuring the wrong
thing.** Every control in Epic 1 now has a run in which it was switched
off and seen to stop working. That is what makes the evidence worth
taking to the ARB.

---

## 6. Running this repo from a clean checkout

```bash
cp .env.example .env     # then fill it: Databricks host/token, Gravitee creds
docker compose up -d     # Gravitee: mgmt :8083, edge :8082, console :8084

python3 scripts/22_check_cac_config.py        # 356 checks, expect 0 failed
python3 scripts/check_secret_hygiene.py       # expect: Clean

python3 scripts/30_gen_gravitee_ai_route.py   # generate the AI route
python3 scripts/05_import_gravitee_api.py \
    --definition gravitee/generated/api-m1-ai-gateway.json

python3 tests/t15_model_route.py              # R12a
python3 tests/t16_mcp_route.py                # B-48 perimeter + M3 backstop
```

### What the hygiene gate says about this archive

**This archive is `epic1.2.zip`, cut 2026-10-22 — 142 files.** It
supersedes `epic-one.zip` (2026-10-21, also 142 files but a different
set): it adds `docs/leadership/` (the W43 3-pack), `tests/e2_egress_d2d.py`,
`scripts/32_probe_m2_mcp_methods.py`, the two B-32c evidence files, and
the rewritten closure record. `epic-one.zip` is kept rather than
replaced, because a superseded artifact is labelled in place and not
erased (B-19).

Run from inside the extracted archive — not from the original repo,
which is a different tree and would report on the wrong files:

```bash
python3 scripts/check_secret_hygiene.py
python3 scripts/22_check_cac_config.py     # 356 checks, 0 failed
```

Expect from the hygiene gate: **135 files scanned, no token-shaped
strings, 4 declared placeholders exempted**, and exactly **one FAIL —
"no git repository"**.
That one is correct and expected: `.gitignore` is inert until there is a
git repo for it to govern, and the check exists because an ignore file
with nothing to ignore gives false assurance. It clears the moment this
is pushed into your GitHub repo; re-run it there as the first thing you
do, and it should go to Clean.

`_secrets/` and `.env` are **not** in this archive. `evidence/` is, with
credential values redacted — `evidence/t16-api-snapshot-before.json`
carries `_refill_with` telling you the command that puts the real value
back. A restore source that silently drops a credential is its own trap:
PUT it back and the route runs with an empty injected `Authorization`,
which fails *looking exactly like the gateway being unable to inject at
all* (B-44).
