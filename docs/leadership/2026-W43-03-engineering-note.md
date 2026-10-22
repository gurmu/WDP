# 2026-W43 · Note 03 — Engineering note

**For:** AI/ML Ops · Data Eng · anyone re-running or rebuilding this
**Cut:** 2026-10-22

Everything here is reproducible. Each item names the script or test, the
evidence file it writes, and the verdict string to expect. Verdicts are
long on purpose — a verdict that cannot name the cause blames the nearest
thing.

---

## Conventions you need before reading the evidence

**`CANNOT_SEE` is a third outcome.** It means the check could not observe
the thing it names. It is not a pass and not a failure; it is the absence
of a measurement, recorded rather than rounded. The reason this
vocabulary exists is the defect the whole suite is built against: **a
check that cannot see reports the same output as one that looked and
found nothing.**

**A retracted claim is labelled in place, never deleted.** Evidence files
and docs carry their own corrections with the original text intact. A
record that shows only the final position cannot be audited.

**A control must be the same *path* as its subject, not the same host.**
Positive controls in this suite read the same path, in the same run, with
the same credential.

---

## 1. B-32c — change propagation. **Two failures, and they are real**

```bash
python3 tests/b32c_change_propagation.py                      # widening
python3 tests/b32c_change_propagation.py --narrow             # narrowing
#   --poll-budget 600.0   seconds to wait for the consumer count to move
#   --poll-interval 30.0  seconds between consumer reads
```

| Run | Verdict | Evidence |
|---|---|---|
| Widening | `B32C_CONFIRMED_PROVIDER_MOVED_CONSUMER_DID_NOT_WITHIN_600S` | `evidence/b32c-change-propagation.json` |
| Narrowing | `B32C_NARROWING_DID_NOT_REACH_THE_CONSUMER_REVOKED_ROWS_STILL_READABLE_AFTER_600S` | `evidence/b32c-change-propagation-narrow.json` |

Provider 16 → 33 (widen) and 16 → 8 (narrow). Consumer held at 16 both
times, for the full budget, across 18 and 19 polls.

**What the test does.** Edits `iac/config/entitlements.yaml`, runs
`scripts/24_build_entitlement_model.py` **as a subprocess** rather than
reimplementing the applier, reads the provider's catalog, then polls
**through the share** as the activated recipient, then restores.

**Operational warnings if you run it.**

- It rewrites `entitlements.yaml` with `yaml.safe_dump`, which **strips
  all 68 comments** for the duration of the run. The `finally` block
  restores from a byte-for-byte `shutil.copy2` backup at
  `_secrets/entitlements.yaml.b32c-backup` (gitignored), so comments
  survive — but **do not run the CAC gate concurrently**, and do not run
  any view-reading test concurrently either.
- Verify afterwards: `git diff` on that file must be empty, the comment
  count must be 68, and the predicate must be back to
  `"region = 'us-east'"`.
- Each direction takes 12–15 minutes at the default budget.

**Two things in the test's own history worth knowing.**

The first version **read the consumer once**, immediately after the
applier returned, and recorded 16 against a provider-side 33. That cannot
distinguish *"never propagates"* from *"propagates in four minutes"* —
this repository's own recurring defect, applied to its own test. It is
retracted in place under
`what_this_does_not_prove.propagation_latency`, and the read is now a
bounded poll with the measured wait carried **in the verdict label**, so
the floor can never be read as a ceiling.

And the phase banner printed `WIDENED` in both modes for one run. The
measurement was real and the label named the wrong thing — the same
inversion the suite exists to catch, found in the suite. The evidence key
`1_widened` is kept (the verdict ladder reads it) and the truth is now
carried in a separate `direction` field plus an
`evidence_key_is_legacy` note, with the banner reading from `direction`.

**Why `--narrow` exists at all.** Widening and narrowing are not one
experiment with the sign flipped. Widening leaves the consumer seeing
*less* than it is entitled to — an operational complaint. Narrowing
leaves it reading rows that were just revoked, with the provider's
catalog reporting the narrow definition, so **every provider-side check
agrees the reduction is in force.** If you add a propagation test
anywhere else, run both directions.

---

## 2. E-2 — internal egress channel. **Passes, and names its own limit**

```bash
python3 tests/e2_egress_d2d.py
```

`E2_SCOPE_ENFORCED_AND_DENY_ROW_CLEAN_CONSUMER_IDENTITY_NOT_OBSERVABLE`,
1/1 → `evidence/e2-egress-d2d.json`, `evidence/e2-report.json`.

The verdict ladder **checks the probe before the finding**, in this
order, and this order matters more than the test does:

```
CANNOT_SEE_CONTROL_GRANT_REFUSED_PROBE_UNVERIFIED
PROBE_IS_BLIND_CONTROL_GRANT_DID_NOT_MOVE_IT
CONTROL_LEFT_IN_PLACE_BASE_TABLE_STILL_GRANTED
DENY_ROW_VIOLATED_AS_FOUND_BASE_TABLE_WAS_GRANTED
COLUMN_SCOPE_NOT_DEMONSTRATED
ROW_SCOPE_NOT_DEMONSTRATED
E2_SCOPE_ENFORCED_AND_DENY_ROW_CLEAN_CONSUMER_IDENTITY_NOT_OBSERVABLE
```

A deny row that only ever reads CLEAN is indistinguishable from one
nothing is looking at, so the test grants the thing it forbids, confirms
the probe flips to VIOLATED **naming the principal**, revokes, and
confirms it flips back — then checks the base table was left clean.

**Capability results worth reusing**, recorded in the module docstring as
status codes rather than assumptions:

| Attempt | Result |
|---|---|
| UC permissions PATCH with a **workspace group** | `404 PRINCIPAL_DOES_NOT_EXIST` — UC principals are **account-level** |
| UC permissions PATCH with a **service principal `applicationId`** | `200` — this is what the control grant uses |
| Minting a credential for a non-human principal | **three endpoints, three 404s** — not possible on this tier |
| `effective-permissions` | returns `{}` — inheritance is not enumerable here |

**The near-miss to remember:** workspace groups **are** creatable on this
tier. A matrix row built on one would have looked completely fine and
been invisible to Unity Catalog. The 404 is what upgraded the matrix's
`implementable: false` from a documentation inference to a measured
refusal.

---

## 3. M2 method probe — OD-8's second half

```bash
python3 scripts/32_probe_m2_mcp_methods.py
```

`POST_ONLY_CONFIRMED_NO_EVENT_STREAM_ON_THIS_TIER` →
`evidence/m2-mcp-methods.json`.

| Probe | Result |
|---|---|
| `GET /ai-gateway/mcp-services/{name}` | **405** |
| Same, with `Accept: text/event-stream` | **405** — so the refusal is not content negotiation |
| `POST` with an MCP `initialize` body | reaches the dispatcher; JSON-RPC `-32007 Not authorized to invoke MCP service` |
| `POST` with a malformed name | **HTTP 200**, JSON-RPC **error** body |

So a POST-only selector is correct. **M2 is still ungenerated (AI-5)** —
what closed is the method ambiguity, not the generation.

**Two findings larger than the method question.**

**The path is `{catalog}.{schema}.{leaf}`**, not `{mcp-name}` — the
server states the shape in its own error. MCP authorization is therefore
**per Unity Catalog object**, and the allow-list is a list of UC names.

**HTTP 200 can carry a JSON-RPC error**, so any health check asserting on
status code reports a broken MCP service as **healthy**. Assert on the
envelope.

**The probe refuses to follow redirects on purpose** —
`NoRedirect(urllib.request.HTTPRedirectHandler)`. An earlier ad-hoc check
of the base path returned 200 only because `urllib` follows redirects by
default, so that 200 described a **different URL** than the one asked
about. With redirects off, the base path is a 307. My first version of
the finding keyed `mcp_surface_exists` on that base probe and so reported
no MCP surface on a tier that plainly has one — recorded in the evidence
under `base_path_is_not_the_probe` as *"the measurement was real, the
label was wrong, and nothing in the output said so."*

---

## 4. Credential rotation — three things that will cost you an hour

```bash
python3 scripts/27_build_recipient_model.py \
    --rotate-token psp7-demo-recipient --rotate-overlap-seconds 3600
python3 scripts/28_activate_credential.py \
    --recipient psp7-demo-recipient --activate --also-rewrite --force
python3 tests/t01_gateway_read.py && python3 tests/t03_ip_refusal.py
```

**The recipient is `psp7-demo-recipient`** — no `awoz1227-` prefix,
unlike the other two. The prefixed name returns
`404 RECIPIENT_DOES_NOT_EXIST`.

**`scripts/23_rotate_revoke_provider.py` does not exist.** It was named
as the remedy in two places. `scripts/23` is
`23_gen_outbound_allow_list.py`; rotation is `scripts/27 --rotate-token`.
Both references are now corrected in place.

**The configured overlap is refused in a credential's final 24h.** With
84 minutes left on the token, rotation carrying the configured 86400s
overlap returned:

```
HTTP 400 INVALID_PARAMETER_VALUE
"Cannot extend the token expiration time."
```

The overlap request *is* an extension request once the token has less
life left than the overlap, and extension is refused. The same call with
`--rotate-overlap-seconds 3600` returned **200 `ROTATED`** — one variable
changed, opposite outcomes. So: rotate before `expiry − overlap`, or
shorten the overlap and accept a harder cutover.

`--rotate-overlap-seconds` is new, added for this. It also makes RKI-2's
`expire=0` compromise path **reachable** — still unexercised, no run has
yet proven a hard cutover works.

**Two console lines were lossy where the evidence was sound**, and both
are now fixed:

- Rotation printed `ROTATE_FAILED` and stopped. The status code and error
  were in the evidence file only, so a typo in a recipient name read as a
  platform refusal.
- Rule 4 has **always** measured `psp7-demo-recipient:
  LIFETIME_DIFFERS_SET_AT_BIRTH` — a 24h token window against a
  configured 7d — and the console printed only state and token count. So
  three recipients that differ read as three that agree, and anyone
  planning from the terminal would have assumed a week of credential life
  on a recipient that has a day. **This is not a tier cap:** the other
  two measure `LIFETIME_AS_CONFIGURED` at 7d. The mechanism was right and
  the summary was lossy — and my first reading of it, which blamed the
  tier, was wrong.

Current clocks: `psp7-demo-recipient` → **2026-10-23T07:37:24Z**.
`awoz1227-psp7-t2-us-recipient` → **2026-10-28**, and it is the
credential B-32c and T-04 read through, so it gates re-running the
propagation measurement.

---

## 5. The deny-row count is now three-way

`scripts/31_gen_access_matrix_tf.py` counted
`tested_by present AND no gap → tested`, everything else → not tested.
That put a deny row with a **verified probe** and a named residual gap in
the same bucket as a row nobody had ever looked at.

```
deny rows : 14  (tested, no gap: 5; tested with a named gap: 2; no test: 7)
```

Previously reported as 5 tested and 9 untested. The generated
`what_this_is_not` sentence read *"9 of 14 deny rows have no test, and
they are the separation-of-duty rows"* — **false in both halves** once
E-2 shipped, since one of the newly-covered rows is the internal
base-table row and not a separation-of-duty row at all.

Same defect as the verdict-vocabulary one, in a third place: **a count
too coarse to name the state will name the nearest one.** Folded upward
it overstates coverage; folded downward it discards the only
internal-channel evidence E1 produced.

---

## 6. The §6.3 client verification session — read this before you demo

```bash
python3 tests/run_verification_session.py   # 6 of 9, and 6 is the honest number
```

Not E1's deliverable. It is **the script that implements CONOPS §6.3**,
the session a client is walked through. E1's verification pass ran it and
it had four defects, which is worth your hour because this is the
artifact with an audience.

**It crashed at step 1.** `databricks-sdk` 0.153.0 renamed
`SharesAPI.list` → `list_shares` and removed the old name.
`RecipientsAPI.list` was **not** renamed in the same release, so the
very next line still worked and the breakage looked local rather than
like version skew. One `AttributeError` meant **steps 2–7 produced no
verdict at all** — a crash is not a failure, it is six silent negatives.
Now resolved by name so it runs on either SDK.

**Step 3 certified the drift it existed to catch.** It compared
`rewritten-credential.json`'s endpoint to `GRAVITEE_GATEWAY_EDGE_URL`
and passed — and both of those still say `/delta-sharing`, which
`route-table.yaml` records as **retired**. Two values from one stale
source agree with each other whatever the truth is. **B-40 in a new
place: the control must be the same path as the subject.** Step 3 now
resolves the live path from `gravitee/generated/route-family.json` —
`/opensharing-demo/psp7-demo` — and **fails**, which is correct: the
credential rewriter emits a retired endpoint. That is E2 Task 2.1's
consolidation and it is now a red row instead of a green one.

**Step 4 asked for the base table.** It named
`opensharing_test.test_dataset`, and E1's entitlement model makes every
share object a **view**, so the base table is deliberately not in the
share. Databricks answered `RESOURCE_DOES_NOT_EXIST` — which reads like
a broken share and was a correct refusal of a name this repo's own design
forbids. The object is now **discovered** from the share, and step 4
passes on a real measurement: **50 rows** from
`opensharing_test.v_entitled_t2` through `/opensharing-demo/psp7-demo`,
`internal_notes` absent.

**T-06 passed because the route did not exist.** Assertion was
`status >= 400`; the retired path's `404 ENDPOINT_NOT_FOUND` scored as
*"the edge rejected the malformed body"*. **B-44.** Now asserts a **400
from the edge**, with `CANNOT_SEE_NO_ROUTE_AT_THIS_PATH` and
`CANNOT_SEE_REFUSED_BEFORE_VALIDATION_{401,403}` as separate verdicts.
Still passes, now on a measured 400.

**Steps 6 and 7 were PASS rows with `passed=True` and an actual of "see
that other program's output."** Two of nine rows in the log a client
would be shown measured nothing. Now `NOT_RUN_HERE`, not counted as
passes. Step 7 is not run inline on purpose — it **revokes** a live
recipient four other tests read through.

So: **6 of 9** — one real red row, two honest `NOT_RUN_HERE`. It read
8 of 9 before, and that was the least true of the three numbers.

The evidence log lands in `_secrets/verification-session-evidence.json`
because it carries a bearer token; `_secrets/` is gitignored.

---

## 7. Gates and the full re-run

```bash
python3 scripts/22_check_cac_config.py     # expect 356 checks, 0 failed,
                                           #        CAC_CONFIG_CONSISTENT
python3 scripts/check_secret_hygiene.py    # expect: Clean
python3 -m pyflakes scripts tests          # expect: 14 warnings, see below
python3 tests/run_verification_session.py  # the suite
```

Run the CAC gate **alone** — several tests rewrite config files while
they run.

**Pyflakes is not clean, and this note previously said it was.** It
reports 14 warnings across nine files — `scripts/01`, `06`, `07`, `16`,
`17`, `18`, `19`, `tests/t19_ingress_d2d.py`,
`tests/run_verification_session.py` — in three categories: a local
assigned and never used, an import never used, and an f-string with no
placeholders. None is a logic defect and none is in a file E1's closure
work touched. They are recorded here rather than fixed, because editing
nine unrelated scripts in the hour before an archive cut buys a cosmetic
claim at the price of an untested diff. **The reason this correction is
in the note at all** is that the earlier *"expect: clean"* was written
from assumption and not from a run; propagating a clean claim that a
single command disproves is the same defect this epic spent its week
documenting, committed by its own report.

**Two gate findings worth carrying**, both from this verification pass:

- An unquoted YAML date (`methods_confirmed_on: 2026-10-22`) parses to
  `datetime.date`, which `json.dumps` refuses, which **crashed** the CAC
  gate — zero checks, no verdict, non-zero exit for a reason unrelated
  to configuration. A gate that crashes is worse than one that fails: a
  failure names a cause, a crash names only itself. Fixed in two places
  — the dates are quoted, *and* `scripts/22`'s leak scan now passes
  `default=str` so no future scalar can do this again.
- `shutil.copy2` preserves the **source's** mode, so b32c's backup of a
  tracked 0664 config landed in `_secrets/` world-readable and left the
  repository failing its own hygiene gate. The gate was right and the
  test was wrong; the fix is `BACKUP.chmod(0o600)` in the test, not an
  exemption in the gate (B-47).

---

## 8. Platform facts measured across the epic, so nobody re-derives them

**Gravitee**

- Context paths are **prefixes**.
- An unmatched path is **forwarded, not refused**. This is B-48, the
  epic's largest finding.
- **Array position is not evaluation order.** Flows are evaluated from
  the **most generic selector to the most specific**, so a `/`
  `STARTS_WITH` flow emitted last runs **first**. A reviewer reading a
  generator top to bottom will conclude the opposite of what runs.
- **A step-level `condition` that does not evaluate true silently OMITS
  the policy** — PUT 200, deploy 202, no warning anywhere (AI-10). One
  such line reopened `/api/2.0/token/list` to 200. **Rule: no condition
  on any step whose absence fails open.** A condition is safe on a step
  that *adds* a refusal and unsafe on a step that *is* the refusal.
- `policy-request-validation` with empty `rules` **passes everything** —
  this is how a no-op deny shipped looking like a control.
- Plan creation needs `definitionVersion: "V4"`.
- API-create POST **silently discards `properties`**.
- A PUT-edited definition needs an explicit `POST /apis/{id}/deployments`.
- An **edge refusal** and an **upstream refusal forwarded through the
  edge** are the same status code with opposite remedies (B-44). Attribute
  refusals from the body, never the status alone.

**Databricks Free Edition**

- Row/column security and Delta Sharing are **mutually exclusive**, both
  directions:
  `ROW_COLUMN_SECURITY_NOT_SUPPORTED_WITH_TABLE_IN_DELTA_SHARING`.
- UC permissions PATCH/GET work; **UC principals are account-level**, so
  workspace groups 404.
- UC accepts a service principal by **applicationId**, `account users`,
  and a user email — **not** an SP display name.
- **No credential can be minted for a non-human principal.**
- `effective-permissions` returns `{}`.
- `ALTER VIEW ... AS` is accepted on a shared view where `REPLACE` is
  blocked — and **does not reach a live consumer within 600s** (§1
  above).
- Timing: a newly shared object was unreadable at **170.8s** and readable
  **7.7h** later. A consumer polling for three minutes and concluding the
  share is broken will raise a false defect.

**Data shape** (50 rows, `test_dataset`)

```sql
region = element_at(array('us-east','us-west','us-central'),
                    CAST((id % 3) + 1 AS INT))
```

`region = 'us-east'` → **16** · `region IN ('us-east','us-west')` → **33**
· `region = 'us-east' AND record_id % 2 = 0` → **8**.
`record_id` is `bigint`, `metric_value` is `double`.

---

## 9. The one rule that produced everything above

**Import the rule rather than copy it.** Restating a derived value
instead of deriving it has caused **six** defects in this repository
(B-39). The terminal allow-list in
`scripts/30_gen_gravitee_ai_route.py` derives its patterns from the
forwarding flows' own selectors — when you bring it to the sharing and
storage APIs, copy the **function**, not the patterns.

And the general form, which is worth more than any single finding here:
**a perimeter test that never observes the perimeter absent is measuring
the wrong thing.** Every control in E1 now has a run in which it was
switched off and seen to stop working. That is what makes the evidence
worth taking to the ARB — and it is also, every time, what found the
defect.
