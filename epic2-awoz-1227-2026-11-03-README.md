# Epic 2 migration bundle — AWOZ-1227 / INC17 milestone 1227

**Built 2026-11-03T15:58:28.737767Z by `scripts/41_build_epic2_bundle.py`.** Every test verdict below is read out of the evidence file named beside it at build time. None is typed into the builder, so a verdict here cannot disagree with the evidence it cites.

Platform measured: **Gravitee APIM CE 4.12.23**, Databricks OpenSharing (US-East-2), Free Edition tier.

## Read these three first

1. **`docs/epics/E2-arb-package.md`** — the AC2 package. Every figure traces to a file under `evidence/`, and every gap is stated in the same sentence as the claim it qualifies.
2. **`docs/15-deferred-to-client-environment.md`** — what is deferred, with the specific client-side resource each item needs, *and* Part B: what is owed here before migration. Part B is the part worth checking first, because it is the part that stops the deferred list becoming a parking space.
3. **`docs/11-environment-baseline.md` §11.7** — the blocker register, B-1 to B-55. The most useful thing in the bundle for anyone rebuilding this: it is a list of the mistakes, with what each cost.

## What AC2 claims, and what it does not

Four of AC2's five clauses are evidenced. **Clause 2.5 is not** — the throttles are measured firing and clearing at the configured points, and nothing here demonstrates that the edge trips *before* Databricks, which is what the clause actually asks for. That needs `system.access.audit`. See A-1 in the register.

Three things this bundle deliberately does not claim:

- **Deny-by-default is not native to this gateway.** An unmatched flow is *forwarded*, not refused (B-48). Route X is an explicit catch-all built because §3.2's fallback was the only route, and it returns a correct but **reasonless** 403 — the protocol error format is met on ingress and not on egress (PC-4).
- **Header sanitization covers successes, not refusals** (B-55). A request-phase refusal answers before the response chain runs.
- **Path rewrite is not demonstrated.** I1's upstream path comes from string concatenation, which is B-48's mechanism wearing a useful hat, and calling it a rewrite would be a false capability claim. R12 stays live.

## Epic 2 task status

| Task | | Status | Verdict, read from evidence |
|---|---|---|---|
| **2.1** | Correct the B-1 diagnosis and fix the real fault | CLOSED | _no test; see the epic document_ |
| **2.2** | Make the import idempotent | CLOSED | _no test; see the epic document_ |
| **2.3** | Generate the route table into the API definition | CLOSED | **CANNOT_SEE** (1/4) · `t01-report.json` · BINDING_ENFORCED_AND_THE_ERROR_NAMES_BOTH_HALVES · 4 check(s) · 2026-11-03 |
| **2.4** | Policy classes A-E as shared configuration | CLOSED | _no test; see the epic document_ |
| **2.5** | T-03: valid token from an address off the allow-list | CLOSED | PASS · `t03-report.json` · REFUSED_AT_THE_EDGE_AND_REVERSIBLE · 1 check(s) · 2026-10-27 |
| **2.6** | T-05: rate limit, spike arrest, and who trips first | CLOSED (edge half); clause 2.5 deferred | PASS · `t05-report.json` · THROTTLED_WITH_NO_RETRY_INDICATION · 1 check(s) · 2026-11-02 |
| **2.7** | T-06: schema validation, body limits, error format | CLOSED | PASS · `t06-report.json` · BODY_SCHEMA_ENFORCED_NAMES_AND_TYPES · 1 check(s) · 2026-10-28 |
| **2.8** | T-07: header sanitization | CLOSED, NARROWED by B-55 | PASS · `t07-report.json` · INTERNAL_HEADERS_REMOVED_WITH_A_NAMED_REFUSAL_RESIDUE · 1 check(s) · 2026-11-03 |
| **2.9** | T-08 and F1: the storage proxy, and B-3 | DEFERRED (A-2) | _no test; see the epic document_ |
| **2.10** | T-15: class E and the serving routes | PARTIAL -- injection confirmed; route deferred (A-3) | PASS · `t15-report.json` · R12A_CONFIRMED_INJECTION_REPLACES_AND_IS_SCOPED · 1 check(s) · 2026-10-21 |
| **2.11** | T-24: the edge half of push ingest | CLOSED | PASS · `t24-report.json` · EDGE_REFUSALS_ENFORCED_WITH_CORRECT_STATUSES · 1 check(s) · 2026-10-29 |
| **2.12** | Fill in the §3.2 table, then build the package | CLOSED | _no test; see the epic document_ |

- **2.1** — Upstream resolved from the issued credential, never a template.
- **2.2** — scripts/05 re-reads the server to confirm what it kept.
- **2.3** — Both residue items settled; route X built after B-48. T-01 is the faithful-read evidence the route table's claim rests on, so it is cited here rather than left uncited -- which is what lets the guard below notice when its last run could not see.
- **2.4** — Plus class I, labelled ahead-of-document.
- **2.5** — Refusal measured and reversed.
- **2.6** — Both throttles verbatim; clause 2.5 needs system.access.audit (A-1).
- **2.7** — Three rejections, two acceptances.
- **2.8** — Both halves measured. Covers successes only -- see A-5.
- **2.9** — No static upstream; Free Edition storage is Databricks-managed.
- **2.10** — T-15 passes on the half that is measurable here: the gateway replaces the caller's credential and the injected identity is scoped (R12A). What is deferred is a live serving endpoint behind the route, not the capability.
- **2.11** — Six refusals with distinct correct statuses; traversal fixed (B-54).
- **2.12** — Four of seven rows carry an observation; this bundle is the rest.

## What is in here

### Governing document

- **`CONOPS_AWOZ-1227_v1.5.docx`** — The baselined document every finding is measured against.

### Configuration as code (the design, in machine-readable form)

- **`iac/config/route-table.yaml`** — Every route, its class, its target and its refusals. The generator's only input for the route family.
- **`iac/config/policy-classes.yaml`** — Classes A-E plus class I, and the measured notes on each step: the spike-arrest enforced shape, B-55's extent, PC-1/2/4/5.
- **`iac/config/producers.yaml`** — Push-ingest producers and the landing-target rule. One producer, DECLARED_NOT_PROVISIONED.
- **`iac/config/response-header-allowlist.yaml`** — The 11 permitted response headers, derived from measured before/after captures, and the record that enforcement lives in the test rather than the gateway.
- **`iac/config/recipients.yaml`** — The recipient and credential model, including the two-phase T-02/T-03 procedure.
- **`iac/config/channels.yaml`** — Channel definitions (D2O, D2D, I-1, I-2).
- **`iac/config/entitlements.yaml`** — Share and grant model.
- **`iac/config/access-matrix.yaml`** — Principal-to-object access.
- **`iac/config/outbound-allow-list.yaml`** — Egress addresses, generated.
- **`iac/gravitee/schemas/query-body.schema.json`** — Class B's request body schema, GENERATED from route-table S8 rather than written.
- **`iac/databricks/access-matrix.tf`** — Terraform, generated.
- **`iac/databricks/entitlement.tf`** — Terraform, generated.
- **`iac/databricks/providers.tf`** — Terraform providers.
- **`iac/databricks/variables.tf`** — Terraform variables.
- **`iac/databricks/terraform.tfvars.example`** — Variable template. Values are not in the bundle.

### Generators and probes

- **`scripts/05_import_gravitee_api.py`** — Imports a generated definition and re-reads the server to confirm what it kept. Carries confirm_analytics_landed().
- **`scripts/29_gen_gravitee_route_family.py`** — Generates the per-recipient API family and the push family from the route table. One API per recipient (B-42/D-9).
- **`scripts/30_gen_gravitee_ai_route.py`** — Generates the M1 AI route.
- **`scripts/37_gen_query_body_schema.py`** — Derives class B's body schema from the route table; four guards refuse to generate rather than emit a permissive one.
- **`scripts/36_probe_unlisted_paths.py`** — Route X's refusing half: 7 unlisted paths plus before/after controls, attributed by the responder's own voice.
- **`scripts/34_probe_deny_policy.py`** — Which installed policy can refuse AND emit a body. Answer: none (PC-4).
- **`scripts/35_probe_deny_pair.py`** — The paired form of the same question.
- **`scripts/38_probe_ingest_policies.py`** — All 79 installed policy schemas, read from the gateway, with the ingest shortlist printed in full.
- **`scripts/33_probe_s10_path.py`** — S10 path behaviour.
- **`scripts/22_check_cac_config.py`** — The static gate: ~400 checks across the CaC set, including that an ahead-of-document route carries its sanction.
- **`scripts/27_build_recipient_model.py`** — Recipient/credential model, applied and verified in eight rules.
- **`scripts/28_activate_credential.py`** — Credential activation, with a liveness verdict that cannot close on a stale file (B-51).
- **`scripts/06_trace_correlation.py`** — AC5's correlation handle: fires a real route, requires a 200 before asking the header question, then interrogates the log store it has first inspected.
- **`scripts/39_collect_conops_v16_inputs.py`** — Generates docs/14 from every v1.6 mention in the repository.
- **`scripts/40_build_weekly_report.py`** — Week 43's report, as a builder.
- **`scripts/41_build_epic2_bundle.py`** — This script.
- **`scripts/check_secret_hygiene.py`** — The second gate.
- **`scripts/lib/terminal_allow_list.py`** — Derives route X's Ant whitelist from the forwarding flows' own selectors, with the translation shape asserted (B-50).
- **`scripts/hooks/pre-commit`** — The hygiene hook.
- **`scripts/hooks/install.sh`** — Installs it.
- **`scripts/00_check_capabilities.py`** — The first thing to run after any environment change.

### Tests

- **`tests/common.py`** — Shared harness.
- **`tests/t01_gateway_read.py`** — T-01: faithful reads through the edge, with CANNOT_SEE as a third verdict state and 1.1s pacing so a throttle is never scored as a refusal.
- **`tests/t02_ip_access_list.py`** — T-02: the IP allow-list, armed.
- **`tests/t03_ip_refusal.py`** — T-03: refusal from an address off the list, and reversed.
- **`tests/t05_rate_limit.py`** — T-05 edge half: four phases, both throttles captured verbatim, with a recovery control so a throttle that never clears cannot read as a pass.
- **`tests/t06_body_schema.py`** — T-06: class B body schema, each body sent direct and through the edge.
- **`tests/t07_header_sanitization.py`** — T-07: header sanitization, both halves, plus phase 3b which measures whether REFUSALS are sanitized (B-55).
- **`tests/t24_push_refusals.py`** — T-24 edge half: 12 probes, attribution by constraint message, positive controls on the same path.
- **`tests/t15_model_route.py`** — T-15: the model-serving route (blocked, A-3).
- **`tests/t16_mcp_route.py`** — T-16: the MCP route (blocked, A-3).

### Generated gateway definitions (what was deployed)

- **`gravitee/api-definition.json`** — The hand-written seed.
- **`gravitee/generated/route-family.json`** — The family manifest.
- **`gravitee/generated/api-e1-psp7-demo.json`** — Egress API, recipient 1.
- **`gravitee/generated/api-e1-psp7-t2-us.json`** — Egress API, recipient 2.
- **`gravitee/generated/api-e1-t02-iplist.json`** — Egress API, recipient 3.
- **`gravitee/generated/api-i1-push-psp7-producer.json`** — Push ingest, class I.
- **`gravitee/generated/api-f1-storage-proxy.json`** — F1, with FORWARDING_DISABLED. Included BECAUSE it is disabled: the listener is real and the forwarding step is not (A-2).
- **`gravitee/generated/api-m1-ai-gateway.json`** — M1, upstream credential injected.

### Runtime

- **`docker-compose.yml`** — The gateway stack, including the two overrideMode=keep env vars that closed B-52 and the loopback-bound Elasticsearch.
- **`requirements.txt`** — Python dependencies.
- **`.env.example`** — The environment template. Values are NOT in the bundle; the header rule in this file says why.
- **`.gitignore`** — What never gets committed.

### Documentation

- **`docs/epics/E2-T04-11-traffic-control.md`** — Epic 2's working document: twelve tasks, each with its closure block or its stated blocker, and the filled §3.2 table.
- **`docs/epics/E2-arb-package.md`** — The AC2 package. Every figure traceable to evidence/; every gap named in the same sentence as the claim.
- **`docs/11-environment-baseline.md`** — The environment and the blocker register, B-1 to B-55.
- **`docs/12-test-matrix.md`** — All 25 tests, each assigned an epic and a feasibility verdict.
- **`docs/13-decisions-and-risks.md`** — Open decisions (OD-*) and risks (R*).
- **`docs/14-conops-v1.6-inputs.md`** — Every v1.6 input the repository has recorded, GENERATED from the findings rather than transcribed.
- **`docs/16-epic2-end-to-end.md`** — The lead's briefing: Epic 2 end to end in CONOPS terms rather than artifact terms -- what each clause asks, which test measures it, what the test proves and what it cannot. Written to be talked from without opening a file.
- **`docs/15-deferred-to-client-environment.md`** — What is deferred and on which client resource -- and Part B, what is owed HERE before migration.
- **`docs/10-implementation-manual.md`** — How to stand the prototype up.
- **`docs/00-services-setup-guide.md`** — Service prerequisites.
- **`docs/epics/E1-closure-record.md`** — Epic 1's closure, which AC2 builds on.
- **`docs/epics/E1-T04-10-perimeter-and-access.md`** — Epic 1's working document.

### Evidence

`evidence/` is included whole — 71 file(s). It is taken wholesale rather than listed file by file because the package and `docs/11` both cite it, and a hand-kept list would be the first thing to go stale. Per CONOPS 5.1 it carries **metadata only**: no tokens, no credential files, no shared data. The builder scans every included file for credential-shaped strings and refuses to write the archive if it finds one.

### What is deliberately NOT in here

- `_secrets/` — credential files, activation records, server config with values. Excluded by path, and the exclusion wins even if something declares the file.
- `.env` — the live environment. `.env.example` is included; its own header carries the rule that the live file is never copied back over it.
- `.git/` and `__pycache__/` — history and build artifacts.

## Rebuilding from this bundle

```bash
# 1. verify the archive against its own manifest
sha256sum -c MANIFEST.sha256

# 2. re-run both gates FROM THE EXTRACTION, not from a working tree
#    (Epic 1's archive passed in the working tree and was still wrong)
python3 scripts/22_check_cac_config.py
python3 scripts/check_secret_hygiene.py

# 3. environment, then capability probe
cp .env.example .env    # fill it in; never copy it back
python3 scripts/00_check_capabilities.py

# 4. generate and deploy, then test
python3 scripts/29_gen_gravitee_route_family.py
python3 scripts/05_import_gravitee_api.py
python3 tests/t01_gateway_read.py
```

Input hashes are recorded in `evidence/gravitee-route-family.json`, so T-12's *"redeploy from code to a clean target yields the same configuration"* is checkable rather than asserted.

## One sentence worth keeping

> A perimeter test that never observes the perimeter absent is measuring the wrong thing.

Every control in this bundle has a run in which it was switched off and seen to stop working. That is what makes the evidence worth taking to an ARB — and it is why the test count went up and the pass rate went down in the weeks that produced it.

_Bundle id: `2026-11-03`._
