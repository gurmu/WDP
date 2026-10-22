# E6 — 1227-E6: Infrastructure and Deployment, IaC/CaC (AC6)

| | |
|---|---|
| **Epic** | 1227-E6 |
| **Acceptance criterion** | AC6 — Infrastructure and Deployment |
| **CONOPS sections** | 3.6 (AC6 requirements), 4 (IL2 vs IL5 strategy), 5 (build target), 7 (roadmap/checkpoints), 10 (self-build fallback) |
| **Stories** | 1: IaC/CaC build and deployment with Data Eng (§3.6, §5) · 2: Integrate into CONOPS (§3.6, §4) · 3: Review-ready check (§7, §10) |
| **Role** | Integrate — Data Eng builds the IaC/CaC; AI/ML Ops integrates |
| **Target dates** | 10/23 – 11/13 · checkpoint **10/23** E6 kickoff with Data Eng · checkpoint **11/2–11/3** credential provisioning and IaC/CaC working in test environment · checkpoint **11/10** review-ready · checkpoint **11/13** sign-off request |
| **Depends on** | 1694-S3 (IaC/CaC tooling from Data Eng) |
| **Tests** | T-12 |
| **Decisions in play** | OD-3 (IL2/IL5), OD-4 (credential rewrite) |
| **Risks in play** | R1, R6 (week-4 compression) |

> **The criterion, verbatim (CONOPS §3.6):** *Infrastructure and Deployment: IaC/CaC; infrastructure requirements such as SSO, centralized logging, observability for future IL5 production deployment and sustainment.*

---

## E6.0 What this epic actually has to produce

AC6 is narrower than it appears. It has a single test (T-12) and that test is conclusive: "redeploy the configuration from code to a clean target, expected same configuration, no manual steps". This is the build target stated in §10 ("Prototype + IaC artifacts"), and it is the reason E6 can be front-loaded despite starting on 10/23 instead of 10/1.

E6 owns three things in sequence.

**First, the IaC/CaC collection**. Every other epic emits it as it goes — Terraform modules for Databricks objects (catalogs, views, shares, recipients, IP lists), JSON definitions for Gravitee routes and policies, YAML config files for policy-class values and allow-lists. E6's job is to gather them into a coherent tree with clear entry points and prove that they are actually deployable, reproducibly.

**Second, the deployment procedure and its inverse**. T-12 means the test environment must have a clean teardown path (`docker compose down -v`) and a repeatable standing-up path (re-import and Terraform apply). That path must be documented and its logic captured in code — scripts like `scripts/05_import_gravitee_api.py` for the gateway and equivalent patterns for Databricks. The procedure is itself infrastructure as code and belongs in `iac/` as entry points that a CI/CD pipeline or a human operator can call.

**Third, the future IL5 infrastructure requirements**. Section 3.6 lists six rows (SSO, centralized logging, observability, network, secrets and keys, sustainment duties) that are not being built now but whose requirements must be collected from Data Eng, documented, and handed to the post-ARB deployment team with an owner and a confirmation status for each. This is not deferred work — it is collected work that unblocks the next phase.

CONOPS §1.4 and §10.2 note explicitly that if a partner team cannot deliver in time, AI/ML Ops writes the minimum scripts to stand up the test environment so the criteria can still be verified. **This epic is that fallback being exercised**: E6 is owned by AI/ML Ops because Data Eng's IaC/CaC (1694-S3) has not yet arrived. The work is real and the output is the same; the difference is that E6 writes the scripts locally rather than waiting to integrate them from Data Eng.

---

## E6.1 Task list

Each task is independently verifiable. Run them in order. **PARTNER** or **DEFERRED** tasks are not skipped quietly — they produce a written gap with an owner.

### Task 6.1 — Establish the four deployed-from-code rows as the spine

Blocker B-2 (V4 APIs invisible on the v1 management API) and the import idempotency failure that produced the duplicate API definition are the first thing E6 owns. Blocker B-1 is **not** one of them: it was reclassified on 2026-10-18 (§11.7) as an upstream target error — the gateway serves the open protocol correctly, and E2 Task 2.1 converges the two definitions. What E6 inherits is the consequence: a non-idempotent import fails T-12 by construction. Section 3.6 spells out four categories of things that must deploy from code: Gateway definitions (routes, plans, policies, address lists), Databricks objects (shares, recipients, catalogs, grants, landing volume, service principals), Configuration (policy values, allow-lists, route templates, tier mapping), and Secrets (vault references only, never in the repository).

The fourth is trivial — it is a rule about what not to do. The first three are the structure. Get the schema right so every other epic can see where its output goes.

**Deliverable:** `iac/` directory tree with subdirectories `iac/gravitee/`, `iac/databricks/`, and `iac/config/`, and a README in `iac/` explaining which artifact lives where, who owns it, and how it gets deployed. Add a summary table to the README showing the owner and current status of each row.

**Verify:** the directory tree is in place; the README is readable by someone unfamiliar with the codebase; E1-E5 epics can understand where their IaC outputs go without asking.

### Task 6.2 — Own the deployment contract for the Gravitee import, not the script

**Ownership note, so this work is not done twice.** The rewrite of
`scripts/05_import_gravitee_api.py` itself belongs to **E2 Task 2.2** —
management v2 instead of v1 (blocker B-2), and idempotent by **cross-ID
with an update on the existing API** rather than delete-and-recreate.
E2 holds the 10/19 checkpoint and is blocked by it, so it writes the
script. Do not write a second import script here.

Do not substitute a delete-then-create strategy for idempotency either,
even though it is easier. It churns API identifiers, discards
accumulated plan and subscription state, and leaves the gateway briefly
serving nothing — none of which a production deployment path can do,
and T-12 is meant to rehearse a production deployment path.

E6's share is the layer above the script: the **deployment contract**.
That means preconditions checked before anything mutates, evidence
emitted after, and a documented inverse, so that T-12 has something to
exercise and a failed deploy leaves a diagnosis rather than a mess.

**Deliverable:** `iac/deploy.sh` (or `iac/Makefile`) that calls E2's
import only after (1) confirming the compose stack is up and the
services reachable, and (2) asserting the Elasticsearch and Mongo
discrete properties are actually set **in the running gateway
container** — the §11.2 traps, both of which are silent when wrong, one
of them by hanging rather than erroring. Plus the documented inverse
(`docker compose down -v` and what it destroys).

**Verify:** running the entry point twice against a clean stack leaves
exactly one API and one plan; the second run reports an update with an
incremented revision, not a create. If the API count reaches two, E2
Task 2.2 is not finished and T-12 cannot pass — say so rather than
working around it.

### Task 6.3 — Fix and document the Mongo counter configuration

Section 11.2 documents two hard-won fixes in `docker-compose.yml` that must be preserved in any rebuild: `gravitee_ds_elastic_host` / `_port` (not `analytics.elasticsearch.endpoints[0]`, which is silently ignored), and `gravitee_ds_mongodb_host` / `_port` / `_dbname` on the gateway (not `gravitee_management_mongodb_uri`, which is a different key for a different purpose). Both are documented inline in the current file; both will be invisible unless explicitly reproduced.

**Deliverable:** a commented summary section in `iac/` (or as a separate `docs/IaC-README.md`) listing the two configuration fixes, explaining what happens if either is omitted (Elasticsearch metrics lost, rate-limit/spike-arrest policies hang), and pointing to the section 11.2 evidence.

**Verify:** someone not involved in the original debugging can read the summary and understand why both keys are necessary without having to re-discover the problem.

### Task 6.4 — Resolve the storage-proxy path contradiction (B-3)

Blocker B-3. `gravitee/api-definition.json` declares `/storage-proxy` as a flow selector beneath the `/delta-sharing` listener, so the real edge path is `/delta-sharing/storage-proxy`. But `.env` sets `GRAVITEE_STORAGE_PROXY_URL=http://localhost:8082/storage-proxy`. One must change.

CONOPS OD-1(b) decides that the storage proxy is a gateway route, so it is correct to use the gateway edge. The question is whether F1 (the storage proxy route) sits under the sharing listener or gets its own listener path. Recommendation: give F1 its own listener path (`/storage-proxy`) with a separate HTTP listener, so the proxy is independent of the sharing listener and `.env` becomes the source of truth.

**Deliverable:** updated `gravitee/api-definition.json` with F1 under its own HTTP listener at `/storage-proxy`; updated `.env.example` to show `GRAVITEE_STORAGE_PROXY_URL=http://localhost:8082/storage-proxy`; a note in `iac/` explaining the change and why it matters (config drift prevention).

**Verify:** the import succeeds and the F1 listener answers at `/storage-proxy/` with the expected class D edge response rather than the `NotFoundProcessor` 404 recorded in §11.7 B-3. Note that **`/delta-sharing/` is retired by E2 Task 2.1** — its upstream target was wrong (B-1 as reclassified), and the consolidated API uses the endpoint from the issued credential file. Verify against the consolidated sharing listener, not against `/delta-sharing/`.

### Task 6.5 — Collect the Databricks Terraform scaffold with placeholders

Data Eng owns the choice of tool for Databricks objects (Terraform, Pulumi, or scripts), and the CONOPS notes "the Databricks Terraform provider is one option". Assume Terraform and build the scaffolding so the structure is clear before Data Eng confirms the tool.

Section 3.6 names six categories of Databricks objects: shares, recipients, catalogs, grants, landing volume, service principals. The scaffold should have a module or a file for each, even if the content is a comment saying "Data Eng to fill this in". The shape matters — E1 needs to know where to write the recipient IP lists, E3 needs to know where DSA tier tags go, E4 needs to know where the ingest landing volume goes.

**Deliverable:** `iac/databricks/` with files `catalogs.tf`, `shares.tf`, `recipients.tf`, `views.tf` (the entitlement views from E1), `landing.tf` (volume and jobs), and `access-matrix.tf` (the §3.1 row/column grants), each with a header comment explaining what it holds and what other epics feed into it. Include a `versions.tf` with the Databricks provider block and a `variables.tf` for parameterization.

**Verify:** the file list is complete relative to section 3.6; the structure is clear to someone familiar with Terraform; there are no secrets in any file, only `.env` or `var.*` references.

### Task 6.6 — Establish the Configuration-as-Code YAML structure

CaC is the bridge between the code that builds infrastructure (IaC) and the operators who change policy values and allow-lists. Section 3.6 lists policy-class values, allow-lists, route templates, and DSA tier mapping as the things that change by change request rather than by code commit. These go in `iac/config/` as versioned YAML files that are neither secrets nor code, and they are both human-readable and machine-consumable by the import script.

Task 1.3 establishes `channels.yaml` and `route-table.yaml`. Task 1.5 establishes `allow-lists.yaml`. Task 1.10 establishes `outbound-allow-list.yaml`. Task 1.11 establishes `access-matrix.yaml`. **E3 Task 3.3** establishes `token-policy.yaml` — not E1 and not here. E6's job in every case is to ensure the schema is consistent across all of them and the import path consumes them correctly, never to author them a second time.

**Deliverable:** a header comment in `iac/config/README.md` explaining the purpose of each file, the schema rules (consistent key naming, version/status fields, owner attribution), and a pointer to the configuration entry point in the import script that reads and applies them.

**Verify:** all five CaC files follow the same schema conventions; the import script has a configuration-load section that reads all of them in the right order.

### Task 6.7 — Make the gateway deploy emit its own evidence

Task 6.2 built the deployment contract. This task makes it **test
evidence** rather than a convenience script, because the gateway half of
T-12 is proven by what the deploy records, not by the operator's memory
of it going green.

The failure mode to design against is a deploy that looks healthy and is
not. §11.2's two traps both produce exactly that: a silently-ignored
Elasticsearch key leaves analytics pointed at `localhost:9200` with no
error anywhere, and missing Mongo properties make policy-bearing
requests hang rather than fail. A deploy that cannot distinguish "worked"
from "appeared to work" is not evidence of reproducibility.

**Deliverable:** the Task 6.2 entry point extended to write a
timestamped record to `evidence/e6-import.json` holding the API id, the
plan ids, the final `state` and `deploymentState`, the revision number,
and the result of each precondition assertion. On failure, a diagnostic
message naming the specific §11.2 trap or §11.7 blocker rather than a
stack trace.

**Verify:** the record is valid JSON matching the §10.4 evidence shape; a
deliberately misconfigured gateway (drop one Mongo property) produces a
diagnosis pointing at §11.2 rather than a hang; the recorded revision
increments on a real change and does not on a no-op.

### Task 6.8 — Build the Terraform apply entry point with state diff

The Terraform apply is the T-12 reproducibility proof for Databricks objects. Like the Gravitee import, it must produce an evidence record that shows the difference between the before and after states, not just "apply succeeded".

The challenge is that `terraform apply` already produces a diff, but only to the console. The entry point script must capture the diff, normalize it (remove timestamps and random IDs), and write a deterministic evidence record that can be compared between runs.

**Deliverable:** `scripts/06_terraform_apply.sh` (or equivalent) that (1) checks that `DATABRICKS_TOKEN` is set in `.env` and the workspace is reachable; (2) runs `terraform -chdir=iac/databricks plan -out=tfplan`; (3) captures the plan as JSON; (4) runs `terraform apply tfplan`; (5) writes a normalized diff to `evidence/e6-terraform.json` showing which resources changed (created, updated, deleted) and their IDs.

**Verify:** the script produces a readable diff; running apply twice against the same state shows "no changes" in the diff; the evidence record is valid JSON and includes timestamps.

### Task 6.9 — Define "same configuration" as a deterministic comparison

T-12 says "same configuration, no manual steps". That requires a definition of "same configuration" that is testable, not an eyeball check. Configuration is not just the infrastructure state — it is also the policy values, routes, and access controls.

For the gateway, "same" means the same routes, plans, policies, and policy values in the Gravitee console after re-import. For Databricks, "same" means the same shares, recipients, views, and grants. The comparison must be deterministic (same input always produces the same output) and normalized (ignoring timestamps, IDs that are system-generated on each deployment).

**Deliverable:** `scripts/07_verify_deployment.py` that (1) exports the gateway API definition from Gravitee (GET `/management/v2/organizations/DEFAULT/environments/DEFAULT/apis/{id}`) and normalizes it (remove created/updated timestamps, sort lists); (2) exports the Databricks shares and recipients (list shares, list recipients, describe each) and normalizes them; (3) compares both exports to a golden reference captured during the first successful deployment; (4) writes a pass/fail result to `evidence/e6-verify.json` with the differences highlighted if they do not match.

**Verify:** running the verification script after a fresh import/apply shows "configuration matches"; making a manual change in the Gravitee console (e.g., adding a policy) causes the verification script to flag the difference.

### Task 6.10 — Assemble the clean-target teardown and rebuild procedure

T-12 requires a clean target. That means the test environment must have a documented way to go from "running with live API and Databricks shares" to "fresh Docker state with no data" and back to "same configuration deployed from code". This is the inverse of the import and apply steps, and it must be idempotent and documented.

CONOPS §5.1 specifies that evidence never contains credentials or sensitive data, only metadata and timestamps. The teardown procedure must respect that by (1) not exporting any secret material, (2) confirming that `_secrets/` files are cleaned up, (3) wiping the Docker volumes (`docker compose down -v`).

**Deliverable:** a documented step-by-step procedure in `docs/IaC-README.md` or `scripts/IaC-README.md`, with a script `scripts/08_teardown.sh` that performs the whole sequence: stop the Gravitee gateway, delete the APIs, revoke the Databricks recipients, drop the shares, drop the views, drop the catalog, `docker compose down -v`, verify that `_secrets/` has no live tokens in readable form. Each step logs its action to `evidence/e6-teardown.json`.

**Verify:** running teardown and then importing/applying leaves the environment in the same state as the first deployment; the teardown evidence log shows all steps completed; no credentials are logged or left in `.env`.

### Task 6.11 — Collect IL5 infrastructure requirements from Data Eng

Section 3.6 lists six infrastructure items (SSO, centralized logging, observability, network, secrets and keys, sustainment duties) as future IL5 requirements. These are not being built in this milestone, but they must be written down with an owner and a confirmation status so the next team knows what to build.

Data Eng owns most of them. This task is a **PARTNER DEFERRED** conversation: sit with Data Eng with the six rows visible, note what each one requires, what tier of effort it is, and whether it is confirmed available in the target cloud/region (GovCloud for IL5, per OD-3). Record the answers as-is.

**Deliverable:** the §3.6 six-row table filled in (currently it says "To confirm" for most rows) with Data Eng input on status, effort, and any dependencies discovered (e.g., "SSO requires enterprise IdP; confirm GovCloud OIDC support is available").

**Verify:** **PARTNER DEPENDENT.** The table is filled in for each row with a status other than "To confirm" and with an owner named. If Data Eng cannot fill it in by the time E6 is review-ready (11/10), the rows stay as "To confirm" and that becomes an ask with a date.

### Task 6.12 — Assemble the Story 3 review-ready check and documentation

Checkpoint 11/10: "E6 review-ready". Checkpoint 11/13: "sign-off request".

Pull together the deployment procedure (Task 6.10), the verification script (Task 6.9), the evidence records from a clean-target redeploy (T-12), the collected IL5 requirements (Task 6.11), and the IaC/CaC artifact tree (Tasks 6.1–6.6). Write a summary in `docs/epics/E6-arb-package.md` showing (1) what was deployed, (2) what the clean-target teardown and rebuild proved, (3) what the IL5 future requirements are and who owns them, (4) what blockers remain (B-1 status, B-2 fixed by Task 6.2, B-3 fixed by Task 6.4, B-4 secrets hygiene depends on E1), and (5) any asks that need a person rather than a commit.

**Deliverable:** `docs/epics/E6-arb-package.md` with evidence references, gap statements, and asks. Record T-12's outcome: did the redeploy from code to a clean target produce identical configuration?

**Verify:** every AC6 clause (6.1–6.3) traces to evidence or to a named partner gap; no clause is silent. The IL5 requirements table has all six rows filled. If T-12 passed, that is recorded plainly. If it did not, the failure reason is stated and an owner is named.

---

## E6.2 IaC and CaC deliverables

| Path | Contents |
|---|---|
| `iac/gravitee/api-definition.json` | V4 API definition: listeners, endpoint groups, flows (routes, rate-limit, spike-arrest, IP filtering, schema validation, policies) |
| `iac/gravitee/plans.json` | (embedded in api-definition.json via the `plans` key) Plan definitions (freemium, standard, premium) with rate limit and quota per plan |
| `iac/databricks/catalogs.tf` | Catalog and schema creation |
| `iac/databricks/views.tf` | Entitlement views (view-based granular access per §11.4), with DSA and tier comments |
| `iac/databricks/shares.tf` | Share creation and configuration; share objects = views only, never base tables |
| `iac/databricks/recipients.tf` | Recipients, DSA comments, IP access lists, share grants |
| `iac/databricks/landing.tf` | Landing volume, partition structure, ingest jobs |
| `iac/databricks/access-matrix.tf` | Group grants per §3.1, provisional pending 1694-G1 |
| `iac/databricks/versions.tf` | Provider configuration and terraform version constraint |
| `iac/databricks/variables.tf` | Parameterization for catalog name, share names, tier values, etc. |
| `iac/config/channels.yaml` | §2.1 five-channel model (E-1, E-2, E-3, I-1, I-2) with mechanism, control point, status |
| `iac/config/route-table.yaml` | §2.3.2 routes (S1–S10, F1, M1–M3, A1, X) with method, path, policy class, exposure decision |
| `iac/config/allow-lists.yaml` | Gateway egress CIDRs as the source of truth for recipient IP access lists (E1 Task 1.5) |
| `iac/config/outbound-allow-list.yaml` | Ingress hosts captured from the real T-20 providers — the OSS reference server (D2O) and the `glovashu` metastore endpoint (D2D) — source of truth for allowable outbound hosts. Because both are real, this file carries host shapes the client environment will recognise rather than placeholders. |
| `iac/config/access-matrix.yaml` | Readable form of the §3.1 access matrix, marked `status: provisional` |
| `iac/config/token-policy.yaml` | Token lifetime, rotation cadence, overlap — values pending OD-5 |
| `iac/README.md` | Structure, schema rules, owner/status table, and entry point scripts for both Gravitee and Databricks |
| `iac/deploy.sh` | Deployment entry point and precondition contract (Task 6.2); calls E2's import only after the compose stack and the discrete Elasticsearch/Mongo properties are asserted in the running gateway |
| `scripts/05_import_gravitee_api.py` | **Authored by E2 Task 2.2**, not here: management v2, cross-ID idempotent update. Listed because E6 owns its place in the tree and its precondition contract |
| `scripts/06_terraform_apply.sh` | Deployment entry point: plan and apply Databricks objects, write normalized diff to evidence |
| `scripts/07_verify_deployment.py` | Post-deployment verification: export and normalize Gravitee and Databricks state, compare to reference |
| `scripts/08_teardown.sh` | Clean-target teardown: delete APIs, revoke recipients, drop shares, `docker compose down -v` |
| `docs/IaC-README.md` | Manual page: procedure for teardown, deployment, and verification in sequence; prerequisites; troubleshooting |

Secrets appear in none of these, only as `.env` references (CONOPS §3.6).

---

## E6.3 Tests owned or co-owned

| Test | Verdict | Owner epic | Note |
|---|---|---|---|
| T-12 | BUILD | E6 | The central test: redeploy from code to a clean target and verify identical configuration. Defines "same configuration" deterministically. Depends on Tasks 6.7, 6.8, 6.9, 6.10. |

E6 validates the IaC emitted by every other epic. That validation is implicit in T-12: if the import and apply succeed and the verification shows no unexpected differences, the IaC from E1–E5 is deployable.

---

## E6.4 Exit criteria

The epic is done — for the prototype's purposes — when all of the following hold:

The IaC/CaC artifact tree is in place with clear entry points and documented owner assignment for each row. The Gravitee API import script (05) is rewritten against v2 and proven idempotent in two consecutive runs. The Terraform Databricks scaffold (Tasks 6.5) is complete with file structure and provider configuration. The CaC schema is consistent across all YAML files (Task 6.6), and the import script loads them in the right order. The Mongo and Elasticsearch configuration fixes (Task 6.3) are documented with their impact and evidence. The storage-proxy path (Task 6.4) is resolved and `.env` is the source of truth. The import entry point (Task 6.7) verifies preconditions and writes evidence records. The Terraform entry point (Task 6.8) captures and normalizes the plan diff. The verification script (Task 6.9) compares exported state to a golden reference and flags differences. The teardown procedure (Task 6.10) is documented and tested. T-12 passes: a clean-target redeploy produces identical configuration with no manual steps, and the deterministic comparison (Task 6.9) confirms it. The IL5 infrastructure requirements (Task 6.11) are collected from Data Eng or marked "To confirm" with the reason. The E6 ARB package (Task 6.12) traces all three AC6 clauses to evidence or to a named gap, leads with the T-12 outcome, and lists any blockers still open with their owners and dates.

---

## E6.5 What this epic cannot close

| Item | Needs | Reference |
|---|---|---|
| 1694-S3 tooling choice and integration | Data Eng confirmation and delivery of IaC/CaC in their chosen tool; Local fallback: AI/ML Ops-owned scripts as built here | CONOPS §1.4, §10.2; Task 6.2, 6.5 |
| IL5 infrastructure requirements (SSO, centralized logging, observability, network, secrets and keys) | Data Eng input on feasibility, effort and GovCloud availability; Status per item | Task 6.11; 3.6 requirements table |
| Sustainment duties cadence and SLA | Platform operations owner; proposed cadence pending confirmation | 3.6 sustainment row; 13.8 ask 9 |
| Service principal support on the client workspace tier | Data Eng confirmation for Free Edition substitute and for the client tier | A5, 13.6; T-24 and E-3 upstream identity depend on it |
| Front-door attachment (1636) to Apigee | Data Tooling; relationship unconfirmed in CONOPS | 10-implementation-manual.md §10.5 local posture |

Each of these should leave the epic as a dated ask, not as an empty cell in the ARB package.
