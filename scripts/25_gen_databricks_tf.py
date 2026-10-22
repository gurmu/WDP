#!/usr/bin/env python3
"""
E1 Task 1.4, second deliverable: generate iac/databricks/*.tf from
iac/config/entitlements.yaml.

ONE SOURCE, TWO CONSUMERS. scripts/24 applies the model through the REST
API and verifies it; this script renders the same config as Terraform.
Neither one is the definition. That matters because AC6 is "redeploy the
configuration from code to a clean target" (T-12), and a Terraform file
hand-written beside a live workspace drifts from it the first time
anybody fixes something in the UI -- which is exactly the failure T-12
exists to detect, so it must not be designed in.

WHAT THIS FILE IS NOT
---------------------
It has NEVER been `terraform apply`ed. Free Edition has no account
console and no account-level API, the Databricks Terraform provider
authenticates per workspace, and T-12's clean target does not exist in
this topology. So the honest status of the generated code is
PLAN_ONLY_NOT_APPLIED, and the header says so in the file itself rather
than only here -- a .tf file in a repo is read by people who assume it
runs.

The INTERESTING part of T-12 is not whether Terraform works; it is
whether this repository's configuration is complete enough that a clean
target could be built from it with no hidden manual step. The generator
surfaces that directly: anything it cannot express is emitted as a
`not_expressible` comment block in the output, so the gap is visible in
the artifact a reviewer reads.

DATA IS NOT CONFIGURATION. The base table is emitted as a resource with
its column types, because its shape is part of the model. Its fifty
synthetic rows are not: they come from scripts/01_create_test_dataset.py
and a Terraform file that pretended to own them would be claiming to
redeploy data it cannot reproduce.

Usage:
    python3 scripts/25_gen_databricks_tf.py
    python3 scripts/25_gen_databricks_tf.py --dry-run
"""

import argparse
import datetime
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFIG = REPO / "iac" / "config" / "entitlements.yaml"
OUTDIR = REPO / "iac" / "databricks"
GENERATED = OUTDIR / "entitlement.tf"
PROVIDERS = OUTDIR / "providers.tf"
VARIABLES = OUTDIR / "variables.tf"
TFVARS_EXAMPLE = OUTDIR / "terraform.tfvars.example"


def now():
    return (datetime.datetime.now(datetime.timezone.utc)
            .isoformat().replace("+00:00", "Z"))


def ident(name):
    """HCL resource labels cannot carry a hyphen."""
    return name.replace("-", "_").replace(".", "_")


def hcl_str(text):
    s = str(text).replace("\\", "\\\\").replace('"', '\\"')
    return '"' + " ".join(s.split()) + '"'


HEADER = """\
# =====================================================================
# GENERATED FILE -- DO NOT HAND-EDIT.
# =====================================================================
#
# Produced by scripts/25_gen_databricks_tf.py from
# iac/config/entitlements.yaml, which is the single definition of the
# entitlement model. Edit the YAML and re-run the generator; an edit
# here is overwritten and, worse, diverges from what scripts/24 applies
# and verifies in the meantime.
#
# STATUS: PLAN_ONLY_NOT_APPLIED
#
#   This code has never been `terraform apply`ed. Free Edition exposes
#   no account console and no account-level API, and AC6's clean target
#   (T-12) does not exist in this topology. Treat it as the statement of
#   WHAT would be deployed -- reviewable, diffable, and complete enough
#   to argue about -- not as proven deployment code. T-12 remains
#   NOT_RUN; see docs/12 §12.10.
#
# NOT TRANSFERABLE AS WRITTEN. Catalog and schema names, the DSA
# reference placeholders and the warehouse id belong to the local
# prototype. What transfers is the model: views only in shares, explicit
# select lists, the base table never shared, a DSA reference on every
# shared object.
#
# CONOPS §3.1 / §2.3.1 / §3.4 offer "a view, OR column masks and row
# filters". There are no mask or row-filter resources below because that
# alternative does not exist for OpenSharing tables at any tier -- the
# platform refuses it (docs/11 §11.4). Their absence here is a finding,
# not an omission.
#
# Generated: {generated}
# Source:    iac/config/entitlements.yaml (schema_version {sv})
"""

PROVIDERS_TF = """\
# Hand-maintained (written once if absent; the generator does not
# overwrite it). Only entitlement.tf is generated.
terraform {
  required_version = ">= 1.5.0"
  required_providers {
    databricks = {
      source  = "databricks/databricks"
      version = "~> 1.50"
    }
  }
}

# Workspace-level provider. Free Edition has no account-level API, so
# there is deliberately no account-level provider alias here: a block
# that cannot authenticate in this tier would fail at plan time and the
# failure would be read as a credential problem.
provider "databricks" {
  host  = var.databricks_host
  token = var.databricks_token
}
"""

VARIABLES_TF = """\
# Hand-maintained (written once if absent).

variable "databricks_host" {
  type        = string
  description = "Workspace URL, e.g. https://dbc-xxxx.cloud.databricks.com"
}

variable "databricks_token" {
  type        = string
  sensitive   = true
  description = "Workspace PAT. Never committed -- see terraform.tfvars.example."
}

variable "catalog" {
  type        = string
  default     = "__CATALOG__"
  description = "Unity Catalog catalog name."
}

variable "schema" {
  type        = string
  default     = "__SCHEMA__"
  description = "Schema holding the base table and the entitled views."
}

variable "warehouse_id" {
  type        = string
  description = <<-EOT
    SQL warehouse used to create tables and views. Required because the
    databricks_sql_table resource executes DDL through a warehouse.
    Discovered at apply time rather than pinned here: a warehouse id
    hard-coded in config is the first thing to be wrong on a clean
    target, and AC6 is specifically about a clean target.
  EOT
}
"""

TFVARS = """\
# Copy to terraform.tfvars and fill in. terraform.tfvars is gitignored;
# this example is not. Nothing secret belongs in this file.
databricks_host  = "https://dbc-REPLACE.cloud.databricks.com"
databricks_token = "REPLACE_FROM_YOUR_SECRET_STORE"
warehouse_id     = "REPLACE"
"""


def render(cfg):
    L = [HEADER.format(generated=now(), sv=cfg.get("schema_version"))]

    L.append("""
# ---------------------------------------------------------------------
# Catalog and schema
# ---------------------------------------------------------------------
resource "databricks_catalog" "main" {
  name    = var.catalog
  comment = "AWOZ-1227 prototype. Synthetic non-sensitive data only (CONOPS 1.2)."
}

resource "databricks_schema" "main" {
  catalog_name = databricks_catalog.main.name
  name         = var.schema
  comment      = "Base table plus the entitled views that are shared in its place."
}
""")

    L.append("""
# ---------------------------------------------------------------------
# Base tables. NEVER added to a share.
#
# The SHAPE is configuration; the ROWS are not. Fifty synthetic rows are
# loaded by scripts/01_create_test_dataset.py, and a Terraform resource
# claiming to own them would be claiming to redeploy data it cannot
# reproduce.
# ---------------------------------------------------------------------""")
    for t in cfg.get("base_tables") or []:
        L.append(f'resource "databricks_sql_table" "{ident(t["name"])}" {{')
        L.append(f'  name               = "{t["name"]}"')
        L.append('  catalog_name       = databricks_catalog.main.name')
        L.append('  schema_name        = databricks_schema.main.name')
        L.append('  table_type         = "MANAGED"')
        L.append('  warehouse_id       = var.warehouse_id')
        L.append(f'  comment            = {hcl_str("Base table. Never shared -- see docs/11 11.5.")}')
        L.append("")
        for c in t.get("columns") or []:
            L.append("  column {")
            L.append(f'    name = "{c["name"]}"')
            L.append(f'    type = "{c["type"]}"')
            if not c.get("entitled"):
                L.append("    # NOT entitled. Withheld from every share by "
                         "absence from each view's")
                L.append("    # select list -- there is no mask to "
                         "misconfigure and nothing to fail open.")
            L.append("  }")
        L.append("}")
        L.append("")

    L.append("""
# ---------------------------------------------------------------------
# Entitled views. These are what the shares carry.
#
# Each view_definition is an EXPLICIT column list. `SELECT * EXCEPT
# (...)` is forbidden by EI-2: it fails open, picking up any column the
# base table gains, silently and share-wide. The two forms look equally
# correct in review and behave in opposite directions the first time the
# base table changes.
# ---------------------------------------------------------------------""")
    for v in cfg.get("views") or []:
        base = v["base_table"]
        cols = ", ".join(v["select"])
        where = f" WHERE {v['where']}" if v.get("where") else ""
        definition = (f"SELECT {cols} FROM ${{databricks_catalog.main.name}}."
                      f"${{databricks_schema.main.name}}.{base}{where}")
        comment = (f"AWOZ-1227 entitled view. tier={v['tier']} "
                   f"dsa_ref={v['dsa_ref']} "
                   f"({v.get('dsa_ref_status', 'UNKNOWN')}) "
                   f"purpose={v['purpose']} "
                   f"row_scope={v.get('row_scope')} "
                   f"defined_by=iac/config/entitlements.yaml")
        L.append(f'resource "databricks_sql_table" "{ident(v["id"])}" {{')
        L.append(f'  name            = "{v["id"]}"')
        L.append('  catalog_name    = databricks_catalog.main.name')
        L.append('  schema_name     = databricks_schema.main.name')
        L.append('  table_type      = "VIEW"')
        L.append('  warehouse_id    = var.warehouse_id')
        L.append(f'  view_definition = "{definition}"')
        L.append("")
        L.append("  # EI-4 / CONOPS 3.3 purpose limitation: the COMMENT is "
                 "the only field that")
        L.append("  # travels with the object, so the tier and the DSA "
                 "reference live there. The")
        L.append("  # placeholder status travels with the value so nobody "
                 "downstream mistakes it")
        L.append("  # for an executed agreement reference.")
        L.append(f'  comment         = {hcl_str(comment)}')
        L.append("")
        L.append(f'  depends_on = [databricks_sql_table.{ident(base)}]')
        L.append("}")
        L.append("")

    L.append("""
# ---------------------------------------------------------------------
# Shares. One share per purpose (CONOPS 3.1 share isolation), views only.
#
# Per docs/11 11.7 B-29, 3.1's "one recipient per consuming agency or
# use case" is unsatisfiable for *use case*: a recipient is keyed by the
# consuming metastore identifier, and the second CREATE RECIPIENT returns
# RECIPIENT_ALREADY_EXISTS naming the first. Isolation is therefore one
# recipient per consuming metastore with several shares granted to it --
# which is why the per-purpose split is here, on shares. Recipients and
# their grants are Task 1.5 and are NOT in this file.
# ---------------------------------------------------------------------""")
    for sh in cfg.get("shares") or []:
        L.append(f'resource "databricks_share" "{ident(sh["name"])}" {{')
        L.append(f'  name    = "{sh["name"]}"')
        L.append(f'  comment = {hcl_str(sh.get("comment", ""))}')
        if sh.get("remediation_required"):
            L.append("")
            L.append("  # This share pre-exists and carried the BASE TABLE "
                     "(docs/11 11.5). The name is")
            L.append("  # kept deliberately: renaming it would leave the "
                     "misconfigured share in place")
            L.append("  # under the old name, and the issued recipient "
                     "credential points at this name.")
        for obj in sh.get("objects") or []:
            L.append("")
            L.append("  object {")
            L.append('    name             = "${databricks_catalog.main.name}'
                     '.${databricks_schema.main.name}.' + obj + '"')
            L.append('    data_object_type = "VIEW"')
            L.append(f'    comment          = {hcl_str(sh.get("purpose", ""))}')
            L.append("  }")
        L.append("")
        L.append("  depends_on = [" + ", ".join(
            f"databricks_sql_table.{ident(o)}"
            for o in (sh.get("objects") or [])) + "]")
        L.append("}")
        L.append("")

    # Anything the generator cannot express is emitted, not dropped.
    L.append("""
# ---------------------------------------------------------------------
# not_expressible -- emitted rather than dropped
#
# T-12 asks whether a clean target could be built from this repository
# with no hidden manual step. A generator that silently omitted what it
# could not render would make the answer look like yes.
# ---------------------------------------------------------------------
#
# 1. THE FIFTY SYNTHETIC ROWS. Shape is configuration, data is not. A
#    clean target needs scripts/01_create_test_dataset.py run after
#    apply, and every row-count assertion downstream (rule 5's row-scope
#    difference, T-04's reads) depends on it. This is the one manual
#    step this file knows about and names.
#
# 2. RECIPIENTS, THEIR TOKENS AND THEIR IP ACCESS LISTS. Task 1.5. A
#    recipient resource here would be creating credentials from
#    Terraform state, and the activation link is single-use and manual
#    in this tier.
#
# 3. THE DSA REFERENCE VALUES. Placeholders, labelled as such in every
#    comment. E3 Task 3.2 replaces the values; the mechanism is already
#    proven end to end.
#
# 4. THE WAREHOUSE. Discovered at apply time via var.warehouse_id, not
#    managed here. Free Edition's warehouse is provided by the tier, and
#    a databricks_sql_endpoint resource on a clean target of a different
#    tier would be the wrong size in both directions.
#
# 5. UPDATING A SHARED VIEW IN PLACE -- a live T-12 risk, measured.
#    `CREATE OR REPLACE VIEW` is refused once the view is in a share:
#
#      INVALID_STATE.DELTA_SHARING_SECURABLE_DELETE_BLOCKED.BY_SHARES
#      ... cannot be deleted because it is being shared via OpenSharing
#
#    because REPLACE drops first. scripts/24 now branches to
#    `ALTER VIEW ... AS` plus `COMMENT ON VIEW` for the update path. The
#    Databricks Terraform provider's databricks_sql_table resource
#    recreates on a view_definition change, so `terraform apply` against
#    an already-shared view is expected to hit the same refusal, and the
#    redeploy would stall on an object that is present and correct. A
#    clean target (T-12's actual subject) creates the view BEFORE adding
#    it to the share and does not meet this; a second apply over a live
#    share does. Not worked around here, because the workaround --
#    removing the object from the share, replacing the view, re-adding it
#    -- revokes a consumer's access mid-deploy, and that is a decision
#    for the CONOPS rather than a generator's default.
#
# 6. VERIFICATION. `terraform validate` and `terraform plan` have NOT
#    been run against this output in this topology -- the provider
#    download and a reachable workspace are both required, and neither
#    is part of the local prototype's network allow-list. The claim this
#    file supports is "the model is fully expressed in code", not "the
#    code is known to apply cleanly".
""")
    return "\n".join(L).rstrip() + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    if not CONFIG.exists():
        sys.exit(f"Missing {CONFIG.relative_to(REPO)}")
    try:
        import yaml
    except ImportError:
        sys.exit("pyyaml is required: pip install -r requirements.txt")
    cfg = yaml.safe_load(CONFIG.read_text())

    text = render(cfg)

    print("=" * 70)
    print("Terraform generation from the entitlement model")
    print("=" * 70)
    print(f"  source: {CONFIG.relative_to(REPO)}")
    print(f"  views:  {[v['id'] for v in cfg.get('views') or []]}")
    print(f"  shares: {[s['name'] for s in cfg.get('shares') or []]}")
    print("  status: PLAN_ONLY_NOT_APPLIED (stated in the file header)")

    if args.dry_run:
        print(f"\n--dry-run: {len(text.splitlines())} lines, nothing written.")
        return 0

    OUTDIR.mkdir(parents=True, exist_ok=True)
    GENERATED.write_text(text)
    print(f"\n  Wrote {GENERATED.relative_to(REPO)} "
          f"({len(text.splitlines())} lines)")

    for path, body in ((PROVIDERS, PROVIDERS_TF),
                       (VARIABLES, VARIABLES_TF
                        .replace("__CATALOG__", cfg["catalog"])
                        .replace("__SCHEMA__", cfg["schema"])),
                       (TFVARS_EXAMPLE, TFVARS)):
        if path.exists():
            print(f"  Kept  {path.relative_to(REPO)} (exists; "
                  f"hand-maintained, not overwritten)")
        else:
            path.write_text(body)
            print(f"  Wrote {path.relative_to(REPO)}")

    print("\n  Reminder: terraform.tfvars holds a PAT and must stay out of "
          "git.\n  Check .gitignore covers iac/databricks/terraform.tfvars "
          "and *.tfstate*.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
