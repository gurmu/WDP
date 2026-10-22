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
# Generated: 2026-10-20T22:38:29.240385Z
# Source:    iac/config/entitlements.yaml (schema_version 1)


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


# ---------------------------------------------------------------------
# Base tables. NEVER added to a share.
#
# The SHAPE is configuration; the ROWS are not. Fifty synthetic rows are
# loaded by scripts/01_create_test_dataset.py, and a Terraform resource
# claiming to own them would be claiming to redeploy data it cannot
# reproduce.
# ---------------------------------------------------------------------
resource "databricks_sql_table" "test_dataset" {
  name               = "test_dataset"
  catalog_name       = databricks_catalog.main.name
  schema_name        = databricks_schema.main.name
  table_type         = "MANAGED"
  warehouse_id       = var.warehouse_id
  comment            = "Base table. Never shared -- see docs/11 11.5."

  column {
    name = "record_id"
    type = "BIGINT"
  }
  column {
    name = "agency_name"
    type = "STRING"
  }
  column {
    name = "use_case"
    type = "STRING"
  }
  column {
    name = "region"
    type = "STRING"
  }
  column {
    name = "record_date"
    type = "DATE"
  }
  column {
    name = "metric_value"
    type = "DOUBLE"
  }
  column {
    name = "internal_notes"
    type = "STRING"
    # NOT entitled. Withheld from every share by absence from each view's
    # select list -- there is no mask to misconfigure and nothing to fail open.
  }
}


# ---------------------------------------------------------------------
# Entitled views. These are what the shares carry.
#
# Each view_definition is an EXPLICIT column list. `SELECT * EXCEPT
# (...)` is forbidden by EI-2: it fails open, picking up any column the
# base table gains, silently and share-wide. The two forms look equally
# correct in review and behave in opposite directions the first time the
# base table changes.
# ---------------------------------------------------------------------
resource "databricks_sql_table" "v_entitled_t2" {
  name            = "v_entitled_t2"
  catalog_name    = databricks_catalog.main.name
  schema_name     = databricks_schema.main.name
  table_type      = "VIEW"
  warehouse_id    = var.warehouse_id
  view_definition = "SELECT record_id, agency_name, use_case, region, record_date, metric_value FROM ${databricks_catalog.main.name}.${databricks_schema.main.name}.test_dataset"

  # EI-4 / CONOPS 3.3 purpose limitation: the COMMENT is the only field that
  # travels with the object, so the tier and the DSA reference live there. The
  # placeholder status travels with the value so nobody downstream mistakes it
  # for an executed agreement reference.
  comment         = "AWOZ-1227 entitled view. tier=T2 dsa_ref=DSA-AWOZ-1227-PSP7-001 (PLACEHOLDER) purpose=CDAO PSP7 egress demo -- column scope row_scope=ALL_ROWS defined_by=iac/config/entitlements.yaml"

  depends_on = [databricks_sql_table.test_dataset]
}

resource "databricks_sql_table" "v_entitled_t2_us" {
  name            = "v_entitled_t2_us"
  catalog_name    = databricks_catalog.main.name
  schema_name     = databricks_schema.main.name
  table_type      = "VIEW"
  warehouse_id    = var.warehouse_id
  view_definition = "SELECT record_id, agency_name, use_case, region, record_date, metric_value FROM ${databricks_catalog.main.name}.${databricks_schema.main.name}.test_dataset WHERE region = 'us-east'"

  # EI-4 / CONOPS 3.3 purpose limitation: the COMMENT is the only field that
  # travels with the object, so the tier and the DSA reference live there. The
  # placeholder status travels with the value so nobody downstream mistakes it
  # for an executed agreement reference.
  comment         = "AWOZ-1227 entitled view. tier=T2 dsa_ref=DSA-AWOZ-1227-PSP7-002 (PLACEHOLDER) purpose=CDAO PSP7 egress demo -- column AND row scope row_scope=SINGLE_REGION defined_by=iac/config/entitlements.yaml"

  depends_on = [databricks_sql_table.test_dataset]
}


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
# ---------------------------------------------------------------------
resource "databricks_share" "awoz1227_psp7_demo_share" {
  name    = "awoz1227-psp7-demo-share"
  comment = "AWOZ-1227 demo share. Views only; the base table is never added. Synthetic non-sensitive data (CONOPS 1.2)."

  # This share pre-exists and carried the BASE TABLE (docs/11 11.5). The name is
  # kept deliberately: renaming it would leave the misconfigured share in place
  # under the old name, and the issued recipient credential points at this name.

  object {
    name             = "${databricks_catalog.main.name}.${databricks_schema.main.name}.v_entitled_t2"
    data_object_type = "VIEW"
    comment          = "CDAO PSP7 egress demo -- column scope"
  }

  depends_on = [databricks_sql_table.v_entitled_t2]
}

resource "databricks_share" "awoz1227_psp7_t2_us_share" {
  name    = "awoz1227-psp7-t2-us-share"
  comment = "AWOZ-1227 row-scoped share. Views only. Exists to make §3.1 share isolation observable: two purposes, two shares, one recipient."

  object {
    name             = "${databricks_catalog.main.name}.${databricks_schema.main.name}.v_entitled_t2_us"
    data_object_type = "VIEW"
    comment          = "CDAO PSP7 egress demo -- column AND row scope"
  }

  depends_on = [databricks_sql_table.v_entitled_t2_us]
}


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
