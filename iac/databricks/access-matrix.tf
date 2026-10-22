# =====================================================================
# GENERATED FILE -- DO NOT HAND-EDIT.
# =====================================================================
#
# Produced by scripts/31_gen_access_matrix_tf.py from
# iac/config/access-matrix.yaml, with every Unity Catalog object name
# resolved against iac/config/entitlements.yaml. Edit the YAML and
# re-run; an edit here is overwritten and, in the meantime, diverges
# from the matrix the ARB package cites.
#
# STATUS: PLAN_ONLY_NOT_APPLIED
# STATUS: provisional, awaiting 1694-G1
#
# TWO SEPARATE CAVEATS, AND THEY ARE DIFFERENT SIZES.
#
# 1. PROVISIONAL. CONOPS §3.1 presents this matrix and then says it is
#    "for Data Governance to confirm (input 1694-G1)". That input has
#    not arrived (assumption A1). Every grant below is what the CONOPS
#    PROPOSES. Do not cite this file as an agreed control.
#
# 2. NEVER APPLIED, and for four of six principals NOT APPLIABLE on
#    this tier. 5 of the 6 principals are ACCOUNT-level
#    objects -- groups and service principals -- and Free Edition
#    exposes no account console and no account-level API. The
#    `databricks_group` and `databricks_service_principal` resources
#    below name principals that DO NOT EXIST here. T-12 stays NOT_RUN.
#
# WHAT A REVIEWER SHOULD TAKE FROM THIS FILE
# ------------------------------------------
# Not "the access model is deployed". Rather: this is the access model
# written down precisely enough to be disagreed with, with each row
# labelled by whether the platform can express it, and with the deny
# rows -- the half of a matrix that makes it falsifiable -- marked by
# whether any test covers them. Today, of 14 deny rows, 5
# have a test with no residual gap, 2 have a test that
# verified its own probe and still names a residual gap, and the rest
# have no test at all. Those three are deliberately not collapsed into
# two: a row whose probe was proven to move is not in the same state as
# a row nobody has looked at, and a count that cannot tell them apart
# invites the reader to discount both.
#
# Generated: 2026-10-22T07:40:31.842069Z
# Sources:   iac/config/access-matrix.yaml (schema_version 1)
#            iac/config/entitlements.yaml  (object names resolved)


# ---------------------------------------------------------------------
# Principals
# ---------------------------------------------------------------------

# External recipient -- CONOPS §3.1
#   A named counterparty organisation holding a Delta Sharing
#   credential. Not a Databricks identity and holds no Unity Catalog
#   privilege at all -- its access is entirely the share grant plus
#   the recipient's own properties.
# No resource. A Delta Sharing recipient is created by
# scripts/03 and defined in iac/config/recipients.yaml;
# duplicating it here would give two definitions of one
# object, which is the drift T-12 exists to detect.
# Local instances, verified live:
#   awoz1227-psp7-demo-recipient
#   awoz1227-psp7-t2-us-recipient

# Internal consumer group -- CONOPS §3.1
#   Internal analysts reading shared datasets inside the provider's
#   own metastore. Reads the entitled VIEWS, never the base table.
#
#   NOT IMPLEMENTABLE ON THIS TIER:
#     Account-level groups require the account console or the
#     account-level API. Free Edition exposes neither (docs/11
#     environment baseline). The grants below are expressed in Terraform
#     against a group NAME that does not exist on this tier, so the
#     generated resource is reviewable and not appliable.
#   LOCAL SUBSTITUTE (not an implementation):
#     The prototype operator's own identity holds these privileges
#     directly. That is a substitution, not an implementation, and it
#     means nothing locally distinguishes this row from the data owner
#     row -- the separation of duty the matrix proposes is UNTESTED, not
#     satisfied.
resource "databricks_group" "internal_consumer_group" {
  display_name = "awoz1227-internal-consumers"
}

# Data owner -- CONOPS §3.1
#   Owns the dataset: defines the base table, decides which columns
#   and rows are entitled, and owns the views that express that.
#
#   NOT IMPLEMENTABLE ON THIS TIER:
#     account-level group, as above
#   LOCAL SUBSTITUTE (not an implementation):
#     the prototype operator
resource "databricks_group" "data_owner" {
  display_name = "awoz1227-data-owners"
}

# Sharing admin -- CONOPS §3.1
#   Creates shares and recipients, grants shares to recipients,
#   manages recipient IP access lists and credential rotation.
#
#   NOT IMPLEMENTABLE ON THIS TIER:
#     account-level group, as above
#   LOCAL SUBSTITUTE (not an implementation):
#     the prototype operator
resource "databricks_group" "sharing_admin" {
  display_name = "awoz1227-sharing-admins"
}

# Ingest job identity -- CONOPS §3.1
#   The identity under which the §2.4.1 ingress job runs: reads a
#   remote provider's share and writes landed copies into the local
#   catalog.
#
#   NOT IMPLEMENTABLE ON THIS TIER:
#     Service principal support on Free Edition is UNCONFIRMED (A5
#     substitution note, ask 9). Not "unavailable" -- unconfirmed. No
#     probe has been run, so this row is a known unknown rather than a
#     known gap, and that distinction is itself a 1694-G1 input.
#   LOCAL SUBSTITUTE (not an implementation):
#     T-19 and T-20's ingress ran as the prototype operator. So the
#     ingress procedure is evidenced (T-19 PARTIAL_WITH_NAMED_GAPS, T-20
#     PASS_WITH_SCOPE) while the IDENTITY under which it should run is
#     not.
resource "databricks_service_principal" "ingest_job_identity" {
  display_name = "Ingest job identity"
}

# Gateway upstream identity -- CONOPS §3.1
#   The identity Gravitee presents to Databricks when it proxies a
#   request on the caller's behalf -- the credential injected by the
#   AI route's transform-headers steps.
#
#   NOT IMPLEMENTABLE ON THIS TIER:
#     Two reasons, and they are different sizes. (1) Service principal
#     support on Free Edition is unconfirmed (A5, ask 9), same as the
#     ingest identity. (2) More seriously, the gateway's injected
#     credential is TODAY a long-lived personal access token carrying a
#     human operator's full entitlements (AI-3). That is R12b: R12a
#     ("can the gateway inject an upstream credential") is CONFIRMED and
#     measured by T-15; R12b ("without a long-lived secret") is UNBUILT.
#     So this row is not merely unimplemented on this tier -- it names
#     the single largest unmitigated risk in the prototype.
#   LOCAL SUBSTITUTE (not an implementation):
#     DATABRICKS_TOKEN, a personal access token
resource "databricks_service_principal" "gateway_upstream_identity" {
  display_name = "Gateway upstream identity"
}

# ---------------------------------------------------------------------
# Grants
# ---------------------------------------------------------------------
# Object names below were RESOLVED from entitlements.yaml, not
# transcribed. The reference each one came from is in the comment.

resource "databricks_grants" "catalog_awoz1227_demo" {
  catalog = "awoz1227_demo"
  # internal_consumer_group  (from `catalog:default`)
  grant {
    principal  = "awoz1227-internal-consumers"
    privileges = ["USE_CATALOG"]
  }
  # data_owner  (from `catalog:default`)
  grant {
    principal  = "awoz1227-data-owners"
    privileges = ["USE_CATALOG"]
  }
  # sharing_admin  (from `catalog:default`)
  grant {
    principal  = "awoz1227-sharing-admins"
    privileges = ["USE_CATALOG"]
  }
  # ingest_job_identity  (from `catalog:default`)
  grant {
    principal  = "Ingest job identity"
    privileges = ["USE_CATALOG"]
  }
}

resource "databricks_grants" "schema_awoz1227_demo_opensharing_test" {
  schema = "awoz1227_demo.opensharing_test"
  # internal_consumer_group  (from `schema:default`)
  grant {
    principal  = "awoz1227-internal-consumers"
    privileges = ["USE_SCHEMA"]
  }
  # data_owner  (from `schema:default`)
  grant {
    principal  = "awoz1227-data-owners"
    privileges = ["USE_SCHEMA", "CREATE_TABLE"]
  }
  # sharing_admin  (from `schema:default`)
  grant {
    principal  = "awoz1227-sharing-admins"
    privileges = ["USE_SCHEMA"]
  }
}

resource "databricks_grants" "view_awoz1227_demo_opensharing_test_v_entitled_t2" {
  view = "awoz1227_demo.opensharing_test.v_entitled_t2"
  # internal_consumer_group  (from `view:v_entitled_t2`)
  grant {
    principal  = "awoz1227-internal-consumers"
    privileges = ["SELECT"]
  }
  # sharing_admin  (from `view:v_entitled_t2`)
  grant {
    principal  = "awoz1227-sharing-admins"
    privileges = ["SELECT"]
  }
}

resource "databricks_grants" "view_awoz1227_demo_opensharing_test_v_entitled_t2_us" {
  view = "awoz1227_demo.opensharing_test.v_entitled_t2_us"
  # internal_consumer_group  (from `view:v_entitled_t2_us`)
  grant {
    principal  = "awoz1227-internal-consumers"
    privileges = ["SELECT"]
  }
  # sharing_admin  (from `view:v_entitled_t2_us`)
  grant {
    principal  = "awoz1227-sharing-admins"
    privileges = ["SELECT"]
  }
}

resource "databricks_grants" "table_awoz1227_demo_opensharing_test_test_dataset" {
  table = "awoz1227_demo.opensharing_test.test_dataset"
  # data_owner  (from `table:test_dataset`)
  grant {
    principal  = "awoz1227-data-owners"
    privileges = ["SELECT", "MODIFY"]
  }
}

# NOT EXPRESSIBLE as a databricks_grants block: current (metastore).
#   sharing_admin would hold CREATE_SHARE, CREATE_RECIPIENT
#   CREATE_SHARE / CREATE_RECIPIENT are metastore-level privileges and
#   need the account API this tier does not expose.

resource "databricks_grants" "schema_awoz1227_demo_ingested" {
  schema = "awoz1227_demo.ingested"
  # ingest_job_identity  (from `schema:landing`)
  grant {
    principal  = "Ingest job identity"
    privileges = ["USE_SCHEMA", "CREATE_TABLE"]
  }
}

# NOT EXPRESSIBLE as a databricks_grants block: databricks-gpt-oss-20b (literal).
#   gateway_upstream_identity would hold CAN_QUERY
#   This object is outside Unity Catalog (a serving endpoint); its
#   permission is a databricks_permissions resource, and on this tier
#   the identity holding it is a PAT, not a principal (R12b).

# ---------------------------------------------------------------------
# Deny rows -- what each principal must NOT hold
# ---------------------------------------------------------------------
# Terraform has no resource for 'this principal must not hold X'. The
# absence of a grant is the only expression available, and absence is
# not an assertion -- it is indistinguishable from forgetting. So each
# row below is emitted as a comment WITH its test, and a row whose
# test is NONE is a gap this file makes visible rather than closes.

# external_recipient:
#   [TESTED] must not write to any shared object
#            test: T-21
#            verdict: READ_ONLY_AND_NO_LEAK_BOTH_MEASURED
#   [TESTED] must not read a column excluded from the entitled view
#            test: T-04
#            verdict: COLUMN_AND_ROW_SCOPE_PROVEN_FROM_THE_CONSUMER_SIDE
#   [TESTED] must not read the base table
#            test: T-04 (base-table exposure probe)
#   [TESTED] must not read a share it holds no grant on
#            test: T-19 denial A
#            verdict: DENIAL_A_DEMONSTRATED
#   [TESTED] must not reach the sharing surface from outside the IP access list
#            test: T-02
#            verdict: ENFORCED_MECHANISM_PROVEN

# internal_consumer_group:
#   [GAP ] must not hold SELECT on the base table
#            §3.1's column scope is implemented by the view's select list.
#            SELECT on the base table makes every exclusion cosmetic. This is
#            the single most important deny row in the matrix.
#            test: tests/e2_egress_d2d.py
#   [GAP ] must not create or alter a share
#            that is the sharing admin's privilege, not a consumer's
#            test: NONE

# data_owner:
#   [GAP ] must not create a share, or grant a share to a recipient
#            §3.1 separates owning the data from deciding who outside the
#            organisation receives it. Proposed, not agreed -- this is one of
#            the rows 1694-G1 is being asked about, because in a small team
#            it is commonly the same person and the CONOPS should say so
#            explicitly rather than imply a separation nobody keeps.
#            test: NONE

# sharing_admin:
#   [GAP ] must not hold SELECT on the base table
#            Shares contain views by construction (entitlements.yaml), so a
#            sharing admin never needs the base table. Granting it would let
#            the admin add the base table to a share, which is the one action
#            that defeats the whole entitlement model.
#            test: NONE
#   [GAP ] must not alter a view's select list
#            That is the data owner's decision about entitlement. An admin
#            who can widen a view can widen a share without touching the
#            share.
#            test: NONE

# ingest_job_identity:
#   [GAP ] must not read or write anything in the provider-side schema
#            Ingress writes to a landing schema. An ingest identity with
#            reach into the provider-side schema turns a compromised ingest
#            job into a provider-side data loss.
#            test: NONE
#   [GAP ] must not create shares or recipients
#            test: NONE

# gateway_upstream_identity:
#   [GAP ] must not hold any privilege beyond CAN_QUERY on the named endpoints
#            test: PARTIALLY -- T-16 proves the gateway will not FORWARD a request to any path outside the route allow-list, which bounds the identity's reachable surface at the edge. It does not constrain the identity itself: a caller who obtained the injected credential would hold everything it holds.
#   [GAP ] must not be a long-lived secret
#            R12b
#            test: NONE
#            severity: highest open item in this matrix

# ---------------------------------------------------------------------
# not_expressible -- carried from the config, verbatim
# ---------------------------------------------------------------------
# * account-level groups and service principals
#     why: Free Edition exposes no account console and no account-level API.
#          Four of six principals are account-level objects.
#     consequence: The generated Terraform names principals that do not exist on this
#                  tier. It is reviewable and diffable; it has never been applied and
#                  T-12 stays NOT_RUN.
#
# * the separation-of-duty rows
#     why: Every `must_not` concerning one principal not holding another's
#          privilege requires two distinct identities to test. The prototype
#          has one operator wearing every hat.
#     consequence: The matrix's deny rows are mostly UNTESTED. The ARB package must
#                  say which deny rows have a test (the external recipient's five,
#                  all passing) and which have only a sentence (the other nine).
#
# * short-lived gateway upstream credentials
#     why: R12b is unbuilt
#     consequence: see gateway_upstream_identity above
#
