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
