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
  default     = "awoz1227_demo"
  description = "Unity Catalog catalog name."
}

variable "schema" {
  type        = string
  default     = "opensharing_test"
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
