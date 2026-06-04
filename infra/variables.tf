# Inputs to this Terraform config. Values are supplied in terraform.tfvars (next to this file).
# Declaring them here gives types + descriptions; tfvars fills the actual values.

variable "project_id" {
  type        = string
  description = "GCP project id everything is created in."
}

variable "region" {
  type        = string
  description = "Default region for regional resources (Cloud Run, Artifact Registry, Vertex)."
  default     = "europe-west1"
}

variable "github_repo" {
  type        = string
  description = "owner/repo allowed to deploy via Workload Identity Federation."
  default     = "kotiqdev/kotiq-guard"
}
