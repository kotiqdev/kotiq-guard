# Pins the Terraform CLI and the Google provider versions, so every run (your Mac, a teammate,
# CI) uses the SAME plugin and behaves identically. `terraform init` reads this and downloads
# the google provider into ./.terraform/, recording exact hashes in .terraform.lock.hcl.
terraform {
  required_version = ">= 1.9"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.0"
    }
  }
}
