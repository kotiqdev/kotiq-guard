# Service accounts = non-human identities ("robots"). No password — they act via granted IAM roles
# (and, for the deployer, via Workload Identity from GitHub). Two distinct jobs → two accounts.

# The identity Cloud Run RUNS AS in production. Kept deliberately powerless (see iam.tf).
resource "google_service_account" "runtime" {
  account_id   = "kotiq-run"
  display_name = "kotiq-guard Cloud Run runtime"
}

# The identity GitHub Actions assumes to DEPLOY (wired to GitHub via Workload Identity next).
resource "google_service_account" "deployer" {
  account_id   = "kotiq-deployer"
  display_name = "kotiq-guard CI deployer"
}
