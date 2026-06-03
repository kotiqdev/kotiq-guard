# Values to copy into GitHub repo Variables (Settings → Secrets and variables → Actions → Variables).
# Run `terraform output` any time to print them again.

output "WIF_PROVIDER" {
  description = "GitHub repo variable: full Workload Identity provider resource name."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "DEPLOYER_SA" {
  description = "GitHub repo variable: CI deployer service-account email."
  value       = google_service_account.deployer.email
}

output "RUNTIME_SA" {
  description = "GitHub repo variable: Cloud Run runtime service-account email."
  value       = google_service_account.runtime.email
}

output "GCP_PROJECT_ID" {
  description = "GitHub repo variable: project id."
  value       = var.project_id
}

output "AR_REPO" {
  description = "GitHub repo variable: Artifact Registry repository name."
  value       = google_artifact_registry_repository.containers.repository_id
}
