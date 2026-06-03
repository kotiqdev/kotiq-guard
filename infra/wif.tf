# Workload Identity Federation: lets GitHub Actions authenticate to GCP with NO long-lived key.
# GitHub issues each workflow run a short-lived, signed OIDC token; GCP trusts it — but only for
# our exact repo — and exchanges it for a short-lived token that impersonates the deployer SA.

# 1) A pool to hold external (non-Google) identities.
resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "github-pool"
  display_name              = "GitHub Actions"
  description               = "Federated identities from GitHub Actions"

  depends_on = [google_project_service.enabled]
}

# 2) Trust GitHub's OIDC issuer; map claims; HARD-restrict to our repo.
resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub OIDC"

  # Copy the token's claims into attributes we can match on.
  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }

  # CRITICAL gate: accept a token ONLY if its `repository` claim is exactly our repo. Without this,
  # any GitHub repo on earth could present a valid GitHub token and try to use this provider.
  attribute_condition = "assertion.repository == '${var.github_repo}'"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# 3) Allow identities coming FROM our repo to impersonate the deployer SA.
resource "google_service_account_iam_member" "github_deployer" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_repo}"
}
