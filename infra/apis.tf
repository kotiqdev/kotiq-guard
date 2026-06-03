# Enable the Google Cloud APIs we'll need. A fresh project has almost everything OFF; calling an
# API before enabling it just errors. Terraform turns them on declaratively.
#
# for_each loops over the set below, creating one google_project_service per API.
# disable_on_destroy = false: `terraform destroy` won't try to switch these back off (safer — other
# things in the project might rely on them).
locals {
  services = [
    "run.googleapis.com",                  # Cloud Run
    "artifactregistry.googleapis.com",     # Docker image registry
    "aiplatform.googleapis.com",           # Vertex AI (Gemini)
    "iam.googleapis.com",                  # service accounts + roles
    "iamcredentials.googleapis.com",       # short-lived token minting (used by WIF)
    "sts.googleapis.com",                  # Security Token Service (WIF token exchange)
    "cloudresourcemanager.googleapis.com", # project/IAM management
  ]
}

resource "google_project_service" "enabled" {
  for_each           = toset(local.services)
  service            = each.value
  disable_on_destroy = false
}
