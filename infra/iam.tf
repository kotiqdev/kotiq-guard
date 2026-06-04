# Who may do what. Least privilege: grant the smallest role that gets the job done, nothing more.

# --- Runtime SA: may call Vertex AI. That's its ENTIRE power. ---
resource "google_project_iam_member" "runtime_vertex" {
  project = var.project_id
  role    = "roles/aiplatform.user"
  member  = "serviceAccount:${google_service_account.runtime.email}"
}

# --- Deployer SA: deploy to Cloud Run + push images to Artifact Registry. ---
# run.admin (not just developer) because `--allow-unauthenticated` sets an IAM policy on the
# service, which requires admin-level Cloud Run permission.
resource "google_project_iam_member" "deployer_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_project_iam_member" "deployer_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.deployer.email}"
}

# The "act as" gotcha: to deploy a Cloud Run service that RUNS AS kotiq-run, the deployer must be
# allowed to impersonate kotiq-run. This binding is scoped to the runtime SA itself (not the whole
# project) → the deployer can act as THIS one robot, and no other. Tightest possible scope.
resource "google_service_account_iam_member" "deployer_actas_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}
