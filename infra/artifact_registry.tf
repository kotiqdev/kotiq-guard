# A private Docker repository. CI pushes images here; Cloud Run pulls from here.
# Full image path becomes:
#   europe-west1-docker.pkg.dev/kotiq-guard/containers/kotiq-guard:<git-sha>
# (region-docker.pkg.dev / project / repository_id / image:tag)
#
# depends_on: the artifactregistry API must be ON before we can create a repo. There's no direct
# reference to google_project_service here, so we state the dependency explicitly to avoid a race.
resource "google_artifact_registry_repository" "containers" {
  location      = var.region
  repository_id = "containers"
  format        = "DOCKER"
  description   = "kotiq-guard container images"

  depends_on = [google_project_service.enabled]
}
