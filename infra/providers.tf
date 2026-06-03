# Configures the Google provider — the thing that actually talks to Google Cloud APIs.
# No credentials block: the provider auto-discovers ADC (the `application-default login` you just
# ran). That's the whole reason we set ADC up — Terraform finds the "key on the doorstep".
provider "google" {
  project = var.project_id
  region  = var.region
}
