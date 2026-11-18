resource "google_service_account" "deployer" {
  project      = var.project_id
  account_id   = "deploy-${var.env}"
  display_name = "Deployer (${var.env})"
}

resource "google_service_account" "runtime" {
  project      = var.project_id
  account_id   = "api-${var.env}"
  display_name = "API runtime (${var.env})"
}

resource "google_service_account" "tick" {
  project      = var.project_id
  account_id   = "tick-${var.env}"
  display_name = "Scheduler tick caller (${var.env})"
}

# Only this environment's GitHub environment may impersonate the deployer.
resource "google_service_account_iam_member" "deployer_wif" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/projects/${var.project_number}/locations/global/workloadIdentityPools/github/attribute.environment/${var.env}"
}

resource "google_service_account_iam_member" "deployer_acts_as_runtime" {
  service_account_id = google_service_account.runtime.name
  role               = "roles/iam.serviceAccountUser"
  member             = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_cloud_run_v2_service_iam_member" "deployer" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.developer"
  member   = "serviceAccount:${google_service_account.deployer.email}"
}

resource "google_artifact_registry_repository_iam_member" "deployer_push" {
  project    = var.project_id
  location   = var.region
  repository = "swastik"
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer.email}"
}
