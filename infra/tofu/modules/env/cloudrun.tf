resource "google_cloud_run_v2_service" "api" {
  project  = var.project_id
  name     = "swastik-api-${var.env}"
  location = var.region

  template {
    containers {
      image = var.image
    }
  }
}
