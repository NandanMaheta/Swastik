resource "google_cloud_scheduler_job" "tick" {
  project          = var.project_id
  region           = var.region
  name             = "swastik-tick-${var.env}"
  schedule         = "*/5 * * * *"
  time_zone        = "Asia/Kolkata"
  attempt_deadline = "60s"

  retry_config {
    retry_count = 0
  }

  # Calls the run.app URI directly (the proxy blocks /internal/*); the audience is what the app verifies.
  http_target {
    http_method = "POST"
    uri         = "${google_cloud_run_v2_service.api.uri}/internal/tick"

    oidc_token {
      service_account_email = google_service_account.tick.email
      audience              = local.tick_audience
    }
  }
}
