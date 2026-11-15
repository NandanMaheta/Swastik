# 027 T003 - Cloud Scheduler tick job (FR-007). Resource: google_cloud_scheduler_job.tick

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/swastik-4fcc9/serviceAccounts/x@swastik-4fcc9.iam.gserviceaccount.com"
      email = "x@swastik-4fcc9.iam.gserviceaccount.com"
    }
  }
}
mock_provider "cloudflare" {}

variables {
  env                   = "staging"
  project_number        = "123456789012"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
  cloudflare_zone_id    = "fedcba9876543210fedcba9876543210"
  access_emails         = ["owner@example.com"]
}

run "tick_job_staging" {
  command = plan

  assert {
    condition     = google_cloud_scheduler_job.tick.name == "swastik-tick-staging"
    error_message = "job must be swastik-tick-<env>"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.region == "asia-south1"
    error_message = "job region asia-south1"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.schedule == "*/5 * * * *"
    error_message = "tick every 5 minutes"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.time_zone == "Asia/Kolkata"
    error_message = "time zone Asia/Kolkata"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.attempt_deadline == "60s"
    error_message = "attempt deadline 60s"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.retry_config[0].retry_count == 0
    error_message = "retry_count must be 0 (a missed tick is retried by the next one)"
  }
}

run "tick_target_is_oidc_post_to_run_app" {
  command = plan
  override_resource {
    target = google_service_account.tick
    values = {
      name  = "projects/swastik-4fcc9/serviceAccounts/tick-staging@swastik-4fcc9.iam.gserviceaccount.com"
      email = "tick-staging@swastik-4fcc9.iam.gserviceaccount.com"
    }
  }

  assert {
    condition     = google_cloud_scheduler_job.tick.http_target[0].http_method == "POST"
    error_message = "tick is a POST"
  }
  assert {
    condition     = endswith(google_cloud_scheduler_job.tick.http_target[0].uri, "/internal/tick")
    error_message = "target path must be /internal/tick"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.http_target[0].uri == "${google_cloud_run_v2_service.api.uri}/internal/tick"
    error_message = "scheduler calls the run.app URI directly, not the public proxy (FR-007/FR-008)"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.http_target[0].oidc_token[0].service_account_email == google_service_account.tick.email
    error_message = "OIDC token minted for the tick SA"
  }
  assert {
    condition     = length(google_cloud_scheduler_job.tick.http_target[0].oauth_token) == 0
    error_message = "OIDC only, no OAuth token"
  }
}

run "oidc_audience_matches_TICK_AUDIENCE_staging" {
  command = plan

  assert {
    condition     = google_cloud_scheduler_job.tick.http_target[0].oidc_token[0].audience == "https://api-staging.swastikapp.co.in/internal/tick"
    error_message = "OIDC audience must equal the service's TICK_AUDIENCE"
  }
  assert {
    condition = google_cloud_scheduler_job.tick.http_target[0].oidc_token[0].audience == {
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != ""
    }["TICK_AUDIENCE"]
    error_message = "scheduler audience and service TICK_AUDIENCE must be the same value"
  }
}

run "tick_job_production" {
  command = plan
  override_resource {
    target = google_service_account.tick
    values = {
      name  = "projects/swastik-4fcc9/serviceAccounts/tick-production@swastik-4fcc9.iam.gserviceaccount.com"
      email = "tick-production@swastik-4fcc9.iam.gserviceaccount.com"
    }
  }
  variables {
    env = "production"
  }

  assert {
    condition     = google_cloud_scheduler_job.tick.name == "swastik-tick-production"
    error_message = "production job name"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.http_target[0].oidc_token[0].audience == "https://api.swastikapp.co.in/internal/tick"
    error_message = "production audience"
  }
  assert {
    condition     = google_cloud_scheduler_job.tick.http_target[0].oidc_token[0].service_account_email == "tick-production@swastik-4fcc9.iam.gserviceaccount.com"
    error_message = "production tick SA"
  }
}
