# 027 T003 - Cloud Run service plan tests (FR-003, FR-004, FR-014). Resource: google_cloud_run_v2_service.api
# Module input extra: none beyond iam.tftest.hcl. Lifecycle ignore_changes is verified by tests/lifecycle_test.sh.

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

run "service_identity_and_scaling_caps" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_service.api.name == "swastik-api-staging"
    error_message = "service must be swastik-api-<env>"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.location == "asia-south1"
    error_message = "service must run in asia-south1"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.template[0].scaling[0].min_instance_count == 0
    error_message = "min instances must be 0 (scale to zero, FR-014)"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.template[0].scaling[0].max_instance_count <= 2 && google_cloud_run_v2_service.api.template[0].scaling[0].max_instance_count >= 1
    error_message = "max instances must be 1..2 (FR-014)"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.template[0].service_account == google_service_account.runtime.email
    error_message = "service must run as this env's runtime SA"
  }
}

run "container_resources_and_request_billing" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_service.api.template[0].containers[0].resources[0].limits["memory"] == "512Mi"
    error_message = "memory limit must be 512Mi"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.template[0].containers[0].resources[0].cpu_idle == true
    error_message = "request-based billing (cpu_idle=true) is required for the Rs 0 target"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.template[0].containers[0].resources[0].startup_cpu_boost != true
    error_message = "startup CPU boost is off (cost)"
  }
}

run "plain_env_vars_from_contract_staging" {
  command = plan

  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["APP_ENV"] == "staging"
    error_message = "APP_ENV must equal the environment"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["TICK_AUTH"] == "oidc"
    error_message = "TICK_AUTH must be oidc"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["TICK_AUDIENCE"] == "https://api-staging.swastikapp.co.in/internal/tick"
    error_message = "TICK_AUDIENCE must be the public API host + /internal/tick"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["TICK_SERVICE_ACCOUNT"] == "tick-staging@swastik-4fcc9.iam.gserviceaccount.com"
    error_message = "TICK_SERVICE_ACCOUNT must be the tick SA email"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["WEB_ORIGINS"] == "https://admin-staging.swastikapp.co.in,https://app-staging.swastikapp.co.in"
    error_message = "WEB_ORIGINS must list the admin and app origins"
  }
}

run "plain_env_vars_from_contract_production" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["TICK_AUDIENCE"] == "https://api.swastikapp.co.in/internal/tick"
    error_message = "production audience uses api.swastikapp.co.in"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["WEB_ORIGINS"] == "https://admin.swastikapp.co.in,https://app.swastikapp.co.in"
    error_message = "production origins"
  }
  assert {
    condition     = google_cloud_run_v2_service.api.name == "swastik-api-production"
    error_message = "production service name"
  }
}

run "secrets_only_via_secret_key_ref_FR_003" {
  command = plan

  assert {
    condition = alltrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      (e.value == null || e.value == "") == (length(e.value_source) == 1)
    ])
    error_message = "every env var is either a plain value or a secret reference, never both/neither"
  }
  assert {
    condition = anytrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      e.name == "DATABASE_URL" && length(e.value_source) == 1 &&
      e.value_source[0].secret_key_ref[0].secret == "database-url-staging" &&
      e.value_source[0].secret_key_ref[0].version == "latest"
    ])
    error_message = "DATABASE_URL must come from secret_key_ref database-url-<env>:latest"
  }
  assert {
    condition = alltrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      !contains(["DATABASE_URL", "JWT_SIGNING_KEYS", "PII_ENCRYPTION_KEYS", "BLIND_INDEX_KEY"], e.name) || length(e.value_source) == 1
    ])
    error_message = "secret-valued variables must never carry a literal value"
  }
  assert {
    condition = !anytrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      contains(["JWT_SIGNING_KEYS", "PII_ENCRYPTION_KEYS", "BLIND_INDEX_KEY"], e.name)
    ])
    error_message = "auth key variables are absent while auth_keys_enabled=false"
  }
}

run "auth_keys_wired_when_enabled" {
  command = plan
  variables {
    auth_keys_enabled = true
  }

  assert {
    condition = alltrue([
      for pair in [
        ["JWT_SIGNING_KEYS", "jwt-signing-keys-staging"],
        ["PII_ENCRYPTION_KEYS", "pii-encryption-keys-staging"],
        ["BLIND_INDEX_KEY", "blind-index-key-staging"],
        ] : anytrue([
          for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
          e.name == pair[0] && length(e.value_source) == 1 && e.value_source[0].secret_key_ref[0].secret == pair[1]
      ])
    ])
    error_message = "003 secrets must be wired as secret_key_ref when auth_keys_enabled"
  }
}

run "service_is_publicly_invokable_ADR_0003" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_service_iam_member.public_invoker.role == "roles/run.invoker" && google_cloud_run_v2_service_iam_member.public_invoker.member == "allUsers"
    error_message = "service stays publicly invokable (auth is in the app, ADR 0003 Am. 1)"
  }
  assert {
    condition     = google_cloud_run_v2_service_iam_member.public_invoker.name == google_cloud_run_v2_service.api.name
    error_message = "invoker grant must be on this service only"
  }
}

# 027 review fix 3: production cannot be deleted by a stray apply; staging stays disposable.
run "deletion_protection_production_only" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition     = google_cloud_run_v2_service.api.deletion_protection == true
    error_message = "production Cloud Run service must set deletion_protection = true"
  }
}

run "deletion_protection_off_in_staging" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_service.api.deletion_protection == false
    error_message = "staging service stays disposable"
  }
}
