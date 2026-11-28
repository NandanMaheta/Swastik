# 004 S18 - OTP delivery wiring in the env module (plan "Configuration, secrets and infra").
# New module input: otp_enabled (bool, default false). When true the module references two more
# Secret Manager secrets (logical keys resend_api_key and otp_hmac_key; ids resend-api-key-<env> and
# otp-hmac-key-<env>), the runtime SA gets secretAccessor on them, and Cloud Run gets
# RESEND_API_KEY and OTP_HMAC_KEY as secret_key_ref (never a literal) plus the plain settings
# OTP_EMAIL_FROM and FIREBASE_PROJECT_ID. Disabled (the default until the owner has created the
# secrets, gate G-SECRETS) nothing OTP exists. Tofu never reads a secret value.

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
  auth_keys_enabled     = true
}

run "nothing_otp_when_disabled_by_default" {
  command = plan

  assert {
    condition     = toset(keys(data.google_secret_manager_secret.secret)) == toset(["database_url", "jwt_signing_keys", "pii_encryption_keys", "blind_index_key"])
    error_message = "without otp_enabled no OTP secret is referenced"
  }
  assert {
    condition = !anytrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      contains(["RESEND_API_KEY", "OTP_HMAC_KEY", "OTP_EMAIL_FROM", "FIREBASE_PROJECT_ID"], e.name)
    ])
    error_message = "without otp_enabled Cloud Run has no OTP variable (the API then answers otp.not_configured)"
  }
}

run "secrets_are_referenced_with_runtime_access_when_enabled" {
  command = plan
  variables {
    otp_enabled = true
  }

  assert {
    condition     = toset(keys(data.google_secret_manager_secret.secret)) == toset(["database_url", "jwt_signing_keys", "pii_encryption_keys", "blind_index_key", "resend_api_key", "otp_hmac_key"])
    error_message = "otp_enabled adds exactly resend_api_key and otp_hmac_key"
  }
  assert {
    condition = alltrue([
      data.google_secret_manager_secret.secret["resend_api_key"].secret_id == "resend-api-key-staging",
      data.google_secret_manager_secret.secret["otp_hmac_key"].secret_id == "otp-hmac-key-staging",
    ])
    error_message = "secret ids must be resend-api-key-<env> and otp-hmac-key-<env>"
  }
  assert {
    condition = alltrue([
      for k in ["resend_api_key", "otp_hmac_key"] :
      google_secret_manager_secret_iam_member.runtime[k].role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.runtime[k].member == "serviceAccount:${google_service_account.runtime.email}"
    ])
    error_message = "the runtime SA gets secretAccessor on both OTP secrets"
  }
  assert {
    condition = alltrue([
      for k, m in google_secret_manager_secret_iam_member.runtime :
      m.role == "roles/secretmanager.secretAccessor" && m.member == "serviceAccount:${google_service_account.runtime.email}"
    ])
    error_message = "every referenced secret stays readable by the runtime SA only"
  }
}

run "cloud_run_env_is_wired_when_enabled" {
  command = plan
  variables {
    otp_enabled = true
  }

  assert {
    condition = alltrue([
      for pair in [
        ["RESEND_API_KEY", "resend-api-key-staging"],
        ["OTP_HMAC_KEY", "otp-hmac-key-staging"],
        ] : anytrue([
          for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
          e.name == pair[0] && (e.value == null || e.value == "") && length(e.value_source) == 1 &&
          e.value_source[0].secret_key_ref[0].secret == pair[1] && e.value_source[0].secret_key_ref[0].version == "latest"
      ])
    ])
    error_message = "RESEND_API_KEY and OTP_HMAC_KEY must be secret_key_ref (latest), never a literal value"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["OTP_EMAIL_FROM"] == "no-reply@mail.swastikapp.co.in"
    error_message = "OTP_EMAIL_FROM is the no-reply sender on the mail domain"
  }
  assert {
    condition     = { for e in google_cloud_run_v2_service.api.template[0].containers[0].env : e.name => e.value if e.value != null && e.value != "" }["FIREBASE_PROJECT_ID"] == "swastik-4fcc9"
    error_message = "FIREBASE_PROJECT_ID is the project the app signs in with"
  }
  assert {
    condition = !anytrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      e.name == "FIREBASE_JWKS_URL"
    ])
    error_message = "FIREBASE_JWKS_URL is local/ci only and must never reach Cloud Run (the API refuses it in staging and production)"
  }
  assert {
    condition = alltrue([
      for e in google_cloud_run_v2_service.api.template[0].containers[0].env :
      (e.value == null || e.value == "") == (length(e.value_source) == 1)
    ])
    error_message = "every env var is either a plain value or a secret reference, never both/neither"
  }
}

run "production_uses_production_secret_names" {
  command = plan
  variables {
    env         = "production"
    otp_enabled = true
  }

  assert {
    condition = alltrue([
      data.google_secret_manager_secret.secret["resend_api_key"].secret_id == "resend-api-key-production",
      data.google_secret_manager_secret.secret["otp_hmac_key"].secret_id == "otp-hmac-key-production",
    ])
    error_message = "production references the -production secrets"
  }
}
