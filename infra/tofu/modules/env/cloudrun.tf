locals {
  plain_env = { for k, v in merge({
    APP_ENV              = var.env
    TICK_AUTH            = "oidc"
    TICK_AUDIENCE        = local.tick_audience
    TICK_SERVICE_ACCOUNT = "tick-${var.env}@${var.project_id}.iam.gserviceaccount.com"
    WEB_ORIGINS          = "https://${local.admin_host},https://${local.app_host}"
    TRUSTED_PROXY_HOPS   = var.trusted_proxy_hops
    JWT_ACTIVE_KID       = var.jwt_active_kid
    PII_ACTIVE_KEY_ID    = var.pii_active_key_id
    SENTRY_DSN           = var.sentry_dsn
    SENTRY_ENVIRONMENT   = var.sentry_dsn == "" ? "" : var.env
    }, var.otp_enabled ? {
    OTP_EMAIL_FROM      = var.otp_email_from
    FIREBASE_PROJECT_ID = var.firebase_project_id
    } : {}) : k => v if v != ""
  }

  secret_env = merge(
    { DATABASE_URL = "database_url" },
    var.auth_keys_enabled ? {
      JWT_SIGNING_KEYS    = "jwt_signing_keys"
      PII_ENCRYPTION_KEYS = "pii_encryption_keys"
      BLIND_INDEX_KEY     = "blind_index_key"
    } : {},
    var.otp_enabled ? {
      RESEND_API_KEY = "resend_api_key"
      OTP_HMAC_KEY   = "otp_hmac_key"
    } : {}
  )
}

resource "google_cloud_run_v2_service" "api" {
  project  = var.project_id
  name     = "swastik-api-${var.env}"
  location = var.region

  deletion_protection = var.env == "production"

  template {
    service_account = google_service_account.runtime.email

    scaling {
      min_instance_count = 0
      max_instance_count = var.max_instances
    }

    containers {
      image = var.image

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = false
      }

      dynamic "env" {
        for_each = local.plain_env
        content {
          name  = env.key
          value = env.value
        }
      }

      dynamic "env" {
        for_each = data.google_secret_manager_secret.proxy
        content {
          name = "PROXY_SHARED_SECRETS"
          value_source {
            secret_key_ref {
              secret  = env.value.secret_id
              version = "latest"
            }
          }
        }
      }

      dynamic "env" {
        for_each = local.secret_env
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = data.google_secret_manager_secret.secret[env.value].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  # deploy.yml owns the image and traffic; tofu owns everything else.
  lifecycle {
    ignore_changes = [traffic, client, client_version, template[0].revision, template[0].containers[0].image]
  }

  depends_on = [google_secret_manager_secret_iam_member.runtime, google_secret_manager_secret_iam_member.runtime_proxy]
}

# Auth lives in the app (ADR 0003 Am. 1); /internal/tick is verified in-app via OIDC.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.api.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
