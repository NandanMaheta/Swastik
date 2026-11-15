# Secret values are added out of band by infra/bootstrap/secrets.sh; tofu only references them.
locals {
  secret_ids = merge(
    { database_url = "database-url-${var.env}" },
    var.auth_keys_enabled ? {
      jwt_signing_keys    = "jwt-signing-keys-${var.env}"
      pii_encryption_keys = "pii-encryption-keys-${var.env}"
      blind_index_key     = "blind-index-key-${var.env}"
    } : {}
  )
}

data "google_secret_manager_secret" "secret" {
  for_each  = local.secret_ids
  project   = var.project_id
  secret_id = each.value
}

resource "google_secret_manager_secret_iam_member" "runtime" {
  for_each  = local.secret_ids
  project   = var.project_id
  secret_id = data.google_secret_manager_secret.secret[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}

# Shared secret between the Cloudflare Worker and the API (X-Swastik-Proxy-Key). Created by
# secrets.sh --with-auth, which also pushes the same value to the Worker (wrangler secret put). Tofu
# only references the secret by name; no value ever enters state.
data "google_secret_manager_secret" "proxy" {
  count     = var.auth_keys_enabled ? 1 : 0
  project   = var.project_id
  secret_id = "proxy-shared-secrets-${var.env}"
}

resource "google_secret_manager_secret_iam_member" "runtime_proxy" {
  count     = var.auth_keys_enabled ? 1 : 0
  project   = var.project_id
  secret_id = data.google_secret_manager_secret.proxy[0].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.runtime.email}"
}
