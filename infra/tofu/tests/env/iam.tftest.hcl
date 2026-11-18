# 027 T003 - env module IAM and secrets tests (FR-002, FR-003). Module: infra/tofu/modules/env.
#
# Module input contract (all tests): env, project_id (default swastik-4fcc9), region (default asia-south1),
# project_number (string), cloudflare_account_id, cloudflare_zone_id, access_emails (list(string)),
# auth_keys_enabled (bool, default false).
# Resources (exact addresses): google_service_account.{deployer,runtime,tick},
# google_service_account_iam_member.{deployer_wif,deployer_acts_as_runtime},
# google_cloud_run_v2_service_iam_member.deployer, google_artifact_registry_repository_iam_member.deployer_push,
# data.google_secret_manager_secret.secret (for_each logical key), google_secret_manager_secret_iam_member.runtime
# (same keys). Logical keys: database_url always; jwt_signing_keys, pii_encryption_keys, blind_index_key only
# when auth_keys_enabled. No project-level IAM resource may exist (checked by tests/lifecycle_test.sh).

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

run "service_accounts_named_per_env_staging" {
  command = plan

  assert {
    condition     = google_service_account.deployer.account_id == "deploy-staging"
    error_message = "deployer SA must be deploy-<env>"
  }
  assert {
    condition     = google_service_account.runtime.account_id == "api-staging"
    error_message = "runtime SA must be api-<env>"
  }
  assert {
    condition     = google_service_account.tick.account_id == "tick-staging"
    error_message = "tick SA must be tick-<env>"
  }
}

run "service_accounts_named_per_env_production" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition = (
      google_service_account.deployer.account_id == "deploy-production" &&
      google_service_account.runtime.account_id == "api-production" &&
      google_service_account.tick.account_id == "tick-production"
    )
    error_message = "SA names must carry the production suffix"
  }
}

run "wif_binding_pinned_to_own_github_environment_staging" {
  command = plan

  assert {
    condition     = google_service_account_iam_member.deployer_wif.role == "roles/iam.workloadIdentityUser"
    error_message = "deployer must be impersonable via workloadIdentityUser"
  }
  assert {
    condition = google_service_account_iam_member.deployer_wif.member == (
      "principalSet://iam.googleapis.com/projects/123456789012/locations/global/workloadIdentityPools/github/attribute.environment/staging"
    )
    error_message = "WIF member must be the pool's attribute.environment/<env> set of THIS environment only"
  }
}

run "wif_binding_pinned_to_own_github_environment_production" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition     = endswith(google_service_account_iam_member.deployer_wif.member, "/attribute.environment/production")
    error_message = "production deployer must only trust the production GitHub environment"
  }
}

run "deployer_rights_are_resource_level" {
  command = plan

  assert {
    condition     = google_cloud_run_v2_service_iam_member.deployer.role == "roles/run.developer"
    error_message = "deployer needs run.developer on its own service"
  }
  assert {
    condition     = google_cloud_run_v2_service_iam_member.deployer.name == google_cloud_run_v2_service.api.name
    error_message = "run.developer must be granted on the env's own service"
  }
  assert {
    condition     = google_cloud_run_v2_service_iam_member.deployer.member == "serviceAccount:${google_service_account.deployer.email}"
    error_message = "run.developer member must be the deployer SA"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_acts_as_runtime.role == "roles/iam.serviceAccountUser"
    error_message = "deployer needs serviceAccountUser on the runtime SA"
  }
  assert {
    condition     = google_service_account_iam_member.deployer_acts_as_runtime.service_account_id == google_service_account.runtime.name
    error_message = "serviceAccountUser must be on this env's runtime SA only"
  }
  assert {
    condition     = google_artifact_registry_repository_iam_member.deployer_push.role == "roles/artifactregistry.writer"
    error_message = "deployer pushes images with artifactregistry.writer on the repo"
  }
  assert {
    condition     = google_artifact_registry_repository_iam_member.deployer_push.repository == "swastik"
    error_message = "artifactregistry.writer must be on repo swastik"
  }
}

run "secrets_database_url_only_until_auth_enabled" {
  command = plan

  assert {
    condition     = toset(keys(data.google_secret_manager_secret.secret)) == toset(["database_url"])
    error_message = "with auth_keys_enabled=false only database-url-<env> is referenced"
  }
  assert {
    condition     = data.google_secret_manager_secret.secret["database_url"].secret_id == "database-url-staging"
    error_message = "secret name must be database-url-<env>"
  }
  assert {
    condition = (
      google_secret_manager_secret_iam_member.runtime["database_url"].role == "roles/secretmanager.secretAccessor" &&
      google_secret_manager_secret_iam_member.runtime["database_url"].member == "serviceAccount:${google_service_account.runtime.email}"
    )
    error_message = "runtime SA gets secretAccessor on the secret"
  }
}

run "secrets_all_when_auth_keys_enabled" {
  command = plan
  variables {
    auth_keys_enabled = true
  }

  assert {
    condition     = toset(keys(data.google_secret_manager_secret.secret)) == toset(["database_url", "jwt_signing_keys", "pii_encryption_keys", "blind_index_key"])
    error_message = "auth_keys_enabled adds the three 003 secrets"
  }
  assert {
    condition = alltrue([
      data.google_secret_manager_secret.secret["jwt_signing_keys"].secret_id == "jwt-signing-keys-staging",
      data.google_secret_manager_secret.secret["pii_encryption_keys"].secret_id == "pii-encryption-keys-staging",
      data.google_secret_manager_secret.secret["blind_index_key"].secret_id == "blind-index-key-staging",
    ])
    error_message = "secret names must follow the contract with env suffix"
  }
  assert {
    condition = alltrue([
      for k, m in google_secret_manager_secret_iam_member.runtime :
      m.role == "roles/secretmanager.secretAccessor" && m.member == "serviceAccount:${google_service_account.runtime.email}"
    ])
    error_message = "every referenced secret is readable by the runtime SA only"
  }
}

run "secret_names_carry_production_suffix" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition     = data.google_secret_manager_secret.secret["database_url"].secret_id == "database-url-production"
    error_message = "production must read database-url-production, never the staging secret"
  }
}
