# 027 T003 - shared root plan tests (FR-001, FR-014, spec US-5 retention).
# Contract: infra/tofu/shared declares variable cloudflare_account_id (string) and these resources:
#   google_project_service.apis (for_each over API ids), google_artifact_registry_repository.swastik,
#   cloudflare_r2_bucket.backups, cloudflare_r2_bucket_lifecycle.backups.

mock_provider "google" {}
mock_provider "cloudflare" {}

variables {
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
}

run "required_apis_enabled" {
  command = plan

  assert {
    condition = alltrue([
      for api in [
        "run.googleapis.com",
        "artifactregistry.googleapis.com",
        "secretmanager.googleapis.com",
        "cloudscheduler.googleapis.com",
        "iam.googleapis.com",
        "iamcredentials.googleapis.com",
        "sts.googleapis.com",
        "cloudresourcemanager.googleapis.com",
      ] : contains([for s in values(google_project_service.apis) : s.service], api)
    ])
    error_message = "every API the platform needs must be enabled by tofu (shared root)"
  }

  assert {
    condition     = alltrue([for s in values(google_project_service.apis) : s.disable_on_destroy == false])
    error_message = "APIs must not be disabled on destroy"
  }
}

run "artifact_registry_repo" {
  command = plan

  assert {
    condition     = google_artifact_registry_repository.swastik.repository_id == "swastik"
    error_message = "repository must be named swastik"
  }
  assert {
    condition     = google_artifact_registry_repository.swastik.location == "asia-south1"
    error_message = "repository must live in asia-south1"
  }
  assert {
    condition     = google_artifact_registry_repository.swastik.format == "DOCKER"
    error_message = "repository format must be DOCKER"
  }
}

run "artifact_registry_keeps_newest_10_FR_014" {
  command = plan

  assert {
    condition     = google_artifact_registry_repository.swastik.cleanup_policy_dry_run == false
    error_message = "cleanup policies must be live (dry run off)"
  }
  assert {
    condition = anytrue([
      for p in google_artifact_registry_repository.swastik.cleanup_policies :
      p.action == "KEEP" && length(p.most_recent_versions) == 1 && p.most_recent_versions[0].keep_count == 10
    ])
    error_message = "a KEEP policy for the newest 10 versions is required"
  }
  assert {
    condition = anytrue([
      for p in google_artifact_registry_repository.swastik.cleanup_policies : p.action == "DELETE"
    ])
    error_message = "a DELETE policy for everything else is required, otherwise nothing is cleaned"
  }
}

run "r2_backup_bucket_private_with_30_day_lifecycle" {
  command = plan

  assert {
    condition     = cloudflare_r2_bucket.backups.name == "swastik-backups"
    error_message = "R2 bucket must be swastik-backups"
  }
  assert {
    condition     = cloudflare_r2_bucket.backups.account_id == var.cloudflare_account_id
    error_message = "bucket must be created in the given account"
  }
  assert {
    condition     = cloudflare_r2_bucket_lifecycle.backups.bucket_name == "swastik-backups"
    error_message = "lifecycle must target swastik-backups"
  }
  assert {
    condition = anytrue([
      for r in cloudflare_r2_bucket_lifecycle.backups.rules :
      r.enabled == true && r.delete_objects_transition.condition.type == "Age" && r.delete_objects_transition.condition.max_age == 2592000
    ])
    error_message = "an enabled rule must delete objects after 30 days (2592000 s)"
  }
}
