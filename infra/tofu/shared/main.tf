provider "google" {
  project = var.project_id
  region  = var.region
}

provider "cloudflare" {}

locals {
  apis = toset([
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "cloudscheduler.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "sts.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])
}

resource "google_project_service" "apis" {
  for_each           = local.apis
  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "swastik" {
  project       = var.project_id
  location      = var.region
  repository_id = "swastik"
  format        = "DOCKER"
  description   = "Swastik API images"

  cleanup_policy_dry_run = false

  cleanup_policies {
    id     = "keep-newest-10"
    action = "KEEP"
    most_recent_versions {
      keep_count = 10
    }
  }

  cleanup_policies {
    id     = "delete-the-rest"
    action = "DELETE"
    condition {
      tag_state = "ANY"
    }
  }

  depends_on = [google_project_service.apis]
}

resource "cloudflare_r2_bucket" "backups" {
  account_id = var.cloudflare_account_id
  name       = "swastik-backups"
}

resource "cloudflare_r2_bucket_lifecycle" "backups" {
  account_id  = var.cloudflare_account_id
  bucket_name = cloudflare_r2_bucket.backups.name

  rules = [{
    id      = "delete-after-30-days"
    enabled = true
    conditions = {
      prefix = ""
    }
    delete_objects_transition = {
      condition = {
        type    = "Age"
        max_age = 2592000
      }
    }
  }]
}
