terraform {
  required_version = ">= 1.10"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 7.0"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 5.0"
    }
  }
  backend "gcs" {
    bucket = "swastik-4fcc9-tofu-state"
    prefix = "production"
  }
}

provider "google" {
  project = "swastik-4fcc9"
  region  = "asia-south1"
}

# Token comes from CLOUDFLARE_API_TOKEN in the infra environment.
provider "cloudflare" {}

module "env" {
  source = "../../modules/env"
  env    = "production"

  project_number        = var.project_number
  cloudflare_account_id = var.cloudflare_account_id
  cloudflare_zone_id    = var.cloudflare_zone_id
  access_emails         = var.access_emails
  sentry_dsn            = var.sentry_dsn
}
