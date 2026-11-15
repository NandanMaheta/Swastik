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
    prefix = "staging"
  }
}

module "env" {
  source = "../../modules/env"
  env    = "staging"
}
