# 027 T004 - production root must never contain staging names (FR-001, D-1).
# Run in infra/tofu/envs/production. The module must expose outputs: api_service_name, api_host, admin_host,
# app_host, admin_pages_project, app_pages_project, deployer_sa_email, tick_job_name, worker_name; the root
# re-exports nothing but passes the variables project_number, cloudflare_account_id, cloudflare_zone_id,
# access_emails through (declared in the root).

mock_provider "google" {
  mock_resource "google_service_account" {
    defaults = {
      name  = "projects/swastik-4fcc9/serviceAccounts/x@swastik-4fcc9.iam.gserviceaccount.com"
      email = "x@swastik-4fcc9.iam.gserviceaccount.com"
    }
  }
}
override_resource {
  target = module.env.google_service_account.deployer
  values = {
    name  = "projects/swastik-4fcc9/serviceAccounts/deploy-production@swastik-4fcc9.iam.gserviceaccount.com"
    email = "deploy-production@swastik-4fcc9.iam.gserviceaccount.com"
  }
}

mock_provider "cloudflare" {}

variables {
  project_number        = "123456789012"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
  cloudflare_zone_id    = "fedcba9876543210fedcba9876543210"
  access_emails         = ["owner@example.com"]
}

run "production_root_has_only_production_names" {
  command = plan

  assert {
    condition = alltrue([
      for v in [
        module.env.api_service_name, module.env.api_host, module.env.admin_host, module.env.app_host,
        module.env.admin_pages_project, module.env.app_pages_project, module.env.deployer_sa_email,
        module.env.tick_job_name, module.env.worker_name,
      ] : !strcontains(v, "staging")
    ])
    error_message = "a staging name leaked into the production root"
  }
  assert {
    condition     = module.env.api_service_name == "swastik-api-production" && module.env.api_host == "api.swastikapp.co.in"
    error_message = "production root must build the production environment"
  }
}
