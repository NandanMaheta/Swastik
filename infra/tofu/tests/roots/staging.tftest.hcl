# 027 T004 - staging root builds the staging environment and no production names (FR-001, D-1).
# Run in infra/tofu/envs/staging. Same output/variable contract as roots/production.tftest.hcl.

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
  project_number        = "123456789012"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
  cloudflare_zone_id    = "fedcba9876543210fedcba9876543210"
  access_emails         = ["owner@example.com"]
}

run "staging_root_has_only_staging_names" {
  command = plan

  assert {
    condition = alltrue([
      for v in [
        module.env.api_service_name, module.env.api_host, module.env.admin_host, module.env.app_host,
        module.env.admin_pages_project, module.env.app_pages_project, module.env.deployer_sa_email,
        module.env.tick_job_name, module.env.worker_name,
      ] : strcontains(v, "staging") && !strcontains(v, "production")
    ])
    error_message = "every staging name must contain staging and none production"
  }
  assert {
    condition     = module.env.api_service_name == "swastik-api-staging" && module.env.api_host == "api-staging.swastikapp.co.in"
    error_message = "staging root must build the staging environment"
  }
}
