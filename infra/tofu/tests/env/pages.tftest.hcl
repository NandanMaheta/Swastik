# 027 T004 - Cloudflare Pages projects and custom domains (FR-001, FR-011).
# Resources (exact addresses): cloudflare_pages_project.{admin,app}, cloudflare_pages_domain.{admin,app}.
# Direct-upload projects: no `source` block; production_branch = "main".

mock_provider "google" {}
mock_provider "cloudflare" {}

variables {
  env                   = "staging"
  project_number        = "123456789012"
  cloudflare_account_id = "0123456789abcdef0123456789abcdef"
  cloudflare_zone_id    = "fedcba9876543210fedcba9876543210"
  access_emails         = ["owner@example.com"]
}

run "staging_pages_projects" {
  command = plan

  assert {
    condition     = cloudflare_pages_project.admin.name == "swastik-admin-staging"
    error_message = "admin project name"
  }
  assert {
    condition     = cloudflare_pages_project.app.name == "swastik-app-staging"
    error_message = "client web project name"
  }
  assert {
    condition = alltrue([
      for p in [cloudflare_pages_project.admin, cloudflare_pages_project.app] :
      p.account_id == "0123456789abcdef0123456789abcdef" && p.production_branch == "main" && p.source == null
    ])
    error_message = "projects are direct-upload (no git source) in the given account"
  }
}

run "staging_pages_custom_domains" {
  command = plan

  assert {
    condition     = cloudflare_pages_domain.admin.name == "admin-staging.swastikapp.co.in" && cloudflare_pages_domain.admin.project_name == "swastik-admin-staging"
    error_message = "admin custom domain attached to the admin project"
  }
  assert {
    condition     = cloudflare_pages_domain.app.name == "app-staging.swastikapp.co.in" && cloudflare_pages_domain.app.project_name == "swastik-app-staging"
    error_message = "client custom domain attached to the app project"
  }
  assert {
    condition     = cloudflare_pages_domain.admin.account_id == "0123456789abcdef0123456789abcdef" && cloudflare_pages_domain.app.account_id == "0123456789abcdef0123456789abcdef"
    error_message = "domains in the given account"
  }
}

run "production_pages" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition = (
      cloudflare_pages_project.admin.name == "swastik-admin-production" &&
      cloudflare_pages_project.app.name == "swastik-app-production" &&
      cloudflare_pages_domain.admin.name == "admin.swastikapp.co.in" &&
      cloudflare_pages_domain.app.name == "app.swastikapp.co.in"
    )
    error_message = "production projects and domains"
  }
}
