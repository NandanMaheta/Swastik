# 027 T004 - Cloudflare Access for the admin panel (FR-012, US-4).
# Resources (exact addresses): cloudflare_zero_trust_access_policy.admin_allow,
# cloudflare_zero_trust_access_application.admin (type self_hosted, policies = [admin_allow], session 24h).
# Only the admin is behind Access; there must be no Access app for the API or client app hosts.

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
  access_emails         = ["owner@example.com", "ops@example.com"]
}

run "access_app_covers_custom_and_pages_dev_hosts_staging" {
  command = plan

  assert {
    condition     = cloudflare_zero_trust_access_application.admin.type == "self_hosted"
    error_message = "self_hosted Access application"
  }
  assert {
    condition     = cloudflare_zero_trust_access_application.admin.account_id == "0123456789abcdef0123456789abcdef"
    error_message = "application in the given account"
  }
  assert {
    condition = alltrue([
      for h in [
        "admin-staging.swastikapp.co.in",
        "swastik-admin-staging.pages.dev",
        "*.swastik-admin-staging.pages.dev",
      ] : contains(cloudflare_zero_trust_access_application.admin.self_hosted_domains, h)
    ])
    error_message = "custom domain, pages.dev host and preview wildcard must all be protected (otherwise Access is bypassable)"
  }
  assert {
    condition     = cloudflare_zero_trust_access_application.admin.session_duration == "24h"
    error_message = "session 24h"
  }
}

run "access_never_covers_api_or_client_hosts" {
  command = plan

  assert {
    condition = !anytrue([
      for h in cloudflare_zero_trust_access_application.admin.self_hosted_domains :
      strcontains(h, "api") || strcontains(h, "swastik-app") || startswith(h, "app")
    ])
    error_message = "API and client hosts must never be behind Access (003 P-04)"
  }
}

run "allow_policy_lists_exactly_the_given_emails" {
  command = plan

  assert {
    condition     = cloudflare_zero_trust_access_policy.admin_allow.decision == "allow"
    error_message = "decision allow"
  }
  assert {
    condition     = toset([for i in cloudflare_zero_trust_access_policy.admin_allow.include : i.email.email]) == toset(["owner@example.com", "ops@example.com"])
    error_message = "allow list equals var.access_emails; no everyone/domain rules"
  }
  assert {
    condition     = cloudflare_zero_trust_access_policy.admin_allow.account_id == "0123456789abcdef0123456789abcdef"
    error_message = "policy in the given account"
  }
}

run "access_production_hosts" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition = alltrue([
      for h in [
        "admin.swastikapp.co.in",
        "swastik-admin-production.pages.dev",
        "*.swastik-admin-production.pages.dev",
      ] : contains(cloudflare_zero_trust_access_application.admin.self_hosted_domains, h)
    ])
    error_message = "production admin hosts protected"
  }
  assert {
    condition     = !anytrue([for h in cloudflare_zero_trust_access_application.admin.self_hosted_domains : strcontains(h, "staging")])
    error_message = "production Access app must not mention staging"
  }
}

run "empty_email_list_is_rejected" {
  command = plan
  variables {
    access_emails = []
  }
  expect_failures = [var.access_emails]
}

# 027 review fix 3: Access needs an identity provider; one-time PIN is the only one allowed (emails only).
run "access_app_allows_one_time_pin_idp" {
  command = plan

  assert {
    condition     = length(cloudflare_zero_trust_access_application.admin.allowed_idps) >= 1
    error_message = "the Access application must list a one-time-PIN identity provider in allowed_idps"
  }
}
