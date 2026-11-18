# 027 T004 - DNS records and Worker route per environment (FR-001, FR-008).
# Resources (exact addresses): cloudflare_dns_record.{api,admin,app}, cloudflare_workers_script.proxy,
# cloudflare_workers_route.api. Zone: zone_id = var.cloudflare_zone_id, domain swastikapp.co.in.
# The Worker gets the run.app origin through a plain_text binding named UPSTREAM (see worker.test.js).

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

run "staging_dns_records_proxied_in_zone" {
  command = plan

  assert {
    condition     = cloudflare_dns_record.api.name == "api-staging.swastikapp.co.in"
    error_message = "API host for staging"
  }
  assert {
    condition     = cloudflare_dns_record.admin.name == "admin-staging.swastikapp.co.in"
    error_message = "admin host for staging"
  }
  assert {
    condition     = cloudflare_dns_record.app.name == "app-staging.swastikapp.co.in"
    error_message = "client web host for staging"
  }
  assert {
    condition = alltrue([
      for r in [cloudflare_dns_record.api, cloudflare_dns_record.admin, cloudflare_dns_record.app] :
      r.zone_id == "fedcba9876543210fedcba9876543210" && r.proxied == true && r.ttl == 1
    ])
    error_message = "records live in the zone, are proxied and use automatic TTL (1)"
  }
}

run "staging_pages_hosts_are_cname_to_pages_dev" {
  command = plan

  assert {
    condition     = cloudflare_dns_record.admin.type == "CNAME" && cloudflare_dns_record.admin.content == "swastik-admin-staging.pages.dev"
    error_message = "admin must CNAME to its pages.dev project host"
  }
  assert {
    condition     = cloudflare_dns_record.app.type == "CNAME" && cloudflare_dns_record.app.content == "swastik-app-staging.pages.dev"
    error_message = "app must CNAME to its pages.dev project host"
  }
}

run "api_record_is_a_proxied_placeholder_for_the_worker" {
  command = plan

  assert {
    condition     = contains(["A", "AAAA"], cloudflare_dns_record.api.type)
    error_message = "API host is a proxied placeholder A/AAAA record; the Worker route answers"
  }
}

run "worker_script_and_route_staging" {
  command = plan

  assert {
    condition     = cloudflare_workers_script.proxy.script_name == "swastik-api-proxy-staging"
    error_message = "worker name swastik-api-proxy-<env>"
  }
  assert {
    condition     = cloudflare_workers_script.proxy.account_id == "0123456789abcdef0123456789abcdef"
    error_message = "worker in the given account"
  }
  assert {
    condition     = cloudflare_workers_script.proxy.main_module != null && cloudflare_workers_script.proxy.content != null
    error_message = "worker must be an ES module with its code embedded (content + main_module)"
  }
  assert {
    condition = anytrue([
      for b in cloudflare_workers_script.proxy.bindings : b.name == "UPSTREAM" && b.type == "plain_text"
    ])
    error_message = "Worker needs a plain_text UPSTREAM binding (the Cloud Run origin)"
  }
  assert {
    condition     = cloudflare_workers_route.api.pattern == "api-staging.swastikapp.co.in/*"
    error_message = "route pattern covers the whole API host"
  }
  assert {
    condition     = cloudflare_workers_route.api.script == "swastik-api-proxy-staging" && cloudflare_workers_route.api.zone_id == "fedcba9876543210fedcba9876543210"
    error_message = "route points at this env's worker in the zone"
  }
}

run "production_names_have_no_staging_part" {
  command = plan
  variables {
    env = "production"
  }

  assert {
    condition = (
      cloudflare_dns_record.api.name == "api.swastikapp.co.in" &&
      cloudflare_dns_record.admin.name == "admin.swastikapp.co.in" &&
      cloudflare_dns_record.app.name == "app.swastikapp.co.in"
    )
    error_message = "production hosts"
  }
  assert {
    condition = (
      cloudflare_dns_record.admin.content == "swastik-admin-production.pages.dev" &&
      cloudflare_dns_record.app.content == "swastik-app-production.pages.dev"
    )
    error_message = "production CNAME targets"
  }
  assert {
    condition = (
      cloudflare_workers_script.proxy.script_name == "swastik-api-proxy-production" &&
      cloudflare_workers_route.api.pattern == "api.swastikapp.co.in/*" &&
      cloudflare_workers_route.api.script == "swastik-api-proxy-production"
    )
    error_message = "production worker and route"
  }
}
