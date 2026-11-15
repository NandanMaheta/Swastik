# Only the admin panel is behind Access. Covers the custom domain, the pages.dev host and previews so
# Access cannot be bypassed through the default Pages address. Never the API or client app hosts.
resource "cloudflare_zero_trust_access_policy" "admin_allow" {
  account_id = var.cloudflare_account_id
  name       = "swastik-admin-${var.env}-allow"
  decision   = "allow"

  include = [for e in var.access_emails : { email = { email = e } }]
}

resource "cloudflare_zero_trust_access_application" "admin" {
  account_id       = var.cloudflare_account_id
  name             = "swastik-admin-${var.env}"
  type             = "self_hosted"
  session_duration = "24h"

  self_hosted_domains = [
    local.admin_host,
    "${local.admin_pages_project}.pages.dev",
    "*.${local.admin_pages_project}.pages.dev",
  ]


  policies = [{
    id         = cloudflare_zero_trust_access_policy.admin_allow.id
    precedence = 1
  }]
}
