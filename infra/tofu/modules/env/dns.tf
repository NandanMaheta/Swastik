# Placeholder origin for the API host: the Worker route answers, traffic never reaches 192.0.2.1 (TEST-NET-1).
resource "cloudflare_dns_record" "api" {
  zone_id = var.cloudflare_zone_id
  name    = local.api_host
  type    = "A"
  content = "192.0.2.1"
  proxied = true
  ttl     = 1
  comment = "swastik ${var.env}: proxied placeholder, Worker route answers"
}

resource "cloudflare_dns_record" "admin" {
  zone_id = var.cloudflare_zone_id
  name    = local.admin_host
  type    = "CNAME"
  content = "${local.admin_pages_project}.pages.dev"
  proxied = true
  ttl     = 1
  comment = "swastik ${var.env}: admin Pages"
}

resource "cloudflare_dns_record" "app" {
  zone_id = var.cloudflare_zone_id
  name    = local.app_host
  type    = "CNAME"
  content = "${local.app_pages_project}.pages.dev"
  proxied = true
  ttl     = 1
  comment = "swastik ${var.env}: client web Pages"
}
