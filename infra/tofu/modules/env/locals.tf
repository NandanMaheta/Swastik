locals {
  suffix = var.env == "production" ? "" : "-${var.env}"
  domain = "swastikapp.co.in"

  api_host   = "api${local.suffix}.${local.domain}"
  admin_host = "admin${local.suffix}.${local.domain}"
  app_host   = "app${local.suffix}.${local.domain}"

  admin_pages_project = "swastik-admin-${var.env}"
  app_pages_project   = "swastik-app-${var.env}"

  tick_audience = "https://${local.api_host}/internal/tick"
}
