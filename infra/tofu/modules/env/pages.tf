# Direct-upload projects: deploy.yml uploads the builds, there is no git source.
resource "cloudflare_pages_project" "admin" {
  account_id        = var.cloudflare_account_id
  name              = local.admin_pages_project
  production_branch = "main"
}

resource "cloudflare_pages_project" "app" {
  account_id        = var.cloudflare_account_id
  name              = local.app_pages_project
  production_branch = "main"
}

resource "cloudflare_pages_domain" "admin" {
  account_id   = var.cloudflare_account_id
  project_name = cloudflare_pages_project.admin.name
  name         = local.admin_host
}

resource "cloudflare_pages_domain" "app" {
  account_id   = var.cloudflare_account_id
  project_name = cloudflare_pages_project.app.name
  name         = local.app_host
}
