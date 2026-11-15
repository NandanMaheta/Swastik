resource "cloudflare_workers_script" "proxy" {
  account_id  = var.cloudflare_account_id
  script_name = "swastik-api-proxy-${var.env}"
  main_module = "worker.js"
  content     = file("${path.module}/../../../cloudflare/api-proxy/worker.js")

  bindings = concat(
    [{
      name = "UPSTREAM"
      type = "plain_text"
      text = trimsuffix(google_cloud_run_v2_service.api.uri, "/")
    }],
    [for v in data.google_secret_manager_secret_version_access.proxy : {
      name = "PROXY_KEY"
      type = "secret_text"
      text = v.secret_data
    }]
  )
}

resource "cloudflare_workers_route" "api" {
  zone_id = var.cloudflare_zone_id
  pattern = "${local.api_host}/*"
  script  = cloudflare_workers_script.proxy.script_name
}
