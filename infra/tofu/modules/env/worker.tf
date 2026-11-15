resource "cloudflare_workers_script" "proxy" {
  account_id  = var.cloudflare_account_id
  script_name = "swastik-api-proxy-${var.env}"
  main_module = "worker.js"
  # Keep bindings tofu does not manage (the secret set by secrets.sh) when the script is updated.
  keep_bindings = ["secret_text"]
  content       = file("${path.module}/../../../cloudflare/api-proxy/worker.js")

  # The proxy key secret is set outside tofu (secrets.sh -> wrangler secret put) so no secret value enters state.
  bindings = [{
    name = "UPSTREAM"
    type = "plain_text"
    text = trimsuffix(google_cloud_run_v2_service.api.uri, "/")
  }]
}

resource "cloudflare_workers_route" "api" {
  zone_id = var.cloudflare_zone_id
  pattern = "${local.api_host}/*"
  script  = cloudflare_workers_script.proxy.script_name
}
