variable "project_number" {
  type = string
}

variable "cloudflare_account_id" {
  type = string
}

variable "cloudflare_zone_id" {
  type = string
}

variable "access_emails" {
  type = list(string)
}

variable "sentry_dsn" {
  type      = string
  default   = ""
  sensitive = true
}
