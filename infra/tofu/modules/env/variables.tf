variable "env" {
  description = "Environment name: staging or production."
  type        = string
  validation {
    condition     = contains(["staging", "production"], var.env)
    error_message = "env must be staging or production."
  }
}

variable "project_id" {
  type    = string
  default = "swastik-4fcc9"
}

variable "region" {
  type    = string
  default = "asia-south1"
}

variable "project_number" {
  description = "GCP project number (used in the WIF principalSet)."
  type        = string
}

variable "cloudflare_account_id" {
  type = string
}

variable "cloudflare_zone_id" {
  type = string
}

variable "access_emails" {
  description = "Emails allowed through Cloudflare Access to the admin panel."
  type        = list(string)
  validation {
    condition     = length(var.access_emails) > 0
    error_message = "access_emails must list at least one email."
  }
}

variable "auth_keys_enabled" {
  description = "Wire the 003 auth secrets (JWT, PII, blind index) once they exist."
  type        = bool
  default     = false
}

variable "max_instances" {
  type    = number
  default = 2
}

variable "image" {
  description = "Bootstrap image for the first apply only; deploy.yml owns the image afterwards."
  type        = string
  default     = "us-docker.pkg.dev/cloudrun/container/hello"
}

variable "trusted_proxy_hops" {
  description = "TRUSTED_PROXY_HOPS: Cloud Run sees one hop (the Cloudflare Worker)."
  type        = string
  default     = "1"
}

variable "jwt_active_kid" {
  type    = string
  default = ""
}

variable "pii_active_key_id" {
  type    = string
  default = ""
}

variable "sentry_dsn" {
  type    = string
  default = ""
}
