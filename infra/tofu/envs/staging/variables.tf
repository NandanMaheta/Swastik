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

variable "auth_keys_enabled" {
  description = "Wire the 003 auth secrets once secrets.sh --with-auth has created them."
  type        = bool
  default     = false
}

variable "jwt_active_kid" {
  type    = string
  default = ""
}

variable "pii_active_key_id" {
  type    = string
  default = ""
}

variable "otp_enabled" {
  description = "Wire the 004 OTP delivery secrets and settings once secrets.sh --with-otp has created them (owner gate G-SECRETS)."
  type        = bool
  default     = false
}
