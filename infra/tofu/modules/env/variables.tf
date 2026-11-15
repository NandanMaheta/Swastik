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
