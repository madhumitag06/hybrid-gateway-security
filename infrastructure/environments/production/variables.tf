variable "environment" {
  type        = string
  description = "Target environment"
  default     = "production"
}

variable "project_name" {
  type        = string
  description = "Project name"
  default     = "hybrid-sec-prod"
}

variable "gcp_project_id" {
  type        = string
  description = "GCP Project ID (Google Builders Hub)"
  default     = "gcp-builders-hub-prod"
}

variable "github_repository" {
  type        = string
  description = "GitHub repository for OIDC identity federation"
  default     = "madhumitag06/hybrid-gateway-security"
}

