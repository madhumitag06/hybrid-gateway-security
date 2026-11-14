variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "hybrid-sec"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
}

variable "github_repository" {
  type        = string
  description = "GitHub repository (owner/repo) authorized to assume cloud roles"
  default     = "madhumitag06/hybrid-gateway-security"
}

variable "github_branch" {
  type        = string
  description = "Target Git branch for strict OIDC subject restriction"
  default     = "main"
}

variable "enable_aws" {
  type        = bool
  description = "Enable AWS IAM OIDC Role configuration"
  default     = true
}

variable "enable_gcp" {
  type        = bool
  description = "Enable GCP Workload Identity Federation configuration"
  default     = true
}

variable "gcp_project_id" {
  type        = string
  description = "GCP Project ID"
  default     = "gcp-builders-hub-prod"
}

variable "enable_azure" {
  type        = bool
  description = "Enable Azure Entra ID Federated Credential configuration"
  default     = true
}

