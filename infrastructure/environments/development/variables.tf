variable "environment" {
  type        = string
  description = "Target environment"
  default     = "development"
}

variable "project_name" {
  type        = string
  description = "Project name"
  default     = "hybrid-sec-dev"
}

variable "gcp_project_id" {
  type        = string
  description = "GCP Project ID (Google Builders Hub)"
  default     = "gcp-builders-hub-dev"
}

