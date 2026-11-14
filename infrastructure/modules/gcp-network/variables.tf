variable "project_id" {
  type        = string
  description = "Google Cloud Project ID (Google Builders Hub)"
  default     = "gcp-builders-hub-prod"
}

variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "hybrid-gcp"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
}

variable "region" {
  type        = string
  description = "Primary GCP Region"
  default     = "us-central1"
}

variable "subnet_cidr" {
  type        = string
  description = "CIDR block for GCP subnetwork"
  default     = "10.40.10.0/24"
}

variable "enable_flow_logs" {
  type        = bool
  description = "Enable GCP VPC Flow Logs on subnetwork"
  default     = true
}

