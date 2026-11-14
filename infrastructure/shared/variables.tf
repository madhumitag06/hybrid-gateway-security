# Multi-Cloud Shared Variables Definition

variable "project_name" {
  type        = string
  description = "Project name prefix for all multi-cloud security resources"
  default     = "hybrid-sec-gateway"
}

variable "environment" {
  type        = string
  description = "Target deployment environment (development, staging, production)"
  default     = "production"
}

variable "aws_region" {
  type        = string
  description = "AWS Primary Deployment Region"
  default     = "us-east-1"
}

variable "gcp_region" {
  type        = string
  description = "Google Cloud Primary Deployment Region"
  default     = "us-central1"
}

variable "azure_region" {
  type        = string
  description = "Microsoft Azure Primary Deployment Region"
  default     = "eastus"
}

variable "github_repository" {
  type        = string
  description = "GitHub repository owner and name for OIDC workload federation (e.g. madhumitag06/hybrid-gateway-security)"
  default     = "madhumitag06/hybrid-gateway-security"
}

