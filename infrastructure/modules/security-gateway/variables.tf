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

variable "gateway_image" {
  type        = string
  description = "Container image for Adaptive Security Gateway"
  default     = "ghcr.io/madhumitag06/hybrid-gateway-security:latest"
}

variable "gateway_port" {
  type        = number
  description = "FastAPI backend listening port"
  default     = 8000
}

variable "active_model_version" {
  type        = string
  description = "Authoritative ML model version"
  default     = "candidate_xgboost_v2"
}

variable "cpu_units" {
  type        = number
  description = "CPU core allocation"
  default     = 2
}

variable "memory_mb" {
  type        = number
  description = "RAM allocation in Megabytes"
  default     = 4096
}

