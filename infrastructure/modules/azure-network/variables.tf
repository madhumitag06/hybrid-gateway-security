variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "hybrid-azure"
}

variable "environment" {
  type        = string
  description = "Deployment environment"
  default     = "production"
}

variable "location" {
  type        = string
  description = "Azure datacenter location"
  default     = "eastus"
}

variable "vnet_cidr" {
  type        = string
  description = "Virtual Network address space"
  default     = "10.50.0.0/16"
}

variable "gateway_subnet_cidr" {
  type        = string
  description = "Security Gateway subnet CIDR"
  default     = "10.50.10.0/24"
}

variable "workload_subnet_cidr" {
  type        = string
  description = "Workload subnet CIDR"
  default     = "10.50.20.0/24"
}

variable "enable_flow_logs" {
  type        = bool
  description = "Enable Network Watcher Flow Logs V2"
  default     = true
}

