variable "project_name" {
  type        = string
  description = "Project name prefix"
  default     = "hybrid-sec"
}

variable "environment" {
  type        = string
  description = "Deployment environment (dev, staging, prod)"
  default     = "production"
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block for AWS VPC"
  default     = "10.20.0.0/16"
}

variable "public_subnet_cidr" {
  type        = string
  description = "CIDR block for public ingress subnet"
  default     = "10.20.10.0/24"
}

variable "private_subnet_cidr" {
  type        = string
  description = "CIDR block for private workload subnet"
  default     = "10.20.20.0/24"
}

variable "availability_zone" {
  type        = string
  description = "Primary AWS availability zone"
  default     = "us-east-1a"
}

variable "enable_flow_logs" {
  type        = bool
  description = "Enable AWS VPC Flow Logs ingestion"
  default     = true
}

variable "traffic_type" {
  type        = string
  description = "The type of traffic to capture in Flow Logs (ALL, ACCEPT, REJECT)"
  default     = "ALL"
}

