# Security Gateway Deployment Blueprint Module
# Defines cloud-agnostic container task definition and health probe configuration

terraform {
  required_version = ">= 1.5.0"
}

locals {
  container_environment = [
    { name = "APP_NAME", value = "Adaptive AI Hybrid Security Gateway" },
    { name = "ACTIVE_MODEL_VERSION", value = var.active_model_version },
    { name = "STANDBY_MODEL_VERSION", value = "production_rf" },
    { name = "SHADOW_MODE_ENABLED", value = "true" },
    { name = "SHADOW_SHAP_THRESHOLD", value = "50" },
    { name = "PORT", value = tostring(var.gateway_port) },
  ]
}

# Output container configuration template for ECS, Cloud Run, and Azure Container Apps
resource "terraform_data" "gateway_manifest" {
  input = {
    service_name = "${var.project_name}-gateway-${var.environment}"
    image        = var.gateway_image
    cpu          = var.cpu_units
    memory       = var.memory_mb
    port         = var.gateway_port
    health_check = {
      path                = "/api/health"
      interval_seconds    = 15
      timeout_seconds     = 5
      healthy_threshold   = 2
      unhealthy_threshold = 3
    }
    environment = local.container_environment
  }
}

