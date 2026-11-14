output "service_name" {
  description = "Security Gateway service identifier"
  value       = terraform_data.gateway_manifest.output.service_name
}

output "health_check_path" {
  description = "Gateway HTTP health probe endpoint"
  value       = terraform_data.gateway_manifest.output.health_check.path
}

output "container_manifest" {
  description = "Complete container manifest definition"
  value       = terraform_data.gateway_manifest.output
}

