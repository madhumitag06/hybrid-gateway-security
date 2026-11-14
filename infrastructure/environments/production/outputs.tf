output "aws_vpc_id" {
  value = module.aws_network.vpc_id
}

output "gcp_vpc_id" {
  value = module.gcp_network.vpc_id
}

output "azure_vnet_id" {
  value = module.azure_network.vnet_id
}

output "aws_oidc_role_arn" {
  value = module.identity_federation.aws_role_arn
}

output "gcp_workload_identity_provider" {
  value = module.identity_federation.gcp_workload_identity_provider
}

output "azure_client_id" {
  value = module.identity_federation.azure_client_id
}

output "gateway_service" {
  value = module.security_gateway.service_name
}

