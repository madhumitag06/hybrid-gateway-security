output "aws_vpc_id" {
  value = module.aws_network.vpc_id
}

output "gcp_vpc_id" {
  value = module.gcp_network.vpc_id
}

output "azure_vnet_id" {
  value = module.azure_network.vnet_id
}

output "gateway_service" {
  value = module.security_gateway.service_name
}

