output "resource_group_name" {
  description = "The Name of the Azure Resource Group"
  value       = azurerm_resource_group.rg.name
}

output "vnet_id" {
  description = "The ID of the Azure Virtual Network"
  value       = azurerm_virtual_network.vnet.id
}

output "gateway_subnet_id" {
  description = "The ID of the Gateway Subnet"
  value       = azurerm_subnet.gateway.id
}

output "workload_subnet_id" {
  description = "The ID of the Workload Subnet"
  value       = azurerm_subnet.workload.id
}

output "nsg_id" {
  description = "The ID of the Network Security Group"
  value       = azurerm_network_security_group.nsg.id
}

output "nsg_name" {
  description = "The Name of the Network Security Group"
  value       = azurerm_network_security_group.nsg.name
}

output "storage_account_name" {
  description = "Storage account for flow logs"
  value       = var.enable_flow_logs ? azurerm_storage_account.flow_logs_sa[0].name : ""
}

