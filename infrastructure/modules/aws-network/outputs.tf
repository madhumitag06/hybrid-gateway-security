output "vpc_id" {
  description = "The ID of the AWS VPC"
  value       = aws_vpc.main.id
}

output "vpc_cidr" {
  description = "The CIDR block of the AWS VPC"
  value       = aws_vpc.main.cidr_block
}

output "public_subnet_id" {
  description = "Public ingress subnet ID"
  value       = aws_subnet.public.id
}

output "private_subnet_id" {
  description = "Private workload subnet ID"
  value       = aws_subnet.private.id
}

output "security_group_id" {
  description = "Security Gateway Security Group ID"
  value       = aws_security_group.gateway_sg.id
}

output "nacl_id" {
  description = "Security Gateway Network ACL ID"
  value       = aws_network_acl.gateway_nacl.id
}

output "flow_log_group_name" {
  description = "CloudWatch Log Group capturing VPC Flow Logs"
  value       = var.enable_flow_logs ? aws_cloudwatch_log_group.flow_logs[0].name : ""
}

