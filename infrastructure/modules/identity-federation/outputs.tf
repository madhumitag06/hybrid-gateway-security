output "aws_role_arn" {
  description = "AWS IAM Role ARN assumed by GitHub Actions via OIDC"
  value       = var.enable_aws ? aws_iam_role.github_actions[0].arn : ""
}

output "gcp_workload_identity_provider" {
  description = "GCP Workload Identity Provider resource name"
  value       = var.enable_gcp ? google_iam_workload_identity_pool_provider.github_provider[0].name : ""
}

output "gcp_service_account_email" {
  description = "GCP Service Account Email bound to GitHub Workload Identity"
  value       = var.enable_gcp ? google_service_account.gateway_deployer[0].email : ""
}

output "azure_client_id" {
  description = "Azure Entra ID Application Client ID for GitHub Actions"
  value       = var.enable_azure ? azuread_application.github[0].client_id : ""
}

