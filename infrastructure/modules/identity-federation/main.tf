# Workload Identity Federation Module
# Sets up keyless, secretless OIDC authentication for GitHub Actions across AWS, GCP, and Azure

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

# -------------------------------------------------------------
# 1. AWS IAM OIDC Provider & GitHub Actions Assume Role
# -------------------------------------------------------------
resource "aws_iam_openid_connect_provider" "github" {
  count           = var.enable_aws ? 1 : 0
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1", "1c58a3a8518e8759bf075b76b750d4f8d264fcd9"]

  tags = {
    Environment = var.environment
  }
}

resource "aws_iam_role" "github_actions" {
  count = var.enable_aws ? 1 : 0
  name  = "${var.project_name}-github-oidc-role-${var.environment}"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = aws_iam_openid_connect_provider.github[0].arn
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "token.actions.githubusercontent.com:aud" : "sts.amazonaws.com"
          }
          StringLike = {
            "token.actions.githubusercontent.com:sub" : "repo:${var.github_repository}:ref:refs/heads/${var.github_branch}"
          }
        }
      }
    ]
  })
}

# -------------------------------------------------------------
# 2. GCP Workload Identity Federation (Google Builders Hub)
# -------------------------------------------------------------
resource "google_iam_workload_identity_pool" "github_pool" {
  count                     = var.enable_gcp ? 1 : 0
  project                   = var.gcp_project_id
  workload_identity_pool_id = "${var.project_name}-gh-pool"
  display_name              = "GitHub Actions Identity Pool"
  description               = "Identity pool for GitHub Actions CI/CD workflows"
}

resource "google_iam_workload_identity_pool_provider" "github_provider" {
  count                              = var.enable_gcp ? 1 : 0
  project                            = var.gcp_project_id
  workload_identity_pool_id          = google_iam_workload_identity_pool.github_pool[0].workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"
  display_name                       = "GitHub Provider"

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

resource "google_service_account" "gateway_deployer" {
  count        = var.enable_gcp ? 1 : 0
  project      = var.gcp_project_id
  account_id   = "${var.project_name}-deployer"
  display_name = "Security Gateway Deployer Service Account"
}

resource "google_service_account_iam_member" "workload_identity_user" {
  count              = var.enable_gcp ? 1 : 0
  service_account_id = google_service_account.gateway_deployer[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github_pool[0].name}/attribute.repository/${var.github_repository}"
}

# -------------------------------------------------------------
# 3. Azure Entra ID Application & Federated Credential
# -------------------------------------------------------------
resource "azuread_application" "github" {
  count        = var.enable_azure ? 1 : 0
  display_name = "${var.project_name}-github-app-${var.environment}"
}

resource "azuread_service_principal" "github" {
  count          = var.enable_azure ? 1 : 0
  client_id      = azuread_application.github[0].client_id
}

resource "azuread_application_federated_identity_credential" "github_branch" {
  count                 = var.enable_azure ? 1 : 0
  application_id        = azuread_application.github[0].id
  display_name          = "github-actions-${var.environment}"
  description           = "Federated credential for GitHub Actions branch deployments"
  audiences             = ["api://AzureADTokenExchange"]
  issuer                = "https://token.actions.githubusercontent.com"
  subject               = "repo:${var.github_repository}:ref:refs/heads/${var.github_branch}"
}

