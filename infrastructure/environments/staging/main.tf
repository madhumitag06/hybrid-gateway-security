# Staging Environment Composition

terraform {
  required_version = ">= 1.5.0"
}

provider "aws" {
  region                      = "us-east-1"
  skip_credentials_validation = true
  skip_requesting_account_id  = true
}

provider "google" {
  project = var.gcp_project_id
  region  = "us-central1"
}

provider "azurerm" {
  features {}
  skip_provider_registration = true
}

provider "azuread" {}

module "aws_network" {
  source              = "../../modules/aws-network"
  project_name        = var.project_name
  environment         = var.environment
  vpc_cidr            = "10.20.0.0/16"
  public_subnet_cidr  = "10.20.10.0/24"
  private_subnet_cidr = "10.20.20.0/24"
  enable_flow_logs    = true
}

module "gcp_network" {
  source           = "../../modules/gcp-network"
  project_id       = var.gcp_project_id
  project_name     = var.project_name
  environment      = var.environment
  subnet_cidr      = "10.40.10.0/24"
  enable_flow_logs = true
}

module "azure_network" {
  source              = "../../modules/azure-network"
  project_name        = var.project_name
  environment         = var.environment
  vnet_cidr           = "10.50.0.0/16"
  gateway_subnet_cidr = "10.50.10.0/24"
  enable_flow_logs    = true
}

module "security_gateway" {
  source               = "../../modules/security-gateway"
  project_name         = var.project_name
  environment          = var.environment
  active_model_version = "candidate_xgboost_v2"
}
