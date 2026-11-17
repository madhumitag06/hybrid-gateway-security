# Multi-Cloud Terraform Infrastructure Guide

**Project:** Adaptive AI-Powered Security Gateway for Hybrid Cloud  
**Engine:** HashiCorp Terraform $\ge 1.5.0$  
**Modules:** `aws-network`, `gcp-network`, `azure-network`, `security-gateway`, `identity-federation`  
**Environments:** `development`, `staging`, `production`  

---

## 1. Directory Structure

```
infrastructure/
├── environments/
│   ├── development/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── terraform.tfvars.example
│   ├── staging/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   └── terraform.tfvars.example
│   └── production/
│       ├── main.tf
│       ├── variables.tf
│       ├── outputs.tf
│       └── terraform.tfvars.example
├── modules/
│   ├── aws-network/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── gcp-network/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── azure-network/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   ├── identity-federation/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   └── outputs.tf
│   └── security-gateway/
│       ├── main.tf
│       ├── variables.tf
│       └── outputs.tf
└── shared/
    └── variables.tf
```

---

## 2. Module Catalog

### 2.1 `aws-network`
- **Resources:** `aws_vpc`, `aws_subnet` (public/private), `aws_internet_gateway`, `aws_route_table`, `aws_cloudwatch_log_group`, `aws_iam_role` (flow logs), `aws_flow_log`, `aws_security_group`, `aws_network_acl`.
- **Inputs:** `vpc_cidr` (`10.20.0.0/16`), `public_subnet_cidr`, `private_subnet_cidr`, `enable_flow_logs` (default `true`).
- **Outputs:** `vpc_id`, `public_subnet_id`, `security_group_id`, `flow_log_group_name`.

### 2.2 `gcp-network` (Google Builders Hub)
- **Resources:** `google_compute_network` (custom VPC), `google_compute_subnetwork` (with VPC flow log sampling & 5-sec aggregation), `google_compute_router`, `google_compute_router_nat`, `google_compute_firewall` (allow gateway & high-priority deny template).
- **Inputs:** `project_id`, `subnet_cidr` (`10.40.10.0/24`), `region` (`us-central1`), `enable_flow_logs` (default `true`).
- **Outputs:** `vpc_id`, `subnet_id`, `router_name`.

### 2.3 `azure-network`
- **Resources:** `azurerm_resource_group`, `azurerm_virtual_network`, `azurerm_subnet` (gateway & workload), `azurerm_network_security_group`, `azurerm_storage_account` (for Network Watcher Flow Logs).
- **Inputs:** `vnet_cidr` (`10.50.0.0/16`), `gateway_subnet_cidr`, `location` (`eastus`), `enable_flow_logs` (default `true`).
- **Outputs:** `vnet_id`, `gateway_subnet_id`, `nsg_id`, `storage_account_name`.

### 2.4 `identity-federation`
- **Resources:** `aws_iam_openid_connect_provider`, `aws_iam_role` (GitHub Actions assume role), `google_iam_workload_identity_pool`, `google_iam_workload_identity_pool_provider`, `google_service_account`, `azuread_application`, `azuread_application_federated_identity_credential`.
- **Outputs:** `aws_role_arn`, `gcp_workload_identity_provider`, `azure_client_id`.

### 2.5 `security-gateway`
- **Resources:** Cloud-agnostic container manifest specification, resource allocations (CPU/RAM), health check probes (`/api/health`), environment variable injection (`ACTIVE_MODEL_VERSION=candidate_xgboost_v2`).

---

## 3. Deployment Instructions

### 3.1 Initializing & Validating
To format and validate modules without creating chargeable resources:
```bash
# 1. Format check
terraform fmt -check -recursive infrastructure/

# 2. Initialize in development environment
cd infrastructure/environments/development
terraform init -backend=false
terraform validate
```

### 3.2 State Management & Remote Backends
- **Development:** Local state or shared S3/GCS bucket with state locking.
- **Production:** S3 + DynamoDB table (`LockID`), Google Cloud Storage bucket (`uniform_bucket_level_access`), or Azure Blob Storage container (`blob_lease`).

### 3.3 Safe Rollback Procedures
To revert an applied infrastructure configuration:
```bash
terraform plan -destroy -out=destroy.tfplan
# Review plan carefully before applying
terraform apply destroy.tfplan
```

