# Google Cloud Network Module (Google Builders Hub)
# Configures Custom VPC, Subnetwork with VPC Flow Logs, Cloud Router, and Cloud Firewalls

terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

resource "google_compute_network" "custom_vpc" {
  name                    = "${var.project_name}-vpc-${var.environment}"
  auto_create_subnetworks = false
  project                 = var.project_id
  description             = "Custom VPC Network for Multi-Cloud Security Gateway"
}

resource "google_compute_subnetwork" "subnet" {
  name          = "${var.project_name}-subnet-${var.region}-${var.environment}"
  ip_cidr_range = var.subnet_cidr
  region        = var.region
  network       = google_compute_network.custom_vpc.id
  project       = var.project_id

  # GCP VPC Flow Logs Configuration (5-second aggregation, full metadata)
  dynamic "log_config" {
    for_each = var.enable_flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }
}

# Cloud Router for Outbound Egress NAT
resource "google_compute_router" "router" {
  name    = "${var.project_name}-router-${var.environment}"
  region  = var.region
  network = google_compute_network.custom_vpc.id
  project = var.project_id
}

resource "google_compute_router_nat" "nat" {
  name                               = "${var.project_name}-nat-${var.environment}"
  router                             = google_compute_router.router.name
  region                             = var.region
  nat_ip_allocate_option             = "AUTO_ONLY"
  source_subnetwork_ip_ranges_to_nat = "ALL_SUBNETWORKS_ALL_IP_RANGES"
  project                            = var.project_id

  log_config {
    enable = true
    filter = "ERRORS_ONLY"
  }
}

# Baseline Ingress Allow Firewall Rule
resource "google_compute_firewall" "allow_gateway" {
  name    = "${var.project_name}-allow-gateway-${var.environment}"
  network = google_compute_network.custom_vpc.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["80", "443", "8000"]
  }

  source_ranges = ["0.0.0.0/0"]
  target_tags   = ["security-gateway"]
}

# Dynamic Containment Deny Template (High Priority Rule 100)
resource "google_compute_firewall" "quarantine_block" {
  name     = "${var.project_name}-quarantine-deny-${var.environment}"
  network  = google_compute_network.custom_vpc.name
  project  = var.project_id
  priority = 100

  deny {
    protocol = "all"
  }

  source_ranges = ["198.51.100.0/24"]  # Example blacklisted IP range
  description   = "Dynamic high-priority containment deny rule managed by Security Gateway"
}

