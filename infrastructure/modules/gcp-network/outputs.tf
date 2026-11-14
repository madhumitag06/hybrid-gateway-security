output "vpc_id" {
  description = "The ID of the GCP VPC Network"
  value       = google_compute_network.custom_vpc.id
}

output "vpc_name" {
  description = "The Name of the GCP VPC Network"
  value       = google_compute_network.custom_vpc.name
}

output "subnet_id" {
  description = "The ID of the GCP Subnetwork"
  value       = google_compute_subnetwork.subnet.id
}

output "subnet_cidr" {
  description = "CIDR block of the GCP Subnetwork"
  value       = google_compute_subnetwork.subnet.ip_cidr_range
}

output "router_name" {
  description = "Name of the Cloud Router"
  value       = google_compute_router.router.name
}

