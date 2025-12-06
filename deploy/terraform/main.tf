# Saorsa 500-Node Testnet Infrastructure
# Deploys 5 worker droplets (100 nodes each) + 1 monitoring server

terraform {
  required_providers {
    digitalocean = {
      source  = "digitalocean/digitalocean"
      version = "~> 2.0"
    }
  }
}

variable "do_token" {
  description = "Digital Ocean API token"
  type        = string
  sensitive   = true
}

variable "ssh_key_fingerprint" {
  description = "SSH key fingerprint for droplet access"
  type        = string
}

variable "saorsa_version" {
  description = "Version of saorsa-node to deploy"
  type        = string
  default     = "0.1.0"
}

variable "bootstrap_nodes" {
  description = "Bootstrap node addresses"
  type        = list(string)
  default     = ["165.22.4.178:12000", "164.92.111.156:12000"]
}

provider "digitalocean" {
  token = var.do_token
}

# Worker regions - one large droplet per region
locals {
  worker_regions = {
    "nyc1" = "New York 1"
    "sfo3" = "San Francisco 3"
    "lon1" = "London 1"
    "ams3" = "Amsterdam 3"
    "sgp1" = "Singapore 1"
  }

  nodes_per_worker = 100
  metrics_base_port = 9100
}

# Worker droplets - 100 nodes each
resource "digitalocean_droplet" "worker" {
  for_each = local.worker_regions

  name     = "saorsa-worker-${each.key}"
  region   = each.key
  size     = "s-8vcpu-32gb"  # 8 vCPU, 32GB RAM
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]

  tags = ["saorsa", "testnet", "worker"]

  user_data = templatefile("${path.module}/cloud-init/worker.yml", {
    region           = each.key
    nodes_per_worker = local.nodes_per_worker
    metrics_base_port = local.metrics_base_port
    saorsa_version   = var.saorsa_version
    bootstrap_nodes  = join(",", var.bootstrap_nodes)
  })

  lifecycle {
    create_before_destroy = true
  }
}

# Monitoring droplet
resource "digitalocean_droplet" "monitoring" {
  name     = "saorsa-monitoring"
  region   = "nyc1"
  size     = "s-4vcpu-8gb"  # 4 vCPU, 8GB RAM
  image    = "ubuntu-24-04-x64"
  ssh_keys = [var.ssh_key_fingerprint]

  tags = ["saorsa", "testnet", "monitoring"]

  user_data = templatefile("${path.module}/cloud-init/monitoring.yml", {
    worker_ips = jsonencode([for w in digitalocean_droplet.worker : w.ipv4_address])
    nodes_per_worker = local.nodes_per_worker
    metrics_base_port = local.metrics_base_port
  })

  depends_on = [digitalocean_droplet.worker]
}

# Firewall for workers
resource "digitalocean_firewall" "worker" {
  name = "saorsa-worker-firewall"

  droplet_ids = [for w in digitalocean_droplet.worker : w.id]

  # SSH
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # QUIC ports for P2P (ephemeral range)
  inbound_rule {
    protocol         = "udp"
    port_range       = "32768-60999"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Metrics ports (9100-9199)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "9100-9199"
    source_addresses = [digitalocean_droplet.monitoring.ipv4_address]
  }

  # All outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Firewall for monitoring
resource "digitalocean_firewall" "monitoring" {
  name = "saorsa-monitoring-firewall"

  droplet_ids = [digitalocean_droplet.monitoring.id]

  # SSH
  inbound_rule {
    protocol         = "tcp"
    port_range       = "22"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # Grafana (3000) and Prometheus (9090)
  inbound_rule {
    protocol         = "tcp"
    port_range       = "3000"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  inbound_rule {
    protocol         = "tcp"
    port_range       = "9090"
    source_addresses = ["0.0.0.0/0", "::/0"]
  }

  # All outbound
  outbound_rule {
    protocol              = "tcp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }

  outbound_rule {
    protocol              = "udp"
    port_range            = "1-65535"
    destination_addresses = ["0.0.0.0/0", "::/0"]
  }
}

# Outputs
output "worker_ips" {
  description = "Worker droplet IP addresses by region"
  value = {
    for k, w in digitalocean_droplet.worker : k => w.ipv4_address
  }
}

output "monitoring_ip" {
  description = "Monitoring droplet IP address"
  value       = digitalocean_droplet.monitoring.ipv4_address
}

output "grafana_url" {
  description = "Grafana dashboard URL"
  value       = "http://${digitalocean_droplet.monitoring.ipv4_address}:3000"
}

output "prometheus_url" {
  description = "Prometheus URL"
  value       = "http://${digitalocean_droplet.monitoring.ipv4_address}:9090"
}

output "total_nodes" {
  description = "Total number of nodes deployed"
  value       = length(local.worker_regions) * local.nodes_per_worker
}
