##################################################
# MCP Servers for Lenses - Generic Configuration
##################################################

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile
}

##################################################
# Variables
##################################################

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "AWS CLI profile"
  type        = string
  default     = "default"
}

variable "vpc_id" {
  description = "VPC ID where servers will be deployed"
  type        = string
}

variable "subnet_id" {
  description = "Subnet ID for MCP servers (public subnet)"
  type        = string
}

variable "key_pair_name" {
  description = "EC2 key pair name"
  type        = string
}

variable "mcp_server_count" {
  description = "Number of MCP servers to create"
  type        = number
  default     = 15
}

variable "instance_type" {
  description = "EC2 instance type for MCP servers"
  type        = string
  default     = "m5.xlarge"
}

variable "msk_cluster_arn" {
  description = "MSK cluster ARN for IAM permissions"
  type        = string
}

variable "eks_cluster_name" {
  description = "EKS cluster name"
  type        = string
}

variable "lenses_api_http_url" {
  description = "Lenses HQ HTTP URL (without port)"
  type        = string
}

variable "lenses_api_http_port" {
  description = "Lenses HQ HTTP port"
  type        = string
  default     = "8080"
}

variable "lenses_api_websocket_url" {
  description = "Lenses HQ WebSocket URL"
  type        = string
}

variable "lenses_api_websocket_port" {
  description = "Lenses HQ WebSocket port"
  type        = string
  default     = "8080"
}

variable "lenses_api_key" {
  description = "Lenses API key"
  type        = string
  sensitive   = true
}

##################################################
# Data Sources
##################################################

# Get latest Amazon Linux 2023 AMI
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["al2023-ami-*-x86_64"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

# Get VPC details
data "aws_vpc" "main" {
  id = var.vpc_id
}

# Get AWS account ID
data "aws_caller_identity" "current" {}

##################################################
# Security Group
##################################################

resource "aws_security_group" "mcp_servers" {
  name        = "mcp-servers-sg"
  description = "Security group for MCP servers"
  vpc_id      = var.vpc_id

  # SSH access
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # MCP server port
  ingress {
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "MCP server port"
  }

  # Outbound - allow all
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound"
  }

  tags = {
    Name = "mcp-servers-sg"
  }
}

##################################################
# IAM Role and Policies
##################################################

# IAM Role for MCP servers
resource "aws_iam_role" "mcp_server_role" {
  name = "mcp-server-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name = "mcp-server-role"
  }
}

# Instance profile
resource "aws_iam_instance_profile" "mcp_server_profile" {
  name = "mcp-server-profile"
  role = aws_iam_role.mcp_server_role.name
}

# Policy for MSK access
resource "aws_iam_policy" "msk_access" {
  name        = "mcp-msk-access-policy"
  description = "Policy for MCP servers to access MSK"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:Connect",
          "kafka-cluster:AlterCluster",
          "kafka-cluster:DescribeCluster"
        ]
        Resource = var.msk_cluster_arn
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:*Topic*",
          "kafka-cluster:WriteData",
          "kafka-cluster:ReadData"
        ]
        Resource = "${replace(var.msk_cluster_arn, ":cluster/", ":topic/")}/*"
      },
      {
        Effect = "Allow"
        Action = [
          "kafka-cluster:AlterGroup",
          "kafka-cluster:DescribeGroup"
        ]
        Resource = "${replace(var.msk_cluster_arn, ":cluster/", ":group/")}/*"
      }
    ]
  })
}

# Attach MSK policy to role
resource "aws_iam_role_policy_attachment" "msk_access" {
  role       = aws_iam_role.mcp_server_role.name
  policy_arn = aws_iam_policy.msk_access.arn
}

# Attach EKS policies
resource "aws_iam_role_policy_attachment" "eks_cluster_policy" {
  role       = aws_iam_role.mcp_server_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_worker_node_policy" {
  role       = aws_iam_role.mcp_server_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

##################################################
# User Data Script
##################################################

locals {
  user_data = <<-EOF
    #!/bin/bash
    set -e
    
    # Update system
    dnf update -y
    
    # Install prerequisites (skip curl since it's already installed)
    dnf install -y git wget unzip python3.12 python3.12-pip
    
    # Install kubectl
    curl -O https://s3.us-west-2.amazonaws.com/amazon-eks/1.31.0/2024-09-12/bin/linux/amd64/kubectl
    chmod +x ./kubectl
    mv ./kubectl /usr/local/bin/
    
    # Configure kubectl for EKS
    aws eks update-kubeconfig --region ${var.aws_region} --name ${var.eks_cluster_name}
    
    # Install uv (Python package manager)
    curl -LsSf https://astral.sh/uv/install.sh | sh
    
    # Add uv to PATH for root
    export PATH="/root/.local/bin:$PATH"
    
    # Clone Lenses MCP server
    cd /opt
    git clone https://github.com/lensesio/lenses-mcp.git
    cd lenses-mcp
    
    # Create .env file with correct format
    cat > .env << 'ENVFILE'
LENSES_API_HTTP_URL=${var.lenses_api_http_url}
LENSES_API_HTTP_PORT=${var.lenses_api_http_port}
LENSES_API_WEBSOCKET_URL=${var.lenses_api_websocket_url}
LENSES_API_WEBSOCKET_PORT=${var.lenses_api_websocket_port}
LENSES_API_KEY=${var.lenses_api_key}
ENVFILE
    
    # Install dependencies
    /root/.local/bin/uv sync
    
    # Create systemd service for MCP server with --host=0.0.0.0
    cat > /etc/systemd/system/lenses-mcp.service << 'SYSTEMD'
[Unit]
Description=Lenses MCP Server
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/lenses-mcp
Environment="PATH=/root/.local/bin:/usr/local/bin:/usr/bin:/bin"
ExecStart=/root/.local/bin/uv run fastmcp run /opt/lenses-mcp/src/lenses_mcp/server.py --transport=http --port=8080 --host=0.0.0.0
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SYSTEMD
    
    # Enable and start the service
    systemctl daemon-reload
    systemctl enable lenses-mcp.service
    systemctl start lenses-mcp.service
    
    # Create a setup completion marker
    echo "MCP Server setup completed at $(date)" > /var/log/mcp-setup-complete.log
  EOF
}

##################################################
# EC2 Instances
##################################################

resource "aws_instance" "mcp_servers" {
  count = var.mcp_server_count

  ami                    = data.aws_ami.amazon_linux_2023.id
  instance_type          = var.instance_type
  key_name              = var.key_pair_name
  subnet_id             = var.subnet_id
  vpc_security_group_ids = [aws_security_group.mcp_servers.id]
  iam_instance_profile   = aws_iam_instance_profile.mcp_server_profile.name

  user_data = local.user_data

  root_block_device {
    volume_size = 30
    volume_type = "gp3"
  }

  tags = {
    Name = "mcp-server-${count.index + 1}"
    Type = "mcp-server"
  }
}

##################################################
# Outputs
##################################################

output "mcp_server_ips" {
  description = "Public IP addresses of MCP servers"
  value = {
    for idx, instance in aws_instance.mcp_servers :
    "mcp-server-${idx + 1}" => instance.public_ip
  }
}

output "mcp_server_ssh_commands" {
  description = "SSH commands for each MCP server"
  value = [
    for idx, instance in aws_instance.mcp_servers :
    "ssh -i ~/.ssh/${var.key_pair_name}.pem ec2-user@${instance.public_ip}  # mcp-server-${idx + 1}"
  ]
}

output "mcp_server_urls" {
  description = "MCP server URLs"
  value = [
    for idx, instance in aws_instance.mcp_servers :
    "http://${instance.public_ip}:8080  # mcp-server-${idx + 1}"
  ]
}

output "mcp_server_ids" {
  description = "Instance IDs of MCP servers"
  value       = aws_instance.mcp_servers[*].id
}

output "setup_verification_command" {
  description = "Command to verify MCP server setup on each instance"
  value       = "sudo systemctl status lenses-mcp.service && cat /var/log/mcp-setup-complete.log"
}
