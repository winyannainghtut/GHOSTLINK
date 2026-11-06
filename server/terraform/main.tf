terraform {
  required_version = ">= 1.8, < 2.0"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 6.0" }
  }
}
provider "aws" { region = var.region }
variable "region" {
  type    = string
  default = "ap-southeast-1"
}
variable "admin_cidr" {
  type        = string
  description = "Your fixed IPv4 SSH administration CIDR. Never use 0.0.0.0/0."
  validation {
    condition     = can(cidrnetmask(var.admin_cidr)) && try(tonumber(split("/", var.admin_cidr)[1]) >= 24, false)
    error_message = "Supply a narrow IPv4 CIDR (/24 or narrower) for SSH."
  }
}
variable "key_name" { type = string }
variable "subnet_id" { type = string }
variable "vpc_id" { type = string }
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}
resource "aws_security_group" "vpn" {
  name_prefix = "ghostlink-"
  description = "Personal VPN and restricted administration"
  vpc_id      = var.vpc_id
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }
  ingress {
    from_port   = 1194
    to_port     = 1194
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_instance" "vpn" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.small"
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.vpn.id]
  metadata_options { http_tokens = "required" }
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 12
  }
  tags = { Name = "Ghostlink" }
  lifecycle { ignore_changes = [ami] }
}
resource "aws_eip" "vpn" {
  instance = aws_instance.vpn.id
  domain   = "vpc"
}
output "vpn_endpoint" { value = aws_eip.vpn.public_ip }
output "inventory" { value = "[vpn]\n${aws_eip.vpn.public_ip} ansible_user=ubuntu\n" }
