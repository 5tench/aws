# ========================================
# MODULE: modules/ec2/variables.tf – CLEAN INPUTS
# ========================================

variable "vpc_id" {
  description = "VPC ID where instances will be deployed"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs"
  type        = list(string)
}

variable "availability_zones" {
  description = "List of availability zones"
  type        = list(string)
}

variable "subnet_map" {
  description = "AZ → subnet ID map"
  type        = map(string)
  default     = {}
}

variable "instances" {
  description = "List of EC2 instance configs"
  type = list(object({
    name              = string
    ami_id            = string
    instance_type     = string
    availability_zone = string
  }))
}

variable "security_group_id" {
  description = "Security Group ID"
  type        = string
}

variable "key_pair_name" {
  description = "Key pair name (already created)"
  type        = string
}

variable "user_data_script" {
  description = "Rendered bootstrap script (from root)"
  type        = string
}