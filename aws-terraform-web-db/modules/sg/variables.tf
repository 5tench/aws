variable "terraform_sg" {
  description = "Security group name"
}

variable "terraform_sg_description" {
  description = "Description for security group"
}

variable "ip_protocol" {
  description = "Protocol for traffic rules"
}

variable "application_protocols" {
  description = "List of protocols to allow (http, https)"
  type        = list(string)
}

variable "ingress_description" {
  description = "Ingress rule description"
}

variable "egress_description" {
  description = "Description for outbound traffic"
}

variable "ingress_rules" {
  description = "Map of ingress rules and their ports"
  type        = map(number)
}

variable "egress_rules" {
  description = "Map of egress rules and their ports"
  type        = map(number)
}

variable "vpc_id" {
  description = "ID of the VPC to attach the security group to"
}
