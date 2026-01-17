#security group variables
variable "sg_name" {
  description = "The name of the security group"
  type        = string
}

variable "sg_description" {
  description = "Description for the security group"
  type        = string
}

variable "vpc_id" {
  description = "The ID of the VPC to associate with the security group"
  type        = string
}

variable "sg_ingress_rules" {
  description = "List of ingress rules for the security group"
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
}

variable "sg_egress_rules" {
  description = "List of egress rules for the security group"
  type = list(object({
    description = string
    from_port   = number
    to_port     = number
    protocol    = string
    cidr_blocks = list(string)
  }))
}

