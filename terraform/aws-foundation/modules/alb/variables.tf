###########################
# ALB module variables
###########################

variable "lb_name" {
  description = "Name of the Application Load Balancer"
  type        = string
}

variable "target_group_name" {
  description = "Name of the target group for the ALB"
  type        = string
}

variable "vpc_id" {
  description = "VPC id where the target group and load balancer will be created"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs where the ALB will be placed"
  type        = list(string)
}

variable "security_group_id" {
  description = "Security group id to attach to the ALB"
  type        = string
}

variable "instances" {
  description = "Map/list of instances to register with the target group. Expected to be a map or list with objects that include an 'id' attribute. In this project the root module supplies module.ec2.instances_detailed"
  type = any
}

variable "target_port" {
  description = "Port to use for the target group and listener"
  type        = number
}
