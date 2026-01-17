variable "vpc_name" {
  description = "Name tag for the VPC"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
}

variable "subnet_name" {
  description = "Name tag for the subnet"
}

variable "subnet_cidr_1" {
  description = "CIDR block for the first subnet"
  type        = string
}

variable "subnet_cidr_2" {
  description = "CIDR block for the second subnet"
  type        = string
}

variable "availability_zones" {
  description = "Availability zones for subnets"
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b"]
}

variable "igw_name" {
  description = "Name tag for the Internet Gateway"
}

variable "tfroute" {
  description = "Name tag for the route table"
}

variable "tfroute_destination_cidr" {
  description = "Destination CIDR block for the default route"
}

variable "tfroute_table_association_name" {
  description = "Name tag for the route table association"
}
