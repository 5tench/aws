variable "aws_profile" {
  description = "AWS profile to use"
  type        = string
}

variable "region" {
  description = "AWS region to deploy resources in"
  type        = string
}

variable "availability_zones" {
  description = "List of availability zones for subnets"
  type        = list(string)
}

variable "vpc_name" {
  description = "Name tag assigned to the VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block that defines the IP range of the VPC (e.g., 192.168.0.0/24)"
  type        = string
}

variable "subnet_name" {
  description = "Name tag assigned to the subnet"
  type        = string
}

variable "subnet_cidrs" {
  description = "List of CIDR blocks for subnets"
  type        = list(string)
}

variable "igw_name" {
  description = "Name tag for the Internet Gateway"
  type        = string
}

variable "route_table_name" {
  description = "Name tag for the route table"
  type        = string
}

variable "route_destination_cidr" {
  description = "Destination CIDR block for the default route (e.g., 0.0.0.0/0)"
  type        = string
}

variable "route_table_association_name" {
  description = "Name tag for the route table association"
  type        = string
}

variable "instances" {
  description = "List of EC2 instance configurations"
  type = list(object({
    name              = string
    ami_id            = string
    instance_type     = string
    availability_zone = string
  }))
}

variable "key_pair_name" {
  description = "Key pair name for EC2 instances"
  type        = string
}

variable "public_key_path" {
  description = "Path to your public key"
  type        = string
}

variable "bootstrap_script_path" {
  description = "Path to the Debian/NGINX bootstrap script"
  type        = string
}

variable "sg_name" {
  description = "Name of the security group"
  type        = string
}

variable "sg_description" {
  description = "Description for the security group"
  type        = string
}

variable "security_group" {
  description = "Name of the security group"
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

variable "lb_name" {
  description = "Name for the load balancer"
  type        = string
}

variable "target_group_name" {
  description = "Target group name"
  type        = string
}

variable "target_port" {
  description = "Port for target group"
  type        = number
}

variable "allocated_storage" {
  description = "The allocated storage in GBs"
  type        = number
}

variable "engine" {
  description = "The database engine to use (e.g., mysql, postgres)"
  type        = string
}

variable "engine_version" {
  description = "The engine version"
  type        = string
}

variable "instance_class" {
  description = "The instance type/class"
  type        = string
}

variable "db_name" {
  description = "The name of the initial database"
  type        = string
}

variable "username" {
  description = "Master username for the database"
  type        = string
}

variable "password" {
  description = "Master password for the database"
  type        = string
  sensitive   = true
}

variable "parameter_group_name" {
  description = "Name of DB parameter group"
  type        = string
  default     = null
}

variable "db_subnet_group_name" {
  description = "Subnet group name for RDS"
  type        = string
}

variable "subnet_ids" {
  description = "List of subnet IDs for the DB subnet group"
  type        = list(string)
}

variable "publicly_accessible" {
  description = "Whether the RDS instance is publicly accessible"
  type        = bool
  default     = false
}

variable "skip_final_snapshot" {
  description = "Skip creating a final DB snapshot on delete"
  type        = bool
  default     = true
}

variable "db_instance_name" {
  description = "Tag name for the RDS instance"
  type        = string
}

variable "tfinstance_DB" {
  description = "Tag name for the database EC2 instance"
  type        = string
}

# Plus any DB-specific variables, e.g., DB engine, size, etc.

variable "ec2_user_name" {
  description = "Existing IAM user for EC2/SSM access"
  type        = string
}

variable "rds_user_name" {
  description = "IAM user to be created/managed for RDS"
  type        = string
}

