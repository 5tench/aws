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

variable "vpc_security_group_ids" {
  description = "List of VPC security group IDs"
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

