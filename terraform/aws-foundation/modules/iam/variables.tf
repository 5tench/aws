# rds user created
variable "rds_user_name" {
  description = "The IAM user name to attach the RDS policy to"
  type        = string
}

# EC2 user to attach
variable "ec2_user_name" {
description = "EC2 admin user"
type = string
}
