output "vpc_id" {
  description = "The ID of the created VPC"
  value       = aws_vpc.terraform_vpc.id
}

output "subnet_id_1" {
  description = "ID of subnet 1"
  value       = aws_subnet.terraform_subnet_1.id
}

output "subnet_id_2" {
  description = "ID of subnet 2"
  value       = aws_subnet.terraform_subnet_2.id
}

output "subnet_ids" {
  description = "All subnet IDs in the VPC"
  value       = [
    aws_subnet.terraform_subnet_1.id,
    aws_subnet.terraform_subnet_2.id
  ]
}

output "availability_zones" {
  description = "List of availability zones used in the VPC"
  value       = var.availability_zones
}
