output "subnet_id_1" {
  value = aws_subnet.terraform_subnet_1.id
}

output "subnet_id_2" {
  value = aws_subnet.terraform_subnet_2.id
}

output "subnet_ids" {
  value = [
    aws_subnet.terraform_subnet_1.id,
    aws_subnet.terraform_subnet_2.id,
  ]
}

output "vpc_id" {
  value = aws_vpc.terraform_vpc.id
}
