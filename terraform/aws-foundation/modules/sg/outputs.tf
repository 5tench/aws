output "sg_id" {
  description = "ID of the security group"
  value       = aws_security_group.web_sg.id
}

output "sg_name" {
  description = "Name tag of the security group"
  value       = aws_security_group.web_sg.tags["Name"]
}

