resource "aws_security_group" "web_sg" {
  name        = var.terraform_sg
  description = var.terraform_sg_description
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ingress_rules
    content {
      from_port   = ingress.value
      to_port     = ingress.value
      protocol    = ingress.key == "icmp" ? "icmp" : var.ip_protocol
      description = var.ingress_description
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  dynamic "egress" {
    for_each = var.egress_rules
    content {
      from_port   = egress.value
      to_port     = egress.value
      protocol    = var.ip_protocol
      description = var.egress_description
      cidr_blocks = ["0.0.0.0/0"]
    }
  }

  tags = {
    Name = var.terraform_sg
  }
}
