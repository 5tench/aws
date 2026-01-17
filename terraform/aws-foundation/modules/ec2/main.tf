resource "aws_instance" "ec2" {
  for_each = {
    for inst in var.instances :
    inst.name => inst
  }

  ami                    = each.value.ami_id
  instance_type          = each.value.instance_type
  subnet_id              = var.subnet_map[each.value.availability_zone]
  availability_zone      = each.value.availability_zone
  vpc_security_group_ids = [var.security_group_id]
  key_name               = var.key_pair_name

  user_data = var.user_data_script

  tags = merge(
    {
      Name = each.key
    },
    {
      ManagedBy = "Terraform"
    }
  )
}
