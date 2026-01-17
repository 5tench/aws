# EC2 instance outputs
output "instance_ids" {
  description = "Map of EC2 instance names to their instance IDs"
  value = {
    for name, inst in aws_instance.ec2 :
    name => inst.id
  }
}

output "instance_public_ips" {
  description = "Map of EC2 instance names to their public IPs"
  value = {
    for name, inst in aws_instance.ec2 :
    name => inst.public_ip
  }
}

output "instance_private_ips" {
  description = "Map of EC2 instance names to their private IPs"
  value = {
    for name, inst in aws_instance.ec2 :
    name => inst.private_ip
  }
}

output "instances_detailed" {
  description = "Detailed information about all EC2 instances"
  value = {
    for name, inst in aws_instance.ec2 :
    name => {
      id           = inst.id
      public_ip    = inst.public_ip
      private_ip   = inst.private_ip
      availability_zone = inst.availability_zone
    }
  }
}

