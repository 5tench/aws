# From EC2 module
output "web_public_ip" {
  value = module.ec2_instances.web_public_ip
}

output "web_instance_id" {
  value = module.ec2_instances.web_instance_id
}

output "db_instance_id" {
  value = module.ec2_instances.db_instance_id
}

# From VPC module
output "subnet_id_1" {
  value = module.vpc.subnet_id_1
}

output "subnet_id_2" {
  value = module.vpc.subnet_id_2
}

output "subnet_ids" {
  value = module.vpc.subnet_ids
}

output "vpc_id" {
  value = module.vpc.vpc_id
}

# From SG module
output "sg_id" {
  value = module.sg.sg_id
}

# From RDS module
output "rds_endpoint" {
  value = module.rds.rds_endpoint
}
