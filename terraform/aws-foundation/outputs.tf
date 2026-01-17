output "vpc_id" {
  value = module.vpc.vpc_id
}

output "subnet_ids" {
  value = [
    module.vpc.subnet_id_1,
    module.vpc.subnet_id_2
  ]
}

output "security_group_id" {
  value = module.sg.sg_id
}

output "ec2_instances" {
  value = module.ec2.instances_detailed
}

output "load_balancer_dns" {
  value = module.alb.lb_dns
}

output "rds_policy_arn" {
  value = module.iam.rds_policy_arn
}

output "rds_policy_user" {
  value = module.iam.rds_policy_user
}

output "ec2_policy_arn" {
  value = module.iam.ec2_policy_arn
}

output "ec2_policy_user" {
  value = module.iam.ec2_policy_user
}

output "ec2_public_ips" {
  value = module.ec2.instance_public_ips
}
