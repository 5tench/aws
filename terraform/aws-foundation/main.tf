# ===== VPC =====
module "vpc" {
  source                       = "./modules/vpc"
  vpc_name                     = var.vpc_name
  vpc_cidr                     = var.vpc_cidr
  subnet_name                  = var.subnet_name
  subnet_cidrs                 = var.subnet_cidrs
  availability_zones           = var.availability_zones
  igw_name                     = var.igw_name
  route_table_name             = var.route_table_name
  route_destination_cidr       = var.route_destination_cidr
  route_table_association_name = var.route_table_association_name
}

# ===== SG =====
module "sg" {
  source           = "./modules/sg"
  vpc_id           = module.vpc.vpc_id # this should match output from VPC module
  sg_name          = var.sg_name
  sg_description   = var.sg_description
  sg_ingress_rules = var.sg_ingress_rules
  sg_egress_rules  = var.sg_egress_rules
}

# === KEY PAIR (GLOBAL) ===
resource "aws_key_pair" "tf_admin" {
  key_name   = "tf_admin-key"
  public_key = file("${path.module}/scripts/tf_admin-key.pub")
}

# ===== EC2 =====
module "ec2" {
  source             = "./modules/ec2"

  vpc_id             = module.vpc.vpc_id
  subnet_ids         = module.vpc.subnet_ids
  availability_zones = module.vpc.availability_zones
  subnet_map         = zipmap(var.availability_zones, module.vpc.subnet_ids)

  instances          = var.instances
  security_group_id  = module.sg.sg_id


  key_pair_name     = aws_key_pair.tf_admin.key_name
  user_data_script  = file(var.bootstrap_script_path)
}

# ===== ALB =====
module "alb" {
  source            = "./modules/alb"
  lb_name           = var.lb_name
  target_group_name = var.target_group_name
  vpc_id            = module.vpc.vpc_id
  subnet_ids        = module.vpc.subnet_ids
  security_group_id = module.sg.sg_id
  instances         = module.ec2.instances_detailed
  target_port       = var.target_port
}

# ===== RDS =====
module "rds" {
  source                 = "./modules/rds"
  db_instance_name       = var.db_instance_name
  allocated_storage      = var.allocated_storage
  engine                 = var.engine
  engine_version         = var.engine_version
  instance_class         = var.instance_class
  db_name                = var.db_name
  username               = var.username
  password               = var.password
  parameter_group_name   = var.parameter_group_name
  db_subnet_group_name   = var.db_subnet_group_name
  subnet_ids             = module.vpc.subnet_ids
  vpc_security_group_ids = [module.sg.sg_id]
  publicly_accessible    = var.publicly_accessible
  skip_final_snapshot    = var.skip_final_snapshot
  tfinstance_DB          = var.tfinstance_DB
}

# ===== IAM =====
module "iam" {
  source        = "./modules/iam"
  rds_user_name = var.rds_user_name
  ec2_user_name = var.ec2_user_name
}


