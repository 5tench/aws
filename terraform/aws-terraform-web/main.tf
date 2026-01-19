module "vpc" {
  source                         = "./modules/vpc"
  vpc_name                       = var.vpc_name
  vpc_cidr                       = var.vpc_cidr
  subnet_name                    = var.subnet_name
  subnet_cidr_1                  = var.subnet_cidr_1
  subnet_cidr_2                  = var.subnet_cidr_2
  availability_zones             = var.availability_zones
  igw_name                       = var.igw_name
  tfroute                        = var.tfroute
  tfroute_destination_cidr       = var.tfroute_destination_cidr
  tfroute_table_association_name = var.tfroute_table_association_name
}

module "sg" {
  source                   = "./modules/sg"
  terraform_sg             = var.terraform_sg
  terraform_sg_description = var.terraform_sg_description
  ip_protocol              = var.ip_protocol
  application_protocols    = var.application_protocols
  ingress_description      = var.ingress_description
  egress_description       = var.egress_description
  ingress_rules            = var.ingress_rules
  egress_rules             = var.egress_rules
  vpc_id                   = module.vpc.vpc_id
}

module "ec2_instances" {
  source = "./modules/ec2"

  ami_id                        = var.ami_id
  instance_type                 = var.instance_type
  subnet_id                     = module.vpc.subnet_id_1
  security_group_id             = module.sg.sg_id
  tfinstance_DB                 = var.tfinstance_DB
  tfinstance_web                = var.tfinstance_web
  tfinstance_web_startup_script = var.tfinstance_web_startup_script
  public_key_path               = var.public_key_path
  key_pair_name                 = var.key_pair_name
}

module "iam" {
  source        = "./modules/iam"
  iam_user_name = var.iam_user_name
}

module "rds" {
  source = "./modules/rds"

  allocated_storage      = var.allocated_storage
  engine                 = var.engine
  engine_version         = var.engine_version
  instance_class         = var.instance_class
  db_name                = var.db_name
  username               = var.username
  password               = var.password
  parameter_group_name   = var.parameter_group_name
  db_subnet_group_name   = var.db_subnet_group_name
  vpc_security_group_ids = [module.sg.sg_id]
  publicly_accessible    = var.publicly_accessible
  skip_final_snapshot    = var.skip_final_snapshot
  db_instance_name       = var.tfinstance_DB
  tfinstance_DB          = var.tfinstance_DB

  subnet_ids = [module.vpc.subnet_id_1, module.vpc.subnet_id_2]
}


