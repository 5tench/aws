variable "region" {
  description = "AWS region to deploy resources in"
  type        = string
}

variable "availability_zones" {
  description = "Availability zones for subnets"
  type        = list(string)
  default     = ["us-east-2a", "us-east-2b"]
}

variable "vpc_name" {
  description = "Name tag for the VPC"
  type        = string
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
}

variable "subnet_name" {
  description = "Name tag for the subnet"
  type        = string
}

variable "subnet_cidr_1" {
  description = "CIDR block for the first subnet"
  type        = string
}

variable "subnet_cidr_2" {
  description = "CIDR block for the second subnet"
  type        = string
}

variable "igw_name" {
  description = "Name tag for the Internet Gateway"
  type        = string
}

variable "tfroute" {
  description = "Name tag for the route table"
  type        = string
}

variable "tfroute_destination_cidr" {
  description = "Destination CIDR block for the default route"
  type        = string
}

variable "tfroute_table_association_name" {
  description = "Name tag for the route table association"
  type        = string
}

variable "ami_id" {
  description = "AMI to use for EC2 instances"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
}

variable "allocated_storage" {
  description = "The allocated storage in gigabytes"
  type        = number
  default     = 20
}

variable "engine" {
  description = "The database engine (e.g., mysql, postgres)"
  type        = string
  default     = "mysql"
}

variable "engine_version" {
  description = "The version of the database engine"
  type        = string
  default     = "8.0"
}

variable "instance_class" {
  description = "The instance class of the RDS instance"
  type        = string
  default     = "db.t3.micro"
}

variable "iam_user_name" {
  description = "The IAM user name for Terraform"
  type        = string
  default     = "terraform-user"
}

variable "db_name" {
  description = "The database name"
  type        = string
  default     = "mydatabase"
}

variable "username" {
  description = "Master username for the database"
  type        = string
  default     = "admin"
}

variable "password" {
  description = "Master password for the database"
  type        = string
  sensitive   = true
}

variable "parameter_group_name" {
  description = "DB parameter group name"
  type        = string
  default     = null
}

variable "db_subnet_group_name" {
  description = "Subnet group name for the RDS instance"
  type        = string
  default     = "my-db-subnet-group"
}

variable "vpc_security_group_ids" {
  description = "List of security group IDs to assign to the RDS instance"
  type        = list(string)
  default     = []
}

variable "publicly_accessible" {
  description = "Whether the RDS instance is publicly accessible"
  type        = bool
  default     = false
}

variable "skip_final_snapshot" {
  description = "Skip final snapshot when deleting the RDS instance"
  type        = bool
  default     = true
}

variable "tfinstance_DB" {
  description = "Name tag for the RDS instance"
  type        = string
  default     = "terraform-rds"
}

variable "tfinstance_web" {
  description = "Tag name for the web EC2 instance"
  type        = string
}

variable "terraform_sg" {
  description = "Security group name"
  type        = string
}

variable "terraform_sg_description" {
  description = "Description for security group"
  type        = string
}

variable "ip_protocol" {
  description = "Protocol for traffic rules"
  type        = string
}

variable "application_protocols" {
  description = "List of protocols to allow (http, https)"
  type        = list(string)
}

variable "ingress_description" {
  description = "Ingress rule description"
  type        = string
}

variable "egress_description" {
  description = "Description for outbound traffic"
  type        = string
}

variable "ingress_rules" {
  description = "Map of ingress rules and their ports"
  type        = map(number)
}

variable "egress_rules" {
  description = "Map of egress rules and their ports"
  type        = map(number)
}

variable "tfinstance_web_startup_script" {
  description = "Inline startup script for web instance"
  type        = string
  default     = <<-EOF
    #!/bin/bash
    sudo yum update -y
    sudo yum install -y httpd mod_ssl
    sudo systemctl start httpd
    sudo systemctl enable httpd
    echo "<h1>Hello from Terraform</h1>" | sudo tee /var/www/html/index.html
    sudo mkdir /etc/httpd/ssl
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
      -keyout /etc/httpd/ssl/selfsigned.key \
      -out /etc/httpd/ssl/selfsigned.crt \
      -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=example.com"
    sudo bash -c 'cat > /etc/httpd/conf.d/ssl.conf <<EOL
    <VirtualHost *:443>
        ServerName localhost
        DocumentRoot /var/www/html
        SSLEngine on
        SSLCertificateFile /etc/httpd/ssl/selfsigned.crt
        SSLCertificateKeyFile /etc/httpd/ssl/selfsigned.key
    </VirtualHost>
    EOL'
    sudo systemctl restart httpd
  EOF
}

variable "public_key_path" {
  description = "Path to your SSH public key"
  type        = string
}

variable "key_pair_name" {
  description = "EC2 Key Pair name"
  type        = string
}
