variable "ami_id" {
  description = "AMI to use for EC2 instances"
}

variable "instance_type" {
  description = "EC2 instance type"
}

variable "subnet_id" {
  description = "Subnet to launch instance in"
}

variable "security_group_id" {
  description = "Security group for the instance"
}

variable "tfinstance_DB" {
  description = "Tag name for the database EC2 instance"
}

variable "tfinstance_web" {
  description = "Tag name for the web EC2 instance"
}

variable "public_key_path" {
  description = "Path to your SSH public key"
}

variable "key_pair_name" {
  description = "EC2 Key Pair name"
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
