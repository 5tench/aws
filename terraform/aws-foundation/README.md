# AWS Terraform Infrastructure Project

This project provisions a simple AWS infrastructure using Terraform. It follows a modular structure for better scalability and maintainability.

## 📦 Modules Used

- **VPC**: Creates a VPC with two public subnets across different availability zones, an internet gateway, and a route table.
- **Security Group**: Configures a security group to allow web traffic (HTTP/HTTPS).
- **EC2**: Launches web and database EC2 instances with appropriate tags and startup scripts.
- **RDS**: Provisions a MySQL RDS instance with a DB subnet group spanning two AZs.
- **IAM**: Manages IAM policy/permissions for Terraform user access to RDS resources.

## 🔧 Prerequisites

- Terraform installed
- AWS CLI configured (`~/.aws/credentials`)
- AWS IAM user with appropriate permissions
- Public SSH key available locally

## 🚀 How to Use

1. Clone the repo  
   `git clone https://github.com/yourusername/your-repo-name.git`

2. Change into the project directory  
   `cd your-repo-name`

3. Initialize Terraform  
   `terraform init`

4. Review the execution plan  
   `terraform plan`

5. Apply the configuration  
   `terraform apply`

## 📤 Outputs

After successful deployment, the following outputs are provided:
- Web EC2 public IP
- RDS endpoint
- Subnet IDs
- VPC ID
- Security group ID
- EC2 instance IDs

## 📁 File Structure
