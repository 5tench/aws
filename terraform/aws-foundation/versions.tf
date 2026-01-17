terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.20"
    }
  }
}


provider "aws" {
  profile = var.aws_profile
  region = var.region # Configuration options
}

