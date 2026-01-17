resource "aws_vpc" "terraform_vpc" {
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.vpc_name
  }
}

resource "aws_subnet" "terraform_subnet_1" {
  vpc_id                  = aws_vpc.terraform_vpc.id
  cidr_block              = var.subnet_cidrs[0]
  availability_zone       = var.availability_zones[0]
  map_public_ip_on_launch = true  # Enable auto-assign public IPv4

  tags = {
    Name = "${var.subnet_name}-1"
  }
}

resource "aws_subnet" "terraform_subnet_2" {
  vpc_id                  = aws_vpc.terraform_vpc.id
  cidr_block              = var.subnet_cidrs[1]
  availability_zone       = var.availability_zones[1]
  map_public_ip_on_launch = true  # Enable auto-assign public IPv4

  tags = {
    Name = "${var.subnet_name}-2"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.terraform_vpc.id

  tags = {
    Name = var.igw_name
  }
}

resource "aws_route_table" "terraform_rt" {
  vpc_id = aws_vpc.terraform_vpc.id

  route {
    cidr_block = var.route_destination_cidr
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = var.route_table_name
  }
}

resource "aws_route_table_association" "terraform_rt_assoc_1" {
  subnet_id      = aws_subnet.terraform_subnet_1.id
  route_table_id = aws_route_table.terraform_rt.id
}

resource "aws_route_table_association" "terraform_rt_assoc_2" {
  subnet_id      = aws_subnet.terraform_subnet_2.id
  route_table_id = aws_route_table.terraform_rt.id
}

