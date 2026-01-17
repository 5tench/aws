resource "aws_key_pair" "this" {
  key_name   = var.key_pair_name
  public_key = file(var.public_key_path)
}

resource "aws_instance" "db" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  key_name               = aws_key_pair.this.key_name

  tags = {
    Name = var.tfinstance_DB
  }
}

resource "aws_instance" "web" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [var.security_group_id]
  user_data              = var.tfinstance_web_startup_script
  key_name               = aws_key_pair.this.key_name

  tags = {
    Name = var.tfinstance_web
  }
}

resource "aws_eip" "web_eip" {
  instance = aws_instance.web.id
}
