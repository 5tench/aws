# modules/iam/main.tf

# ---- RDS user ----
resource "aws_iam_user" "rds_user" {
  name = var.rds_user_name
}

resource "aws_iam_policy" "rds_limited" {
  name        = "TerraformRDSLimitedAccess"
  description = "Least-privilege RDS access for Terraform"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowSpecificRDSActions"
        Effect = "Allow"
        Action = [
          "rds:CreateDBInstance",
          "rds:DeleteDBInstance",
          "rds:DescribeDBInstances",
          "rds:ModifyDBInstance",
          "rds:CreateDBSubnetGroup",
          "rds:DescribeDBSubnetGroups",
          "rds:DeleteDBSubnetGroup",
          "rds:AddTagsToResource",
          "rds:ListTagsForResource"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_rds_policy" {
  user       = var.rds_user_name
  policy_arn = aws_iam_policy.rds_limited.arn
}

# ---- EC2 / SSM user policy ----

resource "aws_iam_user" "ec2_user" {
  name = var.ec2_user_name
}

resource "aws_iam_policy" "ec2_ssm_access" {
  name        = "TerraformEC2SSMAccess"
  description = "Allow EC2 Session Manager access"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "ssm:DescribeInstanceInformation",
          "ssm:GetConnectionStatus",
          "ssm:DescribeSessions",
          "ssm:StartSession",
          "ssm:TerminateSession"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_ec2_policy" {
  user       = var.ec2_user_name
  policy_arn = aws_iam_policy.ec2_ssm_access.arn
}

