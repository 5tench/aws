resource "aws_iam_policy" "rds_limited" {
  name        = "TerraformRDSLimitedAccess"
  description = "Least-privilege RDS access for Terraform"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid    = "AllowSpecificRDSActions",
        Effect = "Allow",
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
        ],
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy_attachment" "attach_rds_policy" {
  user       = var.iam_user_name
  policy_arn = aws_iam_policy.rds_limited.arn
}
