# modules/iam/outputs.tf

# RDS
output "rds_policy_arn" {
  description = "ARN of the RDS IAM policy"
  value       = aws_iam_policy.rds_limited.arn
}

output "rds_policy_user" {
  description = "User attached to the RDS IAM policy"
  value       = aws_iam_user_policy_attachment.attach_rds_policy.user
}

# EC2 / SSM
output "ec2_policy_arn" {
  description = "ARN of the EC2/SSM IAM policy"
  value       = aws_iam_policy.ec2_ssm_access.arn
}

output "ec2_policy_user" {
  description = "User attached to the EC2 IAM policy"
  value       = aws_iam_user_policy_attachment.attach_ec2_policy.user
}

