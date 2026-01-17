output "lb_arn" {
  description = "ARN of the Application Load Balancer"
  value       = aws_lb.app_lb.arn
}

output "lb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  value       = aws_lb.app_lb.dns_name
}

output "lb_dns" {
  description = "Compatibility output: DNS name of the ALB (alias for lb_dns_name)"
  value       = aws_lb.app_lb.dns_name
}

output "lb_security_groups" {
  description = "Security group IDs attached to the ALB"
  value       = aws_lb.app_lb.security_groups
}

output "target_group_arn" {
  description = "ARN of the target group"
  value       = aws_lb_target_group.tg.arn
}

output "target_group_name" {
  description = "Name of the target group"
  value       = aws_lb_target_group.tg.name
}

output "listener_arn" {
  description = "ARN of the ALB listener"
  value       = aws_lb_listener.http.arn
}
