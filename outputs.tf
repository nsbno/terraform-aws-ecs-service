output "service_id" {
  description = "The ARN of the created service"
  value       = aws_ecs_service.service.id
}

output "task_role_name" {
  description = "The name of the task role"
  value       = aws_iam_role.task.arn
}

output "task_role_arn" {
  description = "The ARN of the task role"
  value       = aws_iam_role.task.arn
}

output "log_group_arn" {
  description = "The ARN of the service's log group"
  value       = aws_cloudwatch_log_group.main.arn
}

output "log_group_name" {
  description = "The name of the service's log group"
  value       = aws_cloudwatch_log_group.main.name
}

output "target_group_arns" {
  description = "The ARNs of all created target groups"
  value       = tomap({
    for key, target_group in aws_lb_target_group.service : key => target_group.arn
  })
}

output "target_group_arn_suffixes" {
  description = "The ARNs of all created target groups"
  value       = tomap({
    for key, target_group in aws_lb_target_group.service : key => target_group.arn_suffix
  })
}
