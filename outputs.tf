output "service_id" {
  description = "The ARN of the created service"
  value       = aws_ecs_service.service[0].id
}

output "service_name" {
  description = "The name of the created service"
  value       = aws_ecs_service.service[0].name
}

output "task_role_name" {
  description = "The name of the task role"
  value       = aws_iam_role.task.name
}

output "task_role_arn" {
  description = "The ARN of the task role"
  value       = aws_iam_role.task.arn
}

output "task_execution_role_name" {
  description = "The name of the task role"
  value       = aws_iam_role.execution.name
}

output "task_execution_role_arn" {
  description = "The ARN of the task role"
  value       = aws_iam_role.execution.arn
}

output "security_group_id" {
  description = "The ID of the service's security group"
  value       = length(aws_security_group.ecs_service) > 0 ? aws_security_group.ecs_service[0].id : 0
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
  description = "The ARNs of all primary target groups"
  value = tomap({
    for key, target_group in aws_lb_target_group.service : key => target_group.arn
  })
}

output "target_group_arn_suffixes" {
  description = "The ARN suffixes of all primary target groups"
  value = tomap({
    for key, target_group in aws_lb_target_group.service : key => target_group.arn_suffix
  })
}

output "secondary_target_group_arns" {
  description = "The ARNs of all secondary target groups"
  value = tomap({
    for key, target_group in aws_lb_target_group.secondary : key => target_group.arn
  })
}

output "secondary_target_group_arn_suffixes" {
  description = "The ARN suffixes of all secondary target groups"
  value = tomap({
    for key, target_group in aws_lb_target_group.secondary : key => target_group.arn_suffix
  })
}

output "cpu" {
  description = "How many vCPUs the task definition runs on"
  value       = var.cpu
}

output "memory" {
  description = "How much memory the task definition has"
  value       = var.memory
}
