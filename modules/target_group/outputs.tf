output "target_group_arn" {
  value = aws_lb_target_group.tg.arn
}

output "target_group_arn_suffix" {
  value = aws_lb_target_group.tg.arn_suffix
}
