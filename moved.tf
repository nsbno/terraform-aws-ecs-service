# For module version 3.0.0-rc7 -> 3.0.0-rc8
# Own module for autoscaling is no longer needed as we ignore changes to desired_count as
moved {
  from = aws_ecs_service.service_with_autoscaling[0]
  to   = aws_ecs_service.service
}
