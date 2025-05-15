variable "service_name" {
  description = "Name of service. Used to name the resources."
  type        = string
}

variable "cluster_name" {
  description = "ECS cluster name"
  type        = string
}

variable "ecr_image_base" {
  description = "ECR image base"
  type        = string
}

variable "deployment_group_name" {
  description = "CodeDeploy Deployment group name"
  type        = string
}

variable "deployment_config_name" {
  description = "CodeDeploy Deployment Config name"
  type        = string
  default     = "CodeDeployDefault.ECSAllAtOnce"
}

variable "old_tasks_termination_wait_time" {
  description = "Old ECS task termination wait time in minutes"
  type        = number

  default = 0
}

variable "alb_prod_listener_arn" {
  description = "Arn of ALB Prod listener"
  type        = string
}

variable "alb_test_listener_arn" {
  description = "Arn of ALB Prod listener"
  type        = string
}

variable "alb_blue_target_group_name" {
  description = "ALB Blue target group name"
  type        = string
}

variable "alb_green_target_group_name" {
  description = "ALB Green target group name"
  type        = string
}

variable "application_container_port" {
  description = "Port of the application container"
  type        = number
}
