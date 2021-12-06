variable "name_prefix" {
  description = "A prefix used for naming resources."
  type        = string
}

variable "vpc_id" {
  description = "The VPC ID."
  type        = string
}

variable "cluster_id" {
  description = "The Amazon Resource Name (ARN) that identifies the cluster."
  type        = string
}

variable "application_container" {
  description = "The application that is being run by the service"
  type = map(any)
}

variable "sidecar_containers" {
  description = "Sidecars for the main application"
  type = list(map(any))
  default = []
}

variable "launch_type" {
  description = "What to launch the instance on."
  type        = string
  default     = "FARGATE"

  validation {
    condition = contains(["EC2", "FARGATE", "EXTERNAL"], var.launch_type)
    error_message = "The launch_type must be either \"EC2\", \"FARGATE\" or \"EXTERNAL\"."
  }
}

variable "cpu" {
  description = "The amount of cores that are required for the service"
  type = number
  default = 256
}

variable "memory" {
  description = "The amount of memory that is required for the service"
  type = number
  default = 512
}

variable "target_groups" {
  description = "Number of target groups to create"
  type = set(string)
  default = ["main"]
}

variable "lb_health_check" {
  description = "Health checks to verify that the container is running properly"
  type = object({})
  default = null
}

variable "private_subnet_ids" {
  description = "A list of private subnets inside the VPC"
  type        = list(string)
  default     = null
}

variable "desired_count" {
  description = "The number of instances of the task definitions to place and keep running."
  type        = number
  default     = 1
}

variable "assign_public_ip" {
  description = "Assigned public IP to the container."
  type        = bool
  default     = false
}

variable "log_retention_in_days" {
  description = "Number of days the logs will be retained in CloudWatch."
  type        = number
  default     = 30
}

variable "health_check_grace_period_seconds" {
  description = "Seconds to ignore failing load balancer health checks on newly instantiated tasks to prevent premature shutdown, up to 7200. Only valid for services configured to use load balancers."
  type        = number
  default     = 300
}

variable "tags" {
  description = "A map of tags (key-value pairs) passed to resources."
  type        = map(string)
  default     = {}
}

variable "deployment_minimum_healthy_percent" {
  default     = 50
  type        = number
  description = "The lower limit of the number of running tasks that must remain running and healthy in a service during a deployment"
}

variable "deployment_maximum_percent" {
  default     = 200
  type        = number
  description = "The upper limit of the number of running tasks that can be running in a service during a deployment"
}

variable "deployment_controller_type" {
  description = "Type of deployment controller. Valid values: CODE_DEPLOY, ECS."
  type        = string
  default     = "ECS"
}

variable "wait_for_steady_state" {
  description = "Whether to wait for the ECS service to reach a steady state."
  type        = bool
  default     = false
}

variable "task_deregistration_delay" {
  description = "The amount time for Elastic Load Balancing to wait before changing the state of a deregistering target from draining to unused."
  type        = number
  default     = null
}
