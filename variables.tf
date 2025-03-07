variable "service_name" {
  description = "Name of the ECS service."
  type        = string
}

variable "vpc_id" {
  description = "The VPC ID."
  type        = string
  default     = null
}

variable "cluster_id" {
  description = "The Amazon Resource Name (ARN) that identifies the cluster."
  type        = string
}

variable "application_container" {
  description = "The application that is being run by the service"
  type = object({
    name      = string
    image     = string
    essential = optional(bool, true)
    command   = optional(string)

    environment = optional(map(string), {})
    secrets     = optional(map(string), {})

    cpu               = optional(number)
    memory_hard_limit = optional(number)
    memory_soft_limit = optional(number)

    port             = number
    protocol         = string,
    network_protocol = optional(string, "tcp")

    health_check = optional(any)

    extra_options = optional(any)
  })
}

variable "sidecar_containers" {
  description = "Sidecars for the main application"
  type = list(object({
    name      = string
    image     = string
    essential = optional(bool, true)
    command   = optional(string)

    environment = optional(map(string))
    secrets     = optional(map(string))

    cpu               = optional(number)
    memory_hard_limit = optional(number)
    memory_soft_limit = optional(number)

    port             = optional(number)
    protocol         = optional(string)
    network_protocol = optional(string, "tcp")

    health_check = optional(any)

    extra_options = optional(any)
  }))
  default = []
}

variable "launch_type" {
  description = "What to launch the instance on. Mutually exclusive with \"use_spot\"."
  type        = string
  default     = "FARGATE"

  validation {
    condition     = contains(["EC2", "FARGATE", "EXTERNAL"], var.launch_type)
    error_message = "The launch_type must be either \"EC2\", \"FARGATE\" or \"EXTERNAL\"."
  }
}

variable "ecs_service_timeouts" {
  description = <<EOF
  Default 20m. The timeouts for terraform update of the ECS service. If adjusted down, remember to also adjust health_check_grace_period_seconds.
  Normally this should allow the ECS to at least do one retry of starting the container before timing out. The timeout is the whole rollout, not only the container startup.
  I.e. health_check_grace_period_seconds * 2 + a bit extra > ecs_service_timeouts. 
  EOF
  type = object({
    create = optional(string, null)
    update = optional(string, null)
    delete = optional(string, null)
  })
  default = {
    create = "20m"
    update = "20m"
    delete = "20m"
  }
}

variable "use_spot" {
  description = "NB! NOT RECOMMENDED FOR PROD. Whether to use spot instances for the service. Requirement: FARGATE_SPOT enabled capacity providers. Mutually exclusive with \"launch_type\"."
  type        = bool
  default     = false
}

variable "cpu" {
  description = "The amount of cores that are required for the service"
  type        = number
  default     = 256
}

variable "memory" {
  description = "The amount of memory that is required for the service"
  type        = number
  default     = 512
}

variable "lb_listeners" {
  description = "Configuration for load balancing. Note: each condition needs to be wrapped in a separate block"
  type = list(object({
    listener_arn      = string
    security_group_id = string

    conditions = list(object({
      path_pattern = optional(string)
      host_header  = optional(any)
      http_header = optional(object({
        name   = string
        values = list(string)
      }))
    }))
  }))
  default = []
}

variable "placement_constraints" {
  description = "Placement constraints for the service. Note: A maximum of 10 placement constraints may be added to a service. Used to force deployment to specific instances. Not valid for FARGATE launch type."
  type = list(object({
    type       = string
    expression = optional(string)
  }))
  default = []
}

variable "lb_deregistration_delay" {
  description = "The amount time for Elastic Load Balancing to wait before changing the state of a deregistering target from draining to unused."
  type        = number
  default     = null
}

variable "lb_health_check" {
  description = "Health checks to verify that the container is running properly"
  type        = any
  default     = {}
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

variable "autoscaling" {
  description = "Enable autoscaling for the service"
  type = object({
    min_capacity       = number
    max_capacity       = number
    metric_type        = string
    target_value       = string
    scale_in_cooldown  = optional(number, null) # in seconds
    scale_out_cooldown = optional(number, null) # in seconds
  })
  default = null
}

variable "autoscaling_resource_label" {
  description = "Must be set if autoscaling metric type is ALBRequestCountPerTarget. Value must be equal to lb.arn_suffix/target_group.arn_suffix. Example: app/lb-name/lb-id/targetgroup/targetgroup-name/target-group-id"
  type        = string
  default     = ""
}

variable "autoscaling_schedule" {
  description = <<-EOF
    Schedules for changes in the minimum and maximum capacity of the service.
    To learn more, check out the AWS documentation about scheduled autoscaling.
    This also requires that the autoscaling variable is set.
  EOF
  type = object({
    # The timezone could be a separate variable, but I think it is better to get
    # everyone to explicitly set it to be aware of what timezone we're working with.
    # Especially since we only operate in Norway, this is often going to be set to
    # Europe/Oslo, which might have it's own downsides during DST.
    #
    # Setting this to Europe/Oslo implicitly might break some assumptions,
    # and not setting it might also break some assumptions.
    #
    # Thus, we end up making everyone setting it explicilty
    timezone = string
    schedules = list(object({
      schedule     = string
      min_capacity = string
      max_capacity = string
    }))
  })
  default = {
    timezone  = "Europe/Oslo"
    schedules = []
  }
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

variable "propagate_tags" {
  description = "Whether to propagate tags from the service or the task definition to the tasks. Valid values are SERVICE, TASK_DEFINITION or NONE"
  type        = string
  default     = "SERVICE"
}

variable "enable_execute_command" {
  description = "Specifies whether to enable Amazon ECS Exec for the tasks within the service."
  type        = bool
  default     = false
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

variable "xray_daemon" {
  description = "Should a OpenTelemetry Collector for X-Ray be attached to the service?"
  type        = bool
  default     = false
}

variable "xray_daemon_config_path" {
  description = "The config file to use for the X-Ray exporter sidecar. Should be one of the files found here: https://github.com/aws-observability/aws-otel-collector/tree/main/config/ecs."
  type        = string
  default     = "ecs-xray.yaml"
}

variable "custom_metrics" {
  description = "The custom metrics for autoscaling. Check https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/appautoscaling_policy#create-target-tracking-scaling-policy-using-metric-math for more information."
  type = list(object({
    label      = string
    id         = string
    expression = optional(string)
    metric_stat = optional(object({
      metric = object({
        metric_name = string
        namespace   = string
        dimensions = list(object({
          name  = string
          value = string
        }))
      })
      stat = string
    }))
    return_data = bool
  }))
  default = []
}

variable "lb_stickiness" {
  description = "Bind a user's session to a specific target"
  nullable    = false
  type = object({
    type            = string
    enabled         = optional(bool, null)
    cookie_duration = optional(number, null)
    cookie_name     = optional(string, null)
  })
  default = {
    type            = "lb_cookie"
    enabled         = false
    cookie_duration = 86400 # 24h in seconds
  }
}

# DATADOG SETUP
variable "enable_datadog" {
  description = "Enable Datadog for the service"
  type        = bool
  default     = false
}

variable "datadog_instrumentation_runtime" {
  description = "Runtime for autoinstrumentation. Valid values: `node` or `jvm`"
  type        = string
  default     = null
}

variable "datadog_options" {
  description = "Options for the Datadog Lambda Extension"
  type = object({
    trace_startup_logs            = optional(bool)
    trace_partial_flush_min_spans = optional(number)
  })
  default = {
    trace_startup_logs            = false
    trace_partial_flush_min_spans = 1000
  }
}
