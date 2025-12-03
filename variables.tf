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
    name = string
    image = object({
      id                 = string # github-repository-name/working-directory (if any)
      git_sha            = string # Image tag
      ecr_repository_uri = string # ECR Repository URI
    })
    essential = optional(bool, true)
    command   = optional(string)

    environment = optional(map(string), {})
    secrets     = optional(map(string), {})
    # For users providing SSM parameter arn directly
    secrets_from_ssm = optional(map(string), {})
    # Will be used in env_vars_to_ssm_parameters to create secure SSM parameters to be overwritten
    secrets_to_override = optional(map(string), {})

    cpu               = optional(number)
    memory_hard_limit = optional(number)
    memory_soft_limit = optional(number)

    port             = number
    protocol         = string,
    network_protocol = optional(string, "tcp")

    health_check = optional(any)

    extra_options = optional(any)
  })

  validation {
    condition     = var.application_container.image != null
    error_message = "application_container.image must be provided with a valid `vy_ecr_image` data source"
  }
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

variable "force_new_deployment" {
  description = "Whether to force a new deployment of the service. Required if you change from launch_type to capacity_provider_strategy or vice versa."
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
    test_listener_arn = string
    security_group_id = string

    conditions = list(object({
      path_pattern = optional(string)
      host_header  = optional(any)
      http_header = optional(object({
        name   = string
        values = list(string)
      }))
    }))
    # Additional conditions create new listener rules not covered by AND or OR logic for existing rules
    additional_conditions = optional(list(object({
      path_pattern = optional(string)
      host_header  = optional(any)
      http_header = optional(object({
        name   = string
        values = list(string)
      }))
    })), [])
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

variable "autoscaling_capacity" {
  description = "The min and max number of instances to scale to."
  type = object({
    min = number
    max = number
  })
  default = { min = 1, max = 1 }
}

variable "autoscaling_policies" {
  description = "Enable autoscaling for the service"
  type = list(object({
    target_value       = number
    policy_type        = optional(string, "TargetTrackingScaling") # Can be TargetTrackingScaling, StepScaling, or PredictiveScaling
    scale_in_cooldown  = optional(number)
    scale_out_cooldown = optional(number)

    # Target tracking options
    predefined_metric_type = optional(string) # https://docs.aws.amazon.com/autoscaling/application/APIReference/API_PredefinedMetricSpecification.html
    resource_label         = optional(string) # format is app/<load-balancer-name>/<load-balancer-id>/targetgroup/<target-group-name>/<target-group-id>

    # For custom metric specifications (target tracking)
    custom_metrics = optional(list(object({
      label       = string
      id          = string
      expression  = optional(string)
      return_data = optional(bool)
      metric_stat = optional(object({
        stat = string
        metric = object({
          metric_name = string
          namespace   = string
          dimensions  = list(object({ name = string, value = string }))
        })
      }))
    })))

    # Predictive Scaling options
    predictive_scaling_mode = optional(string, "ForecastOnly") # ForecastOnly or ForecastAndScale

    # Option 1: Use predefined metric pair (automatically handles load + scaling metrics)
    predefined_metric_pair_type = optional(string) # ECSServiceCPUUtilization, ECSServiceMemoryUtilization, ALBRequestCount

    # Option 2: Use separate predefined load and scaling metrics (for custom combinations)
    predefined_load_metric_type    = optional(string) # ECSServiceTotalCPUUtilization, ECSServiceTotalMemoryUtilization, TotalALBRequestCount
    predefined_scaling_metric_type = optional(string) # ECSServiceAverageCPUUtilization, ECSServiceAverageMemoryUtilization, ALBRequestCountPerTarget
  }))
  default = []
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

variable "wait_for_steady_state" {
  description = "Whether to wait for the ECS service to reach a steady state."
  type        = bool
  # Default true to avoid race conditions in GHA deployment workflows
  default = false
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
  description = "Runtime for Datadog auto instrumentation"
  type        = string
  default     = null

  validation {
    condition     = var.datadog_instrumentation_runtime == null || try(contains(["node", "jvm"], var.datadog_instrumentation_runtime), false)
    error_message = "The datadog_instrumentation_runtime must be either `node` or `jvm`."
  }
}

variable "datadog_options" {
  description = "Options for the Datadog Agent Extension"
  type = object({
    trace_startup_logs            = optional(bool)
    trace_partial_flush_min_spans = optional(number)
    profiling_enabled             = optional(bool)
    apm_enabled                   = optional(bool)
  })
  default = {
    trace_startup_logs            = false # Datadog default is true.
    trace_partial_flush_min_spans = 2000  # Datadog default is 1000.
    profiling_enabled             = false
    apm_enabled                   = true
    # We set 2000 so the smallest vCPU instances can handle it.
  }
}

variable "rollback_window_in_minutes" {
  description = "Time in minutes to wait before terminating the old tasks."
  type        = number

  default = 0
}

# Deployment variables
variable "deployment_controller_type" {
  description = "The type of deployment controller to use. Valid values are ECS, CODE_DEPLOY, EXTERNAL"
  type        = string
  default     = "ECS"

  validation {
    condition     = contains(["ECS", "CODE_DEPLOY", "EXTERNAL"], var.deployment_controller_type)
    error_message = "The deployment_controller_type must be one of: ECS, CODE_DEPLOY, EXTERNAL"
  }
}

variable "deployment_circuit_breaker" {
  description = "Configuration block for the deployment circuit breaker. If set, it will enable the circuit breaker for the service."
  type = object({
    enable   = bool
    rollback = bool
  })
  default = {
    enable   = true
    rollback = true
  }
}

variable "deployment_configuration_strategy" {
  description = "The deployment strategy to use for the service. Valid values are ROLLING, BLUE_GREEN"
  type        = string
  default     = "ROLLING"

  validation {
    condition     = contains(["ROLLING", "BLUE_GREEN"], var.deployment_configuration_strategy)
    error_message = "The deployment_strategy must be one of: ROLLING, BLUE_GREEN"
  }
}

variable "lifecycle_hooks" {
  description = "Configuration for lifecycle hooks."
  type = list(object({
    hook_target_arn  = string
    role_arn         = string
    lifecycle_stages = list(string)
  }))
  default = []
}

variable "datadog_environment_variables" {
  description = "Additonal environment variables to set for the Datadog Agent Extension"
  type        = map(string)
  default     = {}
}

variable "datadog_api_key_secret_arn" {
  description = "ARN of the Datadog API Key secret in AWS Secrets Manager"
  type        = string
  default     = null

  validation {
    condition     = var.datadog_api_key_secret_arn == null || can(regex("^arn:aws:secretsmanager:[a-z0-9-]+:[0-9]{12}:secret:[a-zA-Z0-9/_+=.@-]+$", var.datadog_api_key_secret_arn))
    error_message = "Datadog API Key must be a valid ARN of a secret in AWS Secrets Manager."
  }
}

variable "team_name_override" {
  description = "Override the team name tag for Datadog. If set, this will override the value from the SSM parameter."
  type        = string
  default     = null
}
