/*
 * ECS Service
 */

locals {
  xray_container = var.xray_daemon == true ? [
    {
      name      = "aws-otel-collector",
      image     = "amazon/aws-otel-collector",
      command   = ["--config=/etc/ecs/${var.xray_daemon_config_path}"]
      essential = true
    }
  ] : []

  # The account alias includes the name of the environment we are in as a suffix
  split_alias       = split("-", data.aws_iam_account_alias.this.account_alias)
  environment_index = length(local.split_alias) - 1
  environment       = local.split_alias[local.environment_index]

  datadog_containers = var.enable_datadog == true ? [
    {
      name = "datadog-agent",

      // Best case, we could pin this agent to an EXACT version, but it is too difficult to maintain
      // and would've become a real pain for the users of this module, having to constantly upgrade.
      // Therefore we lock it to a major version, reducing the risk of unexpected compatibility problems,
      // while ensuring that these agents are running the latest (patched) version.
      //
      // Consider to revisit this approach in the future.
      image     = "public.ecr.aws/datadog/agent:7",
      essential = true,

      environment = merge({
        ECS_FARGATE = "true"

        DD_SITE = "datadoghq.eu"

        DD_SERVICE = var.dd_service_name_override != null ? var.dd_service_name_override : var.service_name
        DD_ENV     = local.environment
        DD_TAGS    = local.team_name_tag

        DD_APM_ENABLED            = local.datadog_options.apm_enabled
        DD_APM_FILTER_TAGS_REJECT = "http.useragent:ELB-HealthChecker/2.0 user_agent:ELB-HealthChecker/2.0"
        # Reject anything ending in /health
        DD_APM_FILTER_TAGS_REGEX_REJECT = "http.url:.*\\/health$"
        DD_ECS_TASK_COLLECTION_ENABLED  = "true"

        # DATADOG Startup
        DD_TRACE_STARTUP_LOGS            = local.datadog_options.trace_startup_logs
        DD_TRACE_PARTIAL_FLUSH_MIN_SPANS = local.datadog_options.trace_partial_flush_min_spans
      }, var.datadog_environment_variables),
      secrets = {
        DD_API_KEY = local.datadog_api_key_secret
      }
      health_check = {
        command     = ["CMD-SHELL", "agent health"]
        interval    = 10
        timeout     = 5
        retries     = 3
        startPeriod = 15
      }
    },
    {
      name      = "log-router",
      image     = "public.ecr.aws/aws-observability/aws-for-fluent-bit:stable",
      essential = true,

      extra_options = {
        firelensConfiguration = {
          type = "fluentbit",
          options = {
            enable-ecs-log-metadata = "true",
            config-file-type        = "file",
            config-file-value       = "/fluent-bit/configs/parse-json.conf"
          }
        }
        # Bug: To avoid recreation of the task definition: https://github.com/hashicorp/terraform-provider-aws/pull/41394
        user = "0"
      }
    }
  ] : null
}

locals {
  existing_java_tool_options = lookup(var.application_container.environment, "JAVA_TOOL_OPTIONS", "")
  existing_node_options      = lookup(var.application_container.environment, "NODE_OPTIONS", "")

  # Filter out runtime-specific options from environment variables to avoid duplication
  # These will be handled by autoinstrumentation module with appended values
  filtered_environment_variables = var.datadog_instrumentation_runtime == null ? var.application_container.environment : {
    for k, v in var.application_container.environment : k => v
    if !contains(["JAVA_TOOL_OPTIONS", "NODE_OPTIONS"], k)
  }

  // A bit hacky. We're basically replicating var.datadog_options
  // but ensuring that if the user has only partially specified the properties under var.datadog_options
  // we will use the default values for the non-specified ones.
  //
  // If not, all non-specified values becomes `null`. Which we don't want.
  datadog_options = {
    trace_startup_logs            = coalesce(var.datadog_options.trace_startup_logs, false)           # Datadog default is true.
    trace_partial_flush_min_spans = coalesce(var.datadog_options.trace_partial_flush_min_spans, 2000) # Datadog default is 1000.
    profiling_enabled             = coalesce(var.datadog_options.profiling_enabled, false)
    apm_enabled                   = coalesce(var.datadog_options.apm_enabled, true)

    app_protection_enabled                = coalesce(var.datadog_options.app_protection_enabled, false)
    runtime_code_analysis                 = coalesce(var.datadog_options.runtime_code_analysis, false)
    runtime_software_composition_analysis = coalesce(var.datadog_options.runtime_software_composition_analysis, false)
  }
}

module "autoinstrumentation_setup" {
  source = "./modules/autoinstrumentation_setup"

  count = var.datadog_instrumentation_runtime == null ? 0 : 1

  datadog_instrumentation_runtime = var.datadog_instrumentation_runtime

  dd_service           = var.dd_service_name_override != null ? var.dd_service_name_override : var.service_name
  dd_env               = local.environment
  dd_team_tag          = local.team_name_tag
  dd_profiling_enabled = local.datadog_options.profiling_enabled

  dd_runtime_code_analysis                 = local.datadog_options.runtime_code_analysis
  dd_runtime_software_composition_analysis = local.datadog_options.runtime_software_composition_analysis
  dd_app_protection                        = local.datadog_options.app_protection_enabled

  existing_java_tool_options = local.existing_java_tool_options
  existing_node_options      = local.existing_node_options
}

module "env_vars_to_ssm_parameters" {
  source = "./modules/env_vars_to_ssm_parameters"

  // Temporary measure. We need the ability to not create this in a future change.
  // Opening the possibility up now, so that we can enable it without destructive changes
  count = true ? 1 : 0

  service_name           = var.service_name
  task_execution_role_id = aws_iam_role.execution.id

  # Use filtered environment variables (runtime options excluded when using autoinstrumentation)
  environment_variables = local.filtered_environment_variables
  secrets               = var.application_container.secrets
  secrets_to_override   = var.application_container.secrets_to_override
  secrets_from_ssm      = var.application_container.secrets_from_ssm
}

// TODO(fredrik) Remove this moved block in the next release
moved {
  from = module.env_vars_to_ssm_parameters
  to   = module.env_vars_to_ssm_parameters[0]
}

locals {
  # Override application container keys
  application_container_with_overrides = merge(var.application_container, {
    image = "${var.application_container.image.ecr_repository_uri}:${var.application_container.image.git_sha}"
    # Environment vars are all converted to SSM parameters, handled in secrets. Only secrets support valueFrom
    environment   = var.datadog_instrumentation_runtime == null ? {} : module.autoinstrumentation_setup[0].new_environment
    secrets       = module.env_vars_to_ssm_parameters[0].ssm_parameter_arns
    extra_options = merge(try(module.autoinstrumentation_setup[0].new_extra_options, {}), var.application_container.extra_options)
    # Extra ports are needed in cases where the Load Balancer Health Check port is different from the application containers normal ports
    extra_ports = try(var.lb_health_check.port, null) != var.application_container.port ? compact([try(var.lb_health_check.port, null)]) : []
  })
  init_container = var.datadog_instrumentation_runtime == null ? [] : [module.autoinstrumentation_setup[0].init_container_definition]

  containers = [
    for container in flatten([
      [local.application_container_with_overrides],
      var.sidecar_containers,
      local.xray_container,
      # We need to handle the case where datadog_containers is null, the variable expects a tuple of two objects
      local.datadog_containers != null ? local.datadog_containers : [null, null],
      local.init_container
      ]) : {
      name    = container.name
      image   = container.image
      command = try(container.command, null)
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential         = try(container.essential, container.name == var.application_container.name)
      environment       = try(container.environment, {})
      secrets           = try(container.secrets, {})
      port              = try(container.port, null)
      network_protocol  = try(container.network_protocol, "tcp")
      health_check      = try(container.health_check, null)
      cpu               = try(container.cpu, null)
      memory_hard_limit = try(container.memory_hard_limit, null)
      memory_soft_limit = try(container.memory_soft_limit, null)
      stop_timeout      = try(container.stop_timeout, null)
      extra_options     = try(container.extra_options, {})
    } if container != null
  ]

  capacity_provider_strategy_spot = {
    capacity_provider = "FARGATE_SPOT"
    weight            = 1
  }
  capacity_provider_strategy_on_demand = {
    capacity_provider = "FARGATE"
    weight            = 1
  }
}


# == Hack for terraform invisible strong typing
#
# This is a workaround for the fact that a variable can't have a ternary
# that returns two objects where the keys are different.
#
# To work around this we conditionally create a task with an AWS logger
# or a Datadog logger.

resource "aws_ecs_task_definition" "task" {
  count = var.enable_datadog == true ? 0 : 1

  # Let Github Actions handle the versioning of the task definition
  track_latest = true
  family       = var.service_name

  container_definitions = jsonencode([
    for container in local.containers : merge({
      name    = container.name
      image   = container.image
      command = container.command
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential = container.essential
      environment = container.environment == null ? [] : [
        for key, value in container.environment : {
          name  = key
          value = value
        }
      ]
      secrets = container.secrets == null ? [] : [
        for key, value in container.secrets : {
          name      = key
          valueFrom = value
        }
      ]
      portMappings = container.port == null ? [] : concat(
        [for port in concat([container.port], local.application_container_with_overrides.extra_ports) :
          {
            containerPort = tonumber(port)
            hostPort      = tonumber(port)
            protocol      = container.network_protocol
          }
        ]
      )
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" : aws_cloudwatch_log_group.main.name,
          "awslogs-region" : data.aws_region.current.region, # AWS Provider >= 6.0.0
          "awslogs-stream-prefix" : container.name
        }
      }
      healthCheck       = container.health_check
      stopTimeout       = container.stop_timeout
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit

      # Bug: To avoid recreation of the task definition: https://github.com/hashicorp/terraform-provider-aws/pull/41394
      systemControls = []
      volumesFrom    = []
      mountPoints    = []
    }, container.extra_options)
  ])

  execution_role_arn = aws_iam_role.execution.arn
  task_role_arn      = aws_iam_role.task.arn

  requires_compatibilities = [var.launch_type]
  cpu                      = var.cpu
  memory                   = var.memory
  # ECS Anywhere can't have "awsvpc" as the network mode
  network_mode = var.launch_type == "EXTERNAL" ? "bridge" : "awsvpc"
}

resource "aws_ecs_task_definition" "task_datadog" {
  count = var.enable_datadog == true ? 1 : 0

  # Let Github Actions handle the versioning of the task definition
  track_latest = true
  family       = var.service_name

  container_definitions = jsonencode([
    for container in local.containers : merge({
      name    = container.name
      image   = container.image
      command = container.command
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential = container.essential
      environment = [
        for key, value in container.environment : {
          name  = key
          value = tostring(value)
        }
      ]
      secrets = [
        for key, value in container.secrets : {
          name      = key
          valueFrom = value
        }
      ]
      portMappings = container.port == null ? [] : concat(
        [for port in concat([container.port], local.application_container_with_overrides.extra_ports) :
          {
            containerPort = tonumber(port)
            hostPort      = tonumber(port)
            protocol      = container.network_protocol
          }
        ]
      )

      logConfiguration = {
        logDriver = "awsfirelens",
        options = {
          Name       = "datadog",
          Host       = "http-intake.logs.datadoghq.eu",
          compress   = "gzip",
          TLS        = "on"
          provider   = "ecs"
          dd_service = var.dd_service_name_override != null ? var.dd_service_name_override : var.service_name,
          # Version tag should be appended dynamically in GitHub Actions
          dd_tags = join(",", compact([local.team_name_tag, "env:${local.environment}", "version:${var.application_container.image.git_sha}"]))
        }
        secretOptions = [
          {
            name      = "apiKey",
            valueFrom = local.datadog_api_key_secret
          }
        ]
      }

      healthCheck       = container.health_check
      stopTimeout       = container.stop_timeout
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
      dockerLabels = {
        "com.datadoghq.tags.service" = var.dd_service_name_override != null ? var.dd_service_name_override : var.service_name
        "com.datadoghq.tags.env"     = local.environment
        "com.datadoghq.tags.team"    = var.team_name_override != null ? var.team_name_override : local.team_name
      }

      # Bug: To avoid recreation of the task definition: https://github.com/hashicorp/terraform-provider-aws/pull/41394
      systemControls = []
      volumesFrom    = []
      mountPoints    = []
    }, container.extra_options)
  ])

  execution_role_arn = aws_iam_role.execution.arn
  task_role_arn      = aws_iam_role.task.arn

  requires_compatibilities = [var.launch_type]
  cpu                      = var.cpu
  memory                   = var.memory
  # ECS Anywhere can't have "awsvpc" as the network mode
  network_mode = var.launch_type == "EXTERNAL" ? "bridge" : "awsvpc"

  dynamic "volume" {
    for_each = var.datadog_instrumentation_runtime != null ? [1] : []

    content {
      configure_at_launch = false
      name                = "datadog-instrumentation-init"
    }
  }
}

locals {
  task_definition = var.enable_datadog == true ? aws_ecs_task_definition.task_datadog[0] : aws_ecs_task_definition.task[0]
}
# == End of hack ==

resource "aws_ecs_service" "service" {
  # Always create a count to ease transition where we had multiple services before
  count = var.service_name != "" ? 1 : 0

  depends_on = [terraform_data.no_launch_type_and_spot]

  name            = var.service_name
  cluster         = var.cluster_id
  task_definition = local.task_definition.arn
  # Desired count will be ignored, configure autoscaling instead if needed.
  desired_count = var.desired_count
  # we use capacity_provider_strategy to set the launch type for Fargate, so we set it to null here.
  launch_type                        = var.use_spot || var.launch_type == "FARGATE" ? null : var.launch_type
  deployment_minimum_healthy_percent = var.deployment_minimum_healthy_percent
  deployment_maximum_percent         = var.deployment_maximum_percent
  health_check_grace_period_seconds  = var.launch_type == "EXTERNAL" ? null : var.health_check_grace_period_seconds
  wait_for_steady_state              = var.wait_for_steady_state
  propagate_tags                     = var.propagate_tags
  enable_execute_command             = var.enable_execute_command
  force_new_deployment               = var.force_new_deployment

  deployment_controller {
    type = var.deployment_controller_type
  }

  deployment_circuit_breaker {
    enable   = var.deployment_circuit_breaker.enable
    rollback = var.deployment_circuit_breaker.rollback
  }

  deployment_configuration {
    strategy             = var.deployment_configuration_strategy
    bake_time_in_minutes = var.rollback_window_in_minutes

    dynamic "lifecycle_hook" {
      for_each = var.lifecycle_hooks
      content {
        hook_target_arn  = lifecycle_hook.value.hook_target_arn
        role_arn         = lifecycle_hook.value.role_arn
        lifecycle_stages = lifecycle_hook.value.lifecycle_stages
      }
    }
  }

  # ECS Anywhere doesn't support VPC networking or load balancers.
  # Because of this, we need to make these resources dynamic!
  dynamic "network_configuration" {
    for_each = var.launch_type == "EXTERNAL" ? [] : [0]

    content {
      subnets          = var.private_subnet_ids
      security_groups  = [aws_security_group.ecs_service[0].id]
      assign_public_ip = var.assign_public_ip
    }
  }

  dynamic "load_balancer" {
    for_each = var.launch_type == "EXTERNAL" ? [] : var.lb_listeners

    content {
      container_name   = var.application_container.name
      container_port   = var.application_container.port
      target_group_arn = aws_lb_target_group.service[load_balancer.key].arn

      advanced_configuration {
        alternate_target_group_arn = aws_lb_target_group.secondary[load_balancer.key].arn
        production_listener_rule   = aws_lb_listener_rule.service[load_balancer.key].arn
        role_arn                   = aws_iam_role.infrastructure_for_load_balancers.arn
        test_listener_rule         = aws_lb_listener_rule.replacement[load_balancer.key].arn
      }
    }
  }

  # We set the service as a spot service through setting up the capacity_provider_strategy.
  dynamic "capacity_provider_strategy" {
    # Only use for Fargate launch type
    for_each = var.launch_type != "FARGATE" ? [] : (var.use_spot ? [local.capacity_provider_strategy_spot] : [local.capacity_provider_strategy_on_demand])

    content {
      capacity_provider = capacity_provider_strategy.value.capacity_provider
      weight            = capacity_provider_strategy.value.weight
    }
  }

  # Placement constraints for EC2 and EXTERNAL launch types. Can be used to ensure that services are placed on specific instances.
  dynamic "placement_constraints" {
    for_each = var.placement_constraints

    content {
      type       = placement_constraints.value.type
      expression = placement_constraints.value.expression
    }
  }

  timeouts {
    create = var.ecs_service_timeouts.create
    update = var.ecs_service_timeouts.update
    delete = var.ecs_service_timeouts.delete
  }

  lifecycle {
    ignore_changes = [task_definition, desired_count]
    precondition {
      condition     = !(length(var.placement_constraints) > 0 && var.launch_type == "FARGATE")
      error_message = "Placement constraints are not valid for FARGATE launch type"
    }
  }
}
