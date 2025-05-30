/*
 * = Logging
 */
resource "aws_cloudwatch_log_group" "main" {
  name              = var.service_name
  retention_in_days = var.log_retention_in_days
  tags              = var.tags
}

/*
 * = IAM
 *
 * Various permissions needed for the module to function
 */

data "aws_iam_policy_document" "task_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

/*
 * == Task execution role
 *
 * This allows the task to pull from ECR, etc
 */
resource "aws_iam_role" "execution" {
  name               = "${var.service_name}-task-execution-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy" "task_execution" {
  name   = "${var.service_name}-task-execution"
  role   = aws_iam_role.execution.id
  policy = data.aws_iam_policy_document.task_execution_permissions.json
}

data "aws_iam_policy_document" "task_execution_permissions" {
  statement {
    effect = "Allow"

    resources = [
      "*",
    ]

    actions = [
      "ecr:GetAuthorizationToken",
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetDownloadUrlForLayer",
      "ecr:BatchGetImage",
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "secretsmanager:GetSecretValue",
    ]

    resources = [
      local.datadog_api_key_secret
    ]
  }

  statement {
    effect = "Allow"

    actions = [
      "kms:Decrypt"
    ]

    resources = [
      local.datadog_api_key_kms
    ]
  }
}

/*
 * == Task Role
 *
 * Gives the actual containers the permissions they need
 */
resource "aws_iam_role" "task" {
  name               = "${var.service_name}-task-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy" "ecs_task_logs" {
  name   = "${var.service_name}-log-permissions"
  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.ecs_task_logs.json
}

data "aws_iam_policy_document" "ecs_task_logs" {
  statement {
    effect = "Allow"

    resources = [
      aws_cloudwatch_log_group.main.arn,
    ]

    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
  }
}

resource "aws_iam_role_policy" "xray_daemon" {
  count = var.xray_daemon ? 1 : 0

  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.xray_daemon.json
}

data "aws_iam_policy_document" "xray_daemon" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "logs:PutLogEvents",
      "logs:CreateLogGroup",
      "logs:CreateLogStream",
      "logs:DescribeLogStreams",
      "logs:DescribeLogGroups",
      "xray:PutTraceSegments",
      "xray:PutTelemetryRecords",
      "xray:GetSamplingRules",
      "xray:GetSamplingTargets",
      "xray:GetSamplingStatisticSummaries",
      "cloudwatch:PutMetricData",
      "ec2:DescribeVolumes",
      "ec2:DescribeTags",
      "ssm:GetParameters"
    ]
  }
}

resource "aws_iam_role_policy" "ssm_messages_for_local_access" {
  count = var.enable_execute_command ? 1 : 0

  role   = aws_iam_role.task.id
  policy = data.aws_iam_policy_document.ssm_messages_for_local_access.json
}

data "aws_iam_policy_document" "ssm_messages_for_local_access" {
  statement {
    effect    = "Allow"
    resources = ["*"]
    actions = [
      "ssmmessages:OpenDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:CreateControlChannel"
    ]
  }
}

/*
 * = Networking
 *
 * Various networking components for the services
 */

/*
 * == Security Groups
 */
resource "aws_security_group" "ecs_service" {
  count = var.launch_type == "EXTERNAL" ? 0 : 1

  vpc_id      = var.vpc_id
  name        = "${var.service_name}-ecs-service-sg"
  description = "Fargate service security group"
  tags = merge(
    var.tags,
    { Name = "${var.service_name}-sg" }
  )
}

resource "aws_security_group_rule" "loadbalancer" {
  for_each = (var.launch_type == "EXTERNAL"
    ? {}
    : { for lb in var.lb_listeners : lb.listener_arn => lb.security_group_id }
  )

  security_group_id = aws_security_group.ecs_service[0].id

  type      = "ingress"
  protocol  = "tcp"
  from_port = var.application_container.port
  to_port   = var.application_container.port

  source_security_group_id = each.value
}

resource "aws_security_group_rule" "loadbalancer_to_service" {
  for_each = (var.launch_type == "EXTERNAL"
    ? {}
    : { for lb in var.lb_listeners : lb.listener_arn => lb.security_group_id }
  )

  security_group_id = each.value

  type      = "egress"
  protocol  = "tcp"
  from_port = var.application_container.port
  to_port   = var.application_container.port

  source_security_group_id = aws_security_group.ecs_service[0].id
}

resource "aws_security_group_rule" "egress_service" {
  count = var.launch_type == "EXTERNAL" ? 0 : 1

  security_group_id = aws_security_group.ecs_service[0].id
  type              = "egress"
  protocol          = "-1"
  from_port         = 0
  to_port           = 0
  cidr_blocks       = ["0.0.0.0/0"]
  ipv6_cidr_blocks  = ["::/0"]
}

/*
 * == Load Balancer
 *
 * Setup load balancing with an existing loadbalancer.
 */
resource "aws_lb_target_group" "service" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  vpc_id = var.vpc_id

  target_type = "ip"
  port        = var.application_container.port
  protocol    = var.application_container.protocol

  deregistration_delay = var.lb_deregistration_delay

  dynamic "health_check" {
    for_each = [var.lb_health_check]

    content {
      enabled             = lookup(health_check.value, "enabled", null)
      healthy_threshold   = lookup(health_check.value, "healthy_threshold", null)
      interval            = lookup(health_check.value, "interval", null)
      matcher             = lookup(health_check.value, "matcher", null)
      path                = lookup(health_check.value, "path", null)
      port                = lookup(health_check.value, "port", null)
      protocol            = lookup(health_check.value, "protocol", null)
      timeout             = lookup(health_check.value, "timeout", null)
      unhealthy_threshold = lookup(health_check.value, "unhealthy_threshold", null)
    }
  }

  dynamic "stickiness" {
    for_each = var.lb_stickiness[*]
    content {
      type            = var.lb_stickiness.type
      enabled         = var.lb_stickiness.enabled
      cookie_duration = var.lb_stickiness.cookie_duration
      cookie_name     = var.lb_stickiness.cookie_name
    }
  }

  # NOTE: TF is unable to destroy a target group while a listener is attached,
  # therefor we have to create a new one before destroying the old. This also means
  # we have to let it have a random name, and then tag it with the desired name.
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    { Name = "${var.service_name}-target-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "service" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  listener_arn = each.value.listener_arn

  # Use default forward type if only one target group is defined
  action {
    type = "forward"
    forward {
      target_group {
        arn    = aws_lb_target_group.service[each.key].arn
        weight = 1
      }
      target_group {
        arn    = aws_lb_target_group.blue[each.key].arn
        weight = 0
      }
    }
  }

  dynamic "condition" {
    for_each = each.value.conditions

    content {
      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        content {
          values = [path_pattern.value]
        }
      }

      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        content {
          values = flatten([host_header.value]) # Accept both a string or a list
        }
      }
      dynamic "http_header" {
        for_each = condition.value.http_header != null ? [condition.value.http_header] : []
        content {
          http_header_name = http_header.value.name
          values           = http_header.value.values
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      # NOTE: This is bound to cause some issues at some point.
      #       This is required because CodeDeploy will take charge of the weighting
      #       after the initial deploy.
      #       We can not reference the target groups directly.
      #       So here we are just blanket ignoring the whole forward block and hoping it is OK.
      # Relevant issue: https://github.com/hashicorp/terraform/issues/26359#issuecomment-2578078480
      action[0].forward[0],
    ]
  }
}

/*
 * ==== Blue listener setup
 *
 * TODO: This is just a plain copy paste of the above.
 *       Should probably refactor into a module
 */
resource "aws_lb_target_group" "blue" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  vpc_id = var.vpc_id

  target_type = "ip"
  port        = var.application_container.port
  protocol    = var.application_container.protocol

  deregistration_delay = var.lb_deregistration_delay

  dynamic "health_check" {
    for_each = [var.lb_health_check]

    content {
      enabled             = lookup(health_check.value, "enabled", null)
      healthy_threshold   = lookup(health_check.value, "healthy_threshold", null)
      interval            = lookup(health_check.value, "interval", null)
      matcher             = lookup(health_check.value, "matcher", null)
      path                = lookup(health_check.value, "path", null)
      port                = lookup(health_check.value, "port", null)
      protocol            = lookup(health_check.value, "protocol", null)
      timeout             = lookup(health_check.value, "timeout", null)
      unhealthy_threshold = lookup(health_check.value, "unhealthy_threshold", null)
    }
  }

  dynamic "stickiness" {
    for_each = var.lb_stickiness[*]
    content {
      type            = var.lb_stickiness.type
      enabled         = var.lb_stickiness.enabled
      cookie_duration = var.lb_stickiness.cookie_duration
      cookie_name     = var.lb_stickiness.cookie_name
    }
  }

  # NOTE: TF is unable to destroy a target group while a listener is attached,
  # therefor we have to create a new one before destroying the old. This also means
  # we have to let it have a random name, and then tag it with the desired name.
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    { Name = "${var.service_name}-target-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "blue" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  listener_arn = each.value.test_listener_arn

  # forward blocks require at least two target group blocks
  dynamic "action" {
    for_each = length(aws_lb_target_group.blue) > 1 ? [1] : []
    content {
      type = "forward"
      forward {
        target_group {
          arn = aws_lb_target_group.blue[each.key].arn
        }
        dynamic "stickiness" {
          for_each = var.lb_stickiness.enabled ? [1] : []
          content {
            enabled  = true
            duration = var.lb_stickiness.cookie_duration
          }
        }
      }
    }
  }

  # Use default forward type if only one target group is defined
  dynamic "action" {
    for_each = length(aws_lb_target_group.blue) == 1 ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.blue[each.key].arn
    }
  }

  dynamic "condition" {
    for_each = each.value.conditions

    content {
      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        content {
          values = [path_pattern.value]
        }
      }

      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        content {
          values = flatten([host_header.value]) # Accept both a string or a list
        }
      }

      dynamic "http_header" {
        for_each = condition.value.http_header != null ? [condition.value.http_header] : []
        content {
          http_header_name = http_header.value.name
          values           = http_header.value.values
        }
      }
    }
  }
}


/*
 * = ECS Service
 *
 * This is what users are here for
 */
resource "aws_ssm_parameter" "deployment_version" {
  # This parameter is used to initially store the version of the Lambda function. Will be overwritten
  name  = "/__platform__/versions/${var.service_name}"
  type  = "String"
  value = "latest"

  overwrite = true

  lifecycle {
    ignore_changes = [
      value
    ]
  }
}

data "aws_ssm_parameter" "team_name" {
  count = var.enable_datadog ? 1 : 0

  name = "/__platform__/team_name_handle"
}

data "aws_secretsmanager_secret" "datadog_agent_api_key" {
  arn = "arn:aws:secretsmanager:eu-west-1:727646359971:secret:datadog_agent_api_key"
}

data "aws_iam_account_alias" "this" {}

locals {
  xray_container = var.xray_daemon == true ? [
    {
      name      = "aws-otel-collector",
      image     = "amazon/aws-otel-collector",
      command   = ["--config=/etc/ecs/${var.xray_daemon_config_path}"]
      essential = true
    }
  ] : []

  # non sensitive team name value to avoid recreation of the task definition
  team_name              = var.enable_datadog && length(data.aws_ssm_parameter.team_name) > 0 ? nonsensitive(data.aws_ssm_parameter.team_name[0].value) : null
  team_name_tag          = local.team_name != null ? format("team:%s", local.team_name) : null
  datadog_api_key_secret = data.aws_secretsmanager_secret.datadog_agent_api_key.arn
  datadog_api_key_kms    = "arn:aws:kms:eu-west-1:727646359971:key/1bfdf87f-a69c-41f8-929a-2a491fc64f69"

  # The account alias includes the name of the environment we are in as a suffix
  split_alias       = split("-", data.aws_iam_account_alias.this.account_alias)
  environment_index = length(local.split_alias) - 1
  environment       = local.split_alias[local.environment_index]

  datadog_containers = var.enable_datadog == true ? [
    {
      name      = "datadog-agent",
      image     = "public.ecr.aws/datadog/agent:latest",
      essential = true,

      environment = {
        ECS_FARGATE = "true"

        DD_SITE = "datadoghq.eu"

        DD_SERVICE = var.service_name
        DD_ENV     = local.environment
        DD_TAGS    = local.team_name_tag

        DD_APM_ENABLED            = "true"
        DD_APM_FILTER_TAGS_REJECT = "http.useragent:ELB-HealthChecker/2.0 user_agent:ELB-HealthChecker/2.0"
        # Reject anything ending in /health
        DD_APM_FILTER_TAGS_REGEX_REJECT = "http.url:.*\\/health$"
        DD_ECS_TASK_COLLECTION_ENABLED  = "true"

        # DATADOG Startup
        DD_TRACE_STARTUP_LOGS            = var.datadog_options.trace_startup_logs
        DD_TRACE_PARTIAL_FLUSH_MIN_SPANS = var.datadog_options.trace_partial_flush_min_spans
      },
      secrets = {
        DD_API_KEY = local.datadog_api_key_secret
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

module "autoinstrumentation_setup" {
  source = "./modules/autoinstrumentation_setup"

  count = var.datadog_instrumentation_runtime == null ? 0 : 1

  application_container           = var.application_container
  datadog_instrumentation_runtime = var.datadog_instrumentation_runtime

  dd_service  = var.service_name
  dd_env      = local.environment
  dd_team_tag = local.team_name_tag
}

locals {
  application_container = var.datadog_instrumentation_runtime == null ? var.application_container : module.autoinstrumentation_setup[0].application_container_definition
  # TODO: Should refactor to something easier to maintain
  application_container_with_image = merge(local.application_container, { image = "${var.application_container.repository_url}:${aws_ssm_parameter.deployment_version.value}" })
  init_container                   = var.datadog_instrumentation_runtime == null ? [] : [module.autoinstrumentation_setup[0].init_container_definition]

  containers = [
    for container in flatten([
      [local.application_container_with_image],
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
      extra_options     = try(container.extra_options, {})
    } if container != null
  ]

  capacity_provider_strategy = {
    capacity_provider = "FARGATE_SPOT"
    weight            = 1
  }
}

data "aws_region" "current" {}

# == Hack for terraform invisible strong typing
#
# This is a workaround for the fact that a variable can't have a ternary
# that returns two objects where the keys are different.
#
# To work around this we conditionally create a task with an AWS logger
# or a Datadog logger.

resource "aws_ecs_task_definition" "task" {
  count = var.enable_datadog == true ? 0 : 1

  family = var.service_name
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
          value = value
        }
      ]
      secrets = [
        for key, value in container.secrets : {
          name      = key
          valueFrom = value
        }
      ]
      portMappings = container.port == null ? [] : [
        {
          containerPort = tonumber(container.port)
          hostPort      = tonumber(container.port)
          protocol      = container.network_protocol
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" : aws_cloudwatch_log_group.main.name,
          "awslogs-region" : data.aws_region.current.name,
          "awslogs-stream-prefix" : container.name
        }
      }
      healthCheck       = container.health_check
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
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

  family = var.service_name

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
      portMappings = container.port == null ? [] : [
        {
          containerPort = tonumber(container.port)
          hostPort      = tonumber(container.port)
          protocol      = container.network_protocol
        }
      ]

      logConfiguration = {
        logDriver = "awsfirelens",
        options = {
          Name       = "datadog",
          Host       = "http-intake.logs.datadoghq.eu",
          compress   = "gzip",
          TLS        = "on"
          provider   = "ecs"
          dd_service = var.service_name,
          dd_tags    = join(",", compact([local.team_name_tag, "env:${local.environment}"]))
        }
        secretOptions = [
          {
            name      = "apiKey",
            valueFrom = local.datadog_api_key_secret
          }
        ]
      }

      healthCheck       = container.health_check
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
      dockerLabels = {
        "com.datadoghq.tags.service" = var.service_name
        "com.datadoghq.tags.env"     = local.environment
        "com.datadoghq.tags.team"    = local.team_name
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

# Service preconditions to ensure that the user doesn't try combinations we want to avoid.
resource "terraform_data" "no_launch_type_and_spot" {
  lifecycle {
    precondition {
      condition     = !var.use_spot || var.launch_type == "FARGATE"
      error_message = "use_spot and launch_type are mutually exclusive"
    }
  }
}


# When autoscaling is enabled, we have to ignore changes to the desired count.
# This is because the autoscaling group will manage the desired count.
# If terraform apply is run, then the desired count will be reset.
#
# Having two resources allows us to have some users with autoscaling and some
# using desired count.

resource "aws_ecs_service" "service" {
  count      = var.autoscaling == null ? 1 : 0
  depends_on = [terraform_data.no_launch_type_and_spot]

  name                               = var.service_name
  cluster                            = var.cluster_id
  task_definition                    = local.task_definition.arn
  desired_count                      = var.desired_count
  launch_type                        = var.use_spot ? null : var.launch_type
  deployment_minimum_healthy_percent = var.deployment_minimum_healthy_percent
  deployment_maximum_percent         = var.deployment_maximum_percent
  health_check_grace_period_seconds  = var.launch_type == "EXTERNAL" ? null : var.health_check_grace_period_seconds
  wait_for_steady_state              = var.wait_for_steady_state
  propagate_tags                     = var.propagate_tags
  enable_execute_command             = var.enable_execute_command

  deployment_controller {
    type = "CODE_DEPLOY"
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
    }
  }

  dynamic "load_balancer" {
    for_each = var.launch_type == "EXTERNAL" ? [] : var.lb_listeners

    content {
      container_name   = var.application_container.name
      container_port   = var.application_container.port
      target_group_arn = aws_lb_target_group.blue[load_balancer.key].arn
    }
  }

  # We set the service as a spot service through setting up the capacity_provider_strategy.
  # Requires a cluster with 'FARGATE_SPOT' capacity provider enabled.
  dynamic "capacity_provider_strategy" {
    for_each = var.use_spot ? [local.capacity_provider_strategy] : []

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
    ignore_changes = [task_definition, load_balancer, desired_count]
    precondition {
      condition     = !(length(var.placement_constraints) > 0 && var.launch_type == "FARGATE")
      error_message = "Placement constraints are not valid for FARGATE launch type"
    }
  }
}

resource "aws_ecs_service" "service_with_autoscaling" {
  count      = var.autoscaling != null ? 1 : 0
  depends_on = [terraform_data.no_launch_type_and_spot]

  name                               = var.service_name
  cluster                            = var.cluster_id
  task_definition                    = local.task_definition.arn
  desired_count                      = var.desired_count
  launch_type                        = var.use_spot ? null : var.launch_type
  deployment_minimum_healthy_percent = var.deployment_minimum_healthy_percent
  deployment_maximum_percent         = var.deployment_maximum_percent
  health_check_grace_period_seconds  = var.launch_type == "EXTERNAL" ? null : var.health_check_grace_period_seconds
  wait_for_steady_state              = var.wait_for_steady_state
  propagate_tags                     = var.propagate_tags
  enable_execute_command             = var.enable_execute_command

  # ECS Anywhere doesn't support VPC networking or load balancers.
  # Because of this, we need to make these resources dynamic!

  deployment_controller {
    type = "CODE_DEPLOY"
  }

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
    }
  }

  # We set the service as a spot service through setting up the capacity_provider_strategy.
  # Requires a cluster with 'FARGATE_SPOT' capacity provider enabled.
  dynamic "capacity_provider_strategy" {
    for_each = var.use_spot ? [local.capacity_provider_strategy] : []

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


  lifecycle {
    ignore_changes = [desired_count]

    precondition {
      condition     = !(length(var.placement_constraints) > 0 && var.launch_type == "FARGATE")
      error_message = "Placement constraints are not valid for FARGATE launch type"
    }
  }

  timeouts {
    create = var.ecs_service_timeouts.create
    update = var.ecs_service_timeouts.update
    delete = var.ecs_service_timeouts.delete
  }
}

/*
 * = Autoscaling
 */
locals {
  # The Cluster ID is the cluster's ARN.
  # The last part after a '/'is the name of the cluster.
  cluster_name = split("/", var.cluster_id)[1]

  autoscaling = var.autoscaling != null ? var.autoscaling : {
    min_capacity = var.desired_count
    max_capacity = var.desired_count
    metric_type  = "ECSServiceAverageCPUUtilization"
    target_value = "75"
  }
}

resource "aws_appautoscaling_target" "ecs_service" {
  count = var.autoscaling != null ? 1 : 0

  resource_id = "service/${local.cluster_name}/${aws_ecs_service.service_with_autoscaling[0].name}"

  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"

  min_capacity = local.autoscaling.min_capacity
  max_capacity = local.autoscaling.max_capacity
}

resource "aws_appautoscaling_policy" "ecs_service" {
  count = var.autoscaling != null ? 1 : 0

  name = "${var.service_name}-automatic-scaling"
  # Step Scaling is also available, but it's explicitly not recommended by the AWS docs.
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service[0].service_namespace

  target_tracking_scaling_policy_configuration {
    dynamic "predefined_metric_specification" {
      for_each = length(var.custom_metrics) > 0 ? [] : [1]
      content {
        predefined_metric_type = local.autoscaling.metric_type
        resource_label         = var.autoscaling_resource_label
      }
    }

    dynamic "customized_metric_specification" {
      for_each = length(var.custom_metrics) > 0 ? [1] : []
      content {
        dynamic "metrics" {
          for_each = var.custom_metrics
          content {
            label = metrics.value.label
            id    = metrics.value.id
            dynamic "metric_stat" {
              for_each = metrics.value.metric_stat[*]
              content {
                metric {
                  metric_name = metric_stat.value.metric.metric_name
                  namespace   = metric_stat.value.metric.namespace
                  dynamic "dimensions" {
                    for_each = metric_stat.value.metric.dimensions
                    content {
                      name  = dimensions.value.name
                      value = dimensions.value.value
                    }
                  }
                }
                stat = metric_stat.value.stat
              }
            }
            expression  = metrics.value.expression
            return_data = metrics.value.return_data
          }
        }
      }
    }

    target_value       = coalesce(var.autoscaling.target_value, local.autoscaling.target_value)
    scale_in_cooldown  = var.autoscaling.scale_in_cooldown
    scale_out_cooldown = var.autoscaling.scale_out_cooldown
  }

  lifecycle {
    precondition {
      condition     = !(var.autoscaling_resource_label != "" && length(var.custom_metrics) > 0)
      error_message = "Cannot define autoscaling resource label and custom metrics at the same time"
    }
  }
}

# There is an issue with the AWS provider when it comes to creating multiple
# autoscaling groups. This makes the creation of any n+1 scheduled action
# fail on first create, which in turn requires multiple runs of apply.
#
# For more information, check out this issue on GitHub:
# https://github.com/hashicorp/terraform-provider-aws/issues/17915
resource "aws_appautoscaling_scheduled_action" "ecs_service" {
  for_each = {
    for v in var.autoscaling_schedule.schedules : v.schedule => v
    if var.autoscaling != null
  }

  name        = "${var.service_name}-scheduled-scaling"
  resource_id = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[
    0
  ].scalable_dimension
  service_namespace = aws_appautoscaling_target.ecs_service[
    0
  ].service_namespace

  timezone = var.autoscaling_schedule.timezone
  schedule = each.value.schedule

  scalable_target_action {
    min_capacity = each.value.min_capacity
    max_capacity = each.value.max_capacity
  }
}

# CODE DEPLOY SET UP
module "codedeploy" {
  # Only use if we have lb_listeners
  source = "./modules/codedeploy"

  service_name               = var.service_name
  cluster_name               = local.cluster_name
  application_container_port = var.application_container.port

  deployment_group_name = "${var.service_name}-deployment-group"

  # TODO: Need to find out if we can remove the list
  alb_blue_target_group_name  = aws_lb_target_group.service[0].name
  alb_green_target_group_name = aws_lb_target_group.blue[0].name
  alb_prod_listener_arn       = var.lb_listeners[0].listener_arn
  alb_test_listener_arn       = var.lb_listeners[0].test_listener_arn

  rollback_window_in_minutes = var.rollback_window_in_minutes
  ecr_image_base             = var.application_container.repository_url

  depends_on = [aws_ecs_service.service]
}
