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
 * == Infrastructure role for load balancers
 *
 * Gives permissions to the load balancers to be able to use blue/green deployments
 */

data "aws_iam_policy_document" "load_balancers_assume" {
  statement {
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Service"
      identifiers = ["ecs.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "infrastructure_for_load_balancers" {
  name               = "${var.service_name}-lb"
  assume_role_policy = data.aws_iam_policy_document.load_balancers_assume.json
}

data "aws_iam_policy_document" "load_balancer_and_target_groups" {
  statement {
    effect = "Allow"

    actions = [
      "elasticloadbalancing:ModifyTargetGroupAttributes",
      "elasticloadbalancing:ModifyListener",
      "elasticloadbalancing:ModifyRule",
      "elasticloadbalancing:DescribeRules",
      "elasticloadbalancing:DescribeListeners",
      "elasticloadbalancing:DescribeTargetGroups",
      "elasticloadbalancing:DescribeTargetHealth",
      "elasticloadbalancing:RegisterTargets",
      "elasticloadbalancing:DeregisterTargets"
    ]

    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "for_load_balancers" {
  role   = aws_iam_role.infrastructure_for_load_balancers.id
  policy = data.aws_iam_policy_document.load_balancer_and_target_groups.json
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

locals {
  # Additional conditions create new listener rules not covered by AND or OR logic for existing rules
  all_listener_conditions = flatten([
    for idx, value in var.lb_listeners : concat(
      [
        {
          key               = idx
          listener_arn      = value.listener_arn
          test_listener_arn = value.test_listener_arn
          conditions        = value.conditions
          target_group_key  = idx
        }
      ],
      [for rule_idx, rule in try(value.additional_conditions, []) : {
        key               = "${idx}-additional-${rule_idx}"
        listener_arn      = value.listener_arn
        test_listener_arn = value.test_listener_arn
        conditions        = [rule]
        target_group_key  = idx
      }]
  )])
}

resource "aws_lb_listener_rule" "service" {
  for_each = { for lc in local.all_listener_conditions : lc.key => lc }

  listener_arn = each.value.listener_arn

  # Use default forward type if only one target group is defined
  action {
    type = "forward"
    forward {
      target_group {
        arn    = aws_lb_target_group.service[each.value.target_group_key].arn
        weight = 1
      }
      target_group {
        arn    = aws_lb_target_group.secondary[each.value.target_group_key].arn
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
      #       This is required because the ECS Deployment will take charge of the weighting
      #       after the initial deploy.
      #       We can not reference the target groups directly.
      #       So here we are just blanket ignoring the whole forward block and hoping it is OK.
      # Relevant issue: https://github.com/hashicorp/terraform-provider-aws/issues/43905
      # Can cause issues if we do changes which triggers recreate to aws_lb_target_group
      action[0]
    ]
  }
}

/*
 * ==== Blue listener setup
 *
 *       Cannot refactor into module without downtime or moved blocks. Omitting for ease of migration.
 */
resource "aws_lb_target_group" "secondary" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  name   = trimsuffix(substr("${var.service_name}-secondary-${var.application_container.port}-${each.key}", 0, 32), "-")
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
    { Name = "${var.service_name}-secondary-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "replacement" {
  for_each = { for lc in local.all_listener_conditions : lc.key => lc }

  listener_arn = each.value.test_listener_arn

  # forward blocks require at least two target group blocks
  dynamic "action" {
    for_each = length(aws_lb_target_group.service) > 1 ? [1] : []
    content {
      type = "forward"
      forward {
        target_group {
          arn = aws_lb_target_group.service[each.value.target_group_key].arn
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
    for_each = length(aws_lb_target_group.secondary) == 1 ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.secondary[each.value.target_group_key].arn
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
      #       This is required because the ECS Deployment will take charge of the weighting
      #       after the initial deploy.
      #       We can not reference the target groups directly.
      #       So here we are just blanket ignoring the whole forward block and hoping it is OK.
      # Relevant issue: https://github.com/hashicorp/terraform-provider-aws/issues/43905
      # Can cause issues if we do changes which triggers recreate to aws_lb_target_group
      action[0]
    ]
  }
}

/*
 * = ECS Service
 *
 * This is what users are here for
 */
data "aws_ssm_parameter" "team_name" {
  count = var.enable_datadog && var.team_name_override == null ? 1 : 0

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
  team_name_tag          = var.team_name_override != null ? format("team:%s", var.team_name_override) : (local.team_name != null ? format("team:%s", local.team_name) : null)
  datadog_api_key_secret = var.datadog_api_key_secret_arn != null ? var.datadog_api_key_secret_arn : data.aws_secretsmanager_secret.datadog_agent_api_key.arn
  # KMS key for Utvikling API Key
  datadog_api_key_kms = "arn:aws:kms:eu-west-1:727646359971:key/1bfdf87f-a69c-41f8-929a-2a491fc64f69"

  # The account alias includes the name of the environment we are in as a suffix
  split_alias       = split("-", data.aws_iam_account_alias.this.account_alias)
  environment_index = length(local.split_alias) - 1
  environment       = local.split_alias[local.environment_index]

  datadog_containers = var.enable_datadog == true ? [
    {
      name      = "datadog-agent",
      image     = "public.ecr.aws/datadog/agent:latest",
      essential = true,

      environment = merge({
        ECS_FARGATE = "true"

        DD_SITE = "datadoghq.eu"

        DD_SERVICE = var.service_name
        DD_ENV     = local.environment
        DD_TAGS    = local.team_name_tag

        DD_APM_ENABLED            = var.datadog_options.apm_enabled
        DD_APM_FILTER_TAGS_REJECT = "http.useragent:ELB-HealthChecker/2.0 user_agent:ELB-HealthChecker/2.0"
        # Reject anything ending in /health
        DD_APM_FILTER_TAGS_REGEX_REJECT = "http.url:.*\\/health$"
        DD_ECS_TASK_COLLECTION_ENABLED  = "true"

        # DATADOG Startup
        DD_TRACE_STARTUP_LOGS            = var.datadog_options.trace_startup_logs
        DD_TRACE_PARTIAL_FLUSH_MIN_SPANS = var.datadog_options.trace_partial_flush_min_spans
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
}

module "autoinstrumentation_setup" {
  source = "./modules/autoinstrumentation_setup"

  count = var.datadog_instrumentation_runtime == null ? 0 : 1

  datadog_instrumentation_runtime = var.datadog_instrumentation_runtime

  dd_service           = var.service_name
  dd_env               = local.environment
  dd_team_tag          = local.team_name_tag
  dd_profiling_enabled = var.datadog_options.profiling_enabled

  existing_java_tool_options = local.existing_java_tool_options
  existing_node_options      = local.existing_node_options
}

module "env_vars_to_ssm_parameters" {
  source = "./modules/env_vars_to_ssm_parameters"

  service_name           = var.service_name
  task_execution_role_id = aws_iam_role.execution.id

  # Use filtered environment variables (runtime options excluded when using autoinstrumentation)
  environment_variables = local.filtered_environment_variables
  secrets               = var.application_container.secrets
  secrets_to_override   = var.application_container.secrets_to_override
  secrets_from_ssm      = var.application_container.secrets_from_ssm
}

locals {
  # Override application container keys
  application_container_with_overrides = merge(var.application_container, {
    image = "${var.application_container.image.ecr_repository_uri}:${var.application_container.image.git_sha}"
    # Environment vars are all converted to SSM parameters, handled in secrets. Only secrets support valueFrom
    environment   = var.datadog_instrumentation_runtime == null ? {} : module.autoinstrumentation_setup[0].new_environment
    secrets       = module.env_vars_to_ssm_parameters.ssm_parameter_arns
    extra_options = merge(try(module.autoinstrumentation_setup[0].new_extra_options, {}), var.application_container.extra_options)
    # Extra ports are needed in cases where the Load Balancer Health Check port is different from the application containers normal ports
    extra_ports = try(var.lb_health_check.port, null) != var.application_container.port ? compact([try(var.lb_health_check.port, null)]) : []
    }
  )
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

  # Let Github Actions handle the versioning of the task definition
  # track_latest = true
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
  # track_latest = true
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
          dd_service = var.service_name,
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
      cpu               = container.cpu
      memory            = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
      dockerLabels = {
        "com.datadoghq.tags.service" = var.service_name
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

# Service preconditions to ensure that the user doesn't try combinations we want to avoid.
resource "terraform_data" "no_launch_type_and_spot" {
  lifecycle {
    precondition {
      condition     = !var.use_spot || var.launch_type == "FARGATE"
      error_message = "use_spot and launch_type are mutually exclusive"
    }
  }
}

resource "terraform_data" "datadog_and_instrumentation_runtime" {
  lifecycle {
    precondition {
      condition     = !(var.enable_datadog != (var.datadog_instrumentation_runtime != null))
      error_message = "enable_datadog and datadog_instrumentation_runtime must both be set together"
    }
  }
}

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
    ignore_changes = [desired_count]
    precondition {
      condition     = !(length(var.placement_constraints) > 0 && var.launch_type == "FARGATE")
      error_message = "Placement constraints are not valid for FARGATE launch type"
    }
  }
}

/*
 * = Autoscaling
 */
locals {
  # The Cluster ID is the cluster's ARN.
  # The last part after a '/'is the name of the cluster.
  cluster_name = split("/", var.cluster_id)[1]
}

resource "aws_appautoscaling_target" "ecs_service" {
  count = length(var.autoscaling_policies) > 0 ? 1 : 0

  resource_id = "service/${local.cluster_name}/${aws_ecs_service.service[0].name}"

  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"

  # We control desired count through the autoscaling target as desired_count is ignored in the ECS service.
  min_capacity = min(var.autoscaling_capacity.min, var.desired_count)
  max_capacity = max(var.autoscaling_capacity.max, var.desired_count)
}

resource "aws_appautoscaling_policy" "ecs_service" {
  for_each = { for k, v in var.autoscaling_policies : k => v }

  name = "${var.service_name}-scaling-${each.key}"
  # Step Scaling is also available, but it's explicitly not recommended by the AWS docs.
  policy_type        = each.value.policy_type
  resource_id        = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service[0].service_namespace

  dynamic "predictive_scaling_policy_configuration" {
    for_each = each.value.policy_type == "PredictiveScaling" ? [1] : []

    content {
      mode = each.value.predictive_scaling_mode
      metric_specification {
        target_value = each.value.target_value

        dynamic "predefined_metric_pair_specification" {
          for_each = each.value.predefined_metric_pair_type != null ? [1] : []
          content {
            predefined_metric_type = each.value.predefined_metric_pair_type
            resource_label         = each.value.resource_label
          }
        }

        # Option 2: Use separate predefined load and scaling metrics
        dynamic "predefined_load_metric_specification" {
          for_each = each.value.predefined_load_metric_type != null ? [1] : []
          content {
            predefined_metric_type = each.value.predefined_load_metric_type
            resource_label         = each.value.resource_label
          }
        }

        dynamic "predefined_scaling_metric_specification" {
          for_each = each.value.predefined_scaling_metric_type != null ? [1] : []
          content {
            predefined_metric_type = each.value.predefined_scaling_metric_type
            resource_label         = each.value.resource_label
          }
        }
      }
    }
  }

  dynamic "target_tracking_scaling_policy_configuration" {
    for_each = each.value.policy_type == "TargetTrackingScaling" ? [1] : []

    content {
      dynamic "predefined_metric_specification" {
        for_each = each.value.predefined_metric_type != null ? [1] : []
        content {
          predefined_metric_type = each.value.predefined_metric_type
          resource_label         = each.value.resource_label
        }
      }

      dynamic "customized_metric_specification" {
        for_each = length(coalesce(each.value.custom_metrics, [])) > 0 ? [1] : []
        content {
          dynamic "metrics" {
            for_each = each.value.custom_metrics

            content {
              label       = metrics.value.label
              id          = metrics.value.id
              expression  = metrics.value.expression
              return_data = metrics.value.return_data

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
            }
          }
        }
      }

      target_value       = each.value.target_value
      scale_in_cooldown  = try(each.value.scale_in_cooldown, null)
      scale_out_cooldown = try(each.value.scale_out_cooldown, null)
    }
  }

  lifecycle {
    precondition {
      condition     = !(each.value.predefined_metric_type != null && length(coalesce(each.value.custom_metrics, [])) > 0)
      error_message = "Cannot define autoscaling predefined metric type and custom metrics at the same time"
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
    if length(var.autoscaling_policies) > 0
  }

  name               = "${var.service_name}-scheduled-scaling"
  resource_id        = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service[0].service_namespace

  timezone = var.autoscaling_schedule.timezone
  schedule = each.value.schedule

  scalable_target_action {
    min_capacity = each.value.min_capacity
    max_capacity = each.value.max_capacity
  }
}

locals {
  ssm_parameters = {
    ecs_cluster_name   = local.cluster_name
    ecs_service_name   = var.service_name
    ecs_container_name = var.application_container.name
    ecr_image_base     = var.application_container.image.ecr_repository_uri
    ecs_container_port = var.application_container.port
  }
}

resource "aws_ssm_parameter" "ssm_parameters" {
  for_each = local.ssm_parameters

  name  = "/__deployment__/${var.application_container.image.id}/${each.key}"
  type  = "String"
  value = each.value
}
