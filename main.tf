/*
 * = Logging
 */
resource "aws_cloudwatch_log_group" "main" {
  name              = var.name_prefix
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
  name               = "${var.name_prefix}-task-execution-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy" "task_execution" {
  name   = "${var.name_prefix}-task-execution"
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
}

/*
 * == Task Role
 *
 * Gives the actual containers the permissions they need
 */
resource "aws_iam_role" "task" {
  name               = "${var.name_prefix}-task-role"
  assume_role_policy = data.aws_iam_policy_document.task_assume.json
}

resource "aws_iam_role_policy" "ecs_task_logs" {
  name   = "${var.name_prefix}-log-permissions"
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
  name        = "${var.name_prefix}-ecs-service-sg"
  description = "Fargate service security group"
  tags        = merge(
    var.tags,
    { Name = "${var.name_prefix}-sg" }
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
  for_each = {for idx, value in var.lb_listeners : idx => value}

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

  # NOTE: TF is unable to destroy a target group while a listener is attached,
  # therefor we have to create a new one before destroying the old. This also means
  # we have to let it have a random name, and then tag it with the desired name.
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    { Name = "${var.name_prefix}-target-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "service" {
  for_each = {for idx, value in var.lb_listeners : idx => value}

  listener_arn = each.value.listener_arn

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.service[each.key].arn
  }

  condition {
    path_pattern {
      values = [each.value.path_pattern]
    }
  }
}

/*
 * = ECS Service
 *
 * This is what users are here for
 */
locals {
  containers = [
    for container in concat([var.application_container], var.sidecar_containers) : {
      name              = container.name
      image             = container.image
      command           = try(container.command, null)
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential         = try(container.essential, container.name == var.application_container.name)
      environment       = try(container.environment, {})
      secrets           = try(container.secrets, {})
      port              = try(container.port, null)
      protocol          = try(container.protocol, null)
      health_check      = try(container.health_check, null)
      cpu               = try(container.cpu, null)
      memory_hard_limit = try(container.memory_hard_limit, null)
      memory_soft_limit = try(container.memory_soft_limit, null)
      extra_options     = try(container.extra_options, {})
    }
  ]
}

data "aws_region" "current" {}

resource "aws_ecs_task_definition" "task" {
  family                = var.name_prefix
  container_definitions = jsonencode([
    for container in local.containers : merge({
      name = container.name
      image = container.image
      command = container.command
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential = container.essential
      environment = [for key, value in container.environment : {
        name = key
        value = value
      }]
      secrets = [for key, value in container.secrets : {
        name = key
        valueFrom = value
      }]
      portMappings = [container.port == null ? null : {
        containerPort = tonumber(container.port)
        hostPort = tonumber(container.port)
        protocol = "tcp"
      }]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group" : aws_cloudwatch_log_group.main.name,
          "awslogs-region" : data.aws_region.current.name,
          "awslogs-stream-prefix" : container.name
        }
      }
      healthCheck = container.health_check
      cpu = container.cpu
      memory = container.memory_hard_limit
      memoryReservation = container.memory_soft_limit
    }, container.extra_options)
  ])

  execution_role_arn = aws_iam_role.execution.arn
  task_role_arn      = aws_iam_role.task.arn

  requires_compatibilities = [var.launch_type]
  cpu                      = var.cpu
  memory                   = var.memory
  # ECS Anywhere can't have "awsvpc" as the network mode
  network_mode             = var.launch_type == "EXTERNAL" ? "bridge" : "awsvpc"
}

resource "aws_ecs_service" "service" {
  name                               = var.name_prefix
  cluster                            = var.cluster_id
  task_definition                    = aws_ecs_task_definition.task.arn
  desired_count                      = var.desired_count
  launch_type                        = var.launch_type
  deployment_minimum_healthy_percent = var.deployment_minimum_healthy_percent
  deployment_maximum_percent         = var.deployment_maximum_percent
  health_check_grace_period_seconds  = var.launch_type == "EXTERNAL" ? null : var.health_check_grace_period_seconds
  wait_for_steady_state              = var.wait_for_steady_state

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
  count = var.autoscaling != null ? 1 : 0

  resource_id        = "service/${local.cluster_name}/${aws_ecs_service.service.name}"

  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"

  min_capacity       = var.autoscaling.min_capacity
  max_capacity       = var.autoscaling.max_capacity
}

resource "aws_appautoscaling_policy" "ecs_service" {
  count = var.autoscaling != null ? 1 : 0

  name               = "${var.name_prefix}-automatic-scaling"
  # Step Scaling is also available, but it's explicitly not recommended by the AWS docs.
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service[0].service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = var.autoscaling.metric_type
    }

    target_value = var.autoscaling.target_value
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

  name               = "${var.name_prefix}-scheduled-scaling"
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
