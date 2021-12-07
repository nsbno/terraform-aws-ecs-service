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
 * == Loadbalancer
 */
resource "aws_lb_target_group" "service" {
  for_each = var.launch_type == "EXTERNAL" ? [] : var.target_groups

  vpc_id = var.vpc_id

  target_type = "ip"
  port        = var.application_container.port
  protocol    = var.application_container.protocol

  deregistration_delay = var.task_deregistration_delay

  dynamic "health_check" {
    for_each = [var.lb_health_check]

    content {
      enabled             = lookup(health_check, "enabled", null)
      healthy_threshold   = lookup(health_check, "healthy_threshold", null)
      interval            = lookup(health_check, "interval", null)
      matcher             = lookup(health_check, "matcher", null)
      path                = lookup(health_check, "path", null)
      port                = lookup(health_check, "port", null)
      protocol            = lookup(health_check, "protocol", null)
      timeout             = lookup(health_check, "timeout", null)
      unhealthy_threshold = lookup(health_check, "unhealthy_threshold", null)
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

/*
 * = ECS Service
 *
 * This is what users are here for
 */
locals {
  containers = [
    for container in concat([var.application_container], var.sidecar_containers) : {
      name         = container.name
      image        = container.image
      command      = try(container.command, null)
      # Only the application container is essential
      # Container names have to be unique, so this is guaranteed to be correct.
      essential    = try(container.essential, container.name == var.application_container.name)
      environment  = try(container.environment, {})
      secrets      = try(container.secrets, {})
      port         = try(container.port, null)
      protocol     = try(container.protocol, null)
      health_check = try(container.health_check, null)
    }
  ]
}

data "aws_region" "current" {}

resource "aws_ecs_task_definition" "task" {
  family                = var.name_prefix
  container_definitions = jsonencode([
    for container in local.containers : {
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
          "awslogs-stream-prefix" : "container"
        }
      }
      healthCheck = container.health_check
    }
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
  health_check_grace_period_seconds  = var.health_check_grace_period_seconds
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
    for_each = var.launch_type == "EXTERNAL" ? [] : var.target_groups

    content {
      container_name   = var.application_container.name
      container_port   = var.application_container.port
      target_group_arn = aws_lb_target_group.service[load_balancer.key].arn
    }
  }
}
