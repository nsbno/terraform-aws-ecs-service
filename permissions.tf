/*
 * IAM
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

// Fetch info about each secret, so we can automatically discover which KMS
// key permissions are needed
data "aws_secretsmanager_secret" "secrets_to_read" {
  for_each = var.application_container.secrets_from_secretsmanager

  arn = each.value.id
}

locals {
  ssm_parameter_arns_permissions_to_read = [for _, arn in local.ssm_secrets : arn]
  secrets_to_read                        = toset([for secret in data.aws_secretsmanager_secret.secrets_to_read : secret.arn])

  # KMS keys that's being used by SecretsManager
  # should be granted decrypt access
  secrets_kms_key_arns = toset([
    for secret in data.aws_secretsmanager_secret.secrets_to_read : secret.kms_key_id
    if secret.kms_key_id != "" && !startswith(secret.kms_key_id, "alias/aws/")
  ])

  has_any_secrets = length(local.ssm_parameter_arns_permissions_to_read) > 0 || length(local.secrets_to_read) > 0
}

// Grants the execution role access to read Secrets and SSM parameters
// that is referenced in var.application_container.
resource "aws_iam_role_policy" "allow_read_secrets" {
  count = local.has_any_secrets ? 1 : 0

  role   = aws_iam_role.execution.name
  policy = data.aws_iam_policy_document.allow_read_of_secrets[0].json
}

data "aws_iam_policy_document" "allow_read_of_secrets" {
  count = local.has_any_secrets ? 1 : 0

  dynamic "statement" {
    for_each = length(local.ssm_parameter_arns_permissions_to_read) > 0 ? [1] : []

    content {
      effect    = "Allow"
      resources = local.ssm_parameter_arns_permissions_to_read

      actions = [
        "ssm:GetParameter",
        "ssm:GetParameters",
        "ssm:GetParametersByPath",
        "ssm:DescribeParameters",
      ]
    }
  }

  dynamic "statement" {
    for_each = length(local.secrets_to_read) > 0 ? [1] : []

    content {
      effect    = "Allow"
      resources = local.secrets_to_read

      actions = [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret",
      ]
    }
  }

  dynamic "statement" {
    for_each = length(local.secrets_kms_key_arns) > 0 ? [1] : []

    content {
      effect    = "Allow"
      resources = local.secrets_kms_key_arns

      actions = [
        "kms:Decrypt",
        "kms:DescribeKey",
      ]
    }
  }
}
