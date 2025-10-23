resource "aws_ssm_parameter" "environment_vars_to_ssm_parameters" {
  for_each = var.environment_variables

  name  = "/__${var.service_name}__/env_vars/${each.key}"
  type  = "String"
  value = each.value
}

resource "aws_ssm_parameter" "secrets_to_ssm_parameters" {
  for_each = var.secrets
  name     = "/__${var.service_name}__/secrets/${each.key}"
  type     = "SecureString"
  value    = each.value
}

resource "aws_ssm_parameter" "secrets_to_overwrite_ssm_parameters" {
  for_each = var.secrets_to_override

  name  = "/__${var.service_name}__/secrets/${each.key}"
  type  = "SecureString"
  value = each.value

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_iam_role_policy" "task_execution" {
  count = length(var.environment_variables) > 0 ? 1 : 0

  name   = "${var.service_name}-task-execution-ssm-parameters-policy"
  role   = var.task_execution_role_id
  policy = data.aws_iam_policy_document.env_ssm_parameters_permissions.json
}

data "aws_iam_policy_document" "env_ssm_parameters_permissions" {
  statement {
    effect = "Allow"

    resources = [for parameter in merge(
      aws_ssm_parameter.environment_vars_to_ssm_parameters,
      aws_ssm_parameter.secrets_to_ssm_parameters,
      aws_ssm_parameter.secrets_to_overwrite_ssm_parameters
    ) : parameter.arn]

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:DescribeParameters",
      "ssm:PutParameter",
      "ssm:DeleteParameter",
    ]
  }
}

resource "aws_iam_role_policy" "secrets_from_ssm_policy" {
  count = length(var.secrets_from_ssm) > 0 ? 1 : 0

  name   = "${var.service_name}-task-execution-secrets-from-ssm"
  role   = var.task_execution_role_id
  policy = data.aws_iam_policy_document.secrets_arn_from_ssm_permissions.json
}

data "aws_iam_policy_document" "secrets_arn_from_ssm_permissions" {
  statement {
    effect = "Allow"

    resources = [for arn in values(var.secrets_from_ssm) : arn]

    actions = [
      "ssm:GetParameter",
      "ssm:GetParameters",
      "ssm:GetParametersByPath",
      "ssm:DescribeParameters",
    ]
  }
}
