resource "aws_ssm_parameter" "environment_vars_to_ssm_parameters" {
  for_each = var.environment_variables

  name  = "/__${var.service_name}__/env_vars/${each.key}"
  type  = "String"
  value = each.value
}

resource "aws_iam_role_policy" "task_execution" {
  count = var.environment_variables != {} ? 1 : 0

  name   = "${var.service_name}-task-execution-ssm-parameters-policy"
  role   = var.task_execution_role_id
  policy = data.aws_iam_policy_document.env_ssm_parameters_permissions.json
}

data "aws_iam_policy_document" "env_ssm_parameters_permissions" {
  statement {
    effect = "Allow"

    resources = [for parameter in aws_ssm_parameter.environment_vars_to_ssm_parameters : parameter.arn]

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
