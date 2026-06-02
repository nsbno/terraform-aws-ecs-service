data "aws_region" "current" {}
data "aws_iam_account_alias" "this" {}

data "aws_ssm_parameter" "team_name" {
  count = var.enable_datadog && var.team_name_override == null ? 1 : 0

  name = "/__platform__/team_name_handle"
}

data "aws_secretsmanager_secret" "datadog_agent_api_key" {
  arn = "arn:aws:secretsmanager:eu-west-1:727646359971:secret:datadog_agent_api_key"
}

locals {
  # The Cluster ID is the cluster's ARN.
  # The last part after a '/'is the name of the cluster.
  cluster_name = split("/", var.cluster_id)[1]

  ssm_parameters = {
    ecs_cluster_name   = local.cluster_name
    ecs_service_name   = var.service_name
    ecs_container_name = var.application_container.name
    ecr_image_base     = var.application_container.image.ecr_repository_uri
    ecs_container_port = var.application_container.port
  }

  # non sensitive team name value to avoid recreation of the task definition
  team_name     = var.enable_datadog && length(data.aws_ssm_parameter.team_name) > 0 ? nonsensitive(data.aws_ssm_parameter.team_name[0].value) : null
  team_name_tag = var.team_name_override != null ? format("team:%s", var.team_name_override) : (local.team_name != null ? format("team:%s", local.team_name) : null)

  datadog_api_key_secret = var.datadog_api_key_secret_arn != null ? var.datadog_api_key_secret_arn : data.aws_secretsmanager_secret.datadog_agent_api_key.arn
  # KMS key for Utvikling API Key
  datadog_api_key_kms = "arn:aws:kms:eu-west-1:727646359971:key/1bfdf87f-a69c-41f8-929a-2a491fc64f69"
}

/*
 * = Logging
 */
resource "aws_cloudwatch_log_group" "main" {
  name              = var.service_name
  retention_in_days = var.log_retention_in_days
  tags              = var.tags
}

// Used by github Actions during deployment
resource "aws_ssm_parameter" "ssm_parameters" {
  for_each = local.ssm_parameters

  name  = "/__deployment__/${var.application_container.image.id}/${each.key}"
  type  = "String"
  value = each.value
}
