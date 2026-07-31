// This is mainly a PoC all the data resources and workarounds
// with awscc is to be replaced with our own Vy-provider

// TODO(Fredrik) Replace with an official provider resource from Vy
data "external" "github_env_vars" {
  // Reads the GITHUB_RUN_ID and GITHUB_REPOSITORY_ID environment variables from the
  // machine running Terraform. Both are set by GitHub Actions and are optional -
  // they resolve to an empty string when absent (e.g. running locally).
  program = ["sh", "-c", "printf '{\"github_run_id\":\"%s\",\"github_repository_id\":\"%s\"}' \"$${GITHUB_RUN_ID}\" \"$${GITHUB_REPOSITORY_ID}\""]
}

locals {
  executed_in_github_actions = data.external.github_env_vars.result["github_run_id"] != "" && data.external.github_env_vars.result["github_repository_id"] != ""
  // Run ID + repository ID unique identifies one execution of the pipeline.
  // We can use this ID to share context between different Jobs in GHA,
  // without coupling it to artificial and brittle keys.
  run_id        = local.executed_in_github_actions ? data.external.github_env_vars.result["github_run_id"] : null
  repository_id = local.executed_in_github_actions ? data.external.github_env_vars.result["github_repository_id"] : null

  # Only computed when running inside GitHub Actions - run_id/repository_id
  # are null otherwise, and interpolating null into a string is a hard
  # Terraform error (not an empty string). The resource below is skipped
  # entirely (count = 0) whenever this is null.
  deployment_metadata_name = local.executed_in_github_actions ? "/__deployment__/repository/${local.repository_id}/gha/${local.run_id}/ecs/${var.service_name}" : null
}

resource "awscc_ssm_parameter" "deployment_metadata" {
  count = local.executed_in_github_actions ? 1 : 0

  name        = local.deployment_metadata_name
  description = "Contains short-lived deployment metadata from Terraform apply, that Github Actions can use during ECS Deploy"

  type = "String"
  tier = "Advanced"

  value = jsonencode({
    repositoryId  = local.repository_id
    runId         = local.run_id
    serviceName   = var.service_name
    containerName = var.application_container.name
    clusterName   = local.cluster_name
    image         = local.application_container_image_id
  })

  # Auto-deletes the parameter 3 hours after the most recent apply. timestamp()
  # is recomputed every plan/apply, so the TTL keeps extending as long as this
  # resource keeps being applied, instead of being fixed at creation time.
  policies = jsonencode([
    {
      Type    = "Expiration"
      Version = "1.0"
      Attributes = {
        Timestamp = timeadd(timestamp(), "3h")
      }
    }
  ])

  tags = {
    ECSService              = var.service_name
    RepositoryId            = local.repository_id
    RunId                   = local.run_id
    ExecutedInGitHubActions = local.executed_in_github_actions
  }
}
