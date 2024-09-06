variable "application_container" {
  description = "The application that is being run by the service"
  type        = object({
    name  = string
    image = string
    essential = optional(bool, true)
    command = optional(string)

    environment = optional(map(string))
    secrets = optional(map(string))

    cpu = optional(number)
    memory_hard_limit = optional(number)
    memory_soft_limit = optional(number)

    port              = number
    protocol          = string,
    network_protocol  = optional(string, "tcp")

    health_check = optional(any)

    extra_options = optional(any)
  })
}

variable "datadog_instrumentation_language" {
  description = "The language of the application that is being run by the service"
  type        = string
  nullable    = false
}

variable "dd_service" {
  type = string
}
variable "dd_env" {
  type = string
}
variable "dd_version" {
  type = string
}


# Definitions for instrumentation loading
locals {
  # This is an extra container with the required libs
  init_container = var.datadog_instrumentation_language == null ? {} : {
    "js" : {
      name  = "datadog-auto-instrumentation-init"
      image = "public.ecr.aws/datadog/dd-lib-js-init:5"

      command = ["pwd; ls -la; cp -r /datadog-init/. /datadog-instrumentation-init; ls -la /datadog-instrumentation-init"]

      extra_options = {
        entrypoint = ["sh", "-c"]
        mountPoints = [
          {
            sourceVolume  = "datadog-instrumentation-init"
            containerPath = "/datadog-instrumentation-init"
          }
        ]
        user = "root"
      }
    }
    "jvm" : {
      name  = "datadog-auto-instrumentation-init"
      image = "public.ecr.aws/datadog/dd-lib-java-init:1"

      command = ["pwd; ls -la; cp -r /datadog-init/. /datadog-instrumentation-init; ls -la /datadog-instrumentation-init"]

      extra_options = {
        entrypoint = ["sh", "-c"]
        mountPoints = [
          {
            sourceVolume  = "datadog-instrumentation-init"
            containerPath = "/datadog-instrumentation-init"
          }
        ]
        user = "root"
      }
    }
  }

  auto_instrumentation_for_app_container_injection_extra_options = {
    "jvm": {
      environment = {
        JAVA_TOOL_OPTIONS = "-javaagent:/datadog-instrumentation-init/package/dd-java-agent.jar"

        DD_LOGS_INJECTION = "true"
        DD_PROFILING_ENABLED = "true"

        # Remove "java-aws-sdk" and make it the same name as DD_SERVICE
        DD_TRACE_REMOVE_INTEGRATION_SERVICE_NAMES_ENABLED = "true"
        # Make sure AWS Services are split out in the service map
        DD_TRACE_SPLIT_BY_TAGS = "aws.service"

        DD_SERVICE = var.dd_service
        DD_ENV     = var.dd_env
        DD_VERSION = var.dd_version
      }
      # TODO: This could be "base options"
      extra_options = {
        dependsOn = [
          {
            containerName = "datadog-auto-instrumentation-init",
            condition     = "SUCCESS"
          }
        ]
        volumesFrom = [
          {
            sourceContainer = "datadog-auto-instrumentation-init"
            readOnly = true
          }
        ]
      }
    }
    "js" : {
      environment = {
        NODE_OPTIONS = "--require /datadog-instrumentation-init/package/node_modules/dd-trace/init"

        DD_LOGS_INJECTION = "true"
        DD_PROFILING_ENABLED = "true"

        DD_SERVICE = var.dd_service
        DD_ENV     = var.dd_env
        DD_VERSION = var.dd_version
      }
      # TODO: This could be "base options"
      extra_options = {
        dependsOn = [
          {
            containerName = "datadog-auto-instrumentation-init",
            condition     = "SUCCESS"
          }
        ]
        volumesFrom = [
          {
            sourceContainer = "datadog-auto-instrumentation-init"
            readOnly = true
          }
        ]
      }
    }
  }
}


# Construct a new application container definition
# This is a bit of a hack because we can't really modify a map in a good way
locals {
  new_environment = {
    environment = merge(
      lookup(var.application_container, "environment", null),
      local.auto_instrumentation_for_app_container_injection_extra_options[var.datadog_instrumentation_language]["environment"]
    )
  }

  new_extra_options = {
    extra_options = merge(
      lookup(var.application_container, "extra_options", null),
      local.auto_instrumentation_for_app_container_injection_extra_options[var.datadog_instrumentation_language]["extra_options"]
    )
  }

  new_definition = merge(
    var.application_container,
    local.new_environment,
    local.new_extra_options
  )
}

output "application_container_definition" {
  value = local.new_definition

#   precondition {
#     # Error if the application container already has one of the keys we are trying to add
#     condition = anytrue([
#       for key, value in lookup(var.application_container, "environment", {}) :
#       contains(keys(local.auto_instrumentation_for_app_container_injection_extra_options["js"]), key)
#     ])
#     error_message = "Your application already has an env var that is used by the auto-instrumentation. Contact Team Utviklerplatform for help."
#   }
#
#   precondition {
#     # Do the same for extra options
#     condition = anytrue([
#       for key, value in lookup(var.application_container, "extra_options", {}) :
#       contains(keys(local.auto_instrumentation_for_app_container_injection_extra_options["js"]), key)
#     ])
#     error_message = "Your application already has an extra option that is used by the auto-instrumentation. Contact Team Utviklerplatform for help."
#   }
}

output "init_container_definition" {
  value = local.init_container[var.datadog_instrumentation_language]
}
