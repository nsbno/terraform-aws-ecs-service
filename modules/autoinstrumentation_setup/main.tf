# Definitions for instrumentation loading
locals {
  # This is an extra container with the required libs
  init_container = var.datadog_instrumentation_runtime == null ? {} : {
    "node" : {
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
    "jvm" : {
      environment = {
        JAVA_TOOL_OPTIONS = "-javaagent:/datadog-instrumentation-init/package/dd-java-agent.jar"

        DD_LOGS_INJECTION    = "true"
        DD_PROFILING_ENABLED = "true"

        # Remove "java-aws-sdk" and make it the same name as DD_SERVICE
        DD_TRACE_REMOVE_INTEGRATION_SERVICE_NAMES_ENABLED    = "true"
        DD_DATA_STREAMS_ENABLED                              = "true"
        DD_TRACE_SQS_BODY_PROPAGATION_ENABLED                = "true"
        DD_INTEGRATION_KOTLIN_COROUTINE_EXPERIMENTAL_ENABLED = "true"

        # Allow for dynamic instrumentation
        DD_DYNAMIC_INSTRUMENTATION_ENABLED = true
        DD_SYMBOL_DATABASE_UPLOAD_ENABLED  = true

        DD_SERVICE = var.dd_service
        DD_ENV     = var.dd_env
        DD_TAGS    = var.dd_team_tag
      }
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
            readOnly        = true
          }
        ]
      }
    }
    "node" : {
      environment = {
        NODE_OPTIONS = "--require /datadog-instrumentation-init/package/node_modules/dd-trace/init"

        DD_LOGS_INJECTION    = "true"
        DD_PROFILING_ENABLED = "true"

        DD_SERVICE = var.dd_service
        DD_ENV     = var.dd_env
      }
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
            readOnly        = true
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
      local.auto_instrumentation_for_app_container_injection_extra_options[var.datadog_instrumentation_runtime]["environment"]
    )
  }

  new_extra_options = {
    extra_options = merge(
      lookup(var.application_container, "extra_options", null),
      local.auto_instrumentation_for_app_container_injection_extra_options[var.datadog_instrumentation_runtime]["extra_options"]
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
}

output "init_container_definition" {
  value = local.init_container[var.datadog_instrumentation_runtime]
}
