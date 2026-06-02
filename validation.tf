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
