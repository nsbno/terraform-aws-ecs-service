output "init_container_definition" {
  value = local.init_container[var.datadog_instrumentation_runtime]
}

output "new_environment" {
  value = local.new_definition.environment
}

output "new_extra_options" {
  value = local.new_definition.extra_options
}
