variable "datadog_instrumentation_runtime" {
  description = "The runtime of the application that is being run by the service. Can be jvm or node"
  type        = string
  nullable    = false
}

variable "dd_service" {
  type = string
}

variable "dd_env" {
  type = string
}

variable "dd_team_tag" {
  type = string
}
