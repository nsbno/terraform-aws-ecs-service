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

variable "dd_profiling_enabled" {
  description = "Enable Datadog profiling"
  type        = bool
}

variable "existing_java_tool_options" {
  description = "Existing JAVA_TOOL_OPTIONS value to append Datadog javaagent to"
  type        = string
  default     = ""
}

variable "existing_node_options" {
  description = "Existing NODE_OPTIONS value to append Datadog require to"
  type        = string
  default     = ""
}
