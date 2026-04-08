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

variable "dd_app_protection" {
  description = "Enable Datadog App & API Protection"
  type        = bool
}

variable "dd_runtime_code_analysis" {
  description = "Enable Datadog IAST"
  type        = bool
}

variable "dd_runtime_software_composition_analysis" {
  description = "Enable Datadog's Runtime SCA"
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
