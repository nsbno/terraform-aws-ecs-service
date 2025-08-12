variable "application_container" {
  description = "The application that is being run by the service"
  type = object({
    name           = string
    repository_url = string
    essential      = optional(bool, true)
    command        = optional(string)

    environment = optional(map(string))
    secrets     = optional(map(string))
    # To ensure consistent container configuration
    secrets_to_override = optional(map(string), {})

    cpu               = optional(number)
    memory_hard_limit = optional(number)
    memory_soft_limit = optional(number)

    port             = number
    protocol         = string,
    network_protocol = optional(string, "tcp")

    health_check = optional(any)

    extra_options = optional(any)
  })
}

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
