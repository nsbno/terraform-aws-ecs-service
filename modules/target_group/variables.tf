variable "service_name" {
  description = "The name of the service"
  type        = string
}

variable "service_port" {
  description = "The port on which the application is listening"
  type        = number
}

variable "service_protocol" {
  description = "The protocol used by the application"
  type        = string
}

variable "vpc_id" {
  description = "The ID of the VPC where the service will be deployed"
  type        = string
}

variable "lb_deregistration_delay" {
  description = "The time to wait before deregistering a target from the load balancer"
  type        = number
}

variable "lb_health_check" {
  description = "Health check configuration for the target group"
  type = any
}

variable "lb_stickiness" {
  description = "Bind a user's session to a specific target"
  nullable    = false
  type = object({
    type            = string
    enabled         = optional(bool, null)
    cookie_duration = optional(number, null)
    cookie_name     = optional(string, null)
  })
  default = {
    type            = "lb_cookie"
    enabled         = false
    cookie_duration = 86400 # 24h in seconds
  }
}

variable "tags" {
  description = "Tags to apply to the target group"
  type        = map(string)
  default     = {}
}
