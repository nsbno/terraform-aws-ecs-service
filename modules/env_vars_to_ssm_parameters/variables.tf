variable "environment_variables" {
  description = "Environment variables to be stored in SSM Parameter Store"
  type        = map(string)
}

variable "secrets" {
  description = "Secret environment variables to be stored in SSM as SecureString"
  type        = map(string)
}

variable "secrets_to_override" {
  description = "Secret environment variables to be stored in SSM as SecureString to be overwritten"
  type        = map(string)
}

variable "service_name" {
  description = "The name of the service for which SSM parameters are being created"
  type        = string
}

variable "task_execution_role_id" {
  description = "The ID of the IAM role for ECS task execution"
  type        = string
}
