output "ssm_parameter_arns" {
  value = { for key, parameter in aws_ssm_parameter.environment_vars_to_ssm_parameters : key => parameter.arn }
}
