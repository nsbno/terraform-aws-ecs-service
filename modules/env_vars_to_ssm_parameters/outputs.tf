output "ssm_parameter_arns" {
  value = { for key, parameter in merge(
    aws_ssm_parameter.environment_vars_to_ssm_parameters,
    aws_ssm_parameter.secrets_to_ssm_parameters,
    aws_ssm_parameter.secrets_to_overwrite_ssm_parameters
  ) : key => parameter.arn }
}
