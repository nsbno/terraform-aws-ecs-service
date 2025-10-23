output "ssm_parameter_arns" {
  value = merge(
    { for key, param in aws_ssm_parameter.environment_vars_to_ssm_parameters : key => param.arn },
    { for key, param in aws_ssm_parameter.secrets_to_ssm_parameters : key => param.arn },
    { for key, param in aws_ssm_parameter.secrets_to_overwrite_ssm_parameters : key => param.arn },
    var.secrets_from_ssm
  )
}
