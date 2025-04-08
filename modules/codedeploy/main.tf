## Code Deploy role
data "aws_iam_policy_document" "assume_role_code_deploy" {
  statement {
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["codedeploy.amazonaws.com"]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role" "codedeploy_role" {
  name               = "${var.service_name}-codedeploy-role"
  assume_role_policy = data.aws_iam_policy_document.assume_role_code_deploy.json
}

resource "aws_iam_role_policy_attachment" "AWSCodeDeployRole" {
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSCodeDeployRole"
  role       = aws_iam_role.codedeploy_role.name
}

resource "aws_iam_role_policy_attachment" "AWSCodeDeployRoleForECS" {
  policy_arn = "arn:aws:iam::aws:policy/AWSCodeDeployRoleForECS"
  role       = aws_iam_role.codedeploy_role.name
}

## Code Deploy application and deployment group

resource "aws_codedeploy_app" "this" {
  compute_platform = "ECS"
  name             = var.service_name
}

resource "aws_codedeploy_deployment_group" "this" {
  app_name               = aws_codedeploy_app.this.name
  deployment_config_name = var.deployment_config_name
  deployment_group_name  = var.deployment_group_name
  service_role_arn       = aws_iam_role.codedeploy_role.arn

  auto_rollback_configuration {
    enabled = true
    events  = ["DEPLOYMENT_FAILURE"]
  }

  blue_green_deployment_config {
    deployment_ready_option {
      action_on_timeout = "CONTINUE_DEPLOYMENT"
    }

    terminate_blue_instances_on_deployment_success {
      action                           = "TERMINATE"
      termination_wait_time_in_minutes = var.old_tasks_termination_wait_time
    }
  }

  deployment_style {
    deployment_option = "WITH_TRAFFIC_CONTROL"
    deployment_type   = "BLUE_GREEN"
  }

  ecs_service {
    cluster_name = var.cluster_name
    service_name = var.service_name
  }

  load_balancer_info {
    target_group_pair_info {
      prod_traffic_route {
        listener_arns = [var.alb_prod_listener_arn]
      }

      target_group {
        name = var.alb_green_target_group_name
      }

      # TODO: Have to be used if we want to create smoke tests, commenting out for now
      # test_traffic_route {
      #   listener_arns = var.alb_test_listener_arns
      # }

      # TODO: This needs to have an associated listener to be valid.
      #       Right now we do not have this.
      # target_group {
      #   name = var.alb_blue_target_group_name
      # }
    }

  }

  lifecycle {
    ignore_changes = [blue_green_deployment_config]
  }
}

locals {
  ssm_parameters = {
    compute_target = "ecs"
    codedeploy_deployment_group = aws_codedeploy_deployment_group.this.deployment_group_name
    codedeploy_application_name = aws_codedeploy_app.this.name
    ecs_cluster_name = var.cluster_name
    ecs_service_name = var.service_name
    ecr_image_base = var.ecr_image_base # split("/", var.application_container.image)[0]
  }
}

resource "aws_ssm_parameter" "ssm_parameters" {
  for_each = local.ssm_parameters

  name  = "/__deployment__/applications/${var.service_name}/${each.key}"
  type  = "String"
  value = each.value
}

