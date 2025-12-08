locals {
  name_prefix  = "infrademo"
  service_name = "my-webapp"
}

/*
 * = Various required resources
 */

data "aws_vpc" "main" {
  #  Reference your existing VPC which usually is created centrally in -aws repo
  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

data "aws_subnets" "private" {
  #  Reference your existing subnets which usually is created centrally in -aws repo
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

  tags = {
    Tier = "Private"
  }
}

data "aws_ecs_cluster" "main" {
  #  Reference your existing ECS cluster which usually is created centrally in -aws repo
  cluster_name = "${local.name_prefix}-cluster"
}

data "aws_lb" "main" {
  #  Reference your existing ALB which usually is created centrally in -aws repo
  name = "${local.name_prefix}-alb"
}

data "aws_lb_listener" "https" {
  load_balancer_arn = data.aws_lb.main.arn
  port              = 443
}

data "aws_lb_listener" "https_test" {
  load_balancer_arn = data.aws_lb.main.arn
  port              = 8443
}

data "vy_ecs_image" "this" {
  github_repository_name = "infrademo-demo-app"
  ecr_repository_name    = "infrademo-demo-repo"
}

/*
 * = The actual setup
 */

module "service" {
  source = "../../"

  service_name = local.service_name

  vpc_id             = data.aws_vpc.main.id
  private_subnet_ids = data.aws_subnets.private.ids
  cluster_id         = data.aws_ecs_cluster.main.id

  application_container = {
    name     = "main"
    image    = data.vy_ecs_image.this
    port     = 80
    protocol = "HTTP"
  }

  lb_listeners = [{
    listener_arn      = data.aws_lb_listener.https.arn
    test_listener_arn = data.aws_lb_listener.https_test.arn
    security_group_id = one(data.aws_lb.main.security_groups)
    conditions = [{
      path_pattern = "/${local.service_name}/*"
    }]
  }]

  autoscaling_capacity = {
    min = 1
    max = 2
  }

  autoscaling_policies = [
    # Combine with target tracking policies as predictive scaling only scales out
    {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
      target_value           = "75"
    },
    {
      policy_type                 = "PredictiveScaling"
      predictive_scaling_mode     = "ForecastOnly"
      target_value                = "75"
      predefined_metric_pair_type = "ECSServiceCPUUtilization"
    }
    # Can be combined with multiple metric types or custom metrics
    # {
    #   policy_type                 = "PredictiveScaling"
    #   predictive_scaling_mode     = "ForecastAndScale"
    #   target_value                = "75"
    #   predefined_metric_pair_type = "ECSServiceMemoryUtilization"
    # }
    # {
    #   policy_type                 = "PredictiveScaling"
    #   predictive_scaling_mode     = "ForecastAndScale"
    #   target_value                = "75"
    #   predefined_metric_pair_type = "ALBRequestCount"
    #
    #   # The following resource_label can be found by combining the last part of the load balancer and target group ARNs.
    #   resource_label              = "app/<load-balancer-name>/<load-balancer-id>/targetgroup/<target-group-name>/<target-group-id>"
    # }
  ]
}
