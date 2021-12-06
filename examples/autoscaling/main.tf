provider "aws" {
  region = "eu-west-1"
}

locals {
  name_prefix      = "infrademo"
  application_name = "my-webapp"
}

/*
 * = Various required resources
 */

data "aws_vpc" "main" {
  tags = {
    Name = "${local.name_prefix}-vpc"
  }
}

data "aws_subnet_ids" "private" {
  vpc_id = data.aws_vpc.main.id

  tags = {
    Tier = "Private"
  }
}

data "aws_ecs_cluster" "main" {
  cluster_name = "${local.name_prefix}-cluster"
}

data "aws_lb" "main" {
  name = "${local.name_prefix}-alb"
}

data "aws_lb_listener" "http" {
  load_balancer_arn = data.aws_lb.main.arn
  port              = 80
}

/*
 * = The actual setup
 */

module "service" {
  source = "../../"

  name_prefix = local.application_name

  vpc_id             = data.aws_vpc.main.id
  private_subnet_ids = data.aws_subnet_ids.private.ids
  cluster_id         = data.aws_ecs_cluster.main.id

  application_container = {
    name     = "main"
    image    = "nginx:latest"
    port     = 80
    protocol = "HTTP"
  }

  autoscaling = {
    min_capacity = 1
    max_capacity = 3
    metric_type  = "ECSServiceAverageCPUUtilization"
    target_value = "75"
  }

  autoscaling_schedule = {
    timezone  = "Europe/Oslo"
    # Increase capacity in weekdays
    schedules = [
      {
        schedule     = "cron(* * ? * 1 *)"
        min_capacity = 3
        max_capacity = 6
      },
      {
        schedule     = "cron(* * ? * 6 *)"
        min_capacity = 1
        max_capacity = 3
      }
    ]
  }
}

resource "aws_lb_listener_rule" "nginx" {
  listener_arn = data.aws_lb_listener.http.arn

  action {
    type             = "forward"
    target_group_arn = module.service.target_group_arns["main"]
  }

  condition {
    path_pattern {
      values = ["*"]
    }
  }
}
