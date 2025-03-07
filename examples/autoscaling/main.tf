provider "aws" {
  region = "eu-west-1"
}

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

data "aws_lb_listener" "http" {
  #  Reference your existing ALB listener which usually is created centrally in -aws repo
  load_balancer_arn = data.aws_lb.main.arn
  port              = 80
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
    image    = "nginx:latest"
    port     = 80
    protocol = "HTTP"
  }

  lb_listeners = [{
    listener_arn      = data.aws_lb_listener.http.arn
    security_group_id = one(data.aws_lb.main.security_groups)
    conditions = [{
      path_pattern = "/${local.service_name}/*"
    }]
  }]

  autoscaling = {
    min_capacity = 1
    max_capacity = 3
    metric_type  = "ECSServiceAverageCPUUtilization"
    target_value = "75"
  }

  autoscaling_schedule = {
    timezone = "Europe/Oslo"
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
