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

  application_name = local.application_name

  vpc_id             = data.aws_vpc.main.id
  private_subnet_ids = data.aws_subnets.private.ids
  cluster_id         = data.aws_ecs_cluster.main.id

  application_container = {
    # Input your application container
    name     = "main"
    image    = "nginx:latest"
    port     = 80
    protocol = "HTTP"
  }

  lb_listeners = [
    {
      listener_arn      = data.aws_lb_listener.http.arn
      security_group_id = one(data.aws_lb.main.security_groups)
      conditions        = [
        {
          path_pattern = "/${local.application_name}/*"
        }
      ]
    }
  ]

  autoscaling = {
    min_capacity = 1
    max_capacity = 3
    metric_type  = ""
    target_value = "100"
  }

  custom_metrics = [
    {
      label = "Get the queue size (the number of messages waiting to be processed)"
      id    = "m1"
      metric_stat = {
        metric = {
          metric_name = "ApproximateNumberOfMessagesVisible"
          namespace   = "AWS/SQS"
          dimensions  = [
            {
              name  = "QueueName"
              value = "my-queue"
            }
          ]
        }
        stat = "Sum"
      }
      return_data = false
    }
  ]

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
