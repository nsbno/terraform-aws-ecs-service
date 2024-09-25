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

data "aws_subnets" "private" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.main.id]
  }

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

  application_name = local.application_name

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
      path_pattern = "/${local.application_name}/*"
    }]
  }]
}
