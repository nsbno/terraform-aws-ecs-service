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
    name = "vpc-id"
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

# Remember to add: https://github.com/nsbno/terraform-datadog-provider-setup

module "datadog_service" {
  # Find newest version here: https://github.com/nsbno/terraform-datadog-service/releases
  source = "github.com/nsbno/terraform-datadog-service?ref=x.y.z"

  service_name = local.application_name
  display_name = "Infrademo Server"

  github_url    = "https://github.com/nsbno/terraform-aws-ecs-service"
  support_email = "teaminfra@vy.no"
  slack_url     = "https://nsb-utvikling.slack.com/archives/CSXU1BBA6"
}


module "service" {
  source = "../../"

  application_name = module.datadog_service.service_name

  enable_datadog                  = true
  datadog_instrumentation_runtime = "jvm" # Can be jvm or node

  vpc_id             = data.aws_vpc.main.id
  private_subnet_ids = data.aws_subnets.private.ids
  cluster_id         = data.aws_ecs_cluster.main.id

  application_container = {
    name     = "main"
    image    = "nginx:latest"
    port     = 80
    protocol = "HTTP"
  }

  lb_listeners = [
    {
      listener_arn = data.aws_lb_listener.http.arn
      security_group_id = one(data.aws_lb.main.security_groups)
      conditions = [
        {
          path_pattern = "/${local.application_name}/*"
        }
      ]
    }
  ]
}
