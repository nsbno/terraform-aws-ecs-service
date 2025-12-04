locals {
  name_prefix  = "infrademo"
  service_name = "my-webapp"
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

# Remember to add: https://github.com/nsbno/terraform-datadog-provider-setup

module "datadog_service" {
  # Find newest version here: https://github.com/nsbno/terraform-datadog-service/releases
  source = "github.com/nsbno/terraform-datadog-service?ref=0.1.0"

  service_name = local.service_name
  display_name = "Infrademo Server"

  github_url    = "https://github.com/nsbno/terraform-aws-ecs-service"
  support_email = "teaminfra@vy.no"
  slack_url     = "https://nsb-utvikling.slack.com/archives/CSXU1BBA6"
}


module "service" {
  source = "../../"

  service_name = module.datadog_service.service_name

  enable_datadog                  = true
  datadog_instrumentation_runtime = "jvm" # Can be jvm or node

  vpc_id             = data.aws_vpc.main.id
  private_subnet_ids = data.aws_subnets.private.ids
  cluster_id         = data.aws_ecs_cluster.main.id

  application_container = {
    name     = "main"
    image    = data.vy_ecs_image.this
    port     = 80
    protocol = "HTTP"
  }

  lb_listeners = [
    {
      listener_arn      = data.aws_lb_listener.https.arn
      test_listener_arn = data.aws_lb_listener.https_test.arn
      security_group_id = one(data.aws_lb.main.security_groups)
      conditions = [
        {
          path_pattern = "/${local.service_name}/*"
        }
      ]
    }
  ]
}
