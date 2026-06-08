locals {
  name_prefix  = "infrademo"
  service_name = "with-preview"
}

/*
 * = Various required resources
 */

data "aws_vpc" "main" {
  tags = {
    Name = "shared"
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
  ecr_repository_name    = "infrademo-demo-app"
}

resource "aws_ssm_parameter" "secret" {
  name  = "/applications/${local.service_name}/custom_secret"
  type  = "SecureString"
  value = "my-secure-value"
}

resource "aws_secretsmanager_secret" "secret" {
  name = "/applications/${local.service_name}/my_secret"
}

resource "aws_secretsmanager_secret_version" "secret" {
  secret_id     = aws_secretsmanager_secret.secret.id
  secret_string = "my-secret-value"
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

    secrets_from_ssm = {
      SECRET = aws_ssm_parameter.secret.arn
    }

    # These won't be accessible in the preview environments
    # (not supported yet)
    secrets_from_secretsmanager = {
      MY_SECRET = {
        id = aws_secretsmanager_secret.secret.arn
      }
    }

    secrets = {
      DIRECT_SECRET = aws_ssm_parameter.secret.value
    }

    environment = {
      MY_ENV = "Hello world"
    }
  }

  is_preview_supported = true

  lb_listeners = [{
    listener_arn      = data.aws_lb_listener.https.arn
    test_listener_arn = data.aws_lb_listener.https_test.arn
    security_group_id = one(data.aws_lb.main.security_groups)
    conditions = [{
      path_pattern = "/${local.service_name}/*"
    }]
  }]
}
