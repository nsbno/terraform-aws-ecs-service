locals {
  name_prefix  = "infrademo"
  service_name = "my-webapp"
}

/*
 * = Various required resources
 */

data "aws_ecs_cluster" "main" {
  cluster_name = "${local.name_prefix}-cluster"
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

  cluster_id = data.aws_ecs_cluster.main.id

  # This indicates that we are launching to ECS Anywhere
  launch_type = "EXTERNAL"

  application_container = {
    name     = "main"
    image    = data.vy_ecs_image.this
    port     = 80
    protocol = "HTTP"
  }

  placement_constraints = [
    {
      type       = "memberOf"
      expression = "attribute:your_custom_attribute in [your_first_value, your_second_value]"
    }
  ]
}
