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

data "aws_ecs_cluster" "main" {
  cluster_name = "${local.name_prefix}-cluster"
}

data "aws_ecr_repository" "this" {
  name        = "infrademo-demo-repo"
  registry_id = "123456789012" # service account id
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
    name           = "main"
    repository_url = data.aws_ecr_repository.this.repository_url
    port           = 80
    protocol       = "HTTP"
  }

  placement_constraints = [
    {
      type       = "memberOf"
      expression = "attribute:your_custom_attribute in [your_first_value, your_second_value]"
    }
  ]
}
