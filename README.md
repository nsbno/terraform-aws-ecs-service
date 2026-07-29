# ECS Service Module

<!-- TOC -->
* [Usage](#usage)
* [Examples](#examples)
* [Arguments](#arguments)
* [Considerations](#considerations)
  * [Platform differences](#platform-differences)
  * [Migrating from `terraform-aws-ecs-fargate` and `terraform-aws-ecs-anywhere`](#migrating-from-terraform-aws-ecs-fargate-and-terraform-aws-ecs-anywhere)
* [FAQ](#faq)
<!-- TOC -->

A simplification to get ECS Services up and running, without having to think about the details.

This module helps you get up and running with an ECS Service.
It sets up your service, and links it with VPCs, load balancers, monitoring, and more.

## Usage

Remember to check out the [variables](variables.tf) and [outputs](outputs.tf) to see all options.

```hcl
module "ecs_service" {
  source = "github.com/nsbno/terraform-aws-ecs-service?ref=x.y.z"

  service_name = local.service_name

  vpc_id             = data.aws_vpc.main.id
  private_subnet_ids = data.aws_subnets.private.ids
  cluster_id         = data.aws_ecs_cluster.main.id

  // Set to true if you need the ability to deploy preview environments. 
  // Only relevant for frontend applications, and it increases complexity.
  is_preview_supported = false

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
}
```

## Examples

The [examples folder](examples/) is the home of example usages of this module.
These are the examples you can find there.

- [Simple](examples/simple/): The minimum usage of this module.
- [Blue Green Deployment](examples/blue-green-deployment/): A service using blue/green deployments with rollback time set.
- [On Prem](examples/on-prem/): Run your service directly in an on-prem datacenter using ECS Anywhere.
- [Autoscaling](examples/autoscaling/): A simple service using autoscaling to handle increased load.
- [Autoscaling with custom metrics](examples/autoscaling-with-custom-metrics/): A service using autoscaling to handle increased load based on custom metrics.
- [Predictive Autoscaling](examples/autoscaling-predictive/): A simple service using predictive autoscaling.
- [With Datadog](examples/datadog/): A service with Datadog and autoinstrumentation enabled.
- [Without Preview Support](examples/without-preview-support/): Simple service where Preview support is disabled.

## Arguments

These are the arguments that can not be expressed by the terraform module

### `application_container` and `sidecar_containers`

These arguments are where you specify everything ECS needs to know about your container and how to run it.

Both use the same format, but `application_container` will automatically be set as an essential container, while `sidecar_container` will not be set as essential.

| Name                     | Description                                                                                                     | Required                                     | Default                                                          |
|--------------------------|-------------------------------------------------------------------------------------------------------------------|-----------------------------------------------|-------------------------------------------------------------------|
| `name`                   | The name of the container, must be unique.                                                                        | yes                                           | n/a                                                                 |
| `image`                  | The image (and tag) of the container to run                                                                       | yes                                           | n/a                                                                 |
| `command`                | A command to run on the container                                                                                 | no                                             | null                                                                |
| `essential`              | If the container is essential for the service                                                                     | no                                             | `true` if `application_container`, `false` otherwise               |
| `environment`            | A map of environment variables                                                                                    | no                                             | Empty map                                                          |
| `secrets`                | A map of secrets                                                                                                   | no                                             | Empty map                                                          |
| `port`                   | A port to expose from the container.                                                                              | depends (required for `application_container`) | null                                                              |
| `protocol`               | The application layer protocol for the exposed port.                                                              | depends (required for `application_container`) | null                                                              |
| `health_check`           | Container health checks. Not to be confused with LB health checks.                                                | no                                             | null                                                                |
| `cpu`                    | The number of CPU units reserved for this container.                                                              | no                                             | null                                                                |
| `memory_hard_limit`      | The max amount of memory that the specific container can consume.                                                 | no                                             | null                                                                |
| `memory_soft_limit`      | A soft memory limit, that ECS will do best effort to follow when memory is lacking for the service.               | no                                             | null                                                                |
| `extra_options`          | Configure any other options for container definitions                                                             | no                                             | None (Though log_configuration is automatically configured for CloudWatch) |
| `placement_constraints`  | A list of placement constraints for the service. Not valid for FARGATE launch_type. SEE: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/cluster-query-language.html and https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ecs_service#placement_constraints | no | [] |

### `lb_health_check`

These are health checks that will be executed by the loadbalancer.

See [the `health_check` documentation for `aws_lb_target_group`](https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/lb_target_group#health_check).

## Considerations

### Platform differences

The different platforms are quite similar, but some considerations have to be taken.

#### Fargate

You must make sure that the following arguments are present:

- `lb_listeners`
- `private_subnet_ids`
- `vpc_id`

#### ECS Anywhere

Please keep the considerations from AWS in mind.
Only use ECS Anywhere if it is really neccessary.
https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-anywhere.html#ecs-anywhere-considerations

Main things to note:

- There is no VPC networking
- No loadbalancers

### Migrating from `terraform-aws-ecs-fargate` and `terraform-aws-ecs-anywhere`

A guide is available if you were previously using `terraform-aws-ecs-fargate` or `terraform-aws-ecs-anywhere`.

Go check out [the documentation about moving from old modules](docs/move-from-old-modules.adoc)!

## FAQ

- Missing required arguments?
  - Newer versions of this module requires `hashicorp/aws` version >= `6.15.0`
