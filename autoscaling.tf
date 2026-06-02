/*
 * = Autoscaling
 */

resource "aws_appautoscaling_target" "ecs_service" {
  count = length(var.autoscaling_policies) > 0 ? 1 : 0

  resource_id = "service/${local.cluster_name}/${aws_ecs_service.service[0].name}"

  service_namespace  = "ecs"
  scalable_dimension = "ecs:service:DesiredCount"

  # We control desired count through the autoscaling target as desired_count is ignored in the ECS service.
  min_capacity = var.autoscaling_capacity.min
  max_capacity = var.autoscaling_capacity.max
}

resource "aws_appautoscaling_policy" "ecs_service" {
  for_each = { for k, v in var.autoscaling_policies : k => v }

  name = "${var.service_name}-scaling-${each.key}"
  # Step Scaling is also available, but it's explicitly not recommended by the AWS docs.
  policy_type        = each.value.policy_type
  resource_id        = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service[0].service_namespace

  dynamic "predictive_scaling_policy_configuration" {
    for_each = each.value.policy_type == "PredictiveScaling" ? [1] : []

    content {
      mode = each.value.predictive_scaling_mode
      metric_specification {
        target_value = each.value.target_value

        dynamic "predefined_metric_pair_specification" {
          for_each = each.value.predefined_metric_pair_type != null ? [1] : []
          content {
            predefined_metric_type = each.value.predefined_metric_pair_type
            resource_label         = each.value.resource_label
          }
        }

        # Option 2: Use separate predefined load and scaling metrics
        dynamic "predefined_load_metric_specification" {
          for_each = each.value.predefined_load_metric_type != null ? [1] : []
          content {
            predefined_metric_type = each.value.predefined_load_metric_type
            resource_label         = each.value.resource_label
          }
        }

        dynamic "predefined_scaling_metric_specification" {
          for_each = each.value.predefined_scaling_metric_type != null ? [1] : []
          content {
            predefined_metric_type = each.value.predefined_scaling_metric_type
            resource_label         = each.value.resource_label
          }
        }
      }
    }
  }

  dynamic "target_tracking_scaling_policy_configuration" {
    for_each = each.value.policy_type == "TargetTrackingScaling" ? [1] : []

    content {
      dynamic "predefined_metric_specification" {
        for_each = each.value.predefined_metric_type != null ? [1] : []
        content {
          predefined_metric_type = each.value.predefined_metric_type
          resource_label         = each.value.resource_label
        }
      }

      dynamic "customized_metric_specification" {
        for_each = length(coalesce(each.value.custom_metrics, [])) > 0 ? [1] : []
        content {
          dynamic "metrics" {
            for_each = each.value.custom_metrics

            content {
              label       = metrics.value.label
              id          = metrics.value.id
              expression  = metrics.value.expression
              return_data = metrics.value.return_data

              dynamic "metric_stat" {
                for_each = metrics.value.metric_stat[*]

                content {
                  metric {
                    metric_name = metric_stat.value.metric.metric_name
                    namespace   = metric_stat.value.metric.namespace

                    dynamic "dimensions" {
                      for_each = metric_stat.value.metric.dimensions
                      content {
                        name  = dimensions.value.name
                        value = dimensions.value.value
                      }
                    }
                  }
                  stat = metric_stat.value.stat
                }
              }
            }
          }
        }
      }

      target_value       = each.value.target_value
      scale_in_cooldown  = try(each.value.scale_in_cooldown, null)
      scale_out_cooldown = try(each.value.scale_out_cooldown, null)
    }
  }

  lifecycle {
    precondition {
      condition     = !(each.value.predefined_metric_type != null && length(coalesce(each.value.custom_metrics, [])) > 0)
      error_message = "Cannot define autoscaling predefined metric type and custom metrics at the same time"
    }
  }
}

# There is an issue with the AWS provider when it comes to creating multiple
# autoscaling groups. This makes the creation of any n+1 scheduled action
# fail on first create, which in turn requires multiple runs of apply.
#
# For more information, check out this issue on GitHub:
# https://github.com/hashicorp/terraform-provider-aws/issues/17915
resource "aws_appautoscaling_scheduled_action" "ecs_service" {
  for_each = {
    for v in var.autoscaling_schedule.schedules : v.schedule => v
    if length(var.autoscaling_policies) > 0
  }

  name               = "${var.service_name}-scheduled-scaling"
  resource_id        = aws_appautoscaling_target.ecs_service[0].resource_id
  scalable_dimension = aws_appautoscaling_target.ecs_service[0].scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs_service[0].service_namespace

  timezone = var.autoscaling_schedule.timezone
  schedule = each.value.schedule

  scalable_target_action {
    min_capacity = each.value.min_capacity
    max_capacity = each.value.max_capacity
  }
}
