
locals {
  # Additional conditions create new listener rules not covered by AND or OR logic for existing rules
  all_listener_conditions = flatten([
    for idx, value in var.lb_listeners : concat(
      [
        {
          key               = idx
          listener_arn      = value.listener_arn
          test_listener_arn = value.test_listener_arn
          conditions        = value.conditions
          target_group_key  = idx
        }
      ],
      [for rule_idx, rule in try(value.additional_conditions, []) : {
        key               = "${idx}-additional-${rule_idx}"
        listener_arn      = value.listener_arn
        test_listener_arn = value.test_listener_arn
        conditions        = [rule]
        target_group_key  = idx
      }]
  )])
}

/*
 * == Load Balancer
 *
 * Setup load balancing with an existing load balancer.
 */
resource "aws_lb_target_group" "service" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  vpc_id = var.vpc_id

  target_type = "ip"
  port        = var.application_container.port
  protocol    = var.application_container.protocol
  slow_start  = var.slow_start

  deregistration_delay = var.lb_deregistration_delay

  dynamic "health_check" {
    for_each = [var.lb_health_check]

    content {
      enabled             = lookup(health_check.value, "enabled", null)
      healthy_threshold   = lookup(health_check.value, "healthy_threshold", null)
      interval            = lookup(health_check.value, "interval", null)
      matcher             = lookup(health_check.value, "matcher", null)
      path                = lookup(health_check.value, "path", null)
      port                = lookup(health_check.value, "port", null)
      protocol            = lookup(health_check.value, "protocol", null)
      timeout             = lookup(health_check.value, "timeout", null)
      unhealthy_threshold = lookup(health_check.value, "unhealthy_threshold", null)
    }
  }

  dynamic "stickiness" {
    for_each = var.lb_stickiness[*]
    content {
      type            = var.lb_stickiness.type
      enabled         = var.lb_stickiness.enabled
      cookie_duration = var.lb_stickiness.cookie_duration
      cookie_name     = var.lb_stickiness.cookie_name
    }
  }

  # NOTE: TF is unable to destroy a target group while a listener is attached,
  # therefor we have to create a new one before destroying the old. This also means
  # we have to let it have a random name, and then tag it with the desired name.
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    { Name = "${var.service_name}-target-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "service" {
  for_each = { for lc in local.all_listener_conditions : lc.key => lc }

  listener_arn = each.value.listener_arn

  # Use default forward type if only one target group is defined
  action {
    type = "forward"
    forward {
      target_group {
        arn    = aws_lb_target_group.service[each.value.target_group_key].arn
        weight = 1
      }
      target_group {
        arn    = aws_lb_target_group.secondary[each.value.target_group_key].arn
        weight = 0
      }
    }
  }

  dynamic "condition" {
    for_each = each.value.conditions

    content {
      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        content {
          values = [path_pattern.value]
        }
      }

      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        content {
          values = flatten([host_header.value]) # Accept both a string or a list
        }
      }
      dynamic "http_header" {
        for_each = condition.value.http_header != null ? [condition.value.http_header] : []
        content {
          http_header_name = http_header.value.name
          values           = http_header.value.values
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      # NOTE: This is bound to cause some issues at some point.
      #       This is required because the ECS Deployment will take charge of the weighting
      #       after the initial deploy.
      #       We can not reference the target groups directly.
      #       So here we are just blanket ignoring the whole forward block and hoping it is OK.
      # Relevant issue: https://github.com/hashicorp/terraform-provider-aws/issues/43905
      # Can cause issues if we do changes which triggers recreate to aws_lb_target_group
      action[0]
    ]
  }
}

/*
 * ==== Blue listener setup
 *
 *       Cannot refactor into module without downtime or moved blocks. Omitting for ease of migration.
 */
resource "aws_lb_target_group" "secondary" {
  for_each = { for idx, value in var.lb_listeners : idx => value }

  name   = trimsuffix(substr("${var.service_name}-secondary-${var.application_container.port}-${each.key}", 0, 32), "-")
  vpc_id = var.vpc_id

  target_type = "ip"
  port        = var.application_container.port
  protocol    = var.application_container.protocol
  slow_start  = var.slow_start

  deregistration_delay = var.lb_deregistration_delay

  dynamic "health_check" {
    for_each = [var.lb_health_check]

    content {
      enabled             = lookup(health_check.value, "enabled", null)
      healthy_threshold   = lookup(health_check.value, "healthy_threshold", null)
      interval            = lookup(health_check.value, "interval", null)
      matcher             = lookup(health_check.value, "matcher", null)
      path                = lookup(health_check.value, "path", null)
      port                = lookup(health_check.value, "port", null)
      protocol            = lookup(health_check.value, "protocol", null)
      timeout             = lookup(health_check.value, "timeout", null)
      unhealthy_threshold = lookup(health_check.value, "unhealthy_threshold", null)
    }
  }

  dynamic "stickiness" {
    for_each = var.lb_stickiness[*]
    content {
      type            = var.lb_stickiness.type
      enabled         = var.lb_stickiness.enabled
      cookie_duration = var.lb_stickiness.cookie_duration
      cookie_name     = var.lb_stickiness.cookie_name
    }
  }

  # NOTE: TF is unable to destroy a target group while a listener is attached,
  # therefor we have to create a new one before destroying the old. This also means
  # we have to let it have a random name, and then tag it with the desired name.
  lifecycle {
    create_before_destroy = true
  }

  tags = merge(
    var.tags,
    { Name = "${var.service_name}-secondary-${var.application_container.port}-${each.key}" }
  )
}

resource "aws_lb_listener_rule" "replacement" {
  for_each = { for lc in local.all_listener_conditions : lc.key => lc }

  listener_arn = each.value.test_listener_arn

  # forward blocks require at least two target group blocks
  dynamic "action" {
    for_each = length(aws_lb_target_group.service) > 1 ? [1] : []
    content {
      type = "forward"
      forward {
        target_group {
          arn = aws_lb_target_group.service[each.value.target_group_key].arn
        }
        dynamic "stickiness" {
          for_each = var.lb_stickiness.enabled ? [1] : []
          content {
            enabled  = true
            duration = var.lb_stickiness.cookie_duration
          }
        }
      }
    }
  }

  # Use default forward type if only one target group is defined
  dynamic "action" {
    for_each = length(aws_lb_target_group.secondary) == 1 ? [1] : []
    content {
      type             = "forward"
      target_group_arn = aws_lb_target_group.secondary[each.value.target_group_key].arn
    }
  }

  dynamic "condition" {
    for_each = each.value.conditions

    content {
      dynamic "path_pattern" {
        for_each = condition.value.path_pattern != null ? [condition.value.path_pattern] : []
        content {
          values = [path_pattern.value]
        }
      }

      dynamic "host_header" {
        for_each = condition.value.host_header != null ? [condition.value.host_header] : []
        content {
          values = flatten([host_header.value]) # Accept both a string or a list
        }
      }

      dynamic "http_header" {
        for_each = condition.value.http_header != null ? [condition.value.http_header] : []
        content {
          http_header_name = http_header.value.name
          values           = http_header.value.values
        }
      }
    }
  }

  lifecycle {
    ignore_changes = [
      # NOTE: This is bound to cause some issues at some point.
      #       This is required because the ECS Deployment will take charge of the weighting
      #       after the initial deploy.
      #       We can not reference the target groups directly.
      #       So here we are just blanket ignoring the whole forward block and hoping it is OK.
      # Relevant issue: https://github.com/hashicorp/terraform-provider-aws/issues/43905
      # Can cause issues if we do changes which triggers recreate to aws_lb_target_group
      action[0]
    ]
  }
}
