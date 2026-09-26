variable "subnet_ids" { type = list(string) }

resource "aws_lb" "nlb" {
  name               = "sentry-nlb"
  internal           = true
  load_balancer_type = "network"
  subnets            = var.subnet_ids
}

resource "aws_lb_target_group" "this" {
  name     = "sentry-tg"
  port     = 9000
  protocol = "TCP"
}

resource "aws_lb_listener" "this" {
  load_balancer_arn = aws_lb.nlb.arn
  port              = 9000
  protocol          = "TCP"
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.this.arn
  }
}
