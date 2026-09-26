variable "name" {}

resource "aws_lb" "this" {
  name               = var.name
  load_balancer_type = "network"
}
