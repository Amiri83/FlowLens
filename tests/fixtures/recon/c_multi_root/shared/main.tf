variable "name" {
  type = string
}

resource "aws_lb" "this" {
  name               = var.name
  load_balancer_type = "application"
}
