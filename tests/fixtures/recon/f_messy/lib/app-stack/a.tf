variable "name" {}

module "db" {
  source = "./db"
  name   = var.name
}

resource "aws_security_group" "svc" {
  name = var.name

  dynamic "ingress" {
    for_each = var.ports
    content {
      from_port = ingress.value
      to_port   = ingress.value
      protocol  = "tcp"
    }
  }
}

variable "ports" {
  default = [443]
}
