variable "name" {}

resource "aws_db_instance" "main" {
  count          = var.name == "" ? 0 : 1
  identifier     = var.name
  instance_class = "db.t3.micro"
}
