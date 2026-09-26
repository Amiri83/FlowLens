module "a" {
  source = "../cycle-a"
}

resource "aws_sqs_queue" "b" {
  name = "b"
}
