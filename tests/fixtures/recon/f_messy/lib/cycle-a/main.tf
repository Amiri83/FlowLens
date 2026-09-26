module "b" {
  source = "../cycle-b"
}

resource "aws_sqs_queue" "a" {
  name = "a"
}
