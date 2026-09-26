variable "env" {}

module "helper" {
  source = "../modules/helper"
}

resource "aws_lambda_function" "legacy_a" {
  function_name = "a-${var.env}"
  role          = "arn:aws:iam::123456789012:role/a"
  handler       = "main.handler"
  runtime       = "python3.12"
}

resource "aws_lambda_function" "legacy_b" {
  function_name = "b-${var.env}"
  role          = "arn:aws:iam::123456789012:role/b"
  handler       = "main.handler"
  runtime       = "python3.12"
}

resource "aws_lambda_function" "legacy_c" {
  function_name = "c-${var.env}"
  role          = "arn:aws:iam::123456789012:role/c"
  handler       = "main.handler"
  runtime       = "python3.12"
}
