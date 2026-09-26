provider "aws" {
  region = "us-east-1"
}

variable "name" {}

resource "aws_lambda_function" "this" {
  function_name = var.name
  role          = "arn:aws:iam::123456789012:role/x"
  handler       = "main.handler"
  runtime       = "python3.12"
}
