provider "aws" {
  region = var.region
}

variable "region" {
  default = "us-east-1"
}

resource "aws_lambda_function" "api" {
  function_name = "api"
  role          = "arn:aws:iam::123456789012:role/api"
  handler       = "main.handler"
  runtime       = "python3.12"
}
