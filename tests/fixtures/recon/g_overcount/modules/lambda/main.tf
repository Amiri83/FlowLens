variable "function_name" {}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = "arn:aws:iam::123456789012:role/lambda"
  handler       = "main.handler"
  runtime       = "python3.12"
}
