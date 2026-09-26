variable "function_name" {}

resource "aws_lambda_function" "tpl" {
  function_name = var.function_name
  role          = "arn:aws:iam::123456789012:role/tpl"
  handler       = "main.handler"
  runtime       = "python3.12"
}
