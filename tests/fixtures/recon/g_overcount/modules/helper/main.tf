variable "suffix" {
  default = "x"
}

resource "aws_lambda_function" "helper" {
  function_name = "helper-${var.suffix}"
  role          = "arn:aws:iam::123456789012:role/helper"
  handler       = "main.handler"
  runtime       = "python3.12"
}
