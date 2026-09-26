variable "env" {}

resource "aws_lambda_function" "legacy" {
  function_name = "legacy-${var.env}"
  role          = "arn:aws:iam::123456789012:role/legacy"
  handler       = "main.handler"
  runtime       = "python3.12"
}
