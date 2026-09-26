variable "function_name" { type = string }
variable "topic_arn" { type = string }

resource "aws_iam_role" "this" {
  name               = "${var.function_name}-role"
  assume_role_policy = "{}"
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = aws_iam_role.this.arn
  handler       = "index.handler"
  runtime       = "python3.12"
}

resource "aws_sns_topic_subscription" "this" {
  topic_arn = var.topic_arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.this.arn
}
