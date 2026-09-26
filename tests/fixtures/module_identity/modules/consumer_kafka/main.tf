variable "function_name" { type = string }
variable "cluster_arn" { type = string }

resource "aws_iam_role" "this" {
  name               = "${var.function_name}-role"
  assume_role_policy = "{}"
}

resource "aws_lambda_function" "this" {
  function_name = var.function_name
  role          = aws_iam_role.this.arn
  handler       = "index.handler"
  runtime       = "java21"
}

resource "aws_lambda_event_source_mapping" "this" {
  event_source_arn  = var.cluster_arn
  function_name     = aws_lambda_function.this.arn
  topics            = ["email2case"]
  starting_position = "LATEST"
}
