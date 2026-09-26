terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "root-b/terraform.tfstate"
    region = "us-east-1"
  }
}

module "nlb" {
  source = "../modules/nlb"
  name   = "root-b"
}

resource "aws_lambda_function" "this" {
  function_name = "root-b"
  role          = "arn:aws:iam::123456789012:role/root-b"
  handler       = "main.handler"
  runtime       = "python3.12"
}
