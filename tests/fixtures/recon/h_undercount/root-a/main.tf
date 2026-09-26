terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "root-a/terraform.tfstate"
    region = "us-east-1"
  }
}

module "nlb" {
  source = "../modules/nlb"
  name   = "root-a"
}

resource "aws_lambda_function" "this" {
  function_name = "root-a"
  role          = "arn:aws:iam::123456789012:role/root-a"
  handler       = "main.handler"
  runtime       = "python3.12"
}
