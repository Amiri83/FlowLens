terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "application/terraform.tfstate"
    region = "us-east-1"
  }
}

module "network" {
  source = "../shared-network"
  cidr   = "10.20.0.0/16"
}

module "dns" {
  source = "../shared-dns"
}

module "queue" {
  source = "../shared-queue"
}

resource "aws_lambda_function" "app" {
  function_name = "app"
  role          = "arn:aws:iam::123456789012:role/app"
  handler       = "main.handler"
  runtime       = "python3.12"
}
