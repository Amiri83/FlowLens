terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "root/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = var.region
}

module "network" {
  source = "../modules/network"
  cidr   = "10.0.0.0/16"
}

resource "aws_lambda_function" "api" {
  function_name = "api"
  role          = "arn:aws:iam::123456789012:role/api"
  handler       = "main.handler"
  runtime       = "python3.12"
}
