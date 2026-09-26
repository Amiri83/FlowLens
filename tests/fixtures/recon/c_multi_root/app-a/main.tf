terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "app-a/terraform.tfstate"
    region = "us-east-1"
  }
}

module "svc" {
  source = "../shared"
  name   = "app-a"
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-a-logs"
}
