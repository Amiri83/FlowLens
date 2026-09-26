terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "app-b/terraform.tfstate"
    region = "us-east-1"
  }
}

module "svc" {
  source = "../shared"
  name   = "app-b"
}

resource "aws_s3_bucket" "logs" {
  bucket = "app-b-logs"
}
