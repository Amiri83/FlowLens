terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "potato/terraform.tfstate"
    region = "us-east-1"
  }
}

module "network" {
  source = "../banana"
  cidr   = "10.0.0.0/16"
}
