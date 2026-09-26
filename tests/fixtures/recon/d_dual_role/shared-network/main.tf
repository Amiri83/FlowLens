terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "shared-network/terraform.tfstate"
    region = "us-east-1"
  }
}

provider "aws" {
  region = "us-east-1"
}

variable "cidr" {
  type = string
}

resource "aws_vpc" "main" {
  cidr_block = var.cidr
}
