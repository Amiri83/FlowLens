terraform {
  backend "s3" {
    bucket = "tf-state"
    key    = "prod/terraform.tfstate"
    region = "us-east-1"
  }
}

module "api" {
  source        = "../../modules/lambda"
  function_name = "api"
}
