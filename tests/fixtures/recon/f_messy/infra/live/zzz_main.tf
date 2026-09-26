terraform {
  backend "s3" {}
}

module "app" {
  source = "../../lib/app-stack"
  name   = "shop"
}

module "missing" {
  source = "../../lib/does-not-exist"
}
