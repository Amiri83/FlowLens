module "sentry" {
  source     = "../modules/sentry"
  subnet_ids = ["subnet-0a", "subnet-0b"]
}

module "observability" {
  source     = "../modules/observability"
  subnet_ids = ["subnet-0c", "subnet-0d"]
}
