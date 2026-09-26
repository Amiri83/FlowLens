module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.0"
  name    = "a"
}

module "private_lib" {
  source = "git::https://deploy:s3cr3t-t0ken@git.example.com/org/tf-modules.git//lb?ref=v1.2.0"
}
