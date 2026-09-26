variable "bucket" {}

resource "aws_s3_bucket" "scratch" {
  bucket = var.bucket
}
