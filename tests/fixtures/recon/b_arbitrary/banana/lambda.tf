resource "aws_vpc" "main" {
  cidr_block = var.cidr
}

resource "aws_subnet" "private" {
  count      = var.subnet_count
  vpc_id     = aws_vpc.main.id
  cidr_block = cidrsubnet(var.cidr, 8, count.index)
}

output "vpc_id" {
  value = aws_vpc.main.id
}
