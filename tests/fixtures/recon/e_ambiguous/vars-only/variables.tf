variable "env" {
  default = "dev"
}

output "env" {
  value = var.env
}
