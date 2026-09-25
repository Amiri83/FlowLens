# FlowLens example stack: public ALB -> ECS service, plus an API Gateway ->
# Lambda integration, inside one VPC. Used by the README walkthrough:
#
#   flowlens scan examples/terraform --db data/example.db
#   flowlens path aws_api_gateway_integration.hello aws_subnet.private_a --db data/example.db
#   flowlens path aws_lb_listener.https aws_vpc.main --db data/example.db
#
# Nothing here is ever applied by FlowLens; it only parses the files.

provider "aws" {
  region = "us-east-1"
}

resource "aws_vpc" "main" {
  cidr_block = "10.20.0.0/16"
  tags = {
    Name = "shop-vpc"
  }
}

resource "aws_subnet" "public_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.1.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "shop-public-a"
  }
}

resource "aws_subnet" "public_b" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.2.0/24"
  availability_zone = "us-east-1b"
  tags = {
    Name = "shop-public-b"
  }
}

resource "aws_subnet" "private_a" {
  vpc_id            = aws_vpc.main.id
  cidr_block        = "10.20.11.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "shop-private-a"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "shop-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id
  tags = {
    Name = "shop-public-rt"
  }
}

resource "aws_route" "public_internet" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.main.id
}

resource "aws_security_group" "alb" {
  name   = "shop-alb-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "app" {
  name   = "shop-app-sg"
  vpc_id = aws_vpc.main.id

  ingress {
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
}

resource "aws_lb" "web" {
  name               = "shop-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = [aws_subnet.public_a.id, aws_subnet.public_b.id]
}

resource "aws_lb_target_group" "app" {
  name     = "shop-app-tg"
  port     = 8080
  protocol = "HTTP"
  vpc_id   = aws_vpc.main.id
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}

resource "aws_ecs_cluster" "main" {
  name = "shop-cluster"
}

resource "aws_ecs_task_definition" "app" {
  family = "shop-app"
  cpu    = "256"
  memory = "512"
}

resource "aws_ecs_service" "app" {
  name            = "shop-app"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = 2

  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "app"
    container_port   = 8080
  }

  network_configuration {
    subnets         = [aws_subnet.private_a.id]
    security_groups = [aws_security_group.app.id]
  }
}

resource "aws_lambda_function" "hello" {
  function_name = "shop-hello"
  runtime       = "python3.12"
  handler       = "app.handler"

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id]
    security_group_ids = [aws_security_group.app.id]
  }
}

resource "aws_api_gateway_rest_api" "shop" {
  name = "shop-api"
}

resource "aws_api_gateway_integration" "hello" {
  rest_api_id             = aws_api_gateway_rest_api.shop.id
  http_method             = "GET"
  type                    = "AWS_PROXY"
  integration_http_method = "POST"
  uri                     = aws_lambda_function.hello.invoke_arn
}
