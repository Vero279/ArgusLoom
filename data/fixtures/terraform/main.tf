resource "aws_vpc" "main" {
  cidr_block = "10.0.0.0/16"
}

resource "aws_security_group" "app" {
  name = "app-sg"

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-1234"
  instance_type = "t3.micro"
  vpc_security_group_ids = [aws_security_group.app.id]
}

resource "aws_s3_bucket" "logs" {
  bucket = "argus-logs-demo"
}

resource "aws_iam_role" "lambda_exec" {
  name = "argus-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
    }]
  })
}

resource "aws_lambda_function" "handler" {
  function_name = "argus-handler"
  role          = aws_iam_role.lambda_exec.arn
  runtime       = "python3.11"
}

resource "aws_db_instance" "db" {
  identifier     = "argus-db"
  allocated_storage = 20
  engine         = "postgres"
  instance_class = "db.t3.micro"
}

resource "aws_api_gateway_rest_api" "api" {
  name = "argus-api"
}
