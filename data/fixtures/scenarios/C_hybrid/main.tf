resource "aws_vpc" "demo" {
  cidr_block = "10.30.0.0/16"
}

resource "aws_security_group" "public" {
  name = "hybrid-public-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "internal" {
  name = "hybrid-internal-sg"
}

resource "aws_instance" "web" {
  ami                    = "ami-hybrid"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name
  user_data              = "#!/bin/sh\naws lambda invoke --function-name ${aws_lambda_function.handler.arn} /tmp/result\naws s3 cp /tmp/result s3://${aws_s3_bucket.artifacts.bucket}/result"
}

resource "aws_instance" "worker" {
  ami                    = "ami-hybrid"
  instance_type          = "t3.small"
  vpc_security_group_ids = [aws_security_group.internal.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name
}

resource "aws_iam_role" "instance" {
  name = "hybrid-instance-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

resource "aws_iam_instance_profile" "web" {
  name = "hybrid-instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_iam_policy" "bucket_access" {
  name        = "hybrid-bucket-access"
  description = "Access policy for the hybrid artifacts bucket"
  tags = {
    SourceBucket = aws_s3_bucket.artifacts.bucket
  }
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action   = ["s3:GetObject", "s3:PutObject"]
      Effect   = "Allow"
      Resource = "${aws_s3_bucket.artifacts.arn}/*"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "instance_bucket_access" {
  role       = aws_iam_role.instance.name
  policy_arn = aws_iam_policy.bucket_access.arn
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "argusloom-hybrid-artifacts"
}

resource "aws_db_instance" "database" {
  identifier             = "hybrid-database"
  allocated_storage      = 20
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.internal.id]
}

resource "aws_lambda_function" "handler" {
  function_name = "argus-hybrid-handler"
  role          = aws_iam_role.instance.arn
  runtime       = "python3.11"
  vpc_security_group_ids = [aws_security_group.public.id]
  environment {
    variables = {
      QUEUE_URL = aws_sqs_queue.jobs.url
      NEXT_FN   = aws_lambda_function.processor.arn
    }
  }
  logging_config {
    log_group = aws_cloudwatch_log_group.lambda.name
  }
}

resource "aws_lambda_function" "processor" {
  function_name = "argus-hybrid-processor"
  role          = aws_iam_role.instance.arn
  runtime       = "python3.11"
  environment {
    variables = {
      DATABASE_ENDPOINT = aws_db_instance.database.endpoint
    }
  }
}

resource "aws_sqs_queue" "jobs" {
  name = "argus-hybrid-jobs"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name       = "/aws/lambda/argus-hybrid-handler"
  kms_key_id = aws_kms_key.logs.arn
}

resource "aws_kms_key" "logs" {
  description = "Encrypt hybrid Lambda logs"
}

resource "aws_db_instance" "public_analytics" {
  identifier             = "hybrid-public-analytics"
  allocated_storage      = 30
  engine                 = "postgres"
  instance_class         = "db.t3.small"
  vpc_security_group_ids = [aws_security_group.public.id]
}

resource "aws_db_instance" "internal_warehouse" {
  identifier             = "hybrid-internal-warehouse"
  allocated_storage      = 40
  engine                 = "postgres"
  instance_class         = "db.t3.small"
  vpc_security_group_ids = [aws_security_group.internal.id]
}

resource "aws_lambda_function" "queue_worker" {
  function_name = "argus-hybrid-queue-worker"
  role          = aws_iam_role.instance.arn
  runtime       = "python3.11"
  environment {
    variables = {
      QUEUE_URL         = aws_sqs_queue.jobs.url
      DATABASE_ENDPOINT = aws_db_instance.public_analytics.endpoint
    }
  }
}

resource "aws_lambda_function" "s3_writer" {
  function_name = "argus-hybrid-s3-writer"
  role          = aws_iam_role.instance.arn
  runtime       = "python3.11"
  environment {
    variables = {
      DESTINATION_BUCKET = aws_s3_bucket.artifacts.bucket
      ENCRYPTION_KEY     = aws_kms_key.logs.arn
    }
  }
}

resource "aws_api_gateway_rest_api" "api" {
  name = "argus-hybrid-api"
  endpoint_configuration {
    types = ["REGIONAL"]
    vpc_endpoint_ids = [aws_vpc.demo.id]
  }
}

resource "aws_api_gateway_stage" "production" {
  stage_name   = "production"
  rest_api_id  = aws_api_gateway_rest_api.api.id
  deployment_id = aws_lambda_function.handler.arn
}
