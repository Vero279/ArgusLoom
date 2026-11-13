resource "aws_vpc" "demo" {
  cidr_block = "10.10.0.0/16"
}

resource "aws_security_group" "public" {
  name = "demo-public-sg"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "internal" {
  name = "demo-internal-sg"
}

resource "aws_instance" "web" {
  ami                    = "ami-demo"
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.public.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name
  user_data              = "#!/bin/sh\naws lambda invoke --function-name ${aws_lambda_function.handler.arn} /tmp/result\naws s3 cp /tmp/result s3://${aws_s3_bucket.artifacts.bucket}/result"
}

resource "aws_instance" "worker" {
  ami                    = "ami-demo"
  instance_type          = "t3.small"
  vpc_security_group_ids = [aws_security_group.internal.id]
  iam_instance_profile   = aws_iam_instance_profile.web.name
}

resource "aws_iam_role" "instance" {
  name = "demo-instance-role"
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
  name = "demo-instance-profile"
  role = aws_iam_role.instance.name
}

resource "aws_iam_policy" "bucket_access" {
  name        = "demo-bucket-access"
  description = "Access policy for the artifacts bucket"
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
  bucket = "argusloom-demo-artifacts"
}

resource "aws_db_instance" "database" {
  identifier             = "demo-database"
  allocated_storage      = 20
  engine                 = "postgres"
  instance_class         = "db.t3.micro"
  vpc_security_group_ids = [aws_security_group.internal.id]
}

resource "aws_lambda_function" "handler" {
  function_name = "argus-demo-handler"
  role          = aws_iam_role.instance.arn
  runtime       = "python3.11"
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
  function_name = "argus-demo-processor"
  role          = aws_iam_role.instance.arn
  runtime       = "python3.11"
  environment {
    variables = {
      DATABASE_ENDPOINT = aws_db_instance.database.endpoint
    }
  }
}

resource "aws_sqs_queue" "jobs" {
  name = "argus-demo-jobs"
}

resource "aws_cloudwatch_log_group" "lambda" {
  name       = "/aws/lambda/argus-demo-handler"
  kms_key_id = aws_kms_key.logs.arn
}

resource "aws_kms_key" "logs" {
  description = "Encrypt demo Lambda logs"
}
