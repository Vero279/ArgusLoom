terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.84.0"
    }
  }
}

provider "aws" {
  region                      = "us-east-1"
  access_key                  = "test"
  secret_key                  = "test"
  skip_credentials_validation = true
  skip_metadata_api_check     = true
  skip_requesting_account_id  = true
  s3_use_path_style           = true

  endpoints {
    s3 = "http://127.0.0.1:4566"
  }
}

resource "aws_s3_bucket" "cti_corpus" {
  bucket = "argusloom-cti-corpus"
}

resource "aws_s3_bucket_public_access_block" "cti_corpus" {
  bucket                  = aws_s3_bucket.cti_corpus.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "cti_corpus" {
  bucket = aws_s3_bucket.cti_corpus.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_policy" "cti_corpus" {
  bucket = aws_s3_bucket.cti_corpus.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        AWS = "arn:aws:iam::000000000000:role/cti-corpus-writer"
      }
      Action   = ["s3:GetObject", "s3:PutObject"]
      Resource = "${aws_s3_bucket.cti_corpus.arn}/*"
    }]
  })
}
