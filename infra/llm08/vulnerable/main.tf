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
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

resource "aws_s3_bucket_policy" "cti_corpus" {
  bucket = aws_s3_bucket.cti_corpus.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:PutObject"
      Resource  = "${aws_s3_bucket.cti_corpus.arn}/*"
    }]
  })
}
