terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "ca-central-1"
}

resource "aws_iam_role" "lambda_execution_role" {
  name = "authorizer_lambda_execution_role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      },
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_execution_policy" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"                
}

resource "aws_cloudwatch_log_group" "authorizer_lambda_log_group" {
  name = "/aws/lambda/oag-authorizer-lambda"
  retention_in_days = 14
}

resource "aws_lambda_function" "authorizer_lambda" {
  function_name = "oag-authorizer-lambda"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/../lambda.zip"
  role          = aws_iam_role.lambda_execution_role.arn

  environment {
    variables = {
      OIDC_URL = var.oidc_url
      EXPIRED_TOKEN_EXEMPTED = var.expiredTokenExempted
    }
  }

  logging_config {
    log_group = aws_cloudwatch_log_group.authorizer_lambda_log_group.name
    log_format = "JSON"
    system_log_level = "DEBUG"
  }
}