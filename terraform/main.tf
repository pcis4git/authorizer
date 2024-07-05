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

resource "aws_lambda_function" "my_lambda" {
  function_name = "oag-authorizer-lambda"
  handler       = "index.handler"
  runtime       = "nodejs20.x"
  filename      = "${path.module}/../lambda.zip"
  role          = aws_iam_role.lambda_execution_role.arn

  environment {
    variables = {
      OIDC_URL = var.oidc_url
    }
  }  
}