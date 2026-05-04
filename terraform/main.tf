terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = merge(var.tags, {
      Project   = var.project
      ManagedBy = "terraform"
    })
  }
}

# ACM for CloudFront must be in us-east-1 regardless of home region
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"
}

data "aws_caller_identity" "current" {}

resource "random_password" "admin_key" {
  length  = 40
  special = false
}

locals {
  admin_key         = var.admin_api_key != "" ? var.admin_api_key : random_password.admin_key.result
  account_id        = data.aws_caller_identity.current.account_id
  hosts_table_name  = "${var.project}-hosts"
  checks_table_name = "${var.project}-checks"
  function_name     = "${var.project}-management"
  lambda_zip        = "${path.module}/../dist/management.zip"
}

# ── SSM: admin key ────────────────────────────────────────────────────────────
resource "aws_ssm_parameter" "admin_key" {
  name        = "/${var.project}/admin-key"
  description = "Admin API key for ${var.project} management Lambda"
  type        = "SecureString"
  value       = local.admin_key
  overwrite   = true
}

# ── DynamoDB: hosts + region records + settings ───────────────────────────────
# Single table storing host configs, deployed region records (__region__*),
# and a settings pseudo-item (__settings__).
resource "aws_dynamodb_table" "hosts" {
  name         = local.hosts_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "host_id"

  attribute {
    name = "host_id"
    type = "S"
  }

  point_in_time_recovery { enabled = true }
}

# ── DynamoDB: check results ───────────────────────────────────────────────────
resource "aws_dynamodb_table" "checks" {
  name         = local.checks_table_name
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "host_id"
  range_key    = "checked_at"

  attribute {
    name = "host_id"
    type = "S"
  }
  attribute {
    name = "checked_at"
    type = "S"
  }

  # TTL: each check item carries a `ttl` Unix timestamp; DynamoDB deletes it automatically.
  ttl {
    attribute_name = "ttl"
    enabled        = true
  }

  point_in_time_recovery { enabled = true }
}

# ── CloudWatch Logs ───────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "management" {
  name              = "/aws/lambda/${local.function_name}"
  retention_in_days = var.log_retention_days
}

# ── IAM: management Lambda role ───────────────────────────────────────────────
resource "aws_iam_role" "management" {
  name = "${var.project}-management"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "lambda.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy" "management" {
  name = "${var.project}-management"
  role = aws_iam_role.management.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "OwnLogs"
        Effect   = "Allow"
        Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
        Resource = "${aws_cloudwatch_log_group.management.arn}:*"
      },
      {
        Sid    = "Data"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem",
          "dynamodb:DeleteItem", "dynamodb:Query", "dynamodb:Scan",
          "dynamodb:DescribeTable"
        ]
        Resource = [
          aws_dynamodb_table.hosts.arn,
          aws_dynamodb_table.checks.arn,
        ]
      },
      {
        Sid      = "AdminKey"
        Effect   = "Allow"
        Action   = ["ssm:GetParameter"]
        Resource = aws_ssm_parameter.admin_key.arn
      },
      {
        Sid    = "CognitoAdminAuth"
        Effect = "Allow"
        Action = [
          "cognito-idp:AssociateSoftwareToken",
          "cognito-idp:ChangePassword",
          "cognito-idp:DeleteUserAttributes",
          "cognito-idp:InitiateAuth",
          "cognito-idp:SetUserMFAPreference",
          "cognito-idp:RespondToAuthChallenge",
          "cognito-idp:GetUser",
          "cognito-idp:UpdateUserAttributes",
          "cognito-idp:VerifySoftwareToken",
        ]
        Resource = "*"
      },
      {
        Sid      = "Alerts"
        Effect   = "Allow"
        Action   = ["sns:Publish"]
        Resource = "arn:aws:sns:${var.aws_region}:${local.account_id}:*"
      },
      {
        Sid    = "CustomDomain"
        Effect = "Allow"
        Action = [
          "acm:RequestCertificate",
          "acm:DescribeCertificate",
          "acm:DeleteCertificate",
          "acm:AddTagsToCertificate",
          "cloudfront:CreateDistribution",
          "cloudfront:GetDistribution",
          "cloudfront:GetDistributionConfig",
          "cloudfront:UpdateDistribution",
          "cloudfront:DeleteDistribution",
        ]
        Resource = "*"
      },
      {
        Sid      = "Metrics"
        Effect   = "Allow"
        Action   = ["cloudwatch:GetMetricStatistics"]
        Resource = "*"
      },
      # ── Permissions to manage monitor Lambdas in any region ──────────────
      # Scoped to functions named <project>-monitor-* in this account.
      {
        Sid    = "MonitorLambda"
        Effect = "Allow"
        Action = [
          "lambda:InvokeFunction",
          "lambda:CreateFunction",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "lambda:DeleteFunction",
          "lambda:GetFunction",
          "lambda:GetFunctionConfiguration",
          "lambda:AddPermission",
          "lambda:RemovePermission",
          "lambda:ListFunctions",
        ]
        Resource = "arn:aws:lambda:*:${local.account_id}:function:${var.project}-monitor-*"
      },
      # ── Create/delete the monitor IAM role (global, reused across regions) ─
      {
        Sid    = "MonitorIAM"
        Effect = "Allow"
        Action = [
          "iam:CreateRole",
          "iam:GetRole",
          "iam:PutRolePolicy",
          "iam:GetRolePolicy",
          "iam:DeleteRole",
          "iam:DeleteRolePolicy",
          "iam:PassRole",
        ]
        Resource = "arn:aws:iam::${local.account_id}:role/${var.project}-monitor"
      },
      # ── CloudWatch log groups for monitors ────────────────────────────────
      {
        Sid    = "MonitorLogs"
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:PutRetentionPolicy",
          "logs:DeleteLogGroup",
          "logs:DescribeLogGroups",
        ]
        Resource = "arn:aws:logs:*:${local.account_id}:log-group:/aws/lambda/${var.project}-monitor-*"
      },
      # ── STS: needed to get account ID for role ARN construction ──────────
      {
        Sid      = "STS"
        Effect   = "Allow"
        Action   = ["sts:GetCallerIdentity"]
        Resource = "*"
      },
    ]
  })
}

# ── Lambda function ───────────────────────────────────────────────────────────
resource "aws_lambda_function" "management" {
  function_name = local.function_name
  role          = aws_iam_role.management.arn
  filename      = local.lambda_zip
  handler       = "handler.handler"
  runtime       = "python3.12"
  timeout       = var.lambda_timeout_seconds
  memory_size   = var.lambda_memory_mb

  source_code_hash = filebase64sha256(local.lambda_zip)

  environment {
    variables = {
      HOSTS_TABLE       = local.hosts_table_name
      CHECKS_TABLE      = local.checks_table_name
      ADMIN_KEY_PARAM   = aws_ssm_parameter.admin_key.name
      HOME_REGION       = var.aws_region
      PROJECT           = var.project
      RETENTION_DAYS    = tostring(var.retention_days)
      STATUS_PAGE_TITLE = var.status_page_title
      STATUS_PAGE_DESC  = var.status_page_description
    }
  }

  depends_on = [aws_cloudwatch_log_group.management]
}

resource "aws_cloudwatch_event_rule" "management_schedule" {
  name                = "${var.project}-management-schedule"
  description         = "${var.project} central monitor orchestration schedule"
  schedule_expression = var.orchestration_schedule
}

resource "aws_cloudwatch_event_target" "management_schedule" {
  rule      = aws_cloudwatch_event_rule.management_schedule.name
  target_id = "management-lambda"
  arn       = aws_lambda_function.management.arn
}

resource "aws_lambda_permission" "allow_eventbridge_management" {
  statement_id  = "AllowEventBridgeManagement"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.management.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.management_schedule.arn
}

# ── Lambda Function URL ───────────────────────────────────────────────────────
# Auth is handled at the application layer (admin key in SSM).
# Set AuthType = AWS_IAM here if you want to restrict to signed requests.
resource "aws_lambda_function_url" "management" {
  function_name      = aws_lambda_function.management.function_name
  authorization_type = "NONE"

  cors {
    allow_origins = ["*"]
    allow_methods = ["GET", "POST", "PUT", "DELETE"]
    allow_headers = ["Content-Type", "Authorization"]
    max_age       = 300
  }
}

resource "aws_lambda_permission" "allow_public_function_url" {
  statement_id        = "AllowPublicFunctionUrl"
  action              = "lambda:InvokeFunctionUrl"
  function_name       = aws_lambda_function.management.function_name
  principal           = "*"
  function_url_auth_type = "NONE"
}

resource "aws_lambda_permission" "allow_public_function_url_invoke_function" {
  statement_id  = "AllowPublicFunctionUrlInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.management.function_name
  principal     = "*"
  invoked_via_function_url = true
}

# ── Optional: custom domain via CloudFront + ACM + Route53 ───────────────────
data "aws_route53_zone" "main" {
  count = var.custom_domain != "" ? 1 : 0
  name  = var.hosted_zone_name
}

resource "aws_acm_certificate" "status" {
  count             = var.custom_domain != "" ? 1 : 0
  domain_name       = var.custom_domain
  validation_method = "DNS"
  provider          = aws.us_east_1
  lifecycle { create_before_destroy = true }
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.custom_domain != "" ? {
    for dvo in aws_acm_certificate.status[0].domain_validation_options :
    dvo.domain_name => dvo
  } : {}
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = each.value.resource_record_name
  type    = each.value.resource_record_type
  records = [each.value.resource_record_value]
  ttl     = 60
}

resource "aws_acm_certificate_validation" "status" {
  count                   = var.custom_domain != "" ? 1 : 0
  certificate_arn         = aws_acm_certificate.status[0].arn
  validation_record_fqdns = [for r in aws_route53_record.cert_validation : r.fqdn]
  provider                = aws.us_east_1
}

resource "aws_cloudfront_distribution" "status" {
  count   = var.custom_domain != "" ? 1 : 0
  enabled = true
  comment = "${var.project} status page"
  aliases = [var.custom_domain]

  origin {
    domain_name = replace(aws_lambda_function_url.management.function_url, "https://", "")
    origin_id   = "lambda"
    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    target_origin_id       = "lambda"
    viewer_protocol_policy = "redirect-to-https"
    allowed_methods        = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods         = ["GET", "HEAD"]
    forwarded_values {
      query_string = true
      headers      = ["Authorization"]
      cookies { forward = "none" }
    }
    min_ttl     = 0
    default_ttl = 30
    max_ttl     = 60
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.status[0].certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }
}

resource "aws_route53_record" "status" {
  count   = var.custom_domain != "" ? 1 : 0
  zone_id = data.aws_route53_zone.main[0].zone_id
  name    = var.custom_domain
  type    = "A"
  alias {
    name                   = aws_cloudfront_distribution.status[0].domain_name
    zone_id                = aws_cloudfront_distribution.status[0].hosted_zone_id
    evaluate_target_health = false
  }
}
