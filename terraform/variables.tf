variable "aws_region" {
  description = "Home AWS region — where DynamoDB, management Lambda, SSM, and all data live."
  type        = string
  default     = "us-east-1"
}

variable "project" {
  description = "Short prefix applied to every resource name (e.g. 'uptime'). Must be unique per account."
  type        = string
  default     = "uptime"

  validation {
    condition     = can(regex("^[a-z0-9-]{2,20}$", var.project))
    error_message = "project must be 2–20 lowercase letters, numbers, or hyphens."
  }
}

variable "admin_api_key" {
  description = <<-EOF
    Admin API key for the /admin UI and all /api/* endpoints.
    Leave blank to auto-generate a secure 40-character key (recommended).
    Stored in SSM Parameter Store as a SecureString (KMS-encrypted).
    Retrieve after deploy: terraform output -raw admin_key
  EOF
  type        = string
  default     = ""
  sensitive   = true
}

variable "retention_days" {
  description = <<-EOF
    Days to keep check history in DynamoDB (auto-deleted via TTL after expiry).
    7   = minimal storage, short debugging window
    90  = recommended balance (default)
    365 = full year — still cheap at ~$0.06/mo for 10 hosts × 3 regions × 1-min checks
  EOF
  type        = number
  default     = 90

  validation {
    condition     = var.retention_days >= 7 && var.retention_days <= 365
    error_message = "retention_days must be between 7 and 365."
  }
}

variable "status_page_title" {
  description = "Default title for the public status page (editable later in the admin UI)."
  type        = string
  default     = "System Status"
}

variable "status_page_description" {
  description = "Default subtitle on the public status page (editable later in the admin UI)."
  type        = string
  default     = "Real-time status of our services"
}

variable "custom_domain" {
  description = <<-EOF
    Optional custom domain (e.g. 'status.yourdomain.com').
    Requires hosted_zone_name. Leave blank to use the Lambda Function URL (free).
    When set, creates: ACM cert, CloudFront distribution, Route53 records.
  EOF
  type        = string
  default     = ""
}

variable "hosted_zone_name" {
  description = "Route53 hosted zone name (e.g. 'yourdomain.com'). Required when custom_domain is set."
  type        = string
  default     = ""
}

variable "lambda_memory_mb" {
  description = <<-EOF
    Management Lambda memory in MB.
    256 = recommended (handles status page for 100+ hosts, admin UI)
    512 = for very large host lists (500+)
  EOF
  type        = number
  default     = 256
}

variable "lambda_timeout_seconds" {
  description = <<-EOF
    Management Lambda max execution time.
    Must be long enough for region deployment operations (~30–60s each).
    300 = 5 minutes — covers all region deploy/teardown operations with headroom.
  EOF
  type        = number
  default     = 300
}

variable "orchestration_schedule" {
  description = <<-EOF
    EventBridge schedule expression for the management Lambda orchestrator.
    This is the single runtime schedule that triggers all regional worker checks.
    Example: rate(1 minute)
  EOF
  type        = string
  default     = "rate(1 minute)"
}

variable "log_retention_days" {
  description = "Days to retain CloudWatch logs for the management Lambda."
  type        = number
  default     = 14
}

variable "tags" {
  description = "Extra tags applied to all AWS resources."
  type        = map(string)
  default     = {}
}
