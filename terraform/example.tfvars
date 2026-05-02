# Copy to terraform.tfvars and fill in your values.
# terraform.tfvars is gitignored — it may contain your admin key.

aws_region = "us-east-1"
project    = "uptime"

# Leave blank to auto-generate (recommended).
# Retrieve after deploy: terraform output -raw admin_key
admin_api_key = ""

retention_days = 90

status_page_title       = "System Status"
status_page_description = "Real-time status of our services"

# Uncomment both to use a custom domain (requires Route53 hosted zone):
# custom_domain    = "status.yourdomain.com"
# hosted_zone_name = "yourdomain.com"

lambda_memory_mb       = 256
lambda_timeout_seconds = 300
orchestration_schedule = "rate(1 minute)"
log_retention_days     = 14
