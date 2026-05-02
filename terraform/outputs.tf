output "status_page_url" {
  description = "Public status page URL."
  value       = var.custom_domain != "" ? "https://${var.custom_domain}/" : aws_lambda_function_url.management.function_url
}

output "admin_url" {
  description = "Admin UI URL. Append ?key=<admin_key> in your browser."
  value       = var.custom_domain != "" ? "https://${var.custom_domain}/admin" : "${aws_lambda_function_url.management.function_url}admin"
}

output "management_lambda_url" {
  description = "Raw Lambda Function URL (used as API base)."
  value       = aws_lambda_function_url.management.function_url
}

output "admin_key" {
  description = "Admin API key. Keep secret. Use as Bearer token or ?key= param."
  value       = local.admin_key
  sensitive   = true
}

output "admin_key_ssm_path" {
  description = "SSM path where the admin key is stored (SecureString, KMS-encrypted)."
  value       = aws_ssm_parameter.admin_key.name
}

output "hosts_table" {
  description = "DynamoDB table for host configs and region records."
  value       = aws_dynamodb_table.hosts.name
}

output "checks_table" {
  description = "DynamoDB table for check history."
  value       = aws_dynamodb_table.checks.name
}

output "home_region" {
  description = "Home AWS region."
  value       = var.aws_region
}

output "next_steps" {
  description = "What to do after apply."
  value       = <<-EOT
    1. Open admin UI:
       ${var.custom_domain != "" ? "https://${var.custom_domain}/admin" : "${aws_lambda_function_url.management.function_url}admin"}?key=$(terraform output -raw admin_key)

    2. Add your first host in the Hosts tab.

    3. Go to the Regions tab and add worker regions
       (e.g. us-east-1, eu-west-1, ap-southeast-1).

    4. The management Lambda orchestrator already runs on:
       ${var.orchestration_schedule}

    5. Check the status page:
       ${var.custom_domain != "" ? "https://${var.custom_domain}/" : aws_lambda_function_url.management.function_url}
  EOT
}
