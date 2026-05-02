# Terraform Deployment

Terraform is the repo-driven deployment path for this project.

## What It Creates

- management Lambda
- Lambda Function URL
- EventBridge orchestration schedule
- DynamoDB `hosts` table
- DynamoDB `checks` table
- SSM parameter for the admin key
- IAM role and policy for the management Lambda
- CloudWatch log group
- optional custom-domain resources when configured

## Prerequisites

```bash
terraform --version   # >= 1.5
aws --version         # >= 2.0
python3 --version     # >= 3.11
zip --version
```

You also need AWS credentials with permissions for Lambda, DynamoDB, IAM, SSM,
EventBridge, CloudWatch Logs, and optional CloudFront/ACM/Route53 resources.

## Deploy

```bash
cd /Users/assi/Work/repos/maimon33/uptime
./scripts/package.sh

cd terraform
cp example.tfvars terraform.tfvars
# edit terraform.tfvars

terraform init
terraform apply
```

After apply:

```bash
terraform output management_lambda_url
terraform output -raw admin_key
```

Then:

1. Open the admin UI with `?key=<admin_key>`
2. Add your first host
3. Add worker regions from the Regions tab

## Main Variables

See [example.tfvars](/Users/assi/Work/repos/maimon33/uptime/terraform/example.tfvars) for the full file.

- `aws_region`
  Home region for management, DynamoDB, SSM, and logs.
- `project`
  Resource name prefix.
- `admin_api_key`
  Optional explicit admin key. Leave blank to auto-generate.
- `retention_days`
  History retention in days.
- `status_page_title`
  Default status page title.
- `status_page_description`
  Default status page subtitle.
- `lambda_memory_mb`
  Management Lambda memory.
- `lambda_timeout_seconds`
  Management Lambda timeout.
- `orchestration_schedule`
  EventBridge schedule expression.
- `log_retention_days`
  CloudWatch log retention.
- `custom_domain`
  Optional public status/admin domain.
- `hosted_zone_name`
  Required with `custom_domain`.

## Outputs

Important outputs:

- `status_page_url`
- `admin_url`
- `management_lambda_url`
- `admin_key`
- `admin_key_ssm_path`
- `hosts_table`
- `checks_table`
- `home_region`

## Notes

- Terraform currently stores the admin key in SSM, unlike the public CloudFormation
  bootstrap path, which uses Secrets Manager.
- The stack region is the home region.
