# Uptime

Self-hosted AWS uptime monitoring in your own account.

## Why

- You own the data, DNS, costs, and infrastructure.
- You get a public status page plus a private admin UI.
- You can run checks from multiple AWS regions without relying on a third-party monitoring vendor.

## How

The system uses one home-region management Lambda for:

- public status page
- admin UI and API
- central orchestration

It invokes worker Lambdas in any regions you enable. Check history is stored in
DynamoDB, and the admin key is stored in Secrets Manager for the CloudFormation
bootstrap path.

## Features

- HTTP and TCP checks
- Multi-region probes
- Per-host worker-region targeting
- Public status page
- Admin UI
- Status-page themes, brand name, logo, and title
- Status-page maintenance notice and public subscribe links
- Per-host SNS alerts
- Notification controls roadmap: recipient/channel routing, recurring reminders, snooze/delay, quiet hours, sleep windows, TTL where supported
- Metrics roadmap: per-region uptime, host counts, runtime, RAM, execution counts, failures, and latency summaries
- DynamoDB TTL-based retention
- Configurable retention, with `90` days as the default

## Deployment Options

- CloudFormation: the main one-click install path
- Terraform: repo-driven alternative for infra work
  Terraform setup lives in [terraform/README.md](/Users/assi/Work/repos/maimon33/uptime/terraform/README.md)
- SAR: good future packaging layer on top of the CloudFormation flow

## CloudFormation

The official public bootstrap template is hosted from `www.maimons.dev`.
Official home regions currently supported by the artifact mapping:

- `us-east-1`
- `eu-west-1`
- `eu-central-1`
- `ap-southeast-1`

One-click console link:

```text
https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml
```

CLI:

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name uptime \
  --template-url https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

The stack region becomes the **home region**. That region hosts:

- management Lambda
- status page and admin page
- EventBridge schedule
- DynamoDB tables
- Secrets Manager admin key

`AdminApiKey` is optional. If you leave it blank, the stack generates one in
Secrets Manager:

```bash
aws secretsmanager get-secret-value \
  --secret-id uptime/admin-key \
  --query SecretString \
  --output text
```

If the secret was auto-generated, the admin token is in the `password` field.

Open `/admin` and enter the token there. The browser stores it for the current
session and sends it as a bearer token to the admin API.

## Cost

Typical cost is low. For example, `10` hosts, `3` worker regions, `1` minute
checks, and `90` day retention is usually still in the low single-digit USD per
month range, depending on traffic and AWS free tier coverage.

The app also includes a built-in cost estimator at `/api/cost`.

## More

- Deploy latest version:
  `./scripts/deploy-new-version.sh eu-central-1`
  Optional second argument: an SNS topic ARN for deployment notifications.
- Terraform usage: [terraform/README.md](/Users/assi/Work/repos/maimon33/uptime/terraform/README.md)
- CloudFormation templates: [cloudformation](/Users/assi/Work/repos/maimon33/uptime/cloudformation)
- Packaging scripts: [scripts](/Users/assi/Work/repos/maimon33/uptime/scripts)
