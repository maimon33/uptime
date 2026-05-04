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
- Password-only admin auth, with optional admin IP allowlisting
- Optional Cognito admin sign-in with MFA support
- Status-page themes, brand name, logo, and title
- Status-page maintenance notice and public subscribe links
- Custom-domain deploy/destroy flow from the admin UI using CloudFront + ACM, with manual DNS record instructions
- Per-host SNS alerts
- Admin notification settings for defaults, quiet hours, reminder cadence, sleep windows, and maintenance muting
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

## Authentication

Two admin-auth tracks are documented now:

- `Password only`
  This is the active built-in flow today. The admin key lives in Secrets
  Manager and `/admin` uses it as a bearer token for the API.
- `Cognito`
  CloudFormation can now provision a Cognito User Pool, User Pool Client, and
  optional managed-login domain, and `/admin` can sign in directly with
  Cognito username/password plus MFA when enabled.

If you stay on password-only, strongly consider setting `AdminAllowedIpCidrs`
to limit `/admin` and `/api/*` to trusted networks.

Full guide:

- [Authentication Guide](/Users/assi/Work/repos/maimon33/uptime/docs/authentication.md)

Fastest Cognito setup:

```bash
./scripts/prepare-cognito-cf.sh eu-central-1 uptime my-uptime-admin maimons.dev
./scripts/create-cognito-admin-user.sh eu-central-1 uptime you@maimons.dev
```

The first script prints the CloudFormation deploy command. The second one
creates the first Cognito user after the stack is up.

### Simple Cognito User Setup

1. Deploy the stack with `AdminAuthMode=cognito`.
2. Create the first Cognito user:

```bash
./scripts/create-cognito-admin-user.sh eu-central-1 uptime you@maimons.dev
```

3. If you want to choose the first temporary password yourself:

```bash
./scripts/create-cognito-admin-user.sh eu-central-1 uptime you@maimons.dev 'StrongTempPass123!'
```

4. Open `/admin`.
5. Sign in with the Cognito email and password.
6. If Cognito requires it:
   change the temporary password on first sign-in.
7. If MFA is enabled:
   enter the authenticator code when prompted.

What the script does:

- looks up the Cognito User Pool from your stack outputs
- creates the Cognito user
- marks the email as verified
- prints the user pool and client IDs for reference

If you set `CognitoAllowedEmailDomain`, make sure the user email matches that
domain or admin sign-in will be rejected.

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
