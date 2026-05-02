# Uptime — Self-Hosted AWS Uptime Monitor

A fully self-hosted uptime monitoring system deployed entirely on your own AWS account.
**You own everything**: the data, the DNS, the costs, and the infrastructure.

---

## What This Does

| Feature | Details |
|---|---|
| HTTP / TCP checks | Monitor any URL or TCP port |
| Multi-region probes | Deploy monitors to any AWS regions for global coverage |
| Latency tracking | p50/p95/p99 latency, status codes, SSL expiry |
| SNS alerting | Per-host opt-in alerts (email, SMS, Slack via SNS) |
| Status page | Public page showing selected hosts with history bars |
| Admin UI | Secure management page at `<your-url>/admin` |
| History & retention | DynamoDB TTL-based, configurable (default 90 days) |
| Cost transparency | Built-in cost estimator at `/api/cost` |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│  Your AWS Account                                                │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Home Region  (e.g. us-east-1)                           │   │
│  │                                                          │   │
│  │  Lambda (management) ──► Function URL ──► You / public   │   │
│  │         │                                                │   │
│  │         ▼                                                │   │
│  │  DynamoDB (hosts + checks)    SNS topics                 │   │
│  │  Secrets Manager (admin key)  CloudWatch Logs            │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                  │
│  │  EventBridge (single schedule) ─► Management orchestrator │   │
│  └──────────────────────────────┬────────────────────────────┘   │
│                                 │                                │
│                                 ▼                                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌───────────────┐   │
│  │ Worker Lambda   │  │ Worker Lambda   │  │ Worker ...    │   │
│  │ us-east-1       │  │ eu-west-1       │  │ ap-south-1    │   │
│  │ invoked by main │  │ invoked by main │  │ invoked by    │   │
│  │ Lambda          │  │ Lambda          │  │ main Lambda   │   │
│  └────────┬────────┘  └────────┬────────┘  └───────┬───────┘   │
│           └───────────────────┼────────────────────┘           │
│                                ▼                                │
│                   DynamoDB in home region                        │
└─────────────────────────────────────────────────────────────────┘
```

**Management Lambda** — one per account, in your chosen home region.
Serves the status page (public), admin UI (key-gated), REST API, and the
single EventBridge-driven orchestration loop.

**Worker Lambda** — one per AWS region you enable. The management Lambda invokes
these workers each run, workers execute checks in-region, write raw check rows
to DynamoDB, and the management Lambda aggregates state + sends alerts.

---

## Getting Started

### Deployment Options

Choose the install surface that fits the user:

| Option | Best for | Status |
|---|---|---|
| Terraform | dev workflow, infra iteration, full repo-driven changes | available now |
| CloudFormation | one-click bootstrap into an AWS account | available now |
| Serverless Application Repository (SAR) | polished public install UX on top of CloudFormation | good next step after publishing the CloudFormation assets |

### How Lambda Code Is Uploaded

The management Lambda is uploaded as a packaged zip, not as raw Python files.

The flow is:

1. Edit the source files under:
   - [handler.py](/Users/assi/Work/repos/maimon33/uptime/src/management/handler.py)
   - [regions.py](/Users/assi/Work/repos/maimon33/uptime/src/management/regions.py)
   - [worker handler.py](/Users/assi/Work/repos/maimon33/uptime/src/monitor/handler.py)
2. Run [`package.sh`](/Users/assi/Work/repos/maimon33/uptime/scripts/package.sh)
3. That produces [`management.zip`](/Users/assi/Work/repos/maimon33/uptime/dist/management.zip)
4. Upload that zip to S3
5. CloudFormation creates or updates the management Lambda from that S3 object

The zip currently includes:

- `handler.py`
- `regions.py`
- `_monitor_handler.py`

For the official release path in this GitHub repo, uploads are handled by
[`publish.yml`](/Users/assi/Work/repos/maimon33/uptime/.github/workflows/publish.yml).
On `main`, it packages the Lambda and publishes the live artifacts to:

- `s3://www.maimons.dev/uptime/releases/management.zip`
- `s3://www.maimons.dev/uptime/cloudformation/uptime-bootstrap.yaml`
- `s3://www.maimons.dev/uptime/cloudformation/uptime-artifacts.yaml`

It also archives each publish under a versioned prefix:

- `s3://www.maimons.dev/uptime/releases/<git-sha>/...`

So the repo has two supported paths:

- Official release path: GitHub Actions publishes to `www.maimons.dev`
- Fork path: run [`publish-artifacts.sh`](/Users/assi/Work/repos/maimon33/uptime/scripts/publish-artifacts.sh) against your own bucket/prefix

### What The Initial Stack Creates

The bootstrap deployment creates the home-region foundation:

- Management Lambda
- Lambda Function URL for the public status page and admin UI
- EventBridge schedule for the central orchestrator
- DynamoDB `hosts` table
- DynamoDB `checks` table with TTL enabled
- Secrets Manager secret for the admin API key
- IAM role and inline policy for the management Lambda
- CloudWatch log group for the management Lambda
- Optional default SNS topic for alerts

It does **not** create worker-region Lambdas up front. Those are added later from the admin UI as needed.

### Prerequisites

```bash
# Required tools
terraform --version   # >= 1.5
aws --version         # >= 2.0 configured with your credentials
python3 --version     # >= 3.11 (for cost estimator)
zip --version

# AWS permissions needed
# IAM: create roles/policies
# Lambda: create/update functions
# DynamoDB: create tables
# Secrets Manager: create/get secret
# SNS: create topics (optional)
# EventBridge: create rules
# CloudWatch Logs: create log groups
# CloudFront + ACM + Route53: optional, for custom domain
```

### Deploy With Terraform

```bash
cd uptime

# 1. Package Lambda code
./scripts/package.sh

# 2. Deploy the stack
cd terraform
cp example.tfvars terraform.tfvars
# Edit terraform.tfvars with your settings
terraform init
terraform apply

# 3. Note the outputs
terraform output management_lambda_url  # your Lambda Function URL
terraform output admin_key              # your admin API key (sensitive)

# 4. Open the admin UI and add worker regions there
# Example regions: us-east-1, eu-west-1, ap-southeast-1
```

### Deploy With CloudFormation

The Lambda code and CloudFormation template are hosted publicly at `www.maimons.dev`.
You do not need to touch S3 — just deploy the stack and supply an admin key.

#### One-click (AWS Console)

Open this URL. You can either fill in `AdminApiKey`, or leave it blank and let
CloudFormation generate one for you:

```
https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml
```

Change `region=us-east-1` in the URL to deploy into a different home region.

#### CLI

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name uptime \
  --template-url https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM
```

`LambdaCodeS3Bucket` defaults to `www.maimons.dev` and `LambdaCodeS3Key` defaults to
`uptime/releases/management.zip` inside the template, so the only parameter you
may want to provide is `AdminApiKey`.

`AdminApiKey` is your admin password/token for this deployment. It is used to
protect:

- `/admin`
- all authenticated `/api/*` endpoints

It is **not** an encryption key. CloudFormation stores it as an encrypted
Secrets Manager secret, and the management Lambda reads it from there.
If you leave `AdminApiKey` blank, the stack generates one automatically.

After deployment, you can retrieve the generated value from Secrets Manager:

```bash
aws secretsmanager get-secret-value \
  --secret-id uptime/admin-key \
  --query SecretString \
  --output text
```

If the secret was auto-generated, the returned value is JSON. The actual admin
token is in the `password` field.

#### How the official artifacts get there

This repo includes a GitHub Actions workflow at
[`publish.yml`](/Users/assi/Work/repos/maimon33/uptime/.github/workflows/publish.yml).
When changes land on `main`, it:

1. Packages the Lambda zip
2. Assumes an AWS role via GitHub OIDC
3. Publishes the official artifacts into `s3://www.maimons.dev/uptime/...`
4. Keeps a versioned archive by Git commit SHA

That means the CloudFormation template and the default Lambda artifact are both
published from the repo automatically.

#### What the stack creates

- Management Lambda + Function URL (your status page and admin UI)
- EventBridge schedule (orchestration, every minute)
- DynamoDB `hosts` and `checks` tables (with TTL)
- Secrets Manager secret for the admin key
- IAM role for the management Lambda
- CloudWatch log group

Worker Lambdas in other regions are added later from the admin UI — no redeployment needed.

---

### Fork: use your own Lambda build

If you want to modify the Lambda code and host your own build:

1. Edit the source under `src/`.
2. Package and publish to your own public S3 bucket:

```bash
./scripts/publish-artifacts.sh YOUR_BUCKET YOUR_PREFIX
# e.g. ./scripts/publish-artifacts.sh my-assets uptime
```

3. Deploy the stack with your bucket overrides:

```bash
aws cloudformation deploy \
  --region us-east-1 \
  --stack-name uptime \
  --template-file cloudformation/uptime-bootstrap.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    AdminApiKey=YOUR_SECURE_ADMIN_KEY
```

Then edit the template if you want to point it at your own bucket/key instead
of the official release path.

If you don't have a public bucket yet, `cloudformation/uptime-artifacts.yaml` creates one:

```bash
aws cloudformation deploy \
  --stack-name uptime-artifacts \
  --template-file cloudformation/uptime-artifacts.yaml \
  --parameter-overrides BucketName=YOUR_UNIQUE_BUCKET_NAME
```

### Publish Via SAR

SAR is still the right “best UX” public option, but it should sit on top of the same packaged Lambda artifact and CloudFormation shape above. The practical sequence is:

1. Publish `dist/management.zip` and the CloudFormation template to S3.
2. Verify the CloudFormation bootstrap flow.
3. Wrap that package for SAR so users get a friendlier install page.

### Public Site And Demo

Your public site at `www.maimons.dev` can act as the landing page for:

- Product overview
- “Launch in your AWS account” quick-create link
- Demo link

For the demo, the cleanest current option is a **read-only public status page**.
That works today because the status page is naturally public and does not expose
the admin key.

The admin UI is **not** currently read-only. Anyone with the admin key can make
changes. So for a safe public demo:

- Share the status page URL
- Do not share the admin key

If you later want a real read-only admin/demo mode, that should be added as an
application feature rather than faked in the deployment docs.

### Access

- **Status page**: `https://<function-url>/`
- **Admin page**: `https://<function-url>/admin?key=<admin-key>`
- **API**: `https://<function-url>/api/hosts` (Bearer token auth)

---

## Configuration Reference

### terraform/terraform.tfvars

```hcl
# ── Required ──────────────────────────────────────────────────────────────
aws_region = "us-east-1"          # home region for data + management Lambda
project    = "uptime"             # prefix for all resource names

# ── Admin access ──────────────────────────────────────────────────────────
# Leave blank to auto-generate a secure key (recommended)
# The key is stored in the bootstrap stack's secret store
admin_api_key = ""

# ── Retention ─────────────────────────────────────────────────────────────
# How many days to keep check history in DynamoDB
# More days = higher DynamoDB storage cost (see cost guide)
# Minimum: 7  |  Recommended: 90  |  Maximum: 365
retention_days = 90

# ── Status page ───────────────────────────────────────────────────────────
status_page_title       = "System Status"
status_page_description = "Real-time status of our services"

# ── Custom domain (optional) ──────────────────────────────────────────────
# Requires a Route 53 hosted zone in your account
# Leave blank to use the Lambda Function URL (free, no extra cost)
custom_domain    = ""             # e.g. "status.yourdomain.com"
hosted_zone_name = ""             # e.g. "yourdomain.com"

# ── Lambda settings ───────────────────────────────────────────────────────
lambda_memory_mb = 256            # 128–1024 MB
lambda_timeout_seconds = 300
orchestration_schedule = "rate(1 minute)"
log_retention_days = 14           # CloudWatch log retention
```

### cloudformation/uptime-bootstrap.yaml parameters

| Parameter | Required | Description |
|---|---|---|
| `AdminApiKey` | no | Optional admin password/token. Leave blank to have the stack generate one in Secrets Manager. |

For CloudFormation, the **home region is not a template parameter**. It is the region where you run the stack, for example with `aws cloudformation deploy --region us-east-1`.

---

## Adding Hosts

### Via Admin UI

1. Go to `https://<url>/admin?key=<key>`
2. Click **Add Host**
3. Fill in the form (name, URL, check type, interval, etc.)
4. Toggle **Show on Status Page** if you want it public
5. Toggle **Alert via SNS** and paste your SNS topic ARN

### Via API

```bash
ADMIN_KEY="your-admin-key"
URL="https://your-function-url"

curl -X POST "$URL/api/hosts" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Website",
    "url": "https://example.com",
    "check_type": "http",
    "check_interval_seconds": 60,
    "timeout_seconds": 10,
    "expected_status_code": 200,
    "show_on_status_page": true,
    "alert_enabled": true,
    "alert_sns_arn": "arn:aws:sns:us-east-1:123456789:my-alerts"
  }'
```

### Host Fields

| Field | Default | Description |
|---|---|---|
| `name` | required | Display name on status page |
| `url` | required | Full URL (http/https) or `host:port` for TCP |
| `check_type` | `http` | `http` or `tcp` |
| `check_interval_seconds` | `60` | How often to check (60–3600) |
| `timeout_seconds` | `10` | Request timeout |
| `expected_status_code` | `200` | HTTP status that means "up" |
| `show_on_status_page` | `true` | Show on public status page |
| `enabled` | `true` | Whether this host is monitored |
| `alert_enabled` | `false` | Send SNS alert on state change |
| `alert_sns_arn` | `""` | SNS topic ARN for alerts |
| `tags` | `[]` | Free-form tags for grouping |

---

## SNS Alerting

Alerts fire on state transitions:
- **UP → DOWN**: sends "ALERT" message
- **DOWN → UP**: sends "RESOLVED" message

Alerts are **not** sent every check — only on state change, so you won't get
spammed during an outage.

### Setting Up SNS

```bash
# Create a topic
aws sns create-topic --name uptime-alerts --region us-east-1

# Subscribe your email
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789:uptime-alerts \
  --protocol email \
  --notification-endpoint you@example.com

# For Slack: use AWS Chatbot or an SNS → Lambda → Slack webhook
# For PagerDuty: use PagerDuty's SNS integration
```

Use the topic ARN as `alert_sns_arn` on the host.

---

## Check Types

### HTTP / HTTPS
- Checks response status code against `expected_status_code`
- Measures end-to-end latency (DNS + connect + TLS + TTFB + body)
- For HTTPS: also checks SSL cert expiry
  - **< 30 days**: logged as warning in check result
  - **< 7 days**: host marked as `degraded`
- Follows redirects (up to 3)

### TCP
- Opens a TCP connection to `host:port`
- Measures connection time
- No HTTP parsing — useful for databases, SMTP, custom services
- Format: `hostname:port` or `tcp://hostname:port`

---

## Regions

Run workers in multiple regions to detect regional outages and get more
accurate global latency. The management Lambda runs the schedule centrally and
invokes every configured worker region once per orchestration cycle.

### Recommended starter set (cost-optimized)
- `us-east-1` — US East
- `eu-west-1` — Europe  
- `ap-southeast-1` — Asia Pacific

### All supported regions
See `docs/REGIONS.md` for the full list with latency characteristics.

### Adding / removing a region

Use the **Regions** tab in the admin UI to add, update, or remove worker
regions. No extra Terraform apply is needed for day-to-day region changes.

---

## Cost Guide

Costs are extremely low. A typical setup is **under $1/month**.

### Example: 10 hosts, 3 regions, 1-minute checks, 90-day retention

```
Lambda (workers × 3 regions):
  Worker invocations:  3 × 43,200/mo = 129,600    → $0.00 (free tier: 1M/mo)
  Duration:     ~2s × 256MB × 129,600      → ~$0.11/mo

Lambda (management):
  Scheduler invocations: 43,200/mo         → ~$0.00
  UI/API traffic: depends on your traffic  → $0.00–$0.05

DynamoDB (on-demand):
  Writes:       129,600 × 10 hosts = 1.3M → $1.63/mo
  Reads:        status page loads         → $0.01/mo
  Storage:      ~15MB for 90 days         → $0.00 (free tier)

CloudWatch Logs:
  ~50MB/mo × 4 log groups                 → $0.03/mo

Total estimate: ~$1.80/mo
```

Run the built-in cost estimator:

```bash
# Interactive
python3 scripts/cost_estimate.py

# Or via API (uses your actual host count)
curl "$URL/api/cost?regions=3&interval=60" \
  -H "Authorization: Bearer $ADMIN_KEY"
```

See `docs/COST_GUIDE.md` for full breakdown and optimization tips.

---

## Retention

Check history is stored in DynamoDB with a TTL attribute.
After `retention_days` days, DynamoDB automatically deletes old items.

| Retention | Storage (10 hosts, 3 regions, 1-min) | Cost/mo |
|---|---|---|
| 30 days | ~45 MB | ~$0.00 |
| 90 days | ~135 MB | ~$0.00 |
| 180 days | ~270 MB | ~$0.03 |
| 365 days | ~550 MB | ~$0.06 |

Change retention without redeploying:
```bash
curl -X PUT "$URL/api/settings" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{"retention_days": 180}'
```

New checks will use the new TTL. Existing items keep their old TTL.

---

## Custom Domain

1. Set `custom_domain` and `hosted_zone_name` in `terraform.tfvars`
2. `terraform apply` — this creates:
   - ACM certificate (validated via DNS)
   - CloudFront distribution pointing to your Lambda Function URL
   - Route 53 A/AAAA records
3. Wait ~15 min for CloudFront to deploy and ACM to validate

Without a custom domain, you get a free `*.lambda-url.*.on.aws` URL.

---

## Security Notes

- **Admin key** is stored in Secrets Manager (encrypted at rest)
- The key is passed as `?key=` in the browser or `Authorization: Bearer` in API calls
- Status page (`/`) is fully public — only shows hosts with `show_on_status_page: true`
- All other endpoints require the admin key
- Lambda Function URL has `AuthType: NONE` (auth is at the application layer)
- To restrict further: set `AuthType: AWS_IAM` in Terraform and sign requests with SigV4

---

## Teardown

```bash
# Remove everything
cd terraform
terraform destroy
```

This removes all AWS resources. DynamoDB data is deleted permanently.
Take a backup first if you need the history:

```bash
aws dynamodb create-backup \
  --table-name uptime-checks \
  --backup-name uptime-checks-backup-$(date +%Y%m%d)
```
