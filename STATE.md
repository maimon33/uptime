# Uptime — Project State

Shared context for Claude Code + Codex collaboration.
**Update this file when you make a significant architectural or structural change.**

---

## Current Architecture (as of 2026-05-02)

### Deployment model
- **CloudFormation** is the primary deployment method (Codex added this).
  - `cloudformation/uptime-bootstrap.yaml` — full home-region stack (Lambda, DynamoDB, Secrets Manager, IAM, EventBridge).
  - `cloudformation/uptime-artifacts.yaml` — S3 bucket for release artifacts.
  - Lambda code is uploaded to S3 first, then referenced by the CFN stack via `LambdaCodeS3Bucket`/`LambdaCodeS3Key` parameters.
  - Public bootstrap template has since been simplified to a single optional parameter: `AdminApiKey`.
    If omitted, CloudFormation generates the admin key in Secrets Manager.
    The official artifact location is hardcoded to `www.maimons.dev / uptime/releases/management.zip`.
- **Terraform** also exists (`terraform/`) as an alternative.
  - Currently incomplete vs CloudFormation (no EventBridge schedule rule for orchestration).
  - Decision needed: keep both, pick one, or make CFN the default and Terraform optional.

### Orchestration model (Codex changed this from original design)
- The management Lambda has **two responsibilities**:
  1. HTTP handler — serves status page, admin UI, REST API.
  2. **Orchestrator** — triggered by EventBridge every minute (same Lambda), fans out to all registered worker regions.
- On EventBridge trigger (`event.source == "aws.events"`), `_run_orchestration()` runs:
  - Reads all enabled hosts from DynamoDB.
  - Invokes each region's worker Lambda in parallel (ThreadPoolExecutor, max 8).
  - Collects results, writes aggregate status back to hosts table.
  - Sends SNS alerts on state transitions (centralized, not per-worker).
- `/admin` now serves a public login shell. The admin token is entered once in-browser and reused from session storage for Bearer-authenticated API calls.
- `/admin` and `/api/*` now support optional IP allowlisting via `ADMIN_ALLOWED_IP_CIDRS`.
- CloudFormation can now optionally provision Cognito admin-auth resources (User Pool, Client, optional managed-login domain) and pass Cognito-related env vars into the management Lambda, but the app-side Cognito login/session flow is still a follow-up task.
- The public status page now supports theme/brand/logo settings and shows recent history plus latency badges per region.
- The public surface now also includes a dedicated `/history` page with host and worker-region filters so check history does not overload the main status page.
- The public status page also supports a configurable maintenance notice plus public subscribe links for email/SMS/webhook or RSS destinations.
- The status-page admin pane can now start and tear down a custom-domain rollout via ACM + CloudFront. DNS stays manual by design: the app returns the exact validation and traffic records the operator should create or remove.
- The admin UI now includes a Notifications tab for deployment-wide defaults like topic ARN, quiet hours, reminder cadence, sleep windows, TTL, and maintenance muting. These values are stored in settings even where backend enforcement is still pending.
- Hosts can now optionally limit checks to a selected subset of deployed worker regions via `target_regions`.
- Worker Lambdas (`uptime-monitor-<region>`) no longer have their own EventBridge schedules.
  They are only invoked by the orchestrator. They run checks and return results; they do NOT write to DynamoDB themselves (check recording moved to orchestrator via `_apply_aggregate_updates`).

> **OPEN QUESTION**: The worker's `handler.py` (`src/monitor/handler.py` / `src/_monitor_handler.py`) still writes to DynamoDB directly. This conflicts with the orchestrator's `_apply_aggregate_updates`. Need to decide: does the worker write checks, or does it return results to the orchestrator and let it write? Currently both may be happening.

### Key files

| File | Owner | Purpose |
|---|---|---|
| `src/management/handler.py` | Both | HTTP routes + orchestration entry point |
| `src/management/regions.py` | Both | Deploy/teardown worker Lambdas via boto3 |
| `src/management/_monitor_handler.py` | Generated | Copy of `src/monitor/handler.py` — bundled in management zip |
| `src/monitor/handler.py` | Claude | Worker Lambda: runs checks, returns/writes results |
| `DESIGN.md` | Codex | Semantic design system for the public status page and admin console |
| `scripts/render_ui_preview.py` | Codex | Renders static HTML previews of the inline status/admin UI into `dist/preview/` |
| `cloudformation/uptime-bootstrap.yaml` | Codex | Primary infrastructure deployment |
| `cloudformation/uptime-artifacts.yaml` | Codex | S3 bucket for artifacts |
| `terraform/main.tf` | Claude | Alternative Terraform deployment (may lag CFN) |
| `scripts/package.sh` | Both | Builds `dist/management.zip` (copies monitor into management) |
| `scripts/publish-artifacts.sh` | Codex | Packages + uploads to S3 + prints CFN quick-create URL |
| `scripts/deploy-new-version.sh` | Codex | Publishes artifacts, updates the live management Lambda, writes `dist/deploy-last.json`, optionally notifies SNS |

### DynamoDB schema

**`uptime-hosts` table** — PK: `host_id` (string)

| host_id value | Type | Description |
|---|---|---|
| `<uuid>` | Host config | name, url, check_type, enabled, alert_enabled, alert_sns_arn, show_on_status_page, expected_status_code, target_regions, current_status, last_checked_at, last_down_at, last_latency_ms, region_statuses |
| `__settings__` | Settings | status_page_title, status_page_description, status_page_brand_name, status_page_logo_url, status_page_theme, status_page_subscribe_intro, status_page_subscribe_email_url, status_page_subscribe_sms_url, status_page_subscribe_webhook_url, maintenance_enabled, maintenance_message, maintenance_window, maintenance_scope, notifications_default_topic_arn, notifications_sender_label, notifications_initial_delay_seconds, notifications_reminder_interval_minutes, notifications_ttl_seconds, notifications_quiet_hours_enabled, notifications_quiet_hours_timezone, notifications_quiet_hours_start, notifications_quiet_hours_end, notifications_sleep_until, notifications_mute_during_maintenance, custom_domain_name, custom_domain_origin_url, custom_domain_certificate_arn, custom_domain_distribution_id, custom_domain_distribution_domain_name, custom_domain_distribution_status, custom_domain_status, custom_domain_last_error, custom_domain_validation_records, retention_days, default_check_interval, default_timeout |
| `__region__<name>` | Region record | region, function_arn, function_name, memory_mb, status, deployed_at |

**`uptime-checks` table** — PK: `host_id`, SK: `checked_at` (ISO timestamp)

| Field | Description |
|---|---|
| `status` | `up` / `down` / `degraded` |
| `latency_ms` | Decimal |
| `region` | Which region ran the check |
| `status_code` | HTTP status (if HTTP check) |
| `error` | Error string (if failed) |
| `ssl_days_remaining` | Integer (HTTPS only) |
| `ttl` | Unix timestamp for DynamoDB TTL auto-delete |

### Management API routes

| Method | Path | Description |
|---|---|---|
| GET | `/` or `/status` | Public status page |
| GET | `/admin` | Admin SPA login shell |
| GET | `/api/auth` | Validate current bearer token |
| GET | `/api/hosts` | List all hosts |
| POST | `/api/hosts` | Create host |
| GET | `/api/hosts/:id` | Get host |
| PUT | `/api/hosts/:id` | Update host |
| DELETE | `/api/hosts/:id` | Delete host |
| GET | `/api/hosts/:id/checks` | Check history (`?limit=N`) |
| GET | `/api/settings` | Get settings |
| PUT | `/api/settings` | Update settings |
| GET | `/api/cost` | Cost estimate (`?hosts=&regions=&interval=&days=`) |
| GET | `/api/regions` | List deployed worker regions |
| POST | `/api/regions` | Deploy worker to new region (`{region, memory_mb?}`) |
| POST | `/api/regions/:r/update` | Re-deploy code to existing region |
| DELETE | `/api/regions/:r` | Teardown worker in region |

### IAM roles

| Role | Purpose |
|---|---|
| `uptime-management` | Management Lambda execution role — created by CFN/Terraform |
| `uptime-monitor` | Worker Lambda execution role — created dynamically by `regions.py` when first region is added |

The management role has permissions to: manage Lambda functions (`uptime-monitor-*`), create/delete the monitor IAM role, manage CloudWatch log groups for monitors, STS GetCallerIdentity.

---

## Known issues / open questions

1. **Write ownership**: Worker (`_monitor_handler.py`) writes check results to DynamoDB directly AND returns results to orchestrator. Orchestrator also calls `_apply_aggregate_updates`. Check writes are probably duplicated. Decide: worker writes checks table, orchestrator updates hosts table status — or orchestrator does both.

2. **Terraform vs CloudFormation**: Both exist. Terraform is missing the EventBridge schedule for the orchestrator (added to CFN but not TF). Pick a primary or keep both in sync.

3. **`_monitor_handler.py` sync**: This file is a copy of `src/monitor/handler.py`, copied by `scripts/package.sh`. If you edit one, you must run `package.sh` again to sync. Do not edit `_monitor_handler.py` directly.

4. **Worker return format**: `_invoke_region_worker` in handler.py expects worker to return `{"results": [...]}`. The current monitor handler returns `{"checked": N, "up": N, "down": N, "region": ...}` — it does NOT return a `results` list. The orchestrator's `result_rows` will always be empty. Either the worker needs to return per-check results, or the orchestrator needs to read from DynamoDB after workers complete.

5. **CloudFormation section below is stale**: it still shows the older parameterized stack flow. Update it if this file is kept as an operator guide.

6. **Notifications roadmap vs current implementation**: the UI/docs now call out future notification controls like quiet hours, snooze, sleep, recurring reminders, and richer recipient routing. Current code still only sends transition alerts to a configured SNS topic ARN per host.

7. **Metrics roadmap vs current implementation**: the product notes now mention runtime/RAM/execution and per-region rollups, but the current system mainly persists check history, aggregate status, and latency. Additional metric collection and dashboards are still to be implemented.

8. **Custom-domain rollout is intentionally progressive**: the admin API can request the certificate, inspect validation state, create/disable/delete the CloudFront distribution, and tell the operator which DNS records to manage manually. It does not edit DNS itself.

9. **Cognito is infra-prepared, not app-complete**: the bootstrap stack can now create Cognito resources and expose the necessary values, but `/admin` still authenticates with the shared admin token until a dedicated Cognito redirect/callback/session implementation is added.

---

## Deploy flow (CloudFormation path)

```bash
# 1. Create artifacts bucket (one time)
aws cloudformation deploy \
  --template-file cloudformation/uptime-artifacts.yaml \
  --stack-name uptime-artifacts \
  --parameter-overrides BucketName=my-uptime-artifacts

# 2. Package + publish
./scripts/publish-artifacts.sh my-uptime-artifacts public/uptime

# 3. Deploy bootstrap stack
aws cloudformation deploy \
  --template-file cloudformation/uptime-bootstrap.yaml \
  --stack-name uptime \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Project=uptime \
    LambdaCodeS3Bucket=my-uptime-artifacts \
    LambdaCodeS3Key=public/uptime/releases/management.zip \
    AdminApiKey=your-secret-key

# 4. Get outputs
aws cloudformation describe-stacks --stack-name uptime \
  --query 'Stacks[0].Outputs'
```

## Deploy flow (Terraform path)

```bash
./scripts/package.sh
cd terraform
cp example.tfvars terraform.tfvars  # edit values
terraform init && terraform apply
terraform output -raw admin_key
```

---

## What each agent should own

| Area | Primary | Notes |
|---|---|---|
| CloudFormation templates | Codex | Don't edit CFN unless you understand the full stack |
| Terraform templates | Claude | Needs EventBridge schedule rule added to match CFN |
| `src/management/handler.py` | Both | Coordinate on orchestration logic changes |
| `src/management/regions.py` | Both | Coordinate on deploy/teardown contract |
| `src/monitor/handler.py` | Claude | Source of truth for worker code |
| `scripts/` | Both | |
| Admin UI (inside handler.py) | Claude | |

**Before making changes**: check this file for open issues. **After making changes**: update this file.

---

## Session Log

### 2026-05-02 — Public artifact hosting via www.maimons.dev

- `LambdaCodeS3Bucket` now defaults to `www.maimons.dev`; `LambdaCodeS3Key` defaults to `uptime/releases/management.zip`
- Standard deployments require no S3 setup — users just provide `AdminApiKey`
- Fork path documented: users override both params with their own bucket/key
- `publish-artifacts.sh` now defaults to `www.maimons.dev / uptime` prefix; accepts optional args to publish a fork
- README rewritten: one-click URL + CLI for standard path; separate fork section

### 2026-05-03 — Design system + preview pipeline

- Added root-level `DESIGN.md` using the Stitch `design-md` skill approach, adapted to this repo's inline Python-rendered UI
- Refreshed the public status page and admin console styling in `src/management/handler.py` to use a shared visual language
- Added `scripts/render_ui_preview.py` to render static previews to `dist/preview/status-preview.html` and `dist/preview/admin-preview.html`
- Expanded status-page themes into full-atmosphere treatments and added `dist/preview/history-preview.html` for the new public history view
