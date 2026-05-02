"""
Management Lambda — public app, admin API, and central orchestrator.
Serves the status page and admin UI, manages regional worker Lambdas,
and runs the scheduled cross-region monitoring orchestration.

Routes (public):
  GET  /           → status page
  GET  /status     → alias
  GET  /admin      → admin SPA login shell

API (admin key required):
  GET              /api/auth
  GET/POST         /api/hosts
  GET/PUT/DELETE   /api/hosts/:id
  GET              /api/hosts/:id/checks
  GET/PUT          /api/settings
  GET              /api/cost
  GET              /api/regions
  POST             /api/regions            body: {region, memory_mb?}
  POST             /api/regions/:r/update  re-deploy worker code to an existing region
  DELETE           /api/regions/:r
  OPTIONS *        → CORS preflight
"""

import base64
import hmac
import json
import os
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from decimal import Decimal
from urllib.parse import parse_qs, urlparse

import boto3

import regions as reg

# ── AWS clients ───────────────────────────────────────────────────────────────
_dynamodb = None
_ssm = None
_secretsmanager = None
_lambda = None
_sns = None
_acm = None
_cloudfront = None
_route53 = None

def _db():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb

def _ssm_client():
    global _ssm
    if _ssm is None:
        _ssm = boto3.client("ssm")
    return _ssm


def _secretsmanager_client():
    global _secretsmanager
    if _secretsmanager is None:
        _secretsmanager = boto3.client("secretsmanager")
    return _secretsmanager


def _lambda_client(region_name: str | None = None):
    global _lambda
    if region_name:
        return boto3.client("lambda", region_name=region_name)
    if _lambda is None:
        _lambda = boto3.client("lambda")
    return _lambda


def _sns_client():
    global _sns
    if _sns is None:
        _sns = boto3.client("sns", region_name=HOME_REGION)
    return _sns


def _acm_client():
    global _acm
    if _acm is None:
        _acm = boto3.client("acm", region_name="us-east-1")
    return _acm


def _cloudfront_client():
    global _cloudfront
    if _cloudfront is None:
        _cloudfront = boto3.client("cloudfront")
    return _cloudfront


def _route53_client():
    global _route53
    if _route53 is None:
        _route53 = boto3.client("route53")
    return _route53

# ── Config ────────────────────────────────────────────────────────────────────
HOSTS_TABLE     = os.environ["HOSTS_TABLE"]
CHECKS_TABLE    = os.environ["CHECKS_TABLE"]
ADMIN_KEY_PARAM = os.environ.get("ADMIN_KEY_PARAM")
ADMIN_KEY_SECRET = os.environ.get("ADMIN_KEY_SECRET")
HOME_REGION     = os.environ.get("HOME_REGION", os.environ.get("AWS_REGION", "us-east-1"))
RETENTION_DAYS  = int(os.environ.get("RETENTION_DAYS", "90"))

_SETTINGS_DEFAULTS = {
    "status_page_title":       os.environ.get("STATUS_PAGE_TITLE", "System Status"),
    "status_page_description": os.environ.get("STATUS_PAGE_DESC",  "Real-time status of our services"),
    "status_page_brand_name":  os.environ.get("STATUS_PAGE_BRAND_NAME", "Uptime"),
    "status_page_logo_url":    os.environ.get("STATUS_PAGE_LOGO_URL", ""),
    "status_page_theme":       os.environ.get("STATUS_PAGE_THEME", "clean"),
    "status_page_subscribe_intro": os.environ.get("STATUS_PAGE_SUBSCRIBE_INTRO", "Subscribe for status updates."),
    "status_page_subscribe_email_url": os.environ.get("STATUS_PAGE_SUBSCRIBE_EMAIL_URL", ""),
    "status_page_subscribe_sms_url": os.environ.get("STATUS_PAGE_SUBSCRIBE_SMS_URL", ""),
    "status_page_subscribe_webhook_url": os.environ.get("STATUS_PAGE_SUBSCRIBE_WEBHOOK_URL", ""),
    "maintenance_enabled":     False,
    "maintenance_message":     "",
    "maintenance_window":      "",
    "maintenance_scope":       "",
    "notifications_default_topic_arn": "",
    "notifications_sender_label": "",
    "notifications_initial_delay_seconds": 0,
    "notifications_reminder_interval_minutes": 0,
    "notifications_ttl_seconds": 0,
    "notifications_quiet_hours_enabled": False,
    "notifications_quiet_hours_timezone": "UTC",
    "notifications_quiet_hours_start": "",
    "notifications_quiet_hours_end": "",
    "notifications_sleep_until": "",
    "notifications_mute_during_maintenance": True,
    "custom_domain_name": "",
    "custom_domain_origin_url": "",
    "custom_domain_hosted_zone_name": "",
    "custom_domain_zone_id": "",
    "custom_domain_certificate_arn": "",
    "custom_domain_distribution_id": "",
    "custom_domain_distribution_domain_name": "",
    "custom_domain_distribution_status": "",
    "custom_domain_status": "",
    "custom_domain_last_error": "",
    "custom_domain_validation_records": [],
    "retention_days":          RETENTION_DAYS,
    "default_check_interval":  60,
    "default_timeout":         10,
}

_cached_admin_key = None


# ── Entry point ───────────────────────────────────────────────────────────────

def handler(event, context):
    if _is_scheduled_event(event):
        return _run_orchestration()

    method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
    path   = (event.get("rawPath", "/") or "/").rstrip("/") or "/"

    if method == "OPTIONS":
        return _cors_ok()

    if path in ("/", "/status"):
        return _serve_status_page()

    if path == "/admin":
        return _html(200, _admin_page())

    if path.startswith("/api/"):
        if not _auth(event):
            return _json(401, {"error": "Unauthorized. Sign in at /admin or send Authorization: Bearer <key>"})
        return _route_api(method, path, event)

    return _json(404, {"error": "Not found"})


def _is_scheduled_event(event: dict) -> bool:
    return isinstance(event, dict) and event.get("source") == "aws.events"


def _run_orchestration() -> dict:
    db = _db()
    run_id = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    regions = reg.list_regions(db)

    if not regions:
        print("No worker regions configured; skipping orchestration run.")
        return {"run_id": run_id, "regions": 0, "hosts": 0, "results": 0}

    hosts = _list_host_items()
    if not hosts:
        print("No enabled hosts configured; skipping orchestration run.")
        return {"run_id": run_id, "regions": len(regions), "hosts": 0, "results": 0}

    worker_results = []
    with ThreadPoolExecutor(max_workers=min(len(regions), 8)) as pool:
        futures = {
            pool.submit(_invoke_region_worker, region["region"], run_id): region["region"]
            for region in regions
        }
        for fut in as_completed(futures):
            region_name = futures[fut]
            try:
                worker_results.append(fut.result())
            except Exception as exc:
                print(f"[orchestrator] worker invoke failed for {region_name}: {exc}")

    result_rows = []
    for worker in worker_results:
        result_rows.extend(worker.get("results", []))

    _apply_aggregate_updates(db, hosts, result_rows, run_id)
    return {
        "run_id": run_id,
        "regions": len(regions),
        "hosts": len(hosts),
        "results": len(result_rows),
    }


# ── Auth ──────────────────────────────────────────────────────────────────────

def _get_admin_key() -> str:
    global _cached_admin_key
    if _cached_admin_key is None:
        if ADMIN_KEY_SECRET:
            secret_value = _secretsmanager_client().get_secret_value(
                SecretId=ADMIN_KEY_SECRET
            )["SecretString"]
            try:
                secret_json = json.loads(secret_value)
                _cached_admin_key = secret_json.get("password", secret_value)
            except Exception:
                _cached_admin_key = secret_value
        elif ADMIN_KEY_PARAM:
            _cached_admin_key = _ssm_client().get_parameter(
                Name=ADMIN_KEY_PARAM, WithDecryption=True
            )["Parameter"]["Value"]
        else:
            raise RuntimeError("Missing ADMIN_KEY_SECRET or ADMIN_KEY_PARAM environment variable")
    return _cached_admin_key

def _auth(event: dict) -> bool:
    headers = event.get("headers") or {}
    auth    = headers.get("authorization") or headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        token = auth[7:]
    else:
        qs    = event.get("rawQueryString") or ""
        token = parse_qs(qs).get("key", [""])[0]
    if not token:
        return False
    return hmac.compare_digest(token.strip(), _get_admin_key().strip())


# ── API router ────────────────────────────────────────────────────────────────

def _route_api(method: str, path: str, event: dict) -> dict:
    body = _parse_body(event)
    qs   = parse_qs(event.get("rawQueryString") or "")
    segs = path.split("/")   # ['', 'api', '<resource>', ...]

    resource = segs[2] if len(segs) > 2 else ""
    rid      = segs[3] if len(segs) > 3 else ""
    sub      = segs[4] if len(segs) > 4 else ""

    # ── /api/hosts ────────────────────────────────────────────────────────────
    if resource == "hosts":
        if not rid:
            if method == "GET":  return _list_hosts()
            if method == "POST": return _create_host(body)
        else:
            if not sub:
                if method == "GET":    return _get_host(rid)
                if method == "PUT":    return _update_host(rid, body)
                if method == "DELETE": return _delete_host(rid)
            if sub == "checks":
                return _get_checks(rid, int(qs.get("limit", ["200"])[0]))

    # ── /api/settings ─────────────────────────────────────────────────────────
    if resource == "auth":
        if method == "GET":
            return _json(200, {"ok": True})

    if resource == "settings":
        if method == "GET": return _get_settings()
        if method == "PUT": return _update_settings(body)

    if resource == "custom-domain":
        if method == "GET":
            return _get_custom_domain_status(event)
        if method == "POST":
            return _deploy_custom_domain(body, event)
        if method == "DELETE":
            return _destroy_custom_domain()

    # ── /api/cost ─────────────────────────────────────────────────────────────
    if resource == "cost":
        return _cost_estimate(qs)

    # ── /api/regions ──────────────────────────────────────────────────────────
    if resource == "regions":
        if not rid:
            if method == "GET":  return _list_regions()
            if method == "POST": return _add_region(body)
        else:
            if method == "DELETE":               return _remove_region(rid)
            if method == "POST" and sub == "update": return _update_region(rid)

    return _json(404, {"error": "API endpoint not found"})


# ── Hosts CRUD ────────────────────────────────────────────────────────────────

def _list_hosts() -> dict:
    hosts = sorted(_list_host_items(), key=lambda h: h.get("name", ""))
    return _json(200, hosts)


def _list_host_items() -> list[dict]:
    result = _db().Table(HOSTS_TABLE).scan(
        FilterExpression="host_id <> :s AND NOT begins_with(host_id, :r)",
        ExpressionAttributeValues={":s": "__settings__", ":r": "__region__"},
    )
    return result.get("Items", [])

def _get_host(host_id: str) -> dict:
    item = _db().Table(HOSTS_TABLE).get_item(Key={"host_id": host_id}).get("Item")
    return _json(404, {"error": "Host not found"}) if not item else _json(200, item)

def _create_host(body: dict) -> dict:
    if not body.get("name") or not body.get("url"):
        return _json(400, {"error": "'name' and 'url' are required"})
    now  = datetime.now(timezone.utc).isoformat()
    item = {k: v for k, v in {
        "host_id":                str(uuid.uuid4()),
        "name":                   body["name"],
        "url":                    body["url"],
        "check_type":             body.get("check_type", "http"),
        "check_interval_seconds": int(body.get("check_interval_seconds", 60)),
        "timeout_seconds":        int(body.get("timeout_seconds", 10)),
        "enabled":                bool(body.get("enabled", True)),
        "alert_enabled":          bool(body.get("alert_enabled", False)),
        "alert_sns_arn":          body.get("alert_sns_arn", "") or None,
        "show_on_status_page":    bool(body.get("show_on_status_page", True)),
        "expected_status_code":   int(body.get("expected_status_code", 200)),
        "target_regions":         _normalize_target_regions(body.get("target_regions")),
        "tags":                   body.get("tags", []),
        "created_at":             now,
        "updated_at":             now,
        "current_status":         "unknown",
    }.items() if v is not None}
    _db().Table(HOSTS_TABLE).put_item(Item=item)
    return _json(201, item)

def _update_host(host_id: str, body: dict) -> dict:
    table = _db().Table(HOSTS_TABLE)
    if not table.get_item(Key={"host_id": host_id}).get("Item"):
        return _json(404, {"error": "Host not found"})
    allowed = {
        "name", "url", "check_type", "check_interval_seconds", "timeout_seconds",
        "enabled", "alert_enabled", "alert_sns_arn", "show_on_status_page",
        "expected_status_code", "tags", "target_regions",
    }
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return _json(400, {"error": "No updatable fields"})
    if "target_regions" in updates:
        updates["target_regions"] = _normalize_target_regions(updates.get("target_regions"))
    updates["updated_at"] = datetime.now(timezone.utc).isoformat()
    expr   = "SET " + ", ".join(f"#{k} = :{k}" for k in updates)
    table.update_item(
        Key={"host_id": host_id},
        UpdateExpression=expr,
        ExpressionAttributeNames={f"#{k}": k for k in updates},
        ExpressionAttributeValues={f":{k}": v for k, v in updates.items()},
    )
    return _json(200, table.get_item(Key={"host_id": host_id})["Item"])

def _delete_host(host_id: str) -> dict:
    _db().Table(HOSTS_TABLE).delete_item(Key={"host_id": host_id})
    return {"statusCode": 204, "headers": {}, "body": ""}

def _get_checks(host_id: str, limit: int = 200) -> dict:
    from boto3.dynamodb.conditions import Key
    result = _db().Table(CHECKS_TABLE).query(
        KeyConditionExpression=Key("host_id").eq(host_id),
        ScanIndexForward=False,
        Limit=min(limit, 1000),
    )
    return _json(200, result.get("Items", []))


# ── Settings ──────────────────────────────────────────────────────────────────

def _get_settings() -> dict:
    item = _load_settings_item()
    item.pop("host_id", None)
    return _json(200, {**_SETTINGS_DEFAULTS, **item})

def _update_settings(body: dict) -> dict:
    allowed = {
        "status_page_title", "status_page_description",
        "status_page_brand_name", "status_page_logo_url", "status_page_theme",
        "status_page_subscribe_intro", "status_page_subscribe_email_url",
        "status_page_subscribe_sms_url", "status_page_subscribe_webhook_url",
        "maintenance_enabled", "maintenance_message", "maintenance_window",
        "maintenance_scope",
        "notifications_default_topic_arn", "notifications_sender_label",
        "notifications_initial_delay_seconds", "notifications_reminder_interval_minutes",
        "notifications_ttl_seconds", "notifications_quiet_hours_enabled",
        "notifications_quiet_hours_timezone", "notifications_quiet_hours_start",
        "notifications_quiet_hours_end", "notifications_sleep_until",
        "notifications_mute_during_maintenance",
        "custom_domain_name", "custom_domain_origin_url", "custom_domain_hosted_zone_name", "custom_domain_zone_id",
        "custom_domain_certificate_arn", "custom_domain_distribution_id",
        "custom_domain_distribution_domain_name", "custom_domain_distribution_status",
        "custom_domain_status", "custom_domain_last_error", "custom_domain_validation_records",
        "retention_days", "default_check_interval", "default_timeout",
    }
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return _json(400, {"error": "No updatable settings"})
    item = _load_settings_item()
    item.update(updates)
    _save_settings_item(item)
    item.pop("host_id", None)
    return _json(200, item)


def _load_settings_item() -> dict:
    return _db().Table(HOSTS_TABLE).get_item(Key={"host_id": "__settings__"}).get("Item", {"host_id": "__settings__"})


def _save_settings_item(item: dict) -> None:
    payload = {"host_id": "__settings__", **{k: v for k, v in item.items() if k != "host_id"}}
    _db().Table(HOSTS_TABLE).put_item(Item=payload)


def _invoke_region_worker(region: str, run_id: str) -> dict:
    function_name = f"{os.environ.get('PROJECT', 'uptime')}-monitor-{region}"
    response = _lambda_client(region).invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({"run_id": run_id}).encode(),
    )
    payload = response["Payload"].read().decode() or "{}"
    body = json.loads(payload)
    if response.get("FunctionError"):
        raise RuntimeError(f"{function_name} failed: {body}")
    return body


def _normalize_target_regions(value) -> list[str]:
    if not value:
        return []
    if not isinstance(value, list):
        return []
    cleaned = []
    for region in value:
        region_name = str(region or "").strip()
        if region_name and region_name not in cleaned:
            cleaned.append(region_name)
    return cleaned


def _apply_aggregate_updates(db, hosts: list[dict], result_rows: list[dict], run_id: str) -> None:
    by_host = {host["host_id"]: [] for host in hosts}
    for row in result_rows:
        host_id = row.get("host_id")
        if host_id in by_host:
            by_host[host_id].append(row)

    table = db.Table(HOSTS_TABLE)
    for host in hosts:
        host_results = by_host.get(host["host_id"], [])
        region_statuses = _build_region_statuses(host_results)
        aggregate_status = _aggregate_status(host_results)
        avg_latency = round(sum(r.get("latency_ms", 0) for r in host_results) / len(host_results)) if host_results else None
        prev_status = host.get("current_status", "unknown")

        update_item = {
            "current_status": aggregate_status,
            "last_checked_at": run_id,
            "region_statuses": region_statuses,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if avg_latency is not None:
            update_item["last_latency_ms"] = avg_latency
        if aggregate_status == "down" and prev_status != "down":
            update_item["last_down_at"] = run_id

        expr_names = {f"#k{i}": key for i, key in enumerate(update_item)}
        expr_values = {f":v{i}": value for i, value in enumerate(update_item.values())}
        set_parts = [f"{name} = {value}" for name, value in zip(expr_names, expr_values)]

        table.update_item(
            Key={"host_id": host["host_id"]},
            UpdateExpression="SET " + ", ".join(set_parts),
            ExpressionAttributeNames=expr_names,
            ExpressionAttributeValues=expr_values,
        )

        if host.get("alert_enabled") and host.get("alert_sns_arn"):
            if aggregate_status == "down" and prev_status not in ("down", "unknown"):
                _send_alert(host, host_results, "DOWN")
            elif aggregate_status == "up" and prev_status == "down":
                _send_alert(host, host_results, "RECOVERED")


def _build_region_statuses(host_results: list[dict]) -> dict:
    statuses = {}
    for row in host_results:
        statuses[row["region"]] = {
            "status": row.get("status", "unknown"),
            "checked_at": row.get("checked_at"),
            "latency_ms": row.get("latency_ms", 0),
            "status_code": row.get("status_code"),
            "error": row.get("error"),
            "ssl_days_remaining": row.get("ssl_days_remaining"),
        }
    return statuses


def _aggregate_status(host_results: list[dict]) -> str:
    if not host_results:
        return "unknown"
    statuses = [row.get("status", "unknown") for row in host_results]
    if "down" in statuses:
        return "down"
    if "degraded" in statuses:
        return "degraded"
    if all(status == "up" for status in statuses):
        return "up"
    return "unknown"


def _send_alert(host: dict, host_results: list[dict], event_type: str) -> None:
    sns = _sns_client()
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    down_regions = [r["region"] for r in host_results if r.get("status") == "down"]
    degraded_regions = [r["region"] for r in host_results if r.get("status") == "degraded"]
    avg_latency = round(sum(r.get("latency_ms", 0) for r in host_results) / len(host_results)) if host_results else 0

    if event_type == "DOWN":
        subject = f"[DOWN] {host['name']}"
        body = (
            f"{host['name']} is DOWN\n\n"
            f"URL: {host['url']}\n"
            f"Down regions: {', '.join(down_regions) or 'unknown'}\n"
            f"Degraded regions: {', '.join(degraded_regions) or 'none'}\n"
            f"Time: {now_str}\n"
        )
    else:
        subject = f"[RESOLVED] {host['name']}"
        body = (
            f"{host['name']} recovered\n\n"
            f"URL: {host['url']}\n"
            f"Regions checked: {', '.join(sorted(r['region'] for r in host_results))}\n"
            f"Average latency: {avg_latency} ms\n"
            f"Time: {now_str}\n"
        )

    try:
        sns.publish(TopicArn=host["alert_sns_arn"], Subject=subject, Message=body)
        print(f"[alerts] sent {event_type} for {host['name']}")
    except Exception as exc:
        print(f"[alerts] failed for {host['name']}: {exc}")


# ── Regions ───────────────────────────────────────────────────────────────────

def _list_regions() -> dict:
    return _json(200, reg.list_regions(_db()))

def _add_region(body: dict) -> dict:
    region = (body.get("region") or "").strip()
    if not region:
        return _json(400, {"error": "'region' is required (e.g. 'us-east-1')"})
    memory_mb = int(body.get("memory_mb", 256))
    try:
        info = reg.deploy_region(region, memory_mb)
        reg.save_region_record(_db(), info)
        return _json(200, info)
    except Exception as e:
        return _json(500, {"error": str(e)})

def _update_region(region: str) -> dict:
    """Re-deploy the current worker code to an existing region."""
    existing = _db().Table(HOSTS_TABLE).get_item(Key={"host_id": f"__region__{region}"}).get("Item")
    if not existing:
        return _json(404, {"error": f"Region {region} not found. Deploy it first."})
    memory_mb = int(existing.get("memory_mb", 256))
    try:
        info = reg.deploy_region(region, memory_mb)
        reg.save_region_record(_db(), info)
        return _json(200, info)
    except Exception as e:
        return _json(500, {"error": str(e)})

def _remove_region(region: str) -> dict:
    try:
        reg.teardown_region(region)
        reg.delete_region_record(_db(), region)
        # If no regions remain, remove the shared IAM role too
        remaining = reg.list_regions(_db())
        if not remaining:
            reg.delete_monitor_role()
        return _json(200, {"removed": region})
    except Exception as e:
        return _json(500, {"error": str(e)})


# ── Custom domain ─────────────────────────────────────────────────────────────

def _get_custom_domain_status(event: dict | None = None) -> dict:
    settings = _load_settings_item()
    cert_arn = settings.get("custom_domain_certificate_arn")
    if cert_arn:
        try:
            cert = _acm_client().describe_certificate(CertificateArn=cert_arn)["Certificate"]
            settings["custom_domain_validation_records"] = _certificate_validation_records(cert)
            if cert["Status"] != "ISSUED":
                settings["custom_domain_status"] = "pending_validation"
        except Exception as exc:
            settings["custom_domain_last_error"] = str(exc)
    distribution_id = settings.get("custom_domain_distribution_id")
    if distribution_id:
        try:
            distribution = _cloudfront_client().get_distribution(Id=distribution_id)["Distribution"]
            settings["custom_domain_distribution_domain_name"] = distribution["DomainName"]
            settings["custom_domain_distribution_status"] = distribution["Status"]
            settings["custom_domain_status"] = "ready" if distribution["Status"] == "Deployed" else "creating_distribution"
        except Exception as exc:
            settings["custom_domain_last_error"] = str(exc)
    _save_settings_item(settings)
    summary = _custom_domain_summary(settings, event)
    return _json(200, summary)


def _deploy_custom_domain(body: dict, event: dict | None = None) -> dict:
    domain_name = str(body.get("domain_name") or "").strip().lower().rstrip(".")
    if not domain_name:
        return _json(400, {"error": "'domain_name' is required"})

    settings = _load_settings_item()
    existing_domain = str(settings.get("custom_domain_name") or "").strip().lower().rstrip(".")
    if existing_domain and existing_domain != domain_name and (
        settings.get("custom_domain_certificate_arn") or settings.get("custom_domain_distribution_id")
    ):
        return _json(400, {"error": f"Custom domain resources already exist for {existing_domain}. Destroy them first before switching domains."})

    origin_url = _management_origin_url(settings, event)
    if not origin_url:
        return _json(400, {"error": "Unable to determine the raw Lambda Function URL. Open the admin using the Function URL once, then try again."})

    settings["custom_domain_name"] = domain_name
    settings["custom_domain_origin_url"] = origin_url
    settings["custom_domain_last_error"] = ""

    cert_arn = settings.get("custom_domain_certificate_arn")
    if not cert_arn:
        cert_resp = _acm_client().request_certificate(
            DomainName=domain_name,
            ValidationMethod="DNS",
            Tags=[
                {"Key": "Project", "Value": os.environ.get("PROJECT", "uptime")},
                {"Key": "ManagedBy", "Value": "uptime-management"},
            ],
        )
        cert_arn = cert_resp["CertificateArn"]
        settings["custom_domain_certificate_arn"] = cert_arn

    cert = _acm_client().describe_certificate(CertificateArn=cert_arn)["Certificate"]
    validation_records = _certificate_validation_records(cert)
    settings["custom_domain_validation_records"] = validation_records

    if cert["Status"] != "ISSUED":
        settings["custom_domain_status"] = "pending_validation"
        settings["custom_domain_distribution_status"] = ""
        _save_settings_item(settings)
        return _json(200, _custom_domain_summary(settings, event))

    distribution_id = settings.get("custom_domain_distribution_id")
    if not distribution_id:
        distribution = _cloudfront_client().create_distribution(
            DistributionConfig=_cloudfront_distribution_config(
                domain_name=domain_name,
                origin_url=origin_url,
                certificate_arn=cert_arn,
            )
        )["Distribution"]
        settings["custom_domain_distribution_id"] = distribution["Id"]
        settings["custom_domain_distribution_domain_name"] = distribution["DomainName"]
        settings["custom_domain_distribution_status"] = distribution["Status"]
        settings["custom_domain_status"] = "creating_distribution"
        _save_settings_item(settings)
        return _json(200, _custom_domain_summary(settings, event))

    try:
        distribution = _cloudfront_client().get_distribution(Id=distribution_id)["Distribution"]
        settings["custom_domain_distribution_domain_name"] = distribution["DomainName"]
        settings["custom_domain_distribution_status"] = distribution["Status"]
        settings["custom_domain_status"] = "ready" if distribution["Status"] == "Deployed" else "creating_distribution"
    except Exception as exc:
        settings["custom_domain_last_error"] = str(exc)
        settings["custom_domain_status"] = "error"

    _save_settings_item(settings)
    return _json(200, _custom_domain_summary(settings, event))


def _destroy_custom_domain() -> dict:
    settings = _load_settings_item()
    if not settings.get("custom_domain_name") and not settings.get("custom_domain_certificate_arn") and not settings.get("custom_domain_distribution_id"):
        return _json(200, {"ok": True, "status": "not_configured", "dns_records_to_remove": []})
    cleanup_records = _custom_domain_summary(settings).get("dns_records_to_remove", [])

    distribution_id = settings.get("custom_domain_distribution_id")
    if distribution_id:
        try:
            dist_resp = _cloudfront_client().get_distribution_config(Id=distribution_id)
            dist_cfg = dist_resp["DistributionConfig"]
            etag = dist_resp["ETag"]
            if dist_cfg.get("Enabled", False):
                dist_cfg["Enabled"] = False
                _cloudfront_client().update_distribution(Id=distribution_id, IfMatch=etag, DistributionConfig=dist_cfg)
                settings["custom_domain_distribution_status"] = "Disabling"
                settings["custom_domain_status"] = "disabling_distribution"
                _save_settings_item(settings)
                return _json(200, _custom_domain_summary(settings))
            distribution = _cloudfront_client().get_distribution(Id=distribution_id)["Distribution"]
            settings["custom_domain_distribution_status"] = distribution["Status"]
            if distribution["Status"] != "Deployed":
                settings["custom_domain_status"] = "disabling_distribution"
                _save_settings_item(settings)
                return _json(200, _custom_domain_summary(settings))
            _cloudfront_client().delete_distribution(Id=distribution_id, IfMatch=etag)
            settings["custom_domain_distribution_id"] = ""
            settings["custom_domain_distribution_domain_name"] = ""
            settings["custom_domain_distribution_status"] = ""
        except _cloudfront_client().exceptions.NoSuchDistribution:
            settings["custom_domain_distribution_id"] = ""
            settings["custom_domain_distribution_domain_name"] = ""
            settings["custom_domain_distribution_status"] = ""

    cert_arn = settings.get("custom_domain_certificate_arn")
    if cert_arn:
        try:
            _acm_client().delete_certificate(CertificateArn=cert_arn)
            settings["custom_domain_certificate_arn"] = ""
            settings["custom_domain_validation_records"] = []
        except Exception as exc:
            settings["custom_domain_status"] = "waiting_certificate_release"
            settings["custom_domain_last_error"] = str(exc)
            _save_settings_item(settings)
            return _json(200, _custom_domain_summary(settings))

    settings["custom_domain_status"] = "not_configured"
    settings["custom_domain_last_error"] = ""
    _save_settings_item(settings)
    summary = _custom_domain_summary(settings)
    if cleanup_records:
        summary["dns_records_to_remove"] = cleanup_records
    return _json(200, summary)


def _management_origin_url(settings: dict, event: dict | None = None) -> str:
    saved = str(settings.get("custom_domain_origin_url") or "").strip()
    if saved:
        return saved
    request_domain = (((event or {}).get("requestContext") or {}).get("domainName") or "").strip()
    if request_domain and ".lambda-url." in request_domain and request_domain.endswith(".on.aws"):
        proto = ((event or {}).get("headers") or {}).get("x-forwarded-proto", "https")
        return f"{proto}://{request_domain}"
    return ""


def _certificate_validation_records(certificate: dict) -> list[dict]:
    records = []
    for option in certificate.get("DomainValidationOptions", []):
        resource_record = option.get("ResourceRecord") or {}
        if not resource_record:
            continue
        records.append({
            "name": resource_record.get("Name", ""),
            "type": resource_record.get("Type", ""),
            "value": resource_record.get("Value", ""),
        })
    return records


def _cloudfront_distribution_config(domain_name: str, origin_url: str, certificate_arn: str) -> dict:
    origin_domain = urlparse(origin_url).netloc
    return {
        "CallerReference": f"{domain_name}-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
        "Comment": f"{os.environ.get('PROJECT', 'uptime')} status page for {domain_name}",
        "Enabled": True,
        "Aliases": {"Quantity": 1, "Items": [domain_name]},
        "Origins": {
            "Quantity": 1,
            "Items": [{
                "Id": "lambda",
                "DomainName": origin_domain,
                "CustomOriginConfig": {
                    "HTTPPort": 80,
                    "HTTPSPort": 443,
                    "OriginProtocolPolicy": "https-only",
                    "OriginSslProtocols": {"Quantity": 1, "Items": ["TLSv1.2"]},
                },
            }],
        },
        "DefaultCacheBehavior": {
            "TargetOriginId": "lambda",
            "ViewerProtocolPolicy": "redirect-to-https",
            "AllowedMethods": {
                "Quantity": 7,
                "Items": ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"],
                "CachedMethods": {
                    "Quantity": 2,
                    "Items": ["GET", "HEAD"],
                },
            },
            "Compress": True,
            "TrustedSigners": {"Enabled": False, "Quantity": 0},
            "ForwardedValues": {
                "QueryString": True,
                "Cookies": {"Forward": "none"},
                "Headers": {"Quantity": 1, "Items": ["Authorization"]},
            },
            "MinTTL": 0,
            "DefaultTTL": 30,
            "MaxTTL": 60,
        },
        "ViewerCertificate": {
            "ACMCertificateArn": certificate_arn,
            "SSLSupportMethod": "sni-only",
            "MinimumProtocolVersion": "TLSv1.2_2021",
        },
        "Restrictions": {
            "GeoRestriction": {"RestrictionType": "none", "Quantity": 0}
        },
        "PriceClass": "PriceClass_All",
        "HttpVersion": "http2",
        "IsIPV6Enabled": True,
    }


def _custom_domain_summary(settings: dict, event: dict | None = None) -> dict:
    domain_name = str(settings.get("custom_domain_name") or "").strip()
    validation_records = settings.get("custom_domain_validation_records") or []
    distribution_domain = str(settings.get("custom_domain_distribution_domain_name") or "").strip()
    distribution_status = str(settings.get("custom_domain_distribution_status") or "").strip()
    status = str(settings.get("custom_domain_status") or ("not_configured" if not domain_name else "pending_validation"))
    origin_url = _management_origin_url(settings, event)

    dns_records_to_create = []
    if status == "pending_validation":
        for record in validation_records:
            dns_records_to_create.append({
                "purpose": "ACM validation",
                **record,
            })
    if distribution_domain:
        dns_records_to_create.append({
            "purpose": "Status page traffic",
            "type": "CNAME",
            "name": domain_name,
            "value": distribution_domain,
            "note": "For Route53 you can use an Alias A/AAAA to this CloudFront distribution instead of a CNAME.",
        })

    dns_records_to_remove = []
    if distribution_domain:
        dns_records_to_remove.append({
            "purpose": "Status page traffic",
            "type": "CNAME or Alias",
            "name": domain_name,
            "value": distribution_domain,
        })
    for record in validation_records:
        dns_records_to_remove.append({
            "purpose": "ACM validation",
            **record,
        })

    return {
        "configured": bool(domain_name),
        "domain_name": domain_name,
        "origin_url": origin_url,
        "certificate_arn": settings.get("custom_domain_certificate_arn", ""),
        "distribution_id": settings.get("custom_domain_distribution_id", ""),
        "distribution_domain_name": distribution_domain,
        "distribution_status": distribution_status,
        "status": status,
        "last_error": settings.get("custom_domain_last_error", ""),
        "dns_records_to_create": dns_records_to_create,
        "dns_records_to_remove": dns_records_to_remove,
    }


# ── Cost estimate ─────────────────────────────────────────────────────────────

def _cost_estimate(qs: dict) -> dict:
    defaults = _default_cost_inputs()
    hosts    = int(qs.get("hosts",    [str(defaults["hosts"])])[0])
    rcount   = int(qs.get("regions",  [str(defaults["regions"])])[0])
    interval = int(qs.get("interval", [str(defaults["interval_sec"])])[0])
    days     = int(qs.get("days",     [str(defaults["retention_days"])])[0])

    checks_mo    = int((30 * 24 * 3600 / interval) * hosts * rcount)
    invocations  = int((30 * 24 * 3600 / interval) * (rcount + 1))
    gb_sec       = int((30 * 24 * 3600 / interval) * rcount) * 2.0 * (256 / 1024)
    lambda_cost  = max(0, (invocations - 1_000_000) / 1_000_000 * 0.20) + \
                   max(0, (gb_sec - 400_000) * 0.00001667)
    ddb_w        = checks_mo * 2
    ddb_r        = checks_mo * 0.1
    ddb_w_cost   = max(0, (ddb_w - 1_000_000) / 1_000_000 * 1.25)
    ddb_r_cost   = max(0, (ddb_r - 1_000_000) / 1_000_000 * 0.25)
    items        = checks_mo * (days / 30)
    storage_gb   = (items * 500) / (1024 ** 3)
    storage_cost = max(0, (storage_gb - 25) * 0.25)
    log_gb       = (checks_mo * 100) / (1024 ** 3)
    log_cost     = max(0, (log_gb - 5) * 0.50)
    total        = lambda_cost + ddb_w_cost + ddb_r_cost + storage_cost + log_cost

    return _json(200, {
        "inputs": {"hosts": hosts, "regions": rcount, "interval_sec": interval, "retention_days": days},
        "defaults": defaults,
        "monthly_checks": checks_mo,
        "breakdown": {
            "lambda_usd":           round(lambda_cost,  4),
            "dynamodb_writes_usd":  round(ddb_w_cost,   4),
            "dynamodb_reads_usd":   round(ddb_r_cost,   4),
            "dynamodb_storage_usd": round(storage_cost, 4),
            "cloudwatch_logs_usd":  round(log_cost,     4),
        },
        "total_usd_per_month": round(total, 4),
        "note": "AWS Free Tier applied (1M Lambda req/mo, 25GB DynamoDB, 5GB logs). Actual cost may vary.",
    })


def _default_cost_inputs() -> dict:
    hosts = [host for host in _list_host_items() if host.get("enabled", True)]
    settings = _db().Table(HOSTS_TABLE).get_item(Key={"host_id": "__settings__"}).get("Item", {})
    return {
        "hosts": len(hosts),
        "regions": len(reg.list_regions(_db())),
        "interval_sec": int(settings.get("default_check_interval", _SETTINGS_DEFAULTS["default_check_interval"])),
        "retention_days": int(settings.get("retention_days", _SETTINGS_DEFAULTS["retention_days"])),
    }


# ── Public status page ────────────────────────────────────────────────────────

def _serve_status_page() -> dict:
    db = _db()
    settings = db.Table(HOSTS_TABLE).get_item(Key={"host_id": "__settings__"}).get("Item", {})
    title = settings.get("status_page_title",       _SETTINGS_DEFAULTS["status_page_title"])
    desc  = settings.get("status_page_description", _SETTINGS_DEFAULTS["status_page_description"])
    brand_name = settings.get("status_page_brand_name", _SETTINGS_DEFAULTS["status_page_brand_name"])
    logo_url = settings.get("status_page_logo_url", _SETTINGS_DEFAULTS["status_page_logo_url"])
    theme = settings.get("status_page_theme", _SETTINGS_DEFAULTS["status_page_theme"])
    subscribe_intro = settings.get("status_page_subscribe_intro", _SETTINGS_DEFAULTS["status_page_subscribe_intro"])
    subscribe_email_url = settings.get("status_page_subscribe_email_url", _SETTINGS_DEFAULTS["status_page_subscribe_email_url"])
    subscribe_sms_url = settings.get("status_page_subscribe_sms_url", _SETTINGS_DEFAULTS["status_page_subscribe_sms_url"])
    subscribe_webhook_url = settings.get("status_page_subscribe_webhook_url", _SETTINGS_DEFAULTS["status_page_subscribe_webhook_url"])
    maintenance_enabled = bool(settings.get("maintenance_enabled", _SETTINGS_DEFAULTS["maintenance_enabled"]))
    maintenance_message = settings.get("maintenance_message", _SETTINGS_DEFAULTS["maintenance_message"])
    maintenance_window = settings.get("maintenance_window", _SETTINGS_DEFAULTS["maintenance_window"])
    maintenance_scope = settings.get("maintenance_scope", _SETTINGS_DEFAULTS["maintenance_scope"])

    hosts_result = db.Table(HOSTS_TABLE).scan(
        FilterExpression="show_on_status_page = :t AND host_id <> :s AND NOT begins_with(host_id, :r)",
        ExpressionAttributeValues={":t": True, ":s": "__settings__", ":r": "__region__"},
    )
    hosts = sorted(hosts_result.get("Items", []), key=lambda h: h.get("name", ""))

    from boto3.dynamodb.conditions import Key as DKey
    host_data = []
    for host in hosts:
        checks = db.Table(CHECKS_TABLE).query(
            KeyConditionExpression=DKey("host_id").eq(host["host_id"]),
            ScanIndexForward=False,
            Limit=300,
        ).get("Items", [])
        grouped = {}
        for check in checks:
            run_id = check.get("run_id") or check.get("checked_at")
            grouped.setdefault(run_id, []).append(check)

        latest_runs = sorted(grouped.keys(), reverse=True)[:90]
        run_statuses = [_aggregate_status(grouped[run_id]) for run_id in latest_runs]
        flat_checks = [item for run_id in latest_runs for item in grouped[run_id]]

        if run_statuses:
            up_count = sum(1 for status in run_statuses if status == "up")
            uptime_pct = round((up_count / len(run_statuses)) * 100, 1)
            avg_latency = round(sum(float(c.get("latency_ms", 0)) for c in flat_checks) / len(flat_checks))
        else:
            uptime_pct, avg_latency = 100.0, 0
        latest_latency = host.get("last_latency_ms")
        region_summary = []
        for region_name, region_info in sorted((host.get("region_statuses") or {}).items()):
            region_summary.append({
                "region": region_name,
                "status": region_info.get("status", "unknown"),
                "latency_ms": region_info.get("latency_ms"),
            })
        host_data.append({
            "host":           host,
            "uptime_pct":     uptime_pct,
            "avg_latency":    avg_latency,
            "latest_latency": latest_latency,
            "region_summary": region_summary,
            "history":        list(reversed(run_statuses)),
            "current_status": host.get("current_status", "unknown"),
        })
    return _html(
        200,
        _render_status_page(
            title,
            desc,
            brand_name,
            logo_url,
            theme,
            host_data,
            {
                "subscribe_intro": subscribe_intro,
                "subscribe_email_url": subscribe_email_url,
                "subscribe_sms_url": subscribe_sms_url,
                "subscribe_webhook_url": subscribe_webhook_url,
                "maintenance_enabled": maintenance_enabled,
                "maintenance_message": maintenance_message,
                "maintenance_window": maintenance_window,
                "maintenance_scope": maintenance_scope,
            },
        ),
    )


def _render_status_page(title: str, desc: str, brand_name: str, logo_url: str, theme: str, host_data: list, page_options: dict) -> str:
    overall, ocls = "All systems operational", "operational"
    for h in host_data:
        if h["current_status"] == "down":
            overall, ocls = "Some systems are experiencing issues", "down"; break
        if h["current_status"] == "degraded":
            overall, ocls = "Some systems are degraded", "degraded"

    theme_class = theme if theme in {"clean", "midnight", "sunrise", "forest"} else "clean"
    maintenance_block = ""
    if page_options.get("maintenance_enabled") and page_options.get("maintenance_message"):
        window = page_options.get("maintenance_window", "").strip()
        scope = page_options.get("maintenance_scope", "").strip()
        maintenance_meta = []
        if window:
            maintenance_meta.append(f"<span>Window: {window}</span>")
        if scope:
            maintenance_meta.append(f"<span>Affected: {scope}</span>")
        maintenance_block = f"""<div class="maintenance">
  <div class="maintenance-title">Scheduled maintenance</div>
  <div class="maintenance-copy">{page_options["maintenance_message"]}</div>
  <div class="maintenance-meta">{' · '.join(maintenance_meta) if maintenance_meta else 'We will post updates here during the maintenance window.'}</div>
</div>"""

    subscribe_links = []
    if page_options.get("subscribe_email_url"):
        subscribe_links.append(f'<a class="subscribe-btn" href="{page_options["subscribe_email_url"]}">Email</a>')
    if page_options.get("subscribe_sms_url"):
        subscribe_links.append(f'<a class="subscribe-btn" href="{page_options["subscribe_sms_url"]}">SMS</a>')
    if page_options.get("subscribe_webhook_url"):
        subscribe_links.append(f'<a class="subscribe-btn" href="{page_options["subscribe_webhook_url"]}">Webhook / RSS</a>')
    subscribe_block = ""
    if subscribe_links:
        subscribe_block = f"""<div class="subscribe">
  <div>
    <div class="subscribe-title">Stay informed</div>
    <div class="subscribe-copy">{page_options.get("subscribe_intro") or _SETTINGS_DEFAULTS["status_page_subscribe_intro"]}</div>
  </div>
  <div class="subscribe-actions">{''.join(subscribe_links)}</div>
</div>"""

    cards = ""
    for h in host_data:
        s     = h["current_status"]
        badge = {"up": "Operational", "down": "Down", "degraded": "Degraded"}.get(s, "Unknown")
        bars  = "".join(f'<span class="b {c}"></span>' for c in h["history"]) \
                or '<span class="b unknown"></span>' * 10
        latency_bits = []
        if h["latest_latency"] is not None:
            latency_bits.append(f"{h['latest_latency']} ms latest")
        latency_bits.append(f"{h['avg_latency']} ms avg")
        region_pills = "".join(
            f'<span class="pill {r["status"]}">{r["region"]} · {r["latency_ms"] if r["latency_ms"] is not None else "—"} ms</span>'
            for r in h["region_summary"]
        )
        cards += f"""<div class="card">
  <div class="row"><span class="svc">{h['host']['name']}</span><span class="badge {s}">{badge}</span></div>
  <div class="meta">{h['uptime_pct']}% uptime &nbsp;·&nbsp; {' &nbsp;·&nbsp; '.join(latency_bits)}</div>
  <div class="history-title">Recent history</div>
  <div class="bars">{bars}</div>
  <div class="bar-lbl"><span>90 checks ago</span><span>Latest</span></div>
  <div class="regions">{region_pills or '<span class="pill unknown">No regional data yet</span>'}</div>
</div>"""

    if not host_data:
        cards = '<p class="empty">No services configured for the status page yet.</p>'

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    brand = ""
    if brand_name or logo_url:
        logo = f'<img src="{logo_url}" alt="{brand_name}" class="brand-logo">' if logo_url else ""
        brand = f'<div class="brand">{logo}<span>{brand_name or title}</span></div>'
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:var(--bg);color:var(--text)}}
.theme-clean{{--bg:#f8fafc;--text:#1e293b;--card:#ffffff;--border:#e2e8f0;--muted:#64748b;--soft:#94a3b8;--hero:#ffffff;--hero-border:#e2e8f0}}
.theme-midnight{{--bg:#020617;--text:#e2e8f0;--card:#0f172a;--border:#1e293b;--muted:#94a3b8;--soft:#64748b;--hero:#0b1120;--hero-border:#1e293b}}
.theme-sunrise{{--bg:#fff7ed;--text:#431407;--card:#ffffff;--border:#fed7aa;--muted:#9a3412;--soft:#c2410c;--hero:#fffbeb;--hero-border:#fdba74}}
.theme-forest{{--bg:#f0fdf4;--text:#14532d;--card:#ffffff;--border:#bbf7d0;--muted:#15803d;--soft:#16a34a;--hero:#ecfdf5;--hero-border:#86efac}}
.wrap{{max-width:780px;margin:0 auto;padding:40px 20px}}
.brand{{display:flex;align-items:center;gap:12px;font-size:.95rem;font-weight:700;color:var(--muted);margin-bottom:20px}}
.brand-logo{{height:36px;width:36px;object-fit:contain;border-radius:10px;background:var(--card);border:1px solid var(--border);padding:4px}}
h1{{font-size:1.9rem;font-weight:700;margin-bottom:6px}}
.sub{{color:var(--muted);margin-bottom:32px}}
.overall{{display:flex;align-items:center;gap:12px;padding:18px 22px;border-radius:10px;margin-bottom:28px;font-weight:600;background:var(--hero);border:1px solid var(--hero-border)}}
.overall.operational{{background:#f0fdf4;border:1px solid #bbf7d0}}
.overall.down{{background:#fef2f2;border:1px solid #fecaca}}
.overall.degraded{{background:#fffbeb;border:1px solid #fde68a}}
.maintenance,.subscribe{{display:flex;justify-content:space-between;gap:18px;align-items:flex-start;padding:18px 22px;border-radius:10px;margin-bottom:20px;background:var(--hero);border:1px solid var(--hero-border)}}
.maintenance{{background:#eff6ff;border-color:#bfdbfe}}
.maintenance-title,.subscribe-title{{font-size:.82rem;font-weight:800;letter-spacing:.06em;text-transform:uppercase;margin-bottom:6px}}
.maintenance-copy,.subscribe-copy{{font-size:.96rem;line-height:1.5}}
.maintenance-meta{{margin-top:8px;color:var(--muted);font-size:.82rem}}
.subscribe-actions{{display:flex;flex-wrap:wrap;gap:10px}}
.subscribe-btn{{display:inline-flex;align-items:center;justify-content:center;padding:10px 14px;border-radius:999px;border:1px solid var(--border);background:var(--card);color:var(--text);text-decoration:none;font-weight:700;white-space:nowrap}}
.subscribe-btn:hover{{opacity:.92}}
.dot{{width:14px;height:14px;border-radius:50%;flex-shrink:0}}
.operational .dot{{background:#22c55e}}.down .dot{{background:#ef4444}}.degraded .dot{{background:#f59e0b}}
.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:18px;margin-bottom:14px}}
.row{{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}}
.svc{{font-weight:600}}
.badge{{font-size:.78rem;font-weight:700;padding:3px 11px;border-radius:20px}}
.badge.up{{background:#f0fdf4;color:#16a34a}}.badge.down{{background:#fef2f2;color:#dc2626}}
.badge.degraded{{background:#fffbeb;color:#d97706}}.badge.unknown{{background:#f1f5f9;color:#64748b}}
.meta{{font-size:.83rem;color:var(--muted);margin-bottom:10px}}
.history-title{{font-size:.76rem;color:var(--soft);text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px}}
.bars{{display:flex;gap:2px;height:26px}}
.b{{flex:1;border-radius:2px;min-width:3px}}
.b.up{{background:#22c55e}}.b.down{{background:#ef4444}}.b.degraded{{background:#f59e0b}}.b.unknown{{background:#e2e8f0}}
.bar-lbl{{display:flex;justify-content:space-between;font-size:.72rem;color:var(--soft);margin-top:3px}}
.regions{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.pill{{display:inline-flex;align-items:center;padding:4px 9px;border-radius:999px;font-size:.72rem;font-weight:600;background:#f8fafc;color:#475569;border:1px solid var(--border)}}
.pill.up{{background:#f0fdf4;color:#166534;border-color:#bbf7d0}}
.pill.down{{background:#fef2f2;color:#b91c1c;border-color:#fecaca}}
.pill.degraded{{background:#fffbeb;color:#b45309;border-color:#fde68a}}
.pill.unknown{{background:#f8fafc;color:#64748b}}
.empty{{text-align:center;color:var(--soft);padding:40px 0}}
footer{{text-align:center;margin-top:50px;font-size:.78rem;color:var(--soft)}}
@media (max-width: 700px) {{
  .maintenance,.subscribe{{flex-direction:column}}
  .subscribe-actions{{width:100%}}
  .subscribe-btn{{width:100%}}
}}
</style></head><body class="theme-{theme_class}">
<div class="wrap">
  {brand}
  <h1>{title}</h1><p class="sub">{desc}</p>
  <div class="overall {ocls}"><div class="dot"></div><span>{overall}</span></div>
  {maintenance_block}
  {subscribe_block}
  {cards}
  <footer>Updated {now_str}</footer>
</div></body></html>"""


# ── Admin SPA ─────────────────────────────────────────────────────────────────

def _admin_page() -> str:
    # All AWS regions available for monitor deployment
    all_regions = [
        "us-east-1","us-east-2","us-west-1","us-west-2",
        "ca-central-1","ca-west-1",
        "eu-west-1","eu-west-2","eu-west-3","eu-central-1","eu-central-2",
        "eu-north-1","eu-south-1","eu-south-2",
        "ap-east-1","ap-south-1","ap-south-2",
        "ap-southeast-1","ap-southeast-2","ap-southeast-3","ap-southeast-4","ap-southeast-5","ap-southeast-7",
        "ap-northeast-1","ap-northeast-2","ap-northeast-3",
        "sa-east-1","af-south-1","me-south-1","me-central-1","il-central-1","mx-central-1",
    ]
    region_options = "\n".join(f'<option value="{r}">{r}</option>' for r in all_regions)

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Uptime Admin</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}}
nav{{background:#1e293b;border-bottom:1px solid #334155;padding:0 24px;display:flex;align-items:center;height:52px;gap:0}}
.logo{{font-weight:700;color:#f8fafc;font-size:1.05rem;margin-right:32px;white-space:nowrap}}
.nav-spacer{{margin-left:auto}}
.tab{{padding:0 16px;height:52px;display:flex;align-items:center;cursor:pointer;font-size:.9rem;color:#94a3b8;border-bottom:2px solid transparent;white-space:nowrap}}
.tab.active,.tab:hover{{color:#f8fafc;border-bottom-color:#6366f1}}
.main{{max-width:960px;margin:0 auto;padding:32px 20px}}
h2{{font-size:1.3rem;font-weight:700;margin-bottom:20px}}
h3{{font-size:1rem;font-weight:600;margin:20px 0 8px;color:#e2e8f0}}
.btn{{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:7px;border:none;cursor:pointer;font-size:.875rem;font-weight:600;transition:all .15s;text-decoration:none}}
.btn-primary{{background:#6366f1;color:#fff}}.btn-primary:hover{{background:#4f46e5}}
.btn-success{{background:#16a34a;color:#fff}}.btn-success:hover{{background:#15803d}}
.btn-danger{{background:#ef4444;color:#fff}}.btn-danger:hover{{background:#dc2626}}
.btn-warn{{background:#d97706;color:#fff}}.btn-warn:hover{{background:#b45309}}
.btn-ghost{{background:transparent;color:#94a3b8;border:1px solid #334155}}.btn-ghost:hover{{color:#f8fafc;border-color:#64748b}}
.btn-sm{{padding:4px 10px;font-size:.8rem}}
table{{width:100%;border-collapse:collapse;background:#1e293b;border-radius:10px;overflow:hidden}}
th{{background:#0f172a;color:#64748b;font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;padding:10px 14px;text-align:left;white-space:nowrap}}
td{{padding:12px 14px;border-top:1px solid #334155;font-size:.875rem;vertical-align:middle}}
.badge{{display:inline-block;padding:2px 9px;border-radius:12px;font-size:.75rem;font-weight:700}}
.badge.up,.badge.active{{background:#166534;color:#bbf7d0}}
.badge.down{{background:#7f1d1d;color:#fecaca}}
.badge.degraded{{background:#713f12;color:#fde68a}}
.badge.unknown,.badge.inactive{{background:#1e293b;color:#64748b;border:1px solid #334155}}
.badge.http,.badge.tcp{{background:#1e3a5f;color:#93c5fd}}
.modal-overlay{{position:fixed;inset:0;background:rgba(0,0,0,.75);display:none;align-items:center;justify-content:center;z-index:100}}
.modal-overlay.open{{display:flex}}
.modal{{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:28px;width:100%;max-width:520px;max-height:90vh;overflow-y:auto}}
.modal h3{{font-size:1.1rem;margin-bottom:20px;margin-top:0}}
.form-group{{margin-bottom:16px}}
label{{display:block;font-size:.82rem;color:#94a3b8;margin-bottom:5px;font-weight:500}}
input,select,textarea{{width:100%;background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 12px;color:#f8fafc;font-size:.875rem;transition:border .15s}}
input:focus,select:focus{{outline:none;border-color:#6366f1}}
.toggle{{display:flex;align-items:center;gap:10px;cursor:pointer}}
.toggle input[type=checkbox]{{width:auto;cursor:pointer}}
.hint{{font-size:.75rem;color:#64748b;margin-top:3px;line-height:1.4}}
.panel{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:20px;margin-bottom:20px}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.actions{{display:flex;gap:8px;flex-wrap:wrap}}
.toast{{position:fixed;bottom:24px;right:24px;background:#22c55e;color:#fff;padding:10px 18px;border-radius:8px;font-size:.875rem;font-weight:600;z-index:200;transition:opacity .3s}}
.toast.error{{background:#ef4444}}
.toast.hidden{{opacity:0;pointer-events:none}}
.cost-row{{display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid #334155;font-size:.875rem}}
.cost-row:last-child{{border:none;font-weight:700;color:#6366f1;font-size:1rem}}
pre{{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:14px;font-size:.78rem;overflow-x:auto;line-height:1.6;color:#a5b4fc}}
.tip{{background:#1e3a5f;border-left:3px solid #6366f1;padding:10px 14px;border-radius:0 6px 6px 0;font-size:.83rem;color:#93c5fd;margin:12px 0;line-height:1.5}}
p.desc{{color:#94a3b8;font-size:.875rem;line-height:1.6;margin-bottom:12px}}
.region-card{{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:16px;display:flex;justify-content:space-between;align-items:center;margin-bottom:10px}}
.region-info .name{{font-weight:600;margin-bottom:4px}}
.region-info .meta{{font-size:.8rem;color:#64748b}}
.section-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
.spinner{{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}}
.auth-gate{{position:fixed;inset:0;background:rgba(2,6,23,.88);display:flex;align-items:center;justify-content:center;z-index:250;padding:20px}}
.auth-card{{width:100%;max-width:420px;background:#1e293b;border:1px solid #334155;border-radius:16px;padding:28px;box-shadow:0 20px 50px rgba(0,0,0,.35)}}
.auth-card h1{{font-size:1.25rem;margin-bottom:10px}}
.auth-card p{{color:#94a3b8;font-size:.9rem;line-height:1.6;margin-bottom:14px}}
.auth-msg{{font-size:.82rem;color:#94a3b8;min-height:18px;margin-top:10px}}
.checklist{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-top:10px}}
.check-item{{display:flex;align-items:center;gap:8px;background:#0f172a;border:1px solid #334155;border-radius:8px;padding:9px 10px;font-size:.83rem}}
.check-item input{{width:auto}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head><body>
<nav>
  <span class="logo">⬆ Uptime Admin</span>
  <span class="tab active"  onclick="show('hosts')">Hosts</span>
  <span class="tab"         onclick="show('regions')">Regions</span>
  <span class="tab"         onclick="show('status-page')">Status Page</span>
  <span class="tab"         onclick="show('notifications')">Notifications</span>
  <span class="tab"         onclick="show('settings')">Settings</span>
  <span class="tab"         onclick="show('cost')">Cost</span>
  <span class="tab"         onclick="show('guides')">Guides</span>
  <span class="nav-spacer"></span>
  <button class="btn btn-ghost btn-sm" onclick="logoutAdmin()">Sign out</button>
</nav>
<div class="auth-gate" id="auth-gate">
  <div class="auth-card">
    <h1>Admin access</h1>
    <p>Enter the admin password/token for this deployment. It stays in this browser session and is sent as a bearer token to the admin API.</p>
    <div class="form-group" style="margin-bottom:10px">
      <label>Admin Password / Token</label>
      <input id="auth-key" type="password" placeholder="Paste the admin key">
    </div>
    <div style="display:flex;gap:10px">
      <button class="btn btn-primary" onclick="loginAdmin()">Unlock Admin</button>
    </div>
    <div class="auth-msg" id="auth-msg"></div>
    <p style="margin-top:18px">If the stack generated the token for you, retrieve it with:</p>
    <pre>aws secretsmanager get-secret-value \\
  --secret-id uptime/admin-key \\
  --query SecretString \\
  --output text \\
  --region {HOME_REGION}</pre>
  </div>
</div>
<div class="main">

<div id="pane-hosts">
  <div class="section-header">
    <h2>Hosts</h2>
    <button class="btn btn-primary" onclick="openAddHost()">+ Add Host</button>
  </div>
  <table>
    <thead><tr>
      <th>Name</th><th>URL</th><th>Type</th><th>Status</th>
      <th>Uptime</th><th>Latency</th><th>Page</th><th>Alert</th><th></th>
    </tr></thead>
    <tbody id="hosts-body">
      <tr><td colspan="9" style="text-align:center;color:#64748b;padding:32px">Loading…</td></tr>
    </tbody>
  </table>
</div>

<div id="pane-regions" style="display:none">
  <div class="section-header">
    <h2>Worker Regions</h2>
    <button class="btn btn-primary" onclick="openAddRegion()">+ Add Region</button>
  </div>
  <p class="desc">
    The management Lambda owns the schedule and invokes one regional worker Lambda per configured region.
    Add multiple regions for global coverage and to detect regional outages without letting each region self-schedule.
    Worker Lambdas are deployed directly from here.
  </p>
  <div class="tip">
    Recommended starter set: <strong>us-east-1</strong>, <strong>eu-west-1</strong>, <strong>ap-southeast-1</strong>.
  </div>
  <div id="regions-list" style="margin-top:20px">
    <div style="color:#64748b;padding:20px 0">Loading…</div>
  </div>
</div>

<div id="pane-status-page" style="display:none">
  <h2>Status Page</h2>
  <p class="desc">
    Your public status page shows the hosts you select below. Visitors see current state, recent history, and per-region latency badges.
  </p>
  <div class="panel">
    <div class="grid2">
      <div class="form-group">
        <label>Brand Name</label>
        <input id="sp-brand" placeholder="Uptime">
      </div>
      <div class="form-group">
        <label>Theme</label>
        <select id="sp-theme">
          <option value="clean">Clean</option>
          <option value="midnight">Midnight</option>
          <option value="sunrise">Sunrise</option>
          <option value="forest">Forest</option>
        </select>
      </div>
    </div>
    <div class="form-group">
      <label>Page Title</label>
      <input id="sp-title" placeholder="System Status">
    </div>
    <div class="form-group">
      <label>Page Description</label>
      <input id="sp-desc" placeholder="Real-time status of our services">
    </div>
    <div class="form-group">
      <label>Logo URL</label>
      <input id="sp-logo" placeholder="https://example.com/logo.png">
      <div class="hint">Optional. A square PNG or SVG works best.</div>
    </div>
    <div class="form-group">
      <label class="toggle"><input type="checkbox" id="sp-maintenance-enabled"> Show maintenance notice</label>
    </div>
    <div class="form-group">
      <label>Maintenance Message</label>
      <input id="sp-maintenance-message" placeholder="Payments API maintenance is scheduled for Sunday at 02:00 UTC.">
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Maintenance Window</label>
        <input id="sp-maintenance-window" placeholder="Sun 02:00-03:00 UTC">
      </div>
      <div class="form-group">
        <label>Affected Scope</label>
        <input id="sp-maintenance-scope" placeholder="eu-west-1, us-east-1, Payments API">
      </div>
    </div>
    <div class="form-group">
      <label>Subscribe Intro</label>
      <input id="sp-subscribe-intro" placeholder="Subscribe for status updates.">
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Email Subscribe URL</label>
        <input id="sp-subscribe-email" placeholder="mailto:status@example.com?subject=Subscribe">
      </div>
      <div class="form-group">
        <label>SMS Subscribe URL</label>
        <input id="sp-subscribe-sms" placeholder="https://example.com/status/subscribe/sms">
      </div>
    </div>
    <div class="form-group">
      <label>Webhook / RSS URL</label>
      <input id="sp-subscribe-webhook" placeholder="https://example.com/status/feed.xml">
      <div class="hint">Set any public subscribe or feed links you want shown on the page.</div>
    </div>
    <div class="tip">
      Theme ideas: <strong>Clean</strong> for neutral SaaS, <strong>Midnight</strong> for infra teams,
      <strong>Sunrise</strong> for warmer brands, <strong>Forest</strong> for calm/product-trust styling.
    </div>
    <button class="btn btn-primary" onclick="saveStatusPageSettings()">Save</button>
  </div>
  <h3>Which hosts appear on the status page?</h3>
  <table>
    <thead><tr><th>Host</th><th>URL</th><th>Status</th><th>Visible on page</th></tr></thead>
    <tbody id="status-page-hosts">
      <tr><td colspan="4" style="text-align:center;color:#64748b;padding:24px">Loading…</td></tr>
    </tbody>
  </table>
  <div style="margin-top:20px">
    <a class="btn btn-ghost" href="/" target="_blank">Preview status page</a>
  </div>

  <h3 style="margin-top:28px">Custom Domain</h3>
  <div class="panel">
    <p class="desc">
      Deploy a CloudFront distribution in front of the raw Lambda Function URL. DNS is left manual on purpose: after each deploy step, the app will tell you exactly which records to create.
    </p>
    <div class="form-group">
      <label>Custom Domain</label>
      <input id="cd-domain" placeholder="uptime.example.com">
      <div class="hint">Use a subdomain like `uptime.example.com` for the simplest DNS setup.</div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-primary" onclick="deployCustomDomain()">Deploy / Continue</button>
      <button class="btn btn-ghost" onclick="refreshCustomDomain()">Refresh Status</button>
      <button class="btn btn-danger" onclick="destroyCustomDomain()">Destroy</button>
    </div>
    <pre id="cd-status" style="margin-top:14px">No custom domain configured.</pre>
  </div>
</div>

<div id="pane-notifications" style="display:none">
  <h2>Notifications</h2>
  <p class="desc">
    Configure the shared notification defaults for this deployment. Host-level SNS alert toggles still decide which hosts actually send transition alerts today.
  </p>
  <div class="panel">
    <div class="grid2">
      <div class="form-group">
        <label>Default SNS Topic ARN</label>
        <input id="n-topic-arn" placeholder="arn:aws:sns:us-east-1:123456789012:uptime-alerts">
        <div class="hint">Stored as the deployment-wide default target for alert routing.</div>
      </div>
      <div class="form-group">
        <label>Sender Label</label>
        <input id="n-sender-label" placeholder="UPTIME">
        <div class="hint">Useful as a display label for SMS or message templates where supported.</div>
      </div>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Initial Delay (seconds)</label>
        <input id="n-delay" type="number" min="0" max="86400">
      </div>
      <div class="form-group">
        <label>Reminder Interval (minutes)</label>
        <input id="n-reminder" type="number" min="0" max="10080">
        <div class="hint">Use `0` to disable recurring reminders.</div>
      </div>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>TTL (seconds)</label>
        <input id="n-ttl" type="number" min="0" max="2419200">
        <div class="hint">Only relevant for channels that support message expiration.</div>
      </div>
      <div class="form-group">
        <label>Sleep Until</label>
        <input id="n-sleep-until" placeholder="2026-05-04T06:00:00Z">
        <div class="hint">Temporary deployment-wide mute window end.</div>
      </div>
    </div>
    <div class="form-group">
      <label class="toggle"><input type="checkbox" id="n-quiet-enabled"> Enable quiet hours</label>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Quiet Hours Timezone</label>
        <input id="n-quiet-timezone" placeholder="UTC">
      </div>
      <div class="form-group">
        <label>Quiet Hours Range</label>
        <div class="grid2">
          <input id="n-quiet-start" placeholder="22:00">
          <input id="n-quiet-end" placeholder="07:00">
        </div>
      </div>
    </div>
    <div class="form-group">
      <label class="toggle"><input type="checkbox" id="n-maintenance-mute"> Mute notifications during maintenance</label>
    </div>
    <div class="tip">
      Current behavior: transition alerts are already sent via each host's configured SNS topic. Delay, reminder cadence, quiet hours, sleep, and maintenance muting are stored here for the next alerting pass, but are not fully enforced by the backend yet.
    </div>
    <button class="btn btn-primary" onclick="saveNotificationSettings()">Save Notification Settings</button>
  </div>
</div>

<div id="pane-settings" style="display:none">
  <h2>Settings</h2>
  <div class="panel">
    <div class="form-group">
      <label>Check History Retention (days)</label>
      <input id="s-retention" type="number" min="7" max="365">
      <div class="hint">DynamoDB TTL deletes future check rows after this many days.</div>
    </div>
    <div class="form-group">
      <label>Default Check Interval (seconds)</label>
      <input id="s-interval" type="number" min="60" max="3600">
    </div>
    <div class="form-group">
      <label>Default Timeout (seconds)</label>
      <input id="s-timeout" type="number" min="1" max="60">
    </div>
    <button class="btn btn-primary" onclick="saveSettings()">Save Settings</button>
  </div>
</div>

<div id="pane-cost" style="display:none">
  <h2>Cost Estimator</h2>
  <p class="desc">
    Defaults are filled from your live deployment: enabled hosts, active worker regions, default interval, and retention.
  </p>
  <div class="panel grid2" style="margin-bottom:16px">
    <div class="form-group"><label>Hosts</label><input id="c-hosts" type="number" value="0" min="0"></div>
    <div class="form-group"><label>Monitor Regions</label><input id="c-regions" type="number" value="0" min="0"></div>
    <div class="form-group"><label>Check Interval (sec)</label><input id="c-interval" type="number" value="60" min="60"></div>
    <div class="form-group"><label>Retention (days)</label><input id="c-days" type="number" value="90"></div>
  </div>
  <button class="btn btn-primary" onclick="calcCost()" style="margin-bottom:20px">Calculate</button>
  <div class="panel" id="cost-result" style="display:none">
    <div id="cost-rows"></div>
  </div>
</div>

<div id="pane-guides" style="display:none">
  <h2>Guides &amp; Reference</h2>

  <h3>How worker regions work</h3>
  <p class="desc">
    Each orchestration run fans out from the home-region management Lambda to every deployed worker region.
    Hosts can optionally be limited to only specific workers.
  </p>

  <h3>HTTP check vs TCP check</h3>
  <p class="desc">
    <strong>HTTP</strong> checks status code, latency, and SSL expiry for HTTPS.
    <strong>TCP</strong> opens a raw socket to host:port for databases, SMTP, Redis, and similar services.
  </p>

  <h3>Setting up SNS alerts</h3>
  <p class="desc">Alerts fire on transitions, not on every check.</p>
  <pre># 1. Create an SNS topic
aws sns create-topic --name uptime-alerts --region us-east-1

# 2. Subscribe your email
aws sns subscribe \\
  --topic-arn arn:aws:sns:us-east-1:ACCOUNT_ID:uptime-alerts \\
  --protocol email \\
  --notification-endpoint you@example.com</pre>

  <h3>Custom domain / DNS</h3>
  <p class="desc">
    A direct DNS CNAME to a Lambda Function URL is usually not the cleanest production setup.
    The recommended route is CloudFront + ACM + your own DNS record. If you want, we can add that setup next.
  </p>

  <h3>Rotating the admin key</h3>
  <pre>NEW_KEY=$(openssl rand -hex 20)
aws secretsmanager put-secret-value \\
  --secret-id uptime/admin-key \\
  --secret-string "$NEW_KEY" \\
  --region {HOME_REGION}
echo "New key: $NEW_KEY"</pre>

  <h3>Backing up check history</h3>
  <pre>aws dynamodb create-backup \\
  --table-name uptime-checks \\
  --backup-name uptime-backup-$(date +%Y%m%d)</pre>
</div>

</div>

<div class="modal-overlay" id="host-modal">
  <div class="modal">
    <h3 id="host-modal-title">Add Host</h3>
    <input type="hidden" id="m-id">
    <div class="form-group"><label>Name *</label><input id="m-name" placeholder="My Website"></div>
    <div class="form-group"><label>URL *</label><input id="m-url" placeholder="https://example.com or db.host.com:5432"></div>
    <div class="form-group">
      <label>Check Type</label>
      <select id="m-type">
        <option value="http">HTTP / HTTPS</option>
        <option value="tcp">TCP</option>
      </select>
    </div>
    <div class="grid2">
      <div class="form-group"><label>Check Interval (sec)</label><input id="m-interval" type="number" value="60" min="60" max="3600"></div>
      <div class="form-group"><label>Timeout (sec)</label><input id="m-timeout" type="number" value="10" min="1" max="60"></div>
    </div>
    <div class="form-group">
      <label>Expected HTTP Status Code</label>
      <input id="m-code" type="number" value="200">
    </div>
    <div class="form-group">
      <label>Worker Regions</label>
      <div class="hint">Leave all unchecked to run this host from every deployed worker region.</div>
      <div id="m-target-regions" class="checklist"></div>
    </div>
    <div class="form-group">
      <label class="toggle"><input type="checkbox" id="m-page" checked> Show on public status page</label>
    </div>
    <div class="form-group">
      <label class="toggle"><input type="checkbox" id="m-alert" onchange="toggleSNS()"> Enable SNS alerts on state change</label>
    </div>
    <div id="m-sns-group" style="display:none">
      <div class="form-group">
        <label>SNS Topic ARN</label>
        <input id="m-sns" placeholder="arn:aws:sns:us-east-1:123456789012:my-alerts">
      </div>
    </div>
    <div class="form-group">
      <label class="toggle"><input type="checkbox" id="m-enabled" checked> Enabled</label>
    </div>
    <div style="display:flex;gap:10px;margin-top:8px">
      <button class="btn btn-primary" onclick="saveHost()">Save</button>
      <button class="btn btn-ghost" onclick="closeHostModal()">Cancel</button>
    </div>
  </div>
</div>

<div class="modal-overlay" id="region-modal">
  <div class="modal">
    <h3>Add Worker Region</h3>
    <p class="desc" style="margin-bottom:16px">This deploys a new worker Lambda in the selected AWS region.</p>
    <div class="form-group">
      <label>AWS Region</label>
      <select id="r-region">{region_options}</select>
    </div>
    <div class="form-group">
      <label>Lambda Memory (MB)</label>
      <select id="r-memory">
        <option value="128">128 MB</option>
        <option value="256" selected>256 MB</option>
        <option value="512">512 MB</option>
      </select>
    </div>
    <div style="display:flex;gap:10px;margin-top:8px">
      <button class="btn btn-primary" id="r-deploy-btn" onclick="deployRegion()">Deploy</button>
      <button class="btn btn-ghost" onclick="closeRegionModal()">Cancel</button>
    </div>
    <div id="r-status" style="margin-top:12px;display:none"></div>
  </div>
</div>

<div class="toast hidden" id="toast"></div>

<script>
let KEY = sessionStorage.getItem('uptime_admin_key') || '';
const queryKey = new URLSearchParams(location.search).get('key') || '';
let REGIONS_CACHE = [];
if (queryKey) {{
  KEY = queryKey;
  sessionStorage.setItem('uptime_admin_key', KEY);
  history.replaceState(null, '', location.pathname);
}}

function api(path, opts={{}}) {{
  return fetch(path, {{
    ...opts,
    headers: {{ Authorization: 'Bearer ' + KEY, 'Content-Type': 'application/json', ...(opts.headers||{{}}) }}
  }}).then(async r => {{
    const data = await r.json().catch(() => ({{}}));
    if (r.status === 401) return {{...data, error: data.error || 'Unauthorized', unauthorized: true}};
    if (!r.ok && !data.error) return {{...data, error: 'Request failed'}};
    return data;
  }}).catch(e => ({{error: e.message}}));
}}

function toast(msg, err=false) {{
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast' + (err ? ' error' : '');
  setTimeout(() => t.className = 'toast hidden', 3500);
}}

function showAuthGate(message='') {{
  document.getElementById('auth-gate').style.display = 'flex';
  document.getElementById('auth-msg').textContent = message;
}}

function hideAuthGate() {{
  document.getElementById('auth-gate').style.display = 'none';
  document.getElementById('auth-msg').textContent = '';
}}

async function ensureAuthed() {{
  if (!KEY) {{
    showAuthGate('Enter the admin token to continue.');
    return false;
  }}
  const probe = await api('/api/auth');
  if (probe.unauthorized || probe.error) {{
    showAuthGate('That token was rejected. Check the value and try again.');
    return false;
  }}
  hideAuthGate();
  return true;
}}

async function loginAdmin() {{
  KEY = document.getElementById('auth-key').value.trim();
  if (!KEY) {{
    showAuthGate('Enter the admin token first.');
    return;
  }}
  sessionStorage.setItem('uptime_admin_key', KEY);
  if (await ensureAuthed()) {{
    document.getElementById('auth-key').value = '';
    boot();
  }}
}}

function logoutAdmin() {{
  KEY = '';
  sessionStorage.removeItem('uptime_admin_key');
  showAuthGate('Signed out.');
}}

const PANES = ['hosts','regions','status-page','notifications','settings','cost','guides'];
function show(tab) {{
  PANES.forEach((t,i) => {{
    document.getElementById('pane-'+t).style.display = t===tab ? '' : 'none';
    document.querySelectorAll('.tab')[i].classList.toggle('active', t===tab);
  }});
  if (tab === 'hosts') loadHosts();
  if (tab === 'regions') loadRegions();
  if (tab === 'status-page') loadStatusPage();
  if (tab === 'notifications') loadNotificationSettings();
  if (tab === 'settings') loadSettings();
  if (tab === 'cost') loadCostDefaults();
}}

async function ensureRegionsLoaded() {{
  const list = await api('/api/regions');
  REGIONS_CACHE = Array.isArray(list) ? list : [];
  return REGIONS_CACHE;
}}

function renderTargetRegions(selected=[]) {{
  const wrap = document.getElementById('m-target-regions');
  if (!REGIONS_CACHE.length) {{
    wrap.innerHTML = '<div class="hint">No worker regions deployed yet.</div>';
    return;
  }}
  wrap.innerHTML = REGIONS_CACHE.map(r => `
    <label class="check-item">
      <input type="checkbox" value="${{r.region}}" ${{selected.includes(r.region) ? 'checked' : ''}}>
      <span>${{r.region}}</span>
    </label>
  `).join('');
}}

function selectedTargetRegions() {{
  return Array.from(document.querySelectorAll('#m-target-regions input[type=checkbox]:checked')).map(el => el.value);
}}

async function loadHosts() {{
  const hosts = await api('/api/hosts');
  if (hosts.unauthorized) {{
    showAuthGate('Enter the admin token to load hosts.');
    return;
  }}
  const tbody = document.getElementById('hosts-body');
  if (!Array.isArray(hosts) || !hosts.length) {{
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:#64748b;padding:32px">No hosts yet.</td></tr>';
    return;
  }}
  tbody.innerHTML = hosts.map(h => `
    <tr>
      <td style="font-weight:600">${{h.name}}</td>
      <td style="color:#64748b;font-size:.8rem;max-width:200px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="${{h.url}}">${{h.url}}</td>
      <td><span class="badge ${{h.check_type||'http'}}">${{h.check_type||'http'}}</span></td>
      <td><span class="badge ${{h.current_status||'unknown'}}">${{h.current_status||'unknown'}}</span></td>
      <td>${{h.uptime_pct != null ? h.uptime_pct+'%' : '—'}}</td>
      <td>${{h.last_latency_ms != null ? h.last_latency_ms+' ms' : '—'}}</td>
      <td style="text-align:center">${{h.show_on_status_page ? '✓' : '—'}}</td>
      <td style="text-align:center">${{h.alert_enabled ? '✓' : '—'}}</td>
      <td><div class="actions">
        <button class="btn btn-ghost btn-sm" onclick='openEditHost(${{JSON.stringify(h)}})'>Edit</button>
        <button class="btn btn-danger btn-sm" onclick="deleteHost('${{h.host_id}}','${{h.name}}')">Del</button>
      </div></td>
    </tr>`).join('');
}}

async function openAddHost() {{
  await ensureRegionsLoaded();
  document.getElementById('host-modal-title').textContent = 'Add Host';
  ['m-id','m-name','m-url','m-sns'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('m-type').value = 'http';
  document.getElementById('m-interval').value = 60;
  document.getElementById('m-timeout').value = 10;
  document.getElementById('m-code').value = 200;
  document.getElementById('m-page').checked = true;
  document.getElementById('m-alert').checked = false;
  document.getElementById('m-enabled').checked = true;
  document.getElementById('m-sns-group').style.display = 'none';
  renderTargetRegions([]);
  document.getElementById('host-modal').classList.add('open');
}}

async function openEditHost(h) {{
  await ensureRegionsLoaded();
  document.getElementById('host-modal-title').textContent = 'Edit Host';
  document.getElementById('m-id').value = h.host_id;
  document.getElementById('m-name').value = h.name;
  document.getElementById('m-url').value = h.url;
  document.getElementById('m-type').value = h.check_type || 'http';
  document.getElementById('m-interval').value = h.check_interval_seconds || 60;
  document.getElementById('m-timeout').value = h.timeout_seconds || 10;
  document.getElementById('m-code').value = h.expected_status_code || 200;
  document.getElementById('m-page').checked = !!h.show_on_status_page;
  document.getElementById('m-alert').checked = !!h.alert_enabled;
  document.getElementById('m-sns').value = h.alert_sns_arn || '';
  document.getElementById('m-enabled').checked = h.enabled !== false;
  document.getElementById('m-sns-group').style.display = h.alert_enabled ? '' : 'none';
  renderTargetRegions(h.target_regions || []);
  document.getElementById('host-modal').classList.add('open');
}}

function toggleSNS() {{
  document.getElementById('m-sns-group').style.display = document.getElementById('m-alert').checked ? '' : 'none';
}}

function closeHostModal() {{ document.getElementById('host-modal').classList.remove('open'); }}

async function saveHost() {{
  const id = document.getElementById('m-id').value;
  const body = {{
    name: document.getElementById('m-name').value,
    url: document.getElementById('m-url').value,
    check_type: document.getElementById('m-type').value,
    check_interval_seconds: +document.getElementById('m-interval').value,
    timeout_seconds: +document.getElementById('m-timeout').value,
    expected_status_code: +document.getElementById('m-code').value,
    show_on_status_page: document.getElementById('m-page').checked,
    alert_enabled: document.getElementById('m-alert').checked,
    alert_sns_arn: document.getElementById('m-sns').value,
    enabled: document.getElementById('m-enabled').checked,
    target_regions: selectedTargetRegions(),
  }};
  const res = await api(id ? '/api/hosts/'+id : '/api/hosts', {{method: id ? 'PUT' : 'POST', body: JSON.stringify(body)}});
  if (res.error) {{ toast(res.error, true); return; }}
  closeHostModal();
  toast(id ? 'Host updated' : 'Host added');
  loadHosts();
}}

async function deleteHost(id, name) {{
  if (!confirm(`Delete "${{name}}"?`)) return;
  await api('/api/hosts/'+id, {{method:'DELETE'}});
  toast('Host deleted');
  loadHosts();
}}

async function loadRegions() {{
  const list = await api('/api/regions');
  if (list.unauthorized) {{
    showAuthGate('Enter the admin token to load worker regions.');
    return;
  }}
  REGIONS_CACHE = Array.isArray(list) ? list : [];
  const el = document.getElementById('regions-list');
  if (!REGIONS_CACHE.length) {{
    el.innerHTML = '<div style="color:#64748b;padding:20px 0">No worker regions deployed yet.</div>';
    return;
  }}
  el.innerHTML = REGIONS_CACHE.map(r => `
    <div class="region-card">
      <div class="region-info">
        <div class="name">${{r.region}} <span class="badge active" style="margin-left:6px">${{r.status||'active'}}</span></div>
        <div class="meta">Memory: ${{r.memory_mb||256}}MB · Deployed: ${{r.deployed_at ? new Date(r.deployed_at).toLocaleDateString() : '—'}}</div>
      </div>
      <div class="actions">
        <button class="btn btn-warn btn-sm" onclick="updateRegion('${{r.region}}')">Update Code</button>
        <button class="btn btn-danger btn-sm" onclick="removeRegion('${{r.region}}')">Remove</button>
      </div>
    </div>`).join('');
}}

function openAddRegion() {{
  document.getElementById('r-status').style.display = 'none';
  document.getElementById('r-deploy-btn').disabled = false;
  document.getElementById('r-deploy-btn').innerHTML = 'Deploy';
  document.getElementById('region-modal').classList.add('open');
}}

function closeRegionModal() {{ document.getElementById('region-modal').classList.remove('open'); }}

async function deployRegion() {{
  const btn = document.getElementById('r-deploy-btn');
  const stat = document.getElementById('r-status');
  const body = {{region: document.getElementById('r-region').value, memory_mb: +document.getElementById('r-memory').value}};
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Deploying…';
  stat.style.display = '';
  stat.innerHTML = '<span style="color:#94a3b8">Deploying worker Lambda in '+body.region+'…</span>';
  const res = await api('/api/regions', {{method:'POST', body:JSON.stringify(body)}});
  btn.disabled = false;
  btn.innerHTML = 'Deploy';
  if (res.error) {{
    stat.innerHTML = '<span style="color:#ef4444">Error: '+res.error+'</span>';
    return;
  }}
  stat.innerHTML = '<span style="color:#22c55e">Deployed successfully</span>';
  await loadRegions();
  toast('Worker deployed in '+body.region);
}}

async function updateRegion(region) {{
  if (!confirm('Push the latest monitor code to '+region+'?')) return;
  const res = await api('/api/regions/'+region+'/update', {{method:'POST'}});
  if (res.error) {{ toast(res.error, true); return; }}
  toast('Monitor updated in '+region);
  loadRegions();
}}

async function removeRegion(region) {{
  if (!confirm('Remove monitor from '+region+'?')) return;
  const res = await api('/api/regions/'+region, {{method:'DELETE'}});
  if (res.error) {{ toast(res.error, true); return; }}
  toast('Monitor removed from '+region);
  loadRegions();
}}

async function loadStatusPage() {{
  const [settings, hosts] = await Promise.all([api('/api/settings'), api('/api/hosts')]);
  if (settings.unauthorized || hosts.unauthorized) {{
    showAuthGate('Enter the admin token to load status-page settings.');
    return;
  }}
  document.getElementById('sp-brand').value = settings.status_page_brand_name || '';
  document.getElementById('sp-title').value = settings.status_page_title || '';
  document.getElementById('sp-desc').value = settings.status_page_description || '';
  document.getElementById('sp-logo').value = settings.status_page_logo_url || '';
  document.getElementById('sp-theme').value = settings.status_page_theme || 'clean';
  document.getElementById('sp-maintenance-enabled').checked = !!settings.maintenance_enabled;
  document.getElementById('sp-maintenance-message').value = settings.maintenance_message || '';
  document.getElementById('sp-maintenance-window').value = settings.maintenance_window || '';
  document.getElementById('sp-maintenance-scope').value = settings.maintenance_scope || '';
  document.getElementById('sp-subscribe-intro').value = settings.status_page_subscribe_intro || 'Subscribe for status updates.';
  document.getElementById('sp-subscribe-email').value = settings.status_page_subscribe_email_url || '';
  document.getElementById('sp-subscribe-sms').value = settings.status_page_subscribe_sms_url || '';
  document.getElementById('sp-subscribe-webhook').value = settings.status_page_subscribe_webhook_url || '';
  document.getElementById('cd-domain').value = settings.custom_domain_name || '';
  refreshCustomDomain();
  const tbody = document.getElementById('status-page-hosts');
  if (!Array.isArray(hosts) || !hosts.length) {{
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:#64748b;padding:24px">No hosts yet.</td></tr>';
    return;
  }}
  tbody.innerHTML = hosts.map(h => `
    <tr>
      <td style="font-weight:600">${{h.name}}</td>
      <td style="color:#64748b;font-size:.8rem">${{h.url}}</td>
      <td><span class="badge ${{h.current_status||'unknown'}}">${{h.current_status||'unknown'}}</span></td>
      <td><label class="toggle"><input type="checkbox" ${{h.show_on_status_page?'checked':''}} onchange="toggleHostPage('${{h.host_id}}', this.checked)"><span style="font-size:.85rem">${{h.show_on_status_page ? 'Visible' : 'Hidden'}}</span></label></td>
    </tr>`).join('');
}}

async function toggleHostPage(id, visible) {{
  await api('/api/hosts/'+id, {{method:'PUT', body:JSON.stringify({{show_on_status_page:visible}})}});
  toast(visible ? 'Host now shown on status page' : 'Host hidden from status page');
}}

async function saveStatusPageSettings() {{
  const body = {{
    status_page_brand_name: document.getElementById('sp-brand').value,
    status_page_title: document.getElementById('sp-title').value,
    status_page_description: document.getElementById('sp-desc').value,
    status_page_logo_url: document.getElementById('sp-logo').value,
    status_page_theme: document.getElementById('sp-theme').value,
    maintenance_enabled: document.getElementById('sp-maintenance-enabled').checked,
    maintenance_message: document.getElementById('sp-maintenance-message').value,
    maintenance_window: document.getElementById('sp-maintenance-window').value,
    maintenance_scope: document.getElementById('sp-maintenance-scope').value,
    status_page_subscribe_intro: document.getElementById('sp-subscribe-intro').value,
    status_page_subscribe_email_url: document.getElementById('sp-subscribe-email').value,
    status_page_subscribe_sms_url: document.getElementById('sp-subscribe-sms').value,
    status_page_subscribe_webhook_url: document.getElementById('sp-subscribe-webhook').value,
  }};
  const res = await api('/api/settings', {{method:'PUT', body:JSON.stringify(body)}});
  if (res.error) {{ toast(res.error, true); return; }}
  toast('Status page settings saved');
}}

function renderCustomDomainStatus(data) {{
  const statusEl = document.getElementById('cd-status');
  if (!data || data.error) {{
    statusEl.textContent = data?.error || 'Unable to load custom domain status.';
    return;
  }}
  const lines = [];
  lines.push(`Status: ${{data.status || 'unknown'}}`);
  if (data.domain_name) lines.push(`Domain: ${{data.domain_name}}`);
  if (data.origin_url) lines.push(`Origin: ${{data.origin_url}}`);
  if (data.distribution_domain_name) lines.push(`CloudFront: ${{data.distribution_domain_name}} (${{data.distribution_status || 'unknown'}})`);
  if (data.last_error) lines.push(`Last error: ${{data.last_error}}`);
  if (Array.isArray(data.dns_records_to_create) && data.dns_records_to_create.length) {{
    lines.push('');
    lines.push('Create these DNS records:');
    data.dns_records_to_create.forEach((r, idx) => {{
      lines.push(`${{idx + 1}}. [${{r.purpose}}] ${{r.type}} ${{r.name}} -> ${{r.value}}${{r.note ? ' (' + r.note + ')' : ''}}`);
    }});
  }}
  if (Array.isArray(data.dns_records_to_remove) && data.dns_records_to_remove.length && data.status === 'not_configured') {{
    lines.push('');
    lines.push('Clean up these DNS records if they still exist:');
    data.dns_records_to_remove.forEach((r, idx) => {{
      lines.push(`${{idx + 1}}. [${{r.purpose}}] ${{r.type}} ${{r.name}} -> ${{r.value}}`);
    }});
  }}
  statusEl.textContent = lines.join('\n') || 'No custom domain configured.';
}}

async function refreshCustomDomain() {{
  const res = await api('/api/custom-domain');
  if (res.unauthorized) {{
    showAuthGate('Enter the admin token to load custom-domain status.');
    return;
  }}
  renderCustomDomainStatus(res);
}}

async function deployCustomDomain() {{
  const domain = document.getElementById('cd-domain').value.trim();
  if (!domain) {{
    toast('Enter a custom domain first', true);
    return;
  }}
  const res = await api('/api/custom-domain', {{method:'POST', body:JSON.stringify({{domain_name: domain}})}});
  if (res.error) {{ toast(res.error, true); renderCustomDomainStatus(res); return; }}
  renderCustomDomainStatus(res);
  toast('Custom domain step completed');
}}

async function destroyCustomDomain() {{
  if (!confirm('Destroy the custom domain deployment? DNS cleanup will still be manual.')) return;
  const res = await api('/api/custom-domain', {{method:'DELETE'}});
  if (res.error) {{ toast(res.error, true); renderCustomDomainStatus(res); return; }}
  renderCustomDomainStatus(res);
  toast('Custom domain destroy step completed');
}}

async function loadNotificationSettings() {{
  const s = await api('/api/settings');
  if (s.unauthorized) {{
    showAuthGate('Enter the admin token to load notification settings.');
    return;
  }}
  document.getElementById('n-topic-arn').value = s.notifications_default_topic_arn || '';
  document.getElementById('n-sender-label').value = s.notifications_sender_label || '';
  document.getElementById('n-delay').value = s.notifications_initial_delay_seconds || 0;
  document.getElementById('n-reminder').value = s.notifications_reminder_interval_minutes || 0;
  document.getElementById('n-ttl').value = s.notifications_ttl_seconds || 0;
  document.getElementById('n-quiet-enabled').checked = !!s.notifications_quiet_hours_enabled;
  document.getElementById('n-quiet-timezone').value = s.notifications_quiet_hours_timezone || 'UTC';
  document.getElementById('n-quiet-start').value = s.notifications_quiet_hours_start || '';
  document.getElementById('n-quiet-end').value = s.notifications_quiet_hours_end || '';
  document.getElementById('n-sleep-until').value = s.notifications_sleep_until || '';
  document.getElementById('n-maintenance-mute').checked = s.notifications_mute_during_maintenance !== false;
}}

async function saveNotificationSettings() {{
  const body = {{
    notifications_default_topic_arn: document.getElementById('n-topic-arn').value,
    notifications_sender_label: document.getElementById('n-sender-label').value,
    notifications_initial_delay_seconds: +document.getElementById('n-delay').value,
    notifications_reminder_interval_minutes: +document.getElementById('n-reminder').value,
    notifications_ttl_seconds: +document.getElementById('n-ttl').value,
    notifications_quiet_hours_enabled: document.getElementById('n-quiet-enabled').checked,
    notifications_quiet_hours_timezone: document.getElementById('n-quiet-timezone').value,
    notifications_quiet_hours_start: document.getElementById('n-quiet-start').value,
    notifications_quiet_hours_end: document.getElementById('n-quiet-end').value,
    notifications_sleep_until: document.getElementById('n-sleep-until').value,
    notifications_mute_during_maintenance: document.getElementById('n-maintenance-mute').checked,
  }};
  const res = await api('/api/settings', {{method:'PUT', body:JSON.stringify(body)}});
  if (res.error) {{ toast(res.error, true); return; }}
  toast('Notification settings saved');
}}

async function loadSettings() {{
  const s = await api('/api/settings');
  if (s.unauthorized) {{
    showAuthGate('Enter the admin token to load settings.');
    return;
  }}
  document.getElementById('s-retention').value = s.retention_days || 90;
  document.getElementById('s-interval').value = s.default_check_interval || 60;
  document.getElementById('s-timeout').value = s.default_timeout || 10;
}}

async function saveSettings() {{
  const body = {{
    retention_days: +document.getElementById('s-retention').value,
    default_check_interval: +document.getElementById('s-interval').value,
    default_timeout: +document.getElementById('s-timeout').value,
  }};
  const res = await api('/api/settings', {{method:'PUT', body:JSON.stringify(body)}});
  if (res.error) {{ toast(res.error, true); return; }}
  toast('Settings saved');
}}

async function loadCostDefaults() {{
  const data = await api('/api/cost');
  if (data.unauthorized) {{
    showAuthGate('Enter the admin token to load cost estimates.');
    return;
  }}
  const defaults = data.defaults || data.inputs || {{}};
  document.getElementById('c-hosts').value = defaults.hosts ?? 0;
  document.getElementById('c-regions').value = defaults.regions ?? 0;
  document.getElementById('c-interval').value = defaults.interval_sec ?? 60;
  document.getElementById('c-days').value = defaults.retention_days ?? 90;
  await calcCost();
}}

async function calcCost() {{
  const data = await api('/api/cost?hosts='+document.getElementById('c-hosts').value+'&regions='+document.getElementById('c-regions').value+'&interval='+document.getElementById('c-interval').value+'&days='+document.getElementById('c-days').value);
  if (data.unauthorized) {{
    showAuthGate('Enter the admin token to calculate costs.');
    return;
  }}
  const b = data.breakdown || {{}};
  const el = document.getElementById('cost-result');
  el.style.display = '';
  document.getElementById('cost-rows').innerHTML =
    [['Lambda (workers + orchestrator)', b.lambda_usd], ['DynamoDB writes', b.dynamodb_writes_usd], ['DynamoDB reads', b.dynamodb_reads_usd], ['DynamoDB storage', b.dynamodb_storage_usd], ['CloudWatch Logs', b.cloudwatch_logs_usd], ['Total / month', data.total_usd_per_month]]
    .map(([l,v]) => `<div class="cost-row"><span>${{l}}</span><span>$${{(v||0).toFixed(4)}}</span></div>`)
    .join('') + `<div style="color:#64748b;font-size:.75rem;margin-top:10px">${{data.note||''}}</div>`;
}}

async function boot() {{
  if (!await ensureAuthed()) return;
  await Promise.all([ensureRegionsLoaded(), loadHosts()]);
}}

boot();
</script>
</body></html>"""


# ── Response helpers ──────────────────────────────────────────────────────────

def _serial(obj):
    if isinstance(obj, Decimal): return float(obj)
    if isinstance(obj, datetime): return obj.isoformat()
    raise TypeError(f"Not serializable: {type(obj)}")

def _json(status: int, body) -> dict:
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json", "Access-Control-Allow-Origin": "*"},
        "body": json.dumps(body, default=_serial),
    }

def _html(status: int, body: str) -> dict:
    return {"statusCode": status, "headers": {"Content-Type": "text/html; charset=utf-8"}, "body": body}

def _cors_ok() -> dict:
    return {"statusCode": 204, "headers": {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET,POST,PUT,DELETE,OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type,Authorization",
    }, "body": ""}

def _parse_body(event: dict) -> dict:
    raw = event.get("body") or ""
    if event.get("isBase64Encoded"):
        raw = base64.b64decode(raw).decode()
    try:
        return json.loads(raw) if raw else {}
    except Exception:
        return {}
