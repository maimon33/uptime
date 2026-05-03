"""
Management Lambda — public app, admin API, and central orchestrator.
Serves the status page and admin UI, manages regional worker Lambdas,
and runs the scheduled cross-region monitoring orchestration.

Routes (public):
  GET  /           → status page
  GET  /status     → alias
  GET  /history    → public incident/check history
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
import ipaddress
import json
import os
from pathlib import Path
import time
import traceback
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
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
_dynamodb_client = None
_cloudwatch = {}

def _db():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb")
    return _dynamodb

def _ddb_client():
    global _dynamodb_client
    if _dynamodb_client is None:
        _dynamodb_client = boto3.client("dynamodb")
    return _dynamodb_client

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


def _cloudwatch_client(region_name: str):
    client = _cloudwatch.get(region_name)
    if client is None:
        client = boto3.client("cloudwatch", region_name=region_name)
        _cloudwatch[region_name] = client
    return client

# ── Config ────────────────────────────────────────────────────────────────────
HOSTS_TABLE     = os.environ["HOSTS_TABLE"]
CHECKS_TABLE    = os.environ["CHECKS_TABLE"]
ADMIN_KEY_PARAM = os.environ.get("ADMIN_KEY_PARAM")
ADMIN_KEY_SECRET = os.environ.get("ADMIN_KEY_SECRET")
HOME_REGION     = os.environ.get("HOME_REGION", os.environ.get("AWS_REGION", "us-east-1"))
RETENTION_DAYS  = int(os.environ.get("RETENTION_DAYS", "90"))
READ_ONLY_MODE  = str(os.environ.get("READ_ONLY_MODE", "")).strip().lower() in {"1", "true", "yes", "on"}
ADMIN_ALLOWED_IP_CIDRS = [cidr.strip() for cidr in os.environ.get("ADMIN_ALLOWED_IP_CIDRS", "").split(",") if cidr.strip()]
DEFAULT_MONITOR_TIERS = [60, 300]
RECOMMENDED_MONITOR_TIERS = [60, 300, 900, 3600]

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
_build_info_cache = None


# ── Entry point ───────────────────────────────────────────────────────────────

def handler(event, context):
    try:
        if _is_scheduled_event(event):
            _log("info", "scheduled_event_received", source=event.get("source"), resources=event.get("resources", []))
            return _run_orchestration()

        method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
        path   = (event.get("rawPath", "/") or "/").rstrip("/") or "/"
        _log_request(event, method, path)

        if method == "OPTIONS":
            return _cors_ok()

        if path in ("/", "/status"):
            return _serve_status_page()

        if path == "/history":
            return _serve_history_page(event)

        if path == "/admin":
            if not _admin_ip_allowed(event):
                _log("warn", "admin_ip_blocked", path=path, client_ip=_client_ip(event), allowed_cidrs=ADMIN_ALLOWED_IP_CIDRS)
                return _html(403, "<h1>403 Forbidden</h1><p>Admin access from this IP is not allowed.</p>")
            _log("info", "admin_page_served")
            return _html(200, _admin_page())

        if path.startswith("/api/"):
            if not _admin_ip_allowed(event):
                _log("warn", "api_ip_blocked", method=method, path=path, client_ip=_client_ip(event), allowed_cidrs=ADMIN_ALLOWED_IP_CIDRS)
                return _json(403, {"error": "Admin access from this IP is not allowed."})
            authed = _auth(event)
            if not authed:
                _log("warn", "api_request_unauthorized", method=method, path=path)
                return _json(401, {"error": "Unauthorized. Sign in at /admin or send Authorization: Bearer <key>"})
            response = _route_api(method, path, event)
            _log("info", "api_request_completed", method=method, path=path, status_code=response.get("statusCode"))
            return response

        _log("warn", "route_not_found", method=method, path=path)
        return _json(404, {"error": "Not found"})
    except Exception as exc:
        method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper() if isinstance(event, dict) else "UNKNOWN"
        path = (event.get("rawPath", "/") or "/") if isinstance(event, dict) else "/"
        tb = traceback.format_exc()
        request_id = getattr(context, "aws_request_id", None)
        _log("error", "handler_exception", method=method, path=path, request_id=request_id, error=str(exc), traceback=tb)
        if isinstance(event, dict) and path.startswith("/api/"):
            return _json(500, {
                "error": "Internal server error",
                "detail": str(exc),
                "request_id": request_id,
                "path": path,
                "traceback": tb,
            })
        return _json(500, {"error": "Internal server error", "request_id": request_id})


def _is_scheduled_event(event: dict) -> bool:
    return isinstance(event, dict) and event.get("source") == "aws.events"


def _is_read_only() -> bool:
    return READ_ONLY_MODE


def _build_info() -> dict:
    global _build_info_cache
    if _build_info_cache is None:
        info = {
            "version": os.environ.get("APP_VERSION", "unknown"),
            "built_at": os.environ.get("APP_BUILT_AT", ""),
            "region": HOME_REGION,
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "uptime-management"),
            "read_only_mode": _is_read_only(),
        }
        try:
            path = Path(__file__).with_name("_build_info.json")
            if path.exists():
                info.update(json.loads(path.read_text()))
        except Exception as exc:
            _log("warn", "build_info_load_failed", error=str(exc))
        _build_info_cache = info
    return _build_info_cache


def _log(level: str, message: str, **fields) -> None:
    payload = {"level": level, "message": message, "time": datetime.now(timezone.utc).isoformat()}
    payload.update(fields)
    print(json.dumps(payload, default=_serial))


def _log_request(event: dict, method: str, path: str) -> None:
    headers = event.get("headers") or {}
    _log(
        "info",
        "http_request_received",
        method=method,
        path=path,
        source_ip=((event.get("requestContext") or {}).get("http") or {}).get("sourceIp"),
        user_agent=headers.get("user-agent") or headers.get("User-Agent"),
        host=headers.get("host") or headers.get("Host"),
        has_authorization=bool(headers.get("authorization") or headers.get("Authorization")),
        raw_query=event.get("rawQueryString", ""),
    )


def _client_ip(event: dict) -> str:
    headers = event.get("headers") or {}
    forwarded_for = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or ""
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return (((event.get("requestContext") or {}).get("http") or {}).get("sourceIp") or "").strip()


def _admin_ip_allowed(event: dict) -> bool:
    if not ADMIN_ALLOWED_IP_CIDRS:
        return True
    client_ip = _client_ip(event)
    if not client_ip:
        return False
    try:
        candidate = ipaddress.ip_address(client_ip)
    except ValueError:
        return False
    for cidr in ADMIN_ALLOWED_IP_CIDRS:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            continue
        if candidate in network:
            return True
    return False


def _normalize_monitor_tiers(value, *, fallback: list[int] | None = None) -> list[int]:
    tiers = []
    raw_values = value if isinstance(value, list) else ([value] if value not in (None, "") else [])
    for raw in raw_values:
        try:
            tier = int(raw)
        except (TypeError, ValueError):
            continue
        if tier < 60 or tier % 60 != 0:
            continue
        if tier not in tiers:
            tiers.append(tier)
    if tiers:
        return sorted(tiers)
    return list(fallback or DEFAULT_MONITOR_TIERS)


def _host_monitor_tier_seconds(host: dict) -> int:
    value = host.get("monitor_tier_seconds", host.get("check_interval_seconds", 60))
    try:
        tier = int(value)
    except (TypeError, ValueError):
        return 60
    if tier < 60 or tier % 60 != 0:
        return 60
    return tier


def _due_monitor_tiers(now: datetime, all_tiers: list[int]) -> list[int]:
    current_epoch = int(now.timestamp())
    due = []
    for tier in sorted(set(all_tiers)):
        if tier >= 60 and current_epoch % tier == 0:
            due.append(tier)
    return due or [60]


def _run_orchestration() -> dict:
    if _is_read_only():
        _log("info", "orchestration_skipped_read_only")
        return {"skipped": True, "reason": "read_only_mode"}
    db = _db()
    run_time = datetime.now(timezone.utc).replace(microsecond=0)
    run_id = run_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    regions = reg.list_regions(db)
    all_tiers = []
    for region in regions:
        all_tiers.extend(_normalize_monitor_tiers(region.get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS))
    due_tiers = _due_monitor_tiers(run_time, all_tiers or DEFAULT_MONITOR_TIERS)
    _log("info", "orchestration_started", run_id=run_id, configured_regions=len(regions), due_tiers=due_tiers)

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
            pool.submit(_invoke_region_worker, region, run_id, due_tiers): region["region"]
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
    _log("info", "orchestration_completed", run_id=run_id, regions=len(regions), hosts=len(hosts), results=len(result_rows), due_tiers=due_tiers)
    return {
        "run_id": run_id,
        "regions": len(regions),
        "hosts": len(hosts),
        "results": len(result_rows),
        "due_tiers": due_tiers,
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
        _log("warn", "auth_missing_token")
        return False
    ok = hmac.compare_digest(token.strip(), _get_admin_key().strip())
    _log("info" if ok else "warn", "auth_checked", ok=ok, token_length=len(token.strip()))
    return ok


# ── API router ────────────────────────────────────────────────────────────────

def _route_api(method: str, path: str, event: dict) -> dict:
    body = _parse_body(event)
    qs   = parse_qs(event.get("rawQueryString") or "")
    segs = path.split("/")   # ['', 'api', '<resource>', ...]

    resource = segs[2] if len(segs) > 2 else ""
    rid      = segs[3] if len(segs) > 3 else ""
    sub      = segs[4] if len(segs) > 4 else ""
    _log("info", "api_route_dispatch", method=method, path=path, resource=resource, rid=rid, sub=sub)
    if _is_read_only() and _is_mutating_api_request(method, resource, rid, sub):
        _log("warn", "api_mutation_blocked_read_only", method=method, path=path, resource=resource, rid=rid, sub=sub)
        return _json(403, {"error": "Read-only mode is enabled. Mutating actions are disabled."})

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

    if resource == "debug" and rid == "version":
        if method == "GET":
            return _json(200, _build_info())

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

    if resource == "management":
        if method == "GET":
            return _get_management_summary()
        if method == "POST":
            return _run_management_action(body)

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


def _is_mutating_api_request(method: str, resource: str, rid: str, sub: str) -> bool:
    if method in {"GET", "HEAD", "OPTIONS"}:
        return False
    return True


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


def _list_public_hosts() -> list[dict]:
    result = _db().Table(HOSTS_TABLE).scan(
        FilterExpression="show_on_status_page = :t AND host_id <> :s AND NOT begins_with(host_id, :r)",
        ExpressionAttributeValues={":t": True, ":s": "__settings__", ":r": "__region__"},
    )
    return sorted(result.get("Items", []), key=lambda h: h.get("name", ""))

def _get_host(host_id: str) -> dict:
    item = _db().Table(HOSTS_TABLE).get_item(Key={"host_id": host_id}).get("Item")
    return _json(404, {"error": "Host not found"}) if not item else _json(200, item)

def _create_host(body: dict) -> dict:
    if not body.get("name") or not body.get("url"):
        return _json(400, {"error": "'name' and 'url' are required"})
    now  = datetime.now(timezone.utc).isoformat()
    monitor_tier_seconds = int(body.get("monitor_tier_seconds", body.get("check_interval_seconds", 60)))
    target_regions = _normalize_target_regions(body.get("target_regions"))
    tier_error = _validate_host_monitor_tier(monitor_tier_seconds, target_regions)
    if tier_error:
        return _json(400, {"error": tier_error})
    item = {k: v for k, v in {
        "host_id":                str(uuid.uuid4()),
        "name":                   body["name"],
        "url":                    body["url"],
        "check_type":             body.get("check_type", "http"),
        "check_interval_seconds": monitor_tier_seconds,
        "monitor_tier_seconds":   monitor_tier_seconds,
        "timeout_seconds":        int(body.get("timeout_seconds", 10)),
        "enabled":                bool(body.get("enabled", True)),
        "alert_enabled":          bool(body.get("alert_enabled", False)),
        "alert_sns_arn":          body.get("alert_sns_arn", "") or None,
        "show_on_status_page":    bool(body.get("show_on_status_page", True)),
        "expected_status_code":   int(body.get("expected_status_code", 200)),
        "target_regions":         target_regions,
        "tags":                   body.get("tags", []),
        "created_at":             now,
        "updated_at":             now,
        "current_status":         "unknown",
    }.items() if v is not None}
    _db().Table(HOSTS_TABLE).put_item(Item=item)
    return _json(201, item)

def _update_host(host_id: str, body: dict) -> dict:
    table = _db().Table(HOSTS_TABLE)
    existing = table.get_item(Key={"host_id": host_id}).get("Item")
    if not existing:
        return _json(404, {"error": "Host not found"})
    allowed = {
        "name", "url", "check_type", "check_interval_seconds", "monitor_tier_seconds", "timeout_seconds",
        "enabled", "alert_enabled", "alert_sns_arn", "show_on_status_page",
        "expected_status_code", "tags", "target_regions",
    }
    updates = {k: v for k, v in body.items() if k in allowed}
    if not updates:
        return _json(400, {"error": "No updatable fields"})
    if "monitor_tier_seconds" in updates:
        tier = int(updates["monitor_tier_seconds"])
        updates["monitor_tier_seconds"] = tier
        updates["check_interval_seconds"] = tier
    elif "check_interval_seconds" in updates:
        tier = int(updates["check_interval_seconds"])
        updates["check_interval_seconds"] = tier
        updates["monitor_tier_seconds"] = tier
    if "target_regions" in updates:
        updates["target_regions"] = _normalize_target_regions(updates.get("target_regions"))
    tier_error = _validate_host_monitor_tier(
        int(updates.get("monitor_tier_seconds", existing.get("monitor_tier_seconds", existing.get("check_interval_seconds", 60)))),
        updates.get("target_regions", existing.get("target_regions", [])),
    )
    if tier_error:
        return _json(400, {"error": tier_error})
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
    _log("info", "settings_loaded", keys=sorted(item.keys()))
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
    _log("info", "settings_updated", updated_keys=sorted(updates.keys()))
    return _json(200, item)


def _load_settings_item() -> dict:
    return _db().Table(HOSTS_TABLE).get_item(Key={"host_id": "__settings__"}).get("Item", {"host_id": "__settings__"})


def _save_settings_item(item: dict) -> None:
    payload = {"host_id": "__settings__", **{k: v for k, v in item.items() if k != "host_id"}}
    _db().Table(HOSTS_TABLE).put_item(Item=payload)


def _invoke_region_worker(region_info: dict, run_id: str, due_tiers: list[int]) -> dict:
    region = region_info["region"]
    function_name = f"{os.environ.get('PROJECT', 'uptime')}-monitor-{region}"
    supported_tiers = _normalize_monitor_tiers(region_info.get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS)
    response = _lambda_client(region).invoke(
        FunctionName=function_name,
        InvocationType="RequestResponse",
        Payload=json.dumps({
            "run_id": run_id,
            "due_tiers": due_tiers,
            "supported_tiers": supported_tiers,
        }).encode(),
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


def _validate_host_monitor_tier(monitor_tier_seconds: int, target_regions: list[str]) -> str | None:
    if monitor_tier_seconds < 60 or monitor_tier_seconds % 60 != 0:
        return "monitor_tier_seconds must be a whole-minute tier such as 60 or 300"
    if not target_regions:
        return None
    region_records = {region["region"]: region for region in reg.list_regions(_db())}
    unsupported = []
    for region_name in target_regions:
        supported_tiers = _normalize_monitor_tiers((region_records.get(region_name) or {}).get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS)
        if monitor_tier_seconds not in supported_tiers:
            unsupported.append(region_name)
    if unsupported:
        return "Selected worker regions do not support this monitor tier: " + ", ".join(sorted(unsupported))
    return None


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
    supported_tiers = _normalize_monitor_tiers(body.get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS)
    try:
        info = reg.deploy_region(region, memory_mb, supported_tiers)
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
    supported_tiers = _normalize_monitor_tiers(existing.get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS)
    try:
        info = reg.deploy_region(region, memory_mb, supported_tiers)
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

    cert = _wait_for_acm_dns_records(cert_arn)
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


def _get_management_summary() -> dict:
    settings = _load_settings_item()
    hosts_desc = _ddb_client().describe_table(TableName=HOSTS_TABLE)["Table"]
    checks_desc = _ddb_client().describe_table(TableName=CHECKS_TABLE)["Table"]
    hosts = _list_host_items()
    enabled_hosts = [host for host in hosts if host.get("enabled", True)]
    region_records = reg.list_regions(_db())
    worker_summaries = []
    for region_info in region_records:
        try:
            worker_summaries.append(_worker_lambda_summary(region_info))
        except Exception as exc:
            worker_summaries.append({
                "function_name": region_info.get("function_name"),
                "region": region_info.get("region"),
                "memory_mb": int(region_info.get("memory_mb", 0) or 0),
                "deployed_at": region_info.get("deployed_at"),
                "age_human": _age_human(region_info.get("deployed_at")),
                "error": str(exc),
            })
    summary = {
        "home_region": HOME_REGION,
        "tables": {
            "hosts": _table_summary(hosts_desc),
            "checks": _table_summary(checks_desc),
        },
        "hosts": {
            "total": len(hosts),
            "enabled": len(enabled_hosts),
            "on_status_page": sum(1 for host in hosts if host.get("show_on_status_page", True)),
            "alerts_enabled": sum(1 for host in hosts if host.get("alert_enabled")),
        },
        "retention_days": int(settings.get("retention_days", _SETTINGS_DEFAULTS["retention_days"])),
        "worker_regions": len(region_records),
        "lambdas": {
            "management": _management_lambda_summary(),
            "workers": worker_summaries,
        },
    }
    _log("info", "management_summary_loaded", hosts=summary["hosts"], tables=summary["tables"])
    return _json(200, summary)


def _run_management_action(body: dict) -> dict:
    action = str(body.get("action") or "").strip()
    _log("info", "management_action_requested", action=action, body=body)
    if action == "purge_checks":
        older_than_days = int(body.get("older_than_days", 30))
        max_delete = int(body.get("max_delete", 500))
        return _purge_checks_older_than(older_than_days, max_delete)
    if action == "set_retention_days":
        retention_days = int(body.get("retention_days", _SETTINGS_DEFAULTS["retention_days"]))
        settings = _load_settings_item()
        settings["retention_days"] = retention_days
        _save_settings_item(settings)
        _log("info", "management_retention_updated", retention_days=retention_days)
        return _json(200, {"ok": True, "retention_days": retention_days})
    return _json(400, {"error": "Unknown management action"})


def _table_summary(table_desc: dict) -> dict:
    return {
        "name": table_desc["TableName"],
        "status": table_desc.get("TableStatus"),
        "item_count": int(table_desc.get("ItemCount", 0)),
        "size_bytes": int(table_desc.get("TableSizeBytes", 0)),
        "size_human": _human_bytes(int(table_desc.get("TableSizeBytes", 0))),
        "billing_mode": (((table_desc.get("BillingModeSummary") or {}).get("BillingMode")) or "PAY_PER_REQUEST"),
        "created_at": table_desc.get("CreationDateTime"),
    }


def _human_bytes(num: int) -> str:
    value = float(num)
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if value < 1024 or unit == "TB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{num} B"


def _parse_aws_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _age_human(value: str | None) -> str | None:
    dt = _parse_aws_timestamp(value)
    if dt is None:
        return None
    total_seconds = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
    days, remainder = divmod(total_seconds, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, _ = divmod(remainder, 60)
    if days:
        return f"{days}d {hours}h"
    if hours:
        return f"{hours}h {minutes}m"
    return f"{minutes}m"


def _cloudwatch_sum(region_name: str, function_name: str, metric_name: str, start_time: datetime, end_time: datetime) -> float:
    response = _cloudwatch_client(region_name).get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName=metric_name,
        Dimensions=[{"Name": "FunctionName", "Value": function_name}],
        StartTime=start_time,
        EndTime=end_time,
        Period=3600,
        Statistics=["Sum"],
    )
    return float(sum(point.get("Sum", 0.0) for point in response.get("Datapoints", [])))


def _cloudwatch_duration(region_name: str, function_name: str, start_time: datetime, end_time: datetime) -> dict:
    response = _cloudwatch_client(region_name).get_metric_statistics(
        Namespace="AWS/Lambda",
        MetricName="Duration",
        Dimensions=[{"Name": "FunctionName", "Value": function_name}],
        StartTime=start_time,
        EndTime=end_time,
        Period=3600,
        Statistics=["Average", "Maximum", "SampleCount"],
    )
    datapoints = response.get("Datapoints", [])
    if not datapoints:
        return {"average_ms": None, "max_ms": None}
    weighted_sum = 0.0
    total_samples = 0.0
    max_ms = 0.0
    for point in datapoints:
        sample_count = float(point.get("SampleCount", 0.0) or 0.0)
        average = float(point.get("Average", 0.0) or 0.0)
        weighted_sum += average * sample_count
        total_samples += sample_count
        max_ms = max(max_ms, float(point.get("Maximum", 0.0) or 0.0))
    average_ms = (weighted_sum / total_samples) if total_samples else None
    return {
        "average_ms": round(average_ms, 2) if average_ms is not None else None,
        "max_ms": round(max_ms, 2) if max_ms else None,
    }


def _lambda_metrics_snapshot(function_name: str, region_name: str, deployed_at: str | None = None, memory_mb: int | None = None, runtime: str | None = None) -> dict:
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(hours=24)
    invocations = _cloudwatch_sum(region_name, function_name, "Invocations", start_time, end_time)
    errors = _cloudwatch_sum(region_name, function_name, "Errors", start_time, end_time)
    durations = _cloudwatch_duration(region_name, function_name, start_time, end_time)
    return {
        "function_name": function_name,
        "region": region_name,
        "runtime": runtime,
        "memory_mb": memory_mb,
        "deployed_at": deployed_at,
        "age_human": _age_human(deployed_at),
        "last_24h": {
            "invocations": int(round(invocations)),
            "errors": int(round(errors)),
            "avg_duration_ms": durations["average_ms"],
            "max_duration_ms": durations["max_ms"],
        },
    }


def _management_lambda_summary() -> dict:
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "uptime-management")
    try:
        config = _lambda_client().get_function_configuration(FunctionName=function_name)
    except Exception as exc:
        return {
            "function_name": function_name,
            "region": HOME_REGION,
            "error": str(exc),
        }
    return _lambda_metrics_snapshot(
        function_name=function_name,
        region_name=HOME_REGION,
        deployed_at=config.get("LastModified"),
        memory_mb=int(config.get("MemorySize", 0) or 0),
        runtime=config.get("Runtime"),
    )


def _worker_lambda_summary(region_info: dict) -> dict:
    return _lambda_metrics_snapshot(
        function_name=region_info.get("function_name", f"{os.environ.get('PROJECT', 'uptime')}-monitor-{region_info.get('region')}"),
        region_name=region_info.get("region", HOME_REGION),
        deployed_at=region_info.get("deployed_at"),
        memory_mb=int(region_info.get("memory_mb", 0) or 0),
        runtime="python3.12",
    )


def _purge_checks_older_than(older_than_days: int, max_delete: int) -> dict:
    from boto3.dynamodb.conditions import Key

    if older_than_days < 1:
        return _json(400, {"error": "older_than_days must be at least 1"})
    if max_delete < 1 or max_delete > 5000:
        return _json(400, {"error": "max_delete must be between 1 and 5000"})

    cutoff = (datetime.now(timezone.utc) - timedelta(days=older_than_days)).isoformat()
    deleted = 0
    scanned_hosts = 0
    table = _db().Table(CHECKS_TABLE)
    hosts = sorted(_list_host_items(), key=lambda h: h.get("host_id", ""))
    _log("info", "purge_checks_started", older_than_days=older_than_days, max_delete=max_delete, cutoff=cutoff, host_count=len(hosts))

    with table.batch_writer() as batch:
        for host in hosts:
            if deleted >= max_delete:
                break
            scanned_hosts += 1
            remaining = max_delete - deleted
            result = table.query(
                KeyConditionExpression=Key("host_id").eq(host["host_id"]) & Key("checked_at").lt(cutoff),
                ProjectionExpression="host_id, checked_at",
                Limit=remaining,
            )
            items = result.get("Items", [])
            if items:
                _log("info", "purge_checks_host_matches", host_id=host["host_id"], host_name=host.get("name"), match_count=len(items))
            for item in items:
                batch.delete_item(Key={"host_id": item["host_id"], "checked_at": item["checked_at"]})
                deleted += 1
                if deleted >= max_delete:
                    break

    _log("info", "purge_checks_completed", older_than_days=older_than_days, cutoff=cutoff, deleted=deleted, scanned_hosts=scanned_hosts)
    return _json(200, {
        "ok": True,
        "deleted": deleted,
        "cutoff": cutoff,
        "older_than_days": older_than_days,
        "scanned_hosts": scanned_hosts,
    })


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


def _wait_for_acm_dns_records(certificate_arn: str, attempts: int = 5, sleep_seconds: int = 3) -> dict:
    last = _acm_client().describe_certificate(CertificateArn=certificate_arn)["Certificate"]
    if _certificate_validation_records(last):
        return last
    for _ in range(attempts - 1):
        time.sleep(sleep_seconds)
        last = _acm_client().describe_certificate(CertificateArn=certificate_arn)["Certificate"]
        if _certificate_validation_records(last):
            break
    return last


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

    next_action = "Enter a custom domain and click Deploy / Continue."
    cloudfront_created_when = "CloudFront is created only after ACM reports the certificate as ISSUED."
    if status == "pending_validation":
        if dns_records_to_create:
            next_action = "Create the ACM validation DNS record(s), wait for ACM to validate, then click Deploy / Continue again."
        else:
            next_action = "ACM is still preparing the validation DNS record. Click Refresh Status in a few seconds."
    elif status == "creating_distribution":
        next_action = "CloudFront is being created now. Wait for it to finish deploying, then click Refresh Status."
    elif status == "ready":
        next_action = "Create the final traffic DNS record that points your custom domain at CloudFront."
    elif status == "disabling_distribution":
        next_action = "CloudFront is being disabled so it can be deleted. Wait, then click Destroy again if needed."

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
        "next_action": next_action,
        "cloudfront_created_when": cloudfront_created_when,
        "dns_records_to_create": dns_records_to_create,
        "dns_records_to_remove": dns_records_to_remove,
    }


# ── Cost estimate ─────────────────────────────────────────────────────────────

_CLOUDFRONT_PLAN_COSTS = {
    "payg": 0.0,
    "free": 0.0,
    "pro": 15.0,
    "business": 200.0,
    "premium": 1000.0,
}
_COGNITO_ESSENTIALS_DIRECT_MAU_FREE_TIER = 10_000
_COGNITO_ESSENTIALS_DIRECT_MAU_PRICE = 0.015


def _current_scheduler_interval_seconds() -> int:
    # The management EventBridge rule currently runs once per minute.
    return 60


def _checks_per_day(interval_seconds: int) -> int:
    return int(86400 / max(1, interval_seconds))


def _cost_estimate(qs: dict) -> dict:
    defaults = _default_cost_inputs()
    hosts    = int(qs.get("hosts",    [str(defaults["hosts"])])[0])
    rcount   = int(qs.get("regions",  [str(defaults["regions"])])[0])
    interval = int(qs.get("interval", [str(defaults["interval_sec"])])[0])
    days     = int(qs.get("days",     [str(defaults["retention_days"])])[0])
    custom_domain_enabled = str(qs.get("custom_domain", [str(int(defaults.get("custom_domain_enabled", 0)))])[0]).strip().lower() in {"1", "true", "yes", "on"}
    cloudfront_plan = str(qs.get("cloudfront_plan", [defaults.get("cloudfront_plan", "payg")])[0] or "payg").strip().lower()
    cognito_enabled = str(qs.get("cognito_enabled", [str(int(defaults.get("cognito_enabled", 0)))])[0]).strip().lower() in {"1", "true", "yes", "on"}
    cognito_admin_mau = max(0, int(qs.get("cognito_admin_mau", [str(defaults.get("cognito_admin_mau", 0))])[0]))
    if cloudfront_plan not in _CLOUDFRONT_PLAN_COSTS:
        cloudfront_plan = "payg"

    requested_interval = max(1, interval)
    effective_interval = _current_scheduler_interval_seconds()
    runs_per_month = int((30 * 24 * 3600) / effective_interval)
    checks_mo = runs_per_month * hosts * rcount
    management_invocations = runs_per_month
    worker_invocations = runs_per_month * rcount
    invocations = management_invocations + worker_invocations
    gb_sec = worker_invocations * 2.0 * (256 / 1024)
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
    cloudfront_custom_domain_cost = _CLOUDFRONT_PLAN_COSTS[cloudfront_plan] if custom_domain_enabled else 0.0
    cognito_auth_cost = 0.0
    if cognito_enabled:
        cognito_billable_mau = max(0, cognito_admin_mau - _COGNITO_ESSENTIALS_DIRECT_MAU_FREE_TIER)
        cognito_auth_cost = cognito_billable_mau * _COGNITO_ESSENTIALS_DIRECT_MAU_PRICE
    total        = lambda_cost + ddb_w_cost + ddb_r_cost + storage_cost + log_cost + cloudfront_custom_domain_cost + cognito_auth_cost

    return _json(200, {
        "inputs": {
            "hosts": hosts,
            "regions": rcount,
            "interval_sec": interval,
            "retention_days": days,
            "custom_domain": custom_domain_enabled,
            "cloudfront_plan": cloudfront_plan,
            "cognito_enabled": cognito_enabled,
            "cognito_admin_mau": cognito_admin_mau,
        },
        "defaults": defaults,
        "monthly_checks": checks_mo,
        "checks_per_day_per_region": _checks_per_day(effective_interval),
        "requested_checks_per_day_per_region": _checks_per_day(requested_interval),
        "monthly_invocations": {
            "management": management_invocations,
            "workers": worker_invocations,
            "total": invocations,
        },
        "scheduler": {
            "requested_interval_sec": requested_interval,
            "effective_interval_sec": effective_interval,
        },
        "breakdown": {
            "lambda_usd":           round(lambda_cost,  4),
            "dynamodb_writes_usd":  round(ddb_w_cost,   4),
            "dynamodb_reads_usd":   round(ddb_r_cost,   4),
            "dynamodb_storage_usd": round(storage_cost, 4),
            "cloudfront_custom_domain_usd": round(cloudfront_custom_domain_cost, 4),
            "cognito_auth_usd":     round(cognito_auth_cost, 4),
            "cloudwatch_logs_usd":  round(log_cost,     4),
        },
        "total_usd_per_month": round(total, 4),
        "note": "AWS Free Tier applied (1M Lambda req/mo, 25GB DynamoDB, 5GB logs). The current scheduler runs once per minute, so Lambda invocations are driven by worker-region count, not by each host's requested interval. CloudFront uses the selected plan cost; pay-as-you-go request and bandwidth overages are not estimated here. Cognito is estimated as direct sign-in MAUs on the Essentials pricing path and excludes SMS, SES email, and advanced add-ons.",
    })


def _default_cost_inputs() -> dict:
    hosts = [host for host in _list_host_items() if host.get("enabled", True)]
    settings = _db().Table(HOSTS_TABLE).get_item(Key={"host_id": "__settings__"}).get("Item", {})
    return {
        "hosts": len(hosts),
        "regions": len(reg.list_regions(_db())),
        "interval_sec": int(settings.get("default_check_interval", _SETTINGS_DEFAULTS["default_check_interval"])),
        "retention_days": int(settings.get("retention_days", _SETTINGS_DEFAULTS["retention_days"])),
        "custom_domain_enabled": 1 if settings.get("custom_domain_name") else 0,
        "cloudfront_plan": "free" if settings.get("custom_domain_name") else "payg",
        "cognito_enabled": 1 if (os.environ.get("ADMIN_AUTH_MODE") == "cognito" or os.environ.get("COGNITO_USER_POOL_ID")) else 0,
        "cognito_admin_mau": 5 if (os.environ.get("ADMIN_AUTH_MODE") == "cognito" or os.environ.get("COGNITO_USER_POOL_ID")) else 0,
        "monitor_tiers": RECOMMENDED_MONITOR_TIERS,
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

    host_data = _build_public_host_data(db, _list_public_hosts(), history_limit=300)
    return _html(
        200,
        _render_status_page(
            title,
            desc,
            brand_name,
            logo_url,
            theme,
            host_data,
            events_by_month,
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


def _build_public_host_data(db, hosts: list[dict], history_limit: int = 300) -> list[dict]:
    from boto3.dynamodb.conditions import Key as DKey

    host_data = []
    for host in hosts:
        checks = db.Table(CHECKS_TABLE).query(
            KeyConditionExpression=DKey("host_id").eq(host["host_id"]),
            ScanIndexForward=False,
            Limit=history_limit,
        ).get("Items", [])
        grouped = {}
        for check in checks:
            run_id = check.get("run_id") or check.get("checked_at")
            grouped.setdefault(run_id, []).append(check)

        latest_runs = sorted(grouped.keys(), reverse=True)[:90]
        run_statuses = [_aggregate_status(grouped[run_id]) for run_id in latest_runs]
        run_points = []
        for run_id in latest_runs:
            run_status = _aggregate_status(grouped[run_id])
            run_dt = _parse_aws_timestamp(run_id)
            run_points.append({
                "run_id": run_id,
                "status": run_status,
                "checked_at": run_dt.isoformat() if run_dt else run_id,
                "month_label": run_dt.strftime("%B %Y") if run_dt else "Unknown month",
            })
        flat_checks = [item for run_id in latest_runs for item in grouped[run_id]]

        if run_statuses:
            up_count = sum(1 for status in run_statuses if status == "up")
            uptime_pct = round((up_count / len(run_statuses)) * 100, 1)
            avg_latency = round(sum(float(c.get("latency_ms", 0)) for c in flat_checks) / len(flat_checks))
        else:
            uptime_pct, avg_latency = 100.0, 0

        region_summary = []
        for region_name, region_info in sorted((host.get("region_statuses") or {}).items()):
            region_summary.append({
                "region": region_name,
                "status": region_info.get("status", "unknown"),
                "latency_ms": region_info.get("latency_ms"),
            })
        host_data.append({
            "host": host,
            "uptime_pct": uptime_pct,
            "avg_latency": avg_latency,
            "latest_latency": host.get("last_latency_ms"),
            "region_summary": region_summary,
            "history": list(reversed(run_statuses)),
            "history_points": list(reversed(run_points)),
            "history_available": bool(run_statuses),
            "current_status": host.get("current_status", "unknown"),
        })
    return host_data


def _collect_public_history_rows(db, hosts: list[dict], checks_limit: int = 120) -> list[dict]:
    from boto3.dynamodb.conditions import Key as DKey

    rows = []
    host_names = {host["host_id"]: host.get("name", host["host_id"]) for host in hosts}
    for host in hosts:
        checks = db.Table(CHECKS_TABLE).query(
            KeyConditionExpression=DKey("host_id").eq(host["host_id"]),
            ScanIndexForward=False,
            Limit=checks_limit,
        ).get("Items", [])
        for check in checks:
            rows.append({
                "host_id": host["host_id"],
                "host_name": host_names[host["host_id"]],
                "region": check.get("region", ""),
                "status": check.get("status", "unknown"),
                "latency_ms": check.get("latency_ms"),
                "status_code": check.get("status_code"),
                "checked_at": check.get("checked_at", ""),
                "error": check.get("error", ""),
            })
    rows.sort(key=lambda row: row.get("checked_at", ""), reverse=True)
    return rows


def _serve_history_page(event: dict) -> dict:
    db = _db()
    settings = db.Table(HOSTS_TABLE).get_item(Key={"host_id": "__settings__"}).get("Item", {})
    title = settings.get("status_page_title", _SETTINGS_DEFAULTS["status_page_title"])
    brand_name = settings.get("status_page_brand_name", _SETTINGS_DEFAULTS["status_page_brand_name"])
    logo_url = settings.get("status_page_logo_url", _SETTINGS_DEFAULTS["status_page_logo_url"])
    theme = settings.get("status_page_theme", _SETTINGS_DEFAULTS["status_page_theme"])
    hosts = _list_public_hosts()
    query = parse_qs(event.get("rawQueryString") or "")
    selected_host = (query.get("host", ["all"])[0] or "all").strip()
    selected_region = (query.get("region", ["all"])[0] or "all").strip()

    history_rows = _collect_public_history_rows(db, hosts)
    regions = sorted({row["region"] for row in history_rows if row.get("region")})

    filtered_rows = history_rows
    if selected_host != "all":
        filtered_rows = [row for row in filtered_rows if row["host_id"] == selected_host]
    if selected_region != "all":
        filtered_rows = [row for row in filtered_rows if row["region"] == selected_region]

    return _html(
        200,
        _render_history_page(
            title=title,
            brand_name=brand_name,
            logo_url=logo_url,
            theme=theme,
            hosts=hosts,
            regions=regions,
            selected_host=selected_host,
            selected_region=selected_region,
            rows=filtered_rows[:250],
        ),
    )


def _render_status_page(title: str, desc: str, brand_name: str, logo_url: str, theme: str, host_data: list, events_by_month: list, page_options: dict) -> str:
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
        history_note = "" if h["history_available"] else '<div class="history-note">History appears after checks have been recorded for this host.</div>'
        cards += f"""<details class="card svc-card">
  <summary class="svc-summary">
    <div>
      <div class="row" style="margin-bottom:2px"><span class="svc">{h['host']['name']}</span><span class="badge {s}">{badge}</span></div>
      <div class="meta" style="margin-bottom:0">{h['uptime_pct']}% uptime &nbsp;·&nbsp; {' &nbsp;·&nbsp; '.join(latency_bits)}</div>
    </div>
    <span class="summary-hint">Details</span>
  </summary>
  <div class="history-title">Recent history</div>
  {history_note}
  <div class="bars">{bars}</div>
  <div class="bar-lbl"><span>90 checks ago</span><span>Latest</span></div>
  <div class="regions">{region_pills or '<span class="pill unknown">No regional data yet</span>'}</div>
</details>"""

    if not host_data:
        cards = '<p class="empty">No services configured for the status page yet.</p>'

    history_href = "/history"
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    brand = ""
    if brand_name or logo_url:
        logo = f'<img src="{logo_url}" alt="{brand_name}" class="brand-logo">' if logo_url else ""
        brand = f'<div class="brand">{logo}<span>{brand_name or title}</span></div>'
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{color-scheme:light}}
body{{font-family:"IBM Plex Sans","Segoe UI",sans-serif;background:
radial-gradient(circle at top left, rgba(14,165,233,.16), transparent 32%),
radial-gradient(circle at top right, rgba(15,118,110,.12), transparent 28%),
linear-gradient(180deg, var(--bg) 0%, var(--bg-alt) 100%);color:var(--text);min-height:100vh;position:relative}}
body::before{{content:"";position:fixed;inset:0;background:linear-gradient(180deg, rgba(255,255,255,.28), transparent 22%);pointer-events:none}}
.theme-clean{{--bg:#f4f7fb;--bg-alt:#edf3fb;--text:#0f172a;--card:#ffffff;--border:#d7dee8;--muted:#475569;--soft:#64748b;--hero:#ffffffd8;--hero-border:#d7dee8;--shadow:0 18px 44px rgba(15,23,42,.07);--ring:#0f766e;--wash:#eff6ff;--radius-shell:18px;--radius-card:14px;--radius-pill:999px;--surface-opacity:.9}}
.theme-midnight{{--bg:#050b15;--bg-alt:#0b1220;--text:#e5eef8;--card:#101828;--border:#22314a;--muted:#a5b4c8;--soft:#7f91ab;--hero:#0d1625d8;--hero-border:#22314a;--shadow:0 26px 72px rgba(2,6,23,.44);--ring:#38bdf8;--wash:#0d2138;--radius-shell:14px;--radius-card:12px;--radius-pill:999px;--surface-opacity:.86}}
.theme-sunrise{{--bg:#fdf3e8;--bg-alt:#fff7ef;--text:#29180e;--card:#fffdf9;--border:#ead6c0;--muted:#7c5a43;--soft:#a2704f;--hero:#fff8f0d9;--hero-border:#ead6c0;--shadow:0 22px 56px rgba(146,64,14,.1);--ring:#c2410c;--wash:#ffedd5;--radius-shell:22px;--radius-card:18px;--radius-pill:999px;--surface-opacity:.92}}
.theme-forest{{--bg:#edf8f0;--bg-alt:#e4f3e9;--text:#123021;--card:#fbfefc;--border:#c9e4d2;--muted:#315843;--soft:#4e7b63;--hero:#f8fdf9d8;--hero-border:#c9e4d2;--shadow:0 20px 52px rgba(20,83,45,.1);--ring:#15803d;--wash:#dcfce7;--radius-shell:20px;--radius-card:16px;--radius-pill:999px;--surface-opacity:.9}}
.wrap{{max-width:960px;margin:0 auto;padding:56px 20px 72px;position:relative}}
.brand{{display:flex;align-items:center;gap:12px;font-size:.88rem;font-weight:600;color:var(--soft);margin-bottom:22px;letter-spacing:.06em;text-transform:uppercase;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.brand-logo{{height:42px;width:42px;object-fit:contain;border-radius:12px;background:var(--card);border:1px solid var(--border);padding:5px;box-shadow:var(--shadow)}}
h1{{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-size:clamp(2.2rem,4vw,3.35rem);line-height:1.02;font-weight:700;margin-bottom:10px;max-width:11ch;letter-spacing:-.04em}}
.hero{{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;margin-bottom:34px}}
.sub{{color:var(--muted);margin-bottom:0;max-width:58ch;line-height:1.65;font-size:1.02rem}}
.hero-copy{{display:flex;flex-direction:column;gap:18px}}
.hero-actions{{display:flex;flex-wrap:wrap;gap:10px}}
.overall{{display:inline-flex;align-items:center;gap:12px;padding:14px 18px;border-radius:var(--radius-pill);font-weight:700;background:var(--hero);border:1px solid var(--hero-border);white-space:nowrap;box-shadow:var(--shadow);backdrop-filter:blur(14px);font-family:"Space Grotesk","IBM Plex Sans",sans-serif}}
.overall.operational{{background:#ecfdf3;border:1px solid #9de3b1;color:#166534}}
.overall.down{{background:#fef2f2;border:1px solid #f5b5b5;color:#991b1b}}
.overall.degraded{{background:#fffbeb;border:1px solid #f7cf7d;color:#9a4d00}}
.ghost-link{{display:inline-flex;align-items:center;justify-content:center;padding:11px 14px;border-radius:var(--radius-pill);border:1px solid var(--border);background:rgba(255,255,255,.5);color:var(--text);text-decoration:none;font-weight:700;transition:transform .18s ease, border-color .18s ease, box-shadow .18s ease}}
.ghost-link:hover{{transform:translateY(-1px);border-color:var(--ring);box-shadow:0 12px 24px rgba(15,23,42,.08)}}
.maintenance,.subscribe{{display:flex;justify-content:space-between;gap:20px;align-items:flex-start;padding:22px 24px;border-radius:var(--radius-shell);margin-bottom:18px;background:var(--hero);border:1px solid var(--hero-border);box-shadow:var(--shadow);backdrop-filter:blur(14px)}}
.maintenance{{background:linear-gradient(135deg, var(--wash), var(--hero));border-color:color-mix(in srgb, var(--ring) 18%, var(--border))}}
.maintenance-title,.subscribe-title{{font-size:.78rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;margin-bottom:8px;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.maintenance-copy,.subscribe-copy{{font-size:.99rem;line-height:1.6}}
.maintenance-meta{{margin-top:8px;color:var(--muted);font-size:.82rem}}
.maintenance-list{{background:var(--card);border:1px solid var(--border);border-radius:24px;padding:18px 20px;margin-bottom:18px;box-shadow:var(--shadow)}}
.section-summary{{display:flex;justify-content:space-between;align-items:center;gap:12px;cursor:pointer;list-style:none}}
.section-summary::-webkit-details-marker{{display:none}}
.section-summary-title{{font-size:.8rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.section-summary-meta{{font-size:.8rem;color:var(--muted);font-weight:600}}
.maintenance-list-title{{font-size:.8rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;margin-bottom:10px;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.maintenance-list-item{{display:flex;flex-direction:column;gap:6px;margin-top:12px}}
.maintenance-list-copy{{font-size:.95rem;line-height:1.5}}
.maintenance-list-meta,.maintenance-list-empty{{font-size:.83rem;color:var(--muted)}}
.maintenance-list-empty{{margin-top:12px}}
.events-wrap{{margin-bottom:20px}}
.section-heading{{font-size:.8rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--soft);margin-bottom:10px;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.events-month{{background:var(--card);border:1px solid var(--border);border-radius:20px;padding:14px 18px;margin-bottom:10px;box-shadow:var(--shadow)}}
.events-list{{display:flex;flex-direction:column;gap:8px;margin-top:12px}}
.event-item{{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:10px;align-items:center;font-size:.84rem}}
.event-host{{font-weight:600}}
.event-time{{color:var(--muted);font-size:.78rem;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.subscribe-actions{{display:flex;flex-wrap:wrap;gap:10px}}
.subscribe-btn{{display:inline-flex;align-items:center;justify-content:center;padding:11px 15px;border-radius:var(--radius-pill);border:1px solid var(--border);background:var(--card);color:var(--text);text-decoration:none;font-weight:700;white-space:nowrap;transition:transform .18s ease, border-color .18s ease, box-shadow .18s ease}}
.subscribe-btn:hover{{transform:translateY(-1px);border-color:var(--ring);box-shadow:0 12px 24px rgba(15,23,42,.08)}}
.dot{{width:14px;height:14px;border-radius:50%;flex-shrink:0;box-shadow:0 0 0 6px rgba(255,255,255,.56)}}
.operational .dot{{background:#22c55e}}.down .dot{{background:#ef4444}}.degraded .dot{{background:#f59e0b}}
.card{{background:color-mix(in srgb, var(--card) calc(var(--surface-opacity) * 100%), transparent);border:1px solid var(--border);border-radius:var(--radius-card);padding:20px 20px 18px;margin-bottom:12px;box-shadow:var(--shadow);transition:transform .18s ease, box-shadow .18s ease, border-color .18s ease}}
.svc-card[open],.svc-card:hover{{transform:translateY(-1px);border-color:color-mix(in srgb, var(--ring) 24%, var(--border))}}
.svc-summary{{display:flex;justify-content:space-between;align-items:center;gap:18px;cursor:pointer;list-style:none}}
.svc-summary::-webkit-details-marker{{display:none}}
.summary-hint{{font-size:.76rem;color:var(--muted);font-weight:700;white-space:nowrap;font-family:"IBM Plex Mono","SFMono-Regular",monospace;letter-spacing:.08em;text-transform:uppercase}}
.row{{display:flex;justify-content:space-between;align-items:center;margin-bottom:6px}}
.svc{{font-weight:600;font-size:1.06rem;font-family:"Space Grotesk","IBM Plex Sans",sans-serif}}
.badge{{font-size:.76rem;font-weight:700;padding:5px 11px;border-radius:12px;letter-spacing:.04em;text-transform:uppercase}}
.badge.up{{background:#f0fdf4;color:#16a34a}}.badge.down{{background:#fef2f2;color:#dc2626}}
.badge.degraded{{background:#fffbeb;color:#d97706}}.badge.unknown{{background:#f1f5f9;color:#64748b}}
.meta{{font-size:.83rem;color:var(--muted);margin-bottom:12px;line-height:1.5}}
.history-title{{font-size:.76rem;color:var(--soft);text-transform:uppercase;letter-spacing:.16em;margin-bottom:8px;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.history-note{{font-size:.78rem;color:var(--muted);margin-bottom:8px}}
.bars{{display:flex;gap:4px;height:28px}}
.b{{flex:1;border-radius:4px;min-width:3px}}
.b.up{{background:#22c55e}}.b.down{{background:#ef4444}}.b.degraded{{background:#f59e0b}}.b.unknown{{background:#e2e8f0}}
.bar-lbl{{display:flex;justify-content:space-between;font-size:.72rem;color:var(--soft);margin-top:6px;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.regions{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.pill{{display:inline-flex;align-items:center;padding:6px 10px;border-radius:12px;font-size:.72rem;font-weight:600;background:#f8fafc;color:#475569;border:1px solid var(--border);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.pill.up{{background:#f0fdf4;color:#166534;border-color:#bbf7d0}}
.pill.down{{background:#fef2f2;color:#b91c1c;border-color:#fecaca}}
.pill.degraded{{background:#fffbeb;color:#b45309;border-color:#fde68a}}
.pill.unknown{{background:#f8fafc;color:#64748b}}
.empty{{text-align:center;color:var(--soft);padding:40px 0}}
footer{{text-align:center;margin-top:52px;font-size:.78rem;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
@media (max-width: 700px) {{
  .wrap{{padding-top:40px}}
  .hero{{flex-direction:column}}
  .hero-copy{{width:100%}}
  .maintenance,.subscribe{{flex-direction:column}}
  .hero-actions{{width:100%}}
  .ghost-link{{width:100%}}
  .subscribe-actions{{width:100%}}
  .subscribe-btn{{width:100%}}
}}
</style></head><body class="theme-{theme_class}">
<div class="wrap">
  {brand}
  <div class="hero">
    <div class="hero-copy"><div><h1>{title}</h1><p class="sub">{desc}</p></div><div class="hero-actions"><a class="ghost-link" href="{history_href}">Explore full history</a></div></div>
    <div class="overall {ocls}"><div class="dot"></div><span>{overall}</span></div>
  </div>
  {maintenance_block}
  {cards}
  {subscribe_block}
  <footer>Updated {now_str}</footer>
</div></body></html>"""


def _render_history_page(title: str, brand_name: str, logo_url: str, theme: str, hosts: list[dict], regions: list[str], selected_host: str, selected_region: str, rows: list[dict]) -> str:
    theme_class = theme if theme in {"clean", "midnight", "sunrise", "forest"} else "clean"
    brand = ""
    if brand_name or logo_url:
        logo = f'<img src="{logo_url}" alt="{brand_name}" class="brand-logo">' if logo_url else ""
        brand = f'<div class="brand">{logo}<span>{brand_name or title}</span></div>'

    host_options = ['<option value="all">All hosts</option>'] + [
        f'<option value="{host["host_id"]}"{" selected" if selected_host == host["host_id"] else ""}>{host.get("name", host["host_id"])}</option>'
        for host in hosts
    ]
    region_options = ['<option value="all">All workers</option>'] + [
        f'<option value="{region}"{" selected" if selected_region == region else ""}>{region}</option>'
        for region in regions
    ]
    row_markup = "".join(
        f"""<tr>
  <td>{row["host_name"]}</td>
  <td><span class="pill {row["status"]}">{row["status"].title()}</span></td>
  <td>{row["region"] or "—"}</td>
  <td>{row["latency_ms"] if row["latency_ms"] is not None else "—"} ms</td>
  <td>{row["status_code"] if row.get("status_code") is not None else "—"}</td>
  <td>{row["checked_at"].replace("T", " ")[:19]}</td>
  <td>{(row.get("error") or "—")[:120]}</td>
</tr>"""
        for row in rows
    ) or '<tr><td colspan="7" class="empty-cell">No checks matched the selected filters.</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} History</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:"IBM Plex Sans","Segoe UI",sans-serif;background:
radial-gradient(circle at top left, rgba(14,165,233,.16), transparent 32%),
radial-gradient(circle at top right, rgba(15,118,110,.12), transparent 28%),
linear-gradient(180deg, var(--bg) 0%, var(--bg-alt) 100%);color:var(--text);min-height:100vh}}
.theme-clean{{--bg:#f4f7fb;--bg-alt:#edf3fb;--text:#0f172a;--card:#ffffff;--border:#d7dee8;--muted:#475569;--soft:#64748b;--hero:#ffffffd8;--hero-border:#d7dee8;--shadow:0 18px 44px rgba(15,23,42,.07);--ring:#0f766e}}
.theme-midnight{{--bg:#050b15;--bg-alt:#0b1220;--text:#e5eef8;--card:#101828;--border:#22314a;--muted:#a5b4c8;--soft:#7f91ab;--hero:#0d1625d8;--hero-border:#22314a;--shadow:0 26px 72px rgba(2,6,23,.44);--ring:#38bdf8}}
.theme-sunrise{{--bg:#fdf3e8;--bg-alt:#fff7ef;--text:#29180e;--card:#fffdf9;--border:#ead6c0;--muted:#7c5a43;--soft:#a2704f;--hero:#fff8f0d9;--hero-border:#ead6c0;--shadow:0 22px 56px rgba(146,64,14,.1);--ring:#c2410c}}
.theme-forest{{--bg:#edf8f0;--bg-alt:#e4f3e9;--text:#123021;--card:#fbfefc;--border:#c9e4d2;--muted:#315843;--soft:#4e7b63;--hero:#f8fdf9d8;--hero-border:#c9e4d2;--shadow:0 20px 52px rgba(20,83,45,.1);--ring:#15803d}}
.wrap{{max-width:1160px;margin:0 auto;padding:56px 20px 72px}}
.brand{{display:flex;align-items:center;gap:12px;font-size:.88rem;font-weight:600;color:var(--soft);margin-bottom:22px;letter-spacing:.06em;text-transform:uppercase;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.brand-logo{{height:42px;width:42px;object-fit:contain;border-radius:12px;background:var(--card);border:1px solid var(--border);padding:5px;box-shadow:var(--shadow)}}
.hero{{display:flex;justify-content:space-between;gap:18px;align-items:flex-end;margin-bottom:20px}}
h1{{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-size:clamp(2rem,4vw,3rem);line-height:1.02;font-weight:700;letter-spacing:-.04em;margin-bottom:8px}}
.sub{{color:var(--muted);line-height:1.65;max-width:64ch}}
.hero-actions{{display:flex;gap:10px;flex-wrap:wrap}}
.ghost-link{{display:inline-flex;align-items:center;justify-content:center;padding:11px 14px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.5);color:var(--text);text-decoration:none;font-weight:700}}
.panel{{background:var(--hero);border:1px solid var(--hero-border);border-radius:14px;padding:18px 18px 16px;box-shadow:var(--shadow);margin-bottom:16px;backdrop-filter:blur(14px)}}
.filters{{display:grid;grid-template-columns:1fr 1fr auto;gap:12px;align-items:end}}
label{{display:block;font-size:.8rem;color:var(--muted);margin-bottom:6px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}}
select{{width:100%;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:11px 12px;color:var(--text);font-size:.92rem}}
.filter-btn{{display:inline-flex;align-items:center;justify-content:center;padding:11px 16px;border-radius:12px;border:1px solid var(--border);background:var(--text);color:var(--card);text-decoration:none;font-weight:700}}
.summary{{display:flex;justify-content:space-between;gap:16px;flex-wrap:wrap;color:var(--muted);font-size:.92rem}}
table{{width:100%;border-collapse:separate;border-spacing:0;background:var(--card);border:1px solid var(--border);border-radius:14px;overflow:hidden;box-shadow:var(--shadow)}}
th{{background:rgba(148,163,184,.08);color:var(--soft);font-size:.75rem;text-transform:uppercase;letter-spacing:.14em;padding:12px 14px;text-align:left;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
td{{padding:13px 14px;border-top:1px solid var(--border);font-size:.87rem;vertical-align:top}}
.pill{{display:inline-flex;align-items:center;padding:6px 10px;border-radius:12px;font-size:.72rem;font-weight:600;border:1px solid var(--border);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.pill.up{{background:#f0fdf4;color:#166534;border-color:#bbf7d0}}
.pill.down{{background:#fef2f2;color:#b91c1c;border-color:#fecaca}}
.pill.degraded{{background:#fffbeb;color:#b45309;border-color:#fde68a}}
.pill.unknown{{background:#f8fafc;color:#64748b}}
.empty-cell{{text-align:center;color:var(--soft);padding:28px}}
@media (max-width: 900px) {{
  .filters{{grid-template-columns:1fr}}
  .hero{{flex-direction:column;align-items:flex-start}}
  .hero-actions{{width:100%}}
  .ghost-link,.filter-btn{{width:100%}}
  .table-wrap{{overflow-x:auto}}
}}
</style></head><body class="theme-{theme_class}">
<div class="wrap">
  {brand}
  <div class="hero">
    <div>
      <h1>Check History</h1>
      <p class="sub">Browse recent public checks across services and worker regions. Use filters to narrow the timeline without crowding the main status page.</p>
    </div>
    <div class="hero-actions"><a class="ghost-link" href="/status">Back to status</a></div>
  </div>
  <form class="panel filters" method="GET" action="/history">
    <div>
      <label for="host">Host</label>
      <select id="host" name="host">{''.join(host_options)}</select>
    </div>
    <div>
      <label for="region">Worker region</label>
      <select id="region" name="region">{''.join(region_options)}</select>
    </div>
    <button class="filter-btn" type="submit">Apply filters</button>
  </form>
  <div class="panel summary">
    <span>Showing <strong>{len(rows)}</strong> recent checks</span>
    <span>Theme: <strong>{theme_class}</strong></span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Status</th><th>Worker</th><th>Latency</th><th>HTTP</th><th>Checked</th><th>Detail</th></tr></thead>
      <tbody>{row_markup}</tbody>
    </table>
  </div>
</div></body></html>"""


# ── Admin SPA ─────────────────────────────────────────────────────────────────

def _admin_page() -> str:
    # All AWS regions available for monitor deployment
    build = _build_info()
    read_only_banner = ""
    if _is_read_only():
        read_only_banner = """<div class="tip" style="margin-bottom:16px;background:#3f1d1d;border-left-color:#ef4444;color:#fecaca">
Read-only mode is enabled. Browsing still works, but all mutating admin actions are disabled.
</div>"""
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
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
:root{{--bg:#0b1220;--bg-alt:#10192b;--panel:#172235;--panel-strong:#1d2a40;--line:#2d3f5d;--line-soft:rgba(165,180,200,.18);--text:#e5eef8;--muted:#a8b8cd;--soft:#7f91ab;--brand:#0f766e;--brand-strong:#115e59;--sky:#0ea5e9;--success:#16a34a;--warn:#d97706;--danger:#dc2626}}
body{{font-family:"IBM Plex Sans","Segoe UI",sans-serif;background:
radial-gradient(circle at top left, rgba(14,165,233,.16), transparent 26%),
radial-gradient(circle at top right, rgba(15,118,110,.12), transparent 22%),
linear-gradient(180deg, var(--bg) 0%, #08101d 100%);color:var(--text);min-height:100vh}}
button,input,select,textarea{{font:inherit}}
nav{{position:sticky;top:0;z-index:40;background:rgba(11,18,32,.82);backdrop-filter:blur(18px);border-bottom:1px solid var(--line-soft);padding:0 24px;display:flex;align-items:center;min-height:64px;gap:0;box-shadow:0 12px 34px rgba(2,6,23,.25)}}
.logo{{display:flex;align-items:center;gap:12px;font-weight:700;color:#f8fafc;font-size:1.02rem;margin-right:34px;white-space:nowrap;font-family:"Space Grotesk","IBM Plex Sans",sans-serif;letter-spacing:-.02em}}
.logo-mark{{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:12px;background:linear-gradient(135deg, var(--brand), var(--sky));color:white;font-size:.82rem;font-family:"IBM Plex Mono","SFMono-Regular",monospace;box-shadow:0 14px 26px rgba(14,165,233,.18)}}
.logo-version{{font-size:.7rem;color:var(--muted);font-weight:600;font-family:"IBM Plex Mono","SFMono-Regular",monospace;letter-spacing:.08em;text-transform:uppercase}}
.nav-spacer{{margin-left:auto}}
.tab{{padding:0 16px;height:64px;display:flex;align-items:center;cursor:pointer;font-size:.88rem;color:var(--muted);border-bottom:2px solid transparent;white-space:nowrap;font-family:"Space Grotesk","IBM Plex Sans",sans-serif;transition:color .18s ease,border-color .18s ease}}
.tab.active,.tab:hover{{color:#f8fafc;border-bottom-color:var(--sky)}}
.main{{max-width:1180px;margin:0 auto;padding:34px 20px 72px}}
h2{{font-size:1.55rem;font-weight:700;margin-bottom:18px;font-family:"Space Grotesk","IBM Plex Sans",sans-serif;letter-spacing:-.03em}}
h3{{font-size:1rem;font-weight:600;margin:20px 0 8px;color:#e2e8f0;font-family:"Space Grotesk","IBM Plex Sans",sans-serif}}
.btn{{display:inline-flex;align-items:center;gap:8px;padding:10px 16px;border-radius:14px;border:none;cursor:pointer;font-size:.875rem;font-weight:600;transition:transform .16s ease,background .16s ease,border-color .16s ease,box-shadow .16s ease;text-decoration:none}}
.btn:hover{{transform:translateY(-1px)}}
.btn-primary{{background:linear-gradient(135deg, var(--brand), #0f9f93);color:#fff;box-shadow:0 14px 28px rgba(15,118,110,.22)}}.btn-primary:hover{{background:linear-gradient(135deg, var(--brand-strong), var(--brand))}}
.btn-success{{background:#166534;color:#fff}}.btn-success:hover{{background:#15803d}}
.btn-danger{{background:#b91c1c;color:#fff}}.btn-danger:hover{{background:#991b1b}}
.btn-warn{{background:#b45309;color:#fff}}.btn-warn:hover{{background:#92400e}}
.btn-ghost{{background:rgba(255,255,255,.02);color:var(--muted);border:1px solid var(--line)}}.btn-ghost:hover{{color:#f8fafc;border-color:#4a6288}}
.btn-sm{{padding:7px 12px;font-size:.8rem;border-radius:12px}}
table{{width:100%;border-collapse:separate;border-spacing:0;background:rgba(23,34,53,.92);border:1px solid var(--line-soft);border-radius:22px;overflow:hidden;box-shadow:0 24px 60px rgba(2,6,23,.22)}}
th{{background:#101a2b;color:var(--soft);font-size:.76rem;text-transform:uppercase;letter-spacing:.14em;padding:12px 14px;text-align:left;white-space:nowrap;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
td{{padding:14px;border-top:1px solid var(--line-soft);font-size:.875rem;vertical-align:middle}}
.badge{{display:inline-block;padding:4px 9px;border-radius:999px;font-size:.73rem;font-weight:700;letter-spacing:.04em;text-transform:uppercase}}
.badge.up,.badge.active{{background:#166534;color:#bbf7d0}}
.badge.down{{background:#7f1d1d;color:#fecaca}}
.badge.degraded{{background:#713f12;color:#fde68a}}
.badge.unknown,.badge.inactive{{background:#172235;color:var(--soft);border:1px solid var(--line)}}
.badge.http,.badge.tcp{{background:#1e3a5f;color:#93c5fd}}
.modal-overlay{{position:fixed;inset:0;background:rgba(2,6,23,.82);display:none;align-items:center;justify-content:center;z-index:100;padding:20px}}
.modal-overlay.open{{display:flex}}
.modal{{background:linear-gradient(180deg, rgba(23,34,53,.98), rgba(17,28,45,.98));border:1px solid var(--line);border-radius:24px;padding:28px;width:100%;max-width:520px;max-height:90vh;overflow-y:auto;box-shadow:0 36px 80px rgba(0,0,0,.38)}}
.modal h3{{font-size:1.1rem;margin-bottom:20px;margin-top:0}}
.form-group{{margin-bottom:16px}}
label{{display:block;font-size:.8rem;color:var(--muted);margin-bottom:6px;font-weight:600;letter-spacing:.04em;text-transform:uppercase}}
input,select,textarea{{width:100%;background:#0e1828;border:1px solid var(--line);border-radius:14px;padding:10px 12px;color:#f8fafc;font-size:.875rem;transition:border-color .15s ease, box-shadow .15s ease, background .15s ease}}
input:focus,select:focus,textarea:focus{{outline:none;border-color:var(--sky);box-shadow:0 0 0 4px rgba(14,165,233,.14);background:#122037}}
.toggle{{display:flex;align-items:center;gap:10px;cursor:pointer}}
.toggle input[type=checkbox]{{width:auto;cursor:pointer}}
.hint{{font-size:.75rem;color:var(--soft);margin-top:3px;line-height:1.5}}
.panel{{background:rgba(23,34,53,.92);border:1px solid var(--line-soft);border-radius:24px;padding:22px;margin-bottom:20px;box-shadow:0 24px 60px rgba(2,6,23,.18)}}
.grid2{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.actions{{display:flex;gap:8px;flex-wrap:wrap}}
.toast{{position:fixed;bottom:24px;right:24px;background:var(--success);color:#fff;padding:10px 18px;border-radius:14px;font-size:.875rem;font-weight:600;z-index:200;transition:opacity .3s;box-shadow:0 16px 34px rgba(0,0,0,.28)}}
.toast.error{{background:var(--danger)}}
.toast.hidden{{opacity:0;pointer-events:none}}
.cost-row{{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line-soft);font-size:.875rem}}
.cost-row:last-child{{border:none;font-weight:700;color:#67e8f9;font-size:1rem}}
pre{{background:#0e1828;border:1px solid var(--line);border-radius:18px;padding:14px;font-size:.78rem;overflow-x:auto;line-height:1.6;color:#b9d8ff;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.tip{{background:linear-gradient(135deg, rgba(15,118,110,.12), rgba(14,165,233,.1));border:1px solid rgba(14,165,233,.22);padding:12px 14px;border-radius:16px;font-size:.83rem;color:#c7efff;margin:12px 0;line-height:1.55}}
p.desc{{color:var(--muted);font-size:.92rem;line-height:1.65;margin-bottom:12px;max-width:72ch}}
.region-card{{background:rgba(23,34,53,.92);border:1px solid var(--line-soft);border-radius:22px;padding:16px;display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;box-shadow:0 18px 40px rgba(2,6,23,.16)}}
.region-info .name{{font-weight:600;margin-bottom:4px}}
.region-info .meta{{font-size:.8rem;color:var(--soft)}}
.section-header{{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}}
.spinner{{display:inline-block;width:14px;height:14px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:spin .7s linear infinite}}
.auth-gate{{position:fixed;inset:0;background:rgba(2,6,23,.88);display:flex;align-items:center;justify-content:center;z-index:250;padding:20px}}
.auth-card{{width:100%;max-width:440px;background:linear-gradient(180deg, rgba(23,34,53,.98), rgba(11,18,32,.98));border:1px solid var(--line);border-radius:28px;padding:30px;box-shadow:0 28px 70px rgba(0,0,0,.42)}}
.auth-card h1{{font-size:1.45rem;margin-bottom:10px;font-family:"Space Grotesk","IBM Plex Sans",sans-serif;letter-spacing:-.03em}}
.auth-card p{{color:var(--muted);font-size:.9rem;line-height:1.6;margin-bottom:14px}}
.auth-msg{{font-size:.82rem;color:var(--muted);min-height:18px;margin-top:10px}}
.checklist{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin-top:10px}}
.check-item{{display:flex;align-items:center;gap:8px;background:#0e1828;border:1px solid var(--line);border-radius:14px;padding:9px 10px;font-size:.83rem}}
.check-item input{{width:auto}}
strong{{color:#f8fafc}}
@media (max-width: 900px) {{
  nav{{overflow-x:auto}}
  .main{{padding-top:24px}}
}}
@media (max-width: 760px) {{
  .grid2{{grid-template-columns:1fr}}
  .section-header,.region-card{{flex-direction:column;align-items:flex-start}}
}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head><body>
<nav>
  <span class="logo"><span class="logo-mark">UP</span><span>Uptime Control</span><span class="logo-version">v{build.get("version", "unknown")}</span></span>
  <span class="tab active"  onclick="show('hosts')">Hosts</span>
  <span class="tab"         onclick="show('regions')">Regions</span>
  <span class="tab"         onclick="show('status-page')">Status Page</span>
  <span class="tab"         onclick="show('notifications')">Notifications</span>
  <span class="tab"         onclick="show('management')">Management</span>
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
{read_only_banner}
<div class="hint" style="margin-bottom:16px">Build: <strong>{build.get("version", "unknown")}</strong>{' · Built at: ' + build.get('built_at') if build.get('built_at') else ''} · Region: <strong>{build.get("region", HOME_REGION)}</strong></div>

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
          <option value="clean">Clean Control</option>
          <option value="midnight">Midnight Ops</option>
          <option value="sunrise">Sunrise Briefing</option>
          <option value="forest">Forest Calm</option>
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
      Themes now change the whole atmosphere, not just the colors:
      <strong>Clean Control</strong> is crisp and editorial, <strong>Midnight Ops</strong> is sharper and denser,
      <strong>Sunrise Briefing</strong> is warmer and softer, and <strong>Forest Calm</strong> is quieter and more grounded.
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
    <a class="btn btn-ghost" href="/history" target="_blank">Preview history page</a>
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
    <div id="cd-records" style="margin-top:14px"></div>
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

<div id="pane-management" style="display:none">
  <h2>Management</h2>
  <p class="desc">
    Monitor DynamoDB table size and manually reduce stored check history when you need to reclaim space faster than TTL cleanup.
  </p>
  <div class="panel">
    <div id="mgmt-summary" style="color:#94a3b8">Loading…</div>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Retention</h3>
    <div class="grid2">
      <div class="form-group">
        <label>Retention Days</label>
        <input id="mgmt-retention-days" type="number" min="1" max="3650">
        <div class="hint">New checks get a DynamoDB TTL based on this value.</div>
      </div>
      <div class="form-group" style="display:flex;align-items:flex-end">
        <button class="btn btn-primary" onclick="saveManagementRetention()">Save Retention</button>
      </div>
    </div>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Manual Cleanup</h3>
    <div class="grid2">
      <div class="form-group">
        <label>Delete checks older than (days)</label>
        <input id="mgmt-purge-days" type="number" min="1" max="3650" value="30">
      </div>
      <div class="form-group">
        <label>Max items to delete now</label>
        <input id="mgmt-purge-limit" type="number" min="1" max="5000" value="500">
      </div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-danger" onclick="purgeOldChecks()">Purge Old Checks</button>
      <button class="btn btn-ghost" onclick="loadManagement()">Refresh</button>
    </div>
    <pre id="mgmt-result" style="margin-top:14px">No management action has run yet.</pre>
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
    <div class="form-group">
      <label>CloudFront Plan</label>
      <select id="c-cloudfront-plan">
        <option value="payg">Pay as you go (not estimated)</option>
        <option value="free">Free plan ($0/mo)</option>
        <option value="pro">Pro plan ($15/mo)</option>
        <option value="business">Business plan ($200/mo)</option>
        <option value="premium">Premium plan ($1000/mo)</option>
      </select>
    </div>
    <div class="form-group">
      <label>Cognito Admin MAUs / Month</label>
      <input id="c-cognito-mau" type="number" value="0" min="0">
      <div class="hint">Only used when Cognito is deployed. This estimates monthly active admin users, not total user accounts.</div>
    </div>
  </div>
  <button class="btn btn-primary" onclick="calcCost()" style="margin-bottom:20px">Calculate</button>
  <div class="panel" id="cost-result" style="display:none">
    <div id="cost-summary" class="hint" style="margin-bottom:14px"></div>
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

  <h3>Debugging deployed version</h3>
  <p class="desc">This deployment exposes a tiny version endpoint so you can confirm exactly which management build is live.</p>
  <pre>GET /api/debug/version
Authorization: Bearer &lt;admin-token&gt;</pre>
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
      <div class="form-group">
        <label>Monitor Tier</label>
        <select id="m-tier"></select>
        <div class="hint">Choose one of the schedules currently supported by your worker fleet.</div>
      </div>
      <div class="form-group"><label>Timeout (sec)</label><input id="m-timeout" type="number" value="10" min="1" max="60"></div>
    </div>
    <div class="tip" id="m-impact">
      Current scheduler: every 60 seconds. This host will be checked about 1,440 times/day per worker region and does not create one Lambda invocation per check by itself.
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
    <div class="form-group">
      <label>Monitor Tiers</label>
      <div class="hint">Each worker can support one or more shared schedules. Hosts will choose from these tiers.</div>
      <div id="r-supported-tiers" class="checklist"></div>
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
let HOSTS_CACHE = [];
const RECOMMENDED_MONITOR_TIERS = {json.dumps(RECOMMENDED_MONITOR_TIERS)};
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

const PANES = ['hosts','regions','status-page','notifications','management','settings','cost','guides'];
function show(tab) {{
  PANES.forEach((t,i) => {{
    document.getElementById('pane-'+t).style.display = t===tab ? '' : 'none';
    document.querySelectorAll('.tab')[i].classList.toggle('active', t===tab);
  }});
  if (tab === 'hosts') loadHosts();
  if (tab === 'regions') loadRegions();
  if (tab === 'status-page') loadStatusPage();
  if (tab === 'notifications') loadNotificationSettings();
  if (tab === 'management') loadManagement();
  if (tab === 'settings') loadSettings();
  if (tab === 'cost') loadCostDefaults();
}}

async function ensureRegionsLoaded() {{
  const list = await api('/api/regions');
  REGIONS_CACHE = Array.isArray(list) ? list : [];
  return REGIONS_CACHE;
}}

function formatTierLabel(seconds) {{
  const sec = +seconds;
  if (sec % 3600 === 0) return `Every ${{sec / 3600}} hour${{sec === 3600 ? '' : 's'}}`;
  if (sec % 60 === 0) return `Every ${{sec / 60}} minute${{sec === 60 ? '' : 's'}}`;
  return `Every ${{sec}} seconds`;
}}

function availableMonitorTiers(extra=[]) {{
  const tiers = new Set(RECOMMENDED_MONITOR_TIERS);
  REGIONS_CACHE.forEach(region => (region.supported_tiers || []).forEach(tier => tiers.add(+tier)));
  extra.forEach(tier => tiers.add(+tier));
  return Array.from(tiers).filter(tier => tier >= 60 && tier % 60 === 0).sort((a, b) => a - b);
}}

function renderHostTierOptions(selectedTier=60) {{
  const select = document.getElementById('m-tier');
  const tiers = availableMonitorTiers([selectedTier]);
  select.innerHTML = tiers.map(tier => `<option value="${{tier}}" ${{tier === +selectedTier ? 'selected' : ''}}>${{formatTierLabel(tier)}} (${{tier}}s)</option>`).join('');
}}

function renderRegionTierOptions(selectedTiers=[60, 300]) {{
  const wrap = document.getElementById('r-supported-tiers');
  wrap.innerHTML = availableMonitorTiers(selectedTiers).map(tier => `
    <label class="check-item">
      <input type="checkbox" value="${{tier}}" ${{selectedTiers.includes(tier) ? 'checked' : ''}}>
      <span>${{formatTierLabel(tier)}}</span>
    </label>
  `).join('');
}}

function selectedRegionTiers() {{
  return Array.from(document.querySelectorAll('#r-supported-tiers input[type=checkbox]:checked')).map(el => +el.value).sort((a, b) => a - b);
}}

function renderTargetRegions(selected=[]) {{
  const wrap = document.getElementById('m-target-regions');
  if (!REGIONS_CACHE.length) {{
    wrap.innerHTML = '<div class="hint">No worker regions deployed yet.</div>';
    return;
  }}
  wrap.innerHTML = REGIONS_CACHE.map(r => `
    <label class="check-item">
      <input type="checkbox" value="${{r.region}}" ${{selected.includes(r.region) ? 'checked' : ''}} onchange="updateHostImpact()">
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
  HOSTS_CACHE = Array.isArray(hosts) ? hosts : [];
  const tbody = document.getElementById('hosts-body');
  if (!HOSTS_CACHE.length) {{
    tbody.innerHTML = '<tr><td colspan="9" style="text-align:center;color:#64748b;padding:32px">No hosts yet.</td></tr>';
    return;
  }}
  tbody.innerHTML = HOSTS_CACHE.map(h => `
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
        <button class="btn btn-ghost btn-sm" onclick="openEditHostById('${{h.host_id}}')">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="deleteHost('${{h.host_id}}','${{h.name}}')">Del</button>
      </div></td>
    </tr>`).join('');
}}

function openEditHostById(hostId) {{
  const host = HOSTS_CACHE.find(item => item.host_id === hostId);
  if (!host) {{
    toast('Unable to find that host in the current list.', true);
    return;
  }}
  openEditHost(host);
}}

async function openAddHost() {{
  await ensureRegionsLoaded();
  document.getElementById('host-modal-title').textContent = 'Add Host';
  ['m-id','m-name','m-url','m-sns'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('m-type').value = 'http';
  renderHostTierOptions(60);
  document.getElementById('m-timeout').value = 10;
  document.getElementById('m-code').value = 200;
  document.getElementById('m-page').checked = true;
  document.getElementById('m-alert').checked = false;
  document.getElementById('m-enabled').checked = true;
  document.getElementById('m-sns-group').style.display = 'none';
  renderTargetRegions([]);
  updateHostImpact();
  document.getElementById('host-modal').classList.add('open');
}}

async function openEditHost(h) {{
  await ensureRegionsLoaded();
  document.getElementById('host-modal-title').textContent = 'Edit Host';
  document.getElementById('m-id').value = h.host_id;
  document.getElementById('m-name').value = h.name;
  document.getElementById('m-url').value = h.url;
  document.getElementById('m-type').value = h.check_type || 'http';
  renderHostTierOptions(h.monitor_tier_seconds || h.check_interval_seconds || 60);
  document.getElementById('m-timeout').value = h.timeout_seconds || 10;
  document.getElementById('m-code').value = h.expected_status_code || 200;
  document.getElementById('m-page').checked = !!h.show_on_status_page;
  document.getElementById('m-alert').checked = !!h.alert_enabled;
  document.getElementById('m-sns').value = h.alert_sns_arn || '';
  document.getElementById('m-enabled').checked = h.enabled !== false;
  document.getElementById('m-sns-group').style.display = h.alert_enabled ? '' : 'none';
  renderTargetRegions(h.target_regions || []);
  updateHostImpact();
  document.getElementById('host-modal').classList.add('open');
}}

function toggleSNS() {{
  document.getElementById('m-sns-group').style.display = document.getElementById('m-alert').checked ? '' : 'none';
}}

function updateHostImpact() {{
  const requestedInterval = Math.max(60, +(document.getElementById('m-tier').value || 60));
  const effectiveInterval = 60;
  const selectedRegions = selectedTargetRegions();
  const eligibleRegions = (selectedRegions.length ? REGIONS_CACHE.filter(region => selectedRegions.includes(region.region)) : REGIONS_CACHE)
    .filter(region => (region.supported_tiers || [60,300]).includes(requestedInterval));
  const regionCount = eligibleRegions.length;
  const requestedChecksPerDayPerRegion = Math.round(86400 / requestedInterval);
  const effectiveChecksPerDayPerRegion = Math.round(86400 / effectiveInterval);
  const effectiveChecksPerDayTotal = effectiveChecksPerDayPerRegion * regionCount;
  const targetLabel = regionCount ? (regionCount + ' worker region(s) currently support this tier') : 'no worker regions currently support this tier';
  document.getElementById('m-impact').innerHTML =
    `Chosen tier: <strong>${{formatTierLabel(requestedInterval)}}</strong>, which is about <strong>${{requestedChecksPerDayPerRegion.toLocaleString()}}</strong> checks/day per supporting region.<br>` +
    `Current scheduler heartbeat: every <strong>${{effectiveInterval}}s</strong>. This host is currently eligible for about <strong>${{effectiveChecksPerDayTotal.toLocaleString()}}</strong> checks/day across ${{targetLabel}}.<br>` +
    `Lambda invocations are driven by the shared management + worker schedule. Adding this host mainly increases checks and DynamoDB writes, not one Lambda invoke per check.`;
}}

function closeHostModal() {{ document.getElementById('host-modal').classList.remove('open'); }}

async function saveHost() {{
  const id = document.getElementById('m-id').value;
  const chosenTier = +document.getElementById('m-tier').value;
  const targets = selectedTargetRegions();
  const scopedRegions = targets.length ? REGIONS_CACHE.filter(region => targets.includes(region.region)) : REGIONS_CACHE;
  const unsupportedRegions = scopedRegions.filter(region => !(region.supported_tiers || [60,300]).includes(chosenTier)).map(region => region.region);
  if (!scopedRegions.length) {{
    toast('Deploy at least one worker region before saving a host.', true);
    return;
  }}
  if (!targets.length && !scopedRegions.some(region => (region.supported_tiers || [60,300]).includes(chosenTier))) {{
    toast('No deployed worker region currently supports that monitor tier.', true);
    return;
  }}
  if (targets.length && unsupportedRegions.length) {{
    toast('These selected worker regions do not support that tier: ' + unsupportedRegions.join(', '), true);
    return;
  }}
  const body = {{
    name: document.getElementById('m-name').value,
    url: document.getElementById('m-url').value,
    check_type: document.getElementById('m-type').value,
    monitor_tier_seconds: chosenTier,
    timeout_seconds: +document.getElementById('m-timeout').value,
    expected_status_code: +document.getElementById('m-code').value,
    show_on_status_page: document.getElementById('m-page').checked,
    alert_enabled: document.getElementById('m-alert').checked,
    alert_sns_arn: document.getElementById('m-sns').value,
    enabled: document.getElementById('m-enabled').checked,
    target_regions: targets,
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
        <div class="meta">Memory: ${{r.memory_mb||256}}MB · Tiers: ${{(r.supported_tiers || [60,300]).map(formatTierLabel).join(', ')}} · Deployed: ${{r.deployed_at ? new Date(r.deployed_at).toLocaleDateString() : '—'}}</div>
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
  renderRegionTierOptions([60, 300]);
  document.getElementById('region-modal').classList.add('open');
}}

function closeRegionModal() {{ document.getElementById('region-modal').classList.remove('open'); }}

async function deployRegion() {{
  const btn = document.getElementById('r-deploy-btn');
  const stat = document.getElementById('r-status');
  const body = {{
    region: document.getElementById('r-region').value,
    memory_mb: +document.getElementById('r-memory').value,
    supported_tiers: selectedRegionTiers(),
  }};
  if (!body.supported_tiers.length) {{
    toast('Select at least one monitor tier for this worker.', true);
    return;
  }}
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
  closeRegionModal();
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
  const recordsEl = document.getElementById('cd-records');
  if (!data || data.error) {{
    statusEl.textContent = (data && data.error) || 'Unable to load custom domain status.';
    recordsEl.innerHTML = '';
    return;
  }}
  const lines = [];
  lines.push(`Status: ${{data.status || 'unknown'}}`);
  if (data.domain_name) lines.push(`Domain: ${{data.domain_name}}`);
  if (data.origin_url) lines.push(`Origin: ${{data.origin_url}}`);
  if (data.distribution_domain_name) lines.push(`CloudFront: ${{data.distribution_domain_name}} (${{data.distribution_status || 'unknown'}})`);
  if (data.cloudfront_created_when) lines.push(`CloudFront creation: ${{data.cloudfront_created_when}}`);
  if (data.next_action) lines.push(`Next action: ${{data.next_action}}`);
  if (data.last_error) lines.push(`Last error: ${{data.last_error}}`);
  const createRecords = Array.isArray(data.dns_records_to_create) ? data.dns_records_to_create : [];
  const removeRecords = Array.isArray(data.dns_records_to_remove) ? data.dns_records_to_remove : [];
  if (createRecords.length) {{
    lines.push('');
    lines.push('DNS records to create are listed below in copy boxes.');
  }}
  if (Array.isArray(data.dns_records_to_remove) && data.dns_records_to_remove.length && data.status === 'not_configured') {{
    lines.push('');
    lines.push('Cleanup DNS records are listed below if they still exist.');
    removeRecords.forEach((r, idx) => {{
      lines.push(`${{idx + 1}}. [${{r.purpose}}] ${{r.type}} ${{r.name}} -> ${{r.value}}`);
    }});
  }}
  statusEl.textContent = lines.join('\\n') || 'No custom domain configured.';
  const recordCards = [];
  createRecords.forEach((r, idx) => {{
    const value = `${{r.type}}\\n${{r.name}}\\n${{r.value}}`;
    recordCards.push(`
      <div class="panel" style="margin-top:12px;margin-bottom:0;padding:14px">
        <div style="font-weight:700;margin-bottom:6px">${{idx + 1}}. ${{r.purpose}}</div>
        <div class="hint" style="margin-bottom:8px">${{r.note || ''}}</div>
        <textarea readonly style="min-height:82px">${{value}}</textarea>
        <div style="display:flex;gap:8px;margin-top:8px;flex-wrap:wrap">
          <button class="btn btn-ghost btn-sm" onclick="copyRecord(this, ${{JSON.stringify(value)}})">Copy All</button>
          <button class="btn btn-ghost btn-sm" onclick="copyRecord(this, ${{JSON.stringify(r.name)}})">Copy Name</button>
          <button class="btn btn-ghost btn-sm" onclick="copyRecord(this, ${{JSON.stringify(r.value)}})">Copy Value</button>
        </div>
      </div>
    `);
  }});
  if (data.status === 'not_configured') {{
    removeRecords.forEach((r, idx) => {{
      const value = `${{r.type}}\\n${{r.name}}\\n${{r.value}}`;
      recordCards.push(`
        <div class="panel" style="margin-top:12px;margin-bottom:0;padding:14px">
          <div style="font-weight:700;margin-bottom:6px">Cleanup ${{idx + 1}}. ${{r.purpose}}</div>
          <textarea readonly style="min-height:82px">${{value}}</textarea>
        </div>
      `);
    }});
  }}
  recordsEl.innerHTML = recordCards.join('');
}}

async function copyRecord(btn, text) {{
  try {{
    await navigator.clipboard.writeText(text);
    toast('Copied');
  }} catch (err) {{
    toast('Copy failed', true);
  }}
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

function formatBytes(num) {{
  if (num == null) return '0 B';
  let value = Number(num);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {{
    value /= 1024;
    idx += 1;
  }}
  return value.toFixed(1) + ' ' + units[idx];
}}

function renderManagementSummary(data) {{
  const el = document.getElementById('mgmt-summary');
  if (!data || data.error) {{
    el.innerHTML = `<div style="color:#ef4444">${{(data && data.error) || 'Unable to load management summary.'}}</div>`;
    return;
  }}
  const managementLambda = data.lambdas?.management || {{}};
  const workers = Array.isArray(data.lambdas?.workers) ? data.lambdas.workers : [];
  const workerRows = workers.map(worker => `
    <tr>
      <td>${{worker.region || '—'}}</td>
      <td>${{worker.function_name || '—'}}</td>
      <td>${{worker.memory_mb || '—'}} MB</td>
      <td>${{worker.age_human || '—'}}</td>
      <td>${{worker.last_24h?.invocations ?? '—'}}</td>
      <td>${{worker.last_24h?.avg_duration_ms != null ? worker.last_24h.avg_duration_ms + ' ms' : '—'}}</td>
      <td>${{worker.last_24h?.errors ?? '—'}}</td>
    </tr>`).join('') || `<tr><td colspan="7" style="text-align:center;color:#64748b;padding:16px">No worker regions deployed yet.</td></tr>`;
  const workerInvocations24h = workers.reduce((sum, worker) => sum + (worker.last_24h?.invocations || 0), 0);
  const workerErrors24h = workers.reduce((sum, worker) => sum + (worker.last_24h?.errors || 0), 0);
  document.getElementById('mgmt-retention-days').value = data.retention_days || 90;
  el.innerHTML = `
    <div class="grid2">
      <div>
        <h3 style="margin-top:0">Hosts Table</h3>
        <div class="hint">Name: ${{data.tables.hosts.name}}</div>
        <div class="hint">Items: ${{data.tables.hosts.item_count}}</div>
        <div class="hint">Size: ${{data.tables.hosts.size_human}} (${{data.tables.hosts.size_bytes}} bytes)</div>
        <div class="hint">Status: ${{data.tables.hosts.status}}</div>
      </div>
      <div>
        <h3 style="margin-top:0">Checks Table</h3>
        <div class="hint">Name: ${{data.tables.checks.name}}</div>
        <div class="hint">Items: ${{data.tables.checks.item_count}}</div>
        <div class="hint">Size: ${{data.tables.checks.size_human}} (${{data.tables.checks.size_bytes}} bytes)</div>
        <div class="hint">Status: ${{data.tables.checks.status}}</div>
      </div>
    </div>
    <div class="grid2" style="margin-top:16px">
      <div>
        <h3 style="margin-top:0">Management Lambda</h3>
        <div class="hint">Function: ${{managementLambda.function_name || 'uptime-management'}}</div>
        <div class="hint">Memory: ${{managementLambda.memory_mb || '—'}} MB</div>
        <div class="hint">Age: ${{managementLambda.age_human || '—'}}</div>
        <div class="hint">Invocations (24h): ${{managementLambda.last_24h?.invocations ?? '—'}}</div>
        <div class="hint">Avg runtime (24h): ${{managementLambda.last_24h?.avg_duration_ms != null ? managementLambda.last_24h.avg_duration_ms + ' ms' : '—'}}</div>
      </div>
      <div>
        <h3 style="margin-top:0">Worker Fleet</h3>
        <div class="hint">Deployed regions: ${{data.worker_regions}}</div>
        <div class="hint">Home region: ${{data.home_region}}</div>
        <div class="hint">Worker invocations (24h): ${{workerInvocations24h}}</div>
        <div class="hint">Worker errors (24h): ${{workerErrors24h}}</div>
      </div>
    </div>
    <div style="margin-top:16px">
      <table>
        <thead><tr><th>Region</th><th>Function</th><th>Memory</th><th>Age</th><th>Invocations (24h)</th><th>Avg runtime</th><th>Errors</th></tr></thead>
        <tbody>${{workerRows}}</tbody>
      </table>
    </div>
    <div style="margin-top:16px" class="hint">
      Hosts: ${{data.hosts.total}} total, ${{data.hosts.enabled}} enabled, ${{data.hosts.on_status_page}} on status page, ${{data.hosts.alerts_enabled}} with alerts.
      Worker regions: ${{data.worker_regions}}. Home region: ${{data.home_region}}.
    </div>
  `;
}}

async function loadManagement() {{
  const data = await api('/api/management');
  if (data.unauthorized) {{
    showAuthGate('Enter the admin token to load management data.');
    return;
  }}
  renderManagementSummary(data);
}}

async function saveManagementRetention() {{
  const retention = +document.getElementById('mgmt-retention-days').value;
  const res = await api('/api/management', {{method:'POST', body:JSON.stringify({{action:'set_retention_days', retention_days: retention}})}});
  if (res.error) {{ toast(res.error, true); return; }}
  toast('Retention updated');
  loadManagement();
}}

async function purgeOldChecks() {{
  const olderThanDays = +document.getElementById('mgmt-purge-days').value;
  const maxDelete = +document.getElementById('mgmt-purge-limit').value;
  if (!confirm(`Delete up to ${{maxDelete}} checks older than ${{olderThanDays}} days?`)) return;
  const res = await api('/api/management', {{method:'POST', body:JSON.stringify({{action:'purge_checks', older_than_days: olderThanDays, max_delete: maxDelete}})}});
  if (res.error) {{
    document.getElementById('mgmt-result').textContent = res.error;
    toast(res.error, true);
    return;
  }}
  document.getElementById('mgmt-result').textContent =
    `Deleted: ${{res.deleted}}\\nOlder than days: ${{res.older_than_days}}\\nCutoff: ${{res.cutoff}}\\nHosts scanned: ${{res.scanned_hosts}}`;
  toast('Manual cleanup completed');
  loadManagement();
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
  document.getElementById('c-interval').value = defaults.interval_sec ?? 300;
  document.getElementById('c-days').value = defaults.retention_days ?? 90;
  document.getElementById('c-cloudfront-plan').value = defaults.cloudfront_plan ?? 'payg';
  document.getElementById('c-cognito-mau').value = defaults.cognito_admin_mau ?? 0;
  await calcCost();
}}

async function calcCost() {{
  const customDomainInput = document.getElementById('cd-domain');
  const customDomainEnabled = !!(customDomainInput && customDomainInput.value);
  const cognitoEnabled = !!(document.getElementById('c-cognito-mau').value && +document.getElementById('c-cognito-mau').value > 0);
  const data = await api('/api/cost?hosts='+document.getElementById('c-hosts').value+'&regions='+document.getElementById('c-regions').value+'&interval='+document.getElementById('c-interval').value+'&days='+document.getElementById('c-days').value+'&custom_domain='+(customDomainEnabled ? '1' : '0')+'&cloudfront_plan='+encodeURIComponent(document.getElementById('c-cloudfront-plan').value)+'&cognito_enabled='+(cognitoEnabled ? '1' : '0')+'&cognito_admin_mau='+document.getElementById('c-cognito-mau').value);
  if (data.unauthorized) {{
    showAuthGate('Enter the admin token to calculate costs.');
    return;
  }}
  const b = data.breakdown || {{}};
  const el = document.getElementById('cost-result');
  el.style.display = '';
  document.getElementById('cost-summary').innerHTML =
    `Current scheduler: every <strong>${{data.scheduler?.effective_interval_sec || 60}}s</strong>. ` +
    `Requested interval: every <strong>${{data.scheduler?.requested_interval_sec || 60}}s</strong>. ` +
    `Checks/day per region: <strong>${{(data.checks_per_day_per_region || 0).toLocaleString()}}</strong>. ` +
    `Monthly Lambda invocations: <strong>${{(data.monthly_invocations?.total || 0).toLocaleString()}}</strong> ` +
    `(management ${{(data.monthly_invocations?.management || 0).toLocaleString()}}, workers ${{(data.monthly_invocations?.workers || 0).toLocaleString()}}). ` +
    `Cognito admin MAUs: <strong>${{(data.inputs?.cognito_admin_mau || 0).toLocaleString()}}</strong>.`;
  document.getElementById('cost-rows').innerHTML =
    [['Lambda (workers + orchestrator)', b.lambda_usd], ['DynamoDB writes', b.dynamodb_writes_usd], ['DynamoDB reads', b.dynamodb_reads_usd], ['DynamoDB storage', b.dynamodb_storage_usd], ['CloudFront / custom domain', b.cloudfront_custom_domain_usd], ['Cognito auth', b.cognito_auth_usd], ['CloudWatch Logs', b.cloudwatch_logs_usd], ['Total / month', data.total_usd_per_month]]
    .map(([l,v]) => `<div class="cost-row"><span>${{l}}</span><span>$${{(v||0).toFixed(4)}}</span></div>`)
    .join('') + `<div style="color:#64748b;font-size:.75rem;margin-top:10px">${{data.note||''}}</div>`;
}}

async function boot() {{
  if (!await ensureAuthed()) return;
  document.getElementById('m-tier').addEventListener('change', updateHostImpact);
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
