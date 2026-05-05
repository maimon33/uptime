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
  GET/POST         /api/account
  POST             /api/cognito/login
  POST             /api/cognito/respond
  GET/POST         /api/hosts
  GET/PUT/DELETE   /api/hosts/:id
  GET              /api/hosts/:id/checks
  GET/PUT          /api/settings
  GET              /api/cost
  GET              /api/logs
  GET              /api/regions
  POST             /api/regions            body: {region, memory_mb?}
  POST             /api/regions/:r/update  re-deploy worker code to an existing region
  DELETE           /api/regions/:r
  OPTIONS *        → CORS preflight
"""

import base64
import hashlib
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
from urllib.parse import parse_qs, quote, urlparse

import boto3
from botocore.exceptions import ClientError

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
_logs = {}
_cognito_idp = None

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


def _logs_client(region_name: str):
    client = _logs.get(region_name)
    if client is None:
        client = boto3.client("logs", region_name=region_name)
        _logs[region_name] = client
    return client


def _cognito_idp_client():
    global _cognito_idp
    if _cognito_idp is None:
        _cognito_idp = boto3.client("cognito-idp", region_name=HOME_REGION)
    return _cognito_idp

# ── Config ────────────────────────────────────────────────────────────────────
HOSTS_TABLE     = os.environ["HOSTS_TABLE"]
CHECKS_TABLE    = os.environ["CHECKS_TABLE"]
ADMIN_KEY_PARAM = os.environ.get("ADMIN_KEY_PARAM")
ADMIN_KEY_SECRET = os.environ.get("ADMIN_KEY_SECRET")
HOME_REGION     = os.environ.get("HOME_REGION", os.environ.get("AWS_REGION", "us-east-1"))
RETENTION_DAYS  = int(os.environ.get("RETENTION_DAYS", "90"))
READ_ONLY_MODE  = str(os.environ.get("READ_ONLY_MODE", "")).strip().lower() in {"1", "true", "yes", "on"}
ADMIN_ALLOWED_IP_CIDRS = [cidr.strip() for cidr in os.environ.get("ADMIN_ALLOWED_IP_CIDRS", "").split(",") if cidr.strip()]
ADMIN_AUTH_MODE = (os.environ.get("ADMIN_AUTH_MODE", "password") or "password").strip().lower()
COGNITO_USER_POOL_ID = (os.environ.get("COGNITO_USER_POOL_ID", "") or "").strip()
COGNITO_USER_POOL_CLIENT_ID = (os.environ.get("COGNITO_USER_POOL_CLIENT_ID", "") or "").strip()
COGNITO_USER_POOL_DOMAIN = (os.environ.get("COGNITO_USER_POOL_DOMAIN", "") or "").strip()
COGNITO_ALLOWED_EMAIL_DOMAIN = (os.environ.get("COGNITO_ALLOWED_EMAIL_DOMAIN", "") or "").strip().lower()
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
    "maintenance_starts_at":   "",
    "maintenance_ends_at":     "",
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
PROJECT_GITHUB_URL = os.environ.get("PROJECT_GITHUB_URL", "https://github.com/maimon33/uptime")

_cached_admin_key = None
_build_info_cache = None
_cognito_access_token_cache = {}
AUDIT_RETENTION_DAYS = 30


# ── Entry point ───────────────────────────────────────────────────────────────

def handler(event, context):
    try:
        if _is_scheduled_event(event):
            _log("info", "scheduled_event_received", source=event.get("source"), resources=event.get("resources", []))
            return _run_orchestration()

        if isinstance(event, dict) and event.get("action"):
            _log("info", "direct_management_action_received", action=event.get("action"))
            return _run_management_action(event)

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
            if _is_public_api_path(method, path):
                response = _route_api(method, path, event)
                _log("info", "api_public_request_completed", method=method, path=path, status_code=response.get("statusCode"))
                return response
            authed = _auth(event)
            if not authed:
                _log("warn", "api_request_unauthorized", method=method, path=path)
                return _json(401, {"error": "Unauthorized. Sign in at /admin or send a valid admin token."})
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


def _is_cognito_enabled() -> bool:
    return ADMIN_AUTH_MODE == "cognito" and bool(COGNITO_USER_POOL_ID and COGNITO_USER_POOL_CLIENT_ID)


def _build_info() -> dict:
    global _build_info_cache
    if _build_info_cache is None:
        info = {
            "version": os.environ.get("APP_VERSION", "unknown"),
            "built_at": os.environ.get("APP_BUILT_AT", ""),
            "region": HOME_REGION,
            "function_name": os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "uptime-management"),
            "read_only_mode": _is_read_only(),
            "admin_auth_mode": ADMIN_AUTH_MODE,
            "cognito_enabled": _is_cognito_enabled(),
            "cognito_user_pool_id": COGNITO_USER_POOL_ID,
            "cognito_user_pool_client_id": COGNITO_USER_POOL_CLIENT_ID,
            "cognito_user_pool_domain": COGNITO_USER_POOL_DOMAIN,
            "cognito_allowed_email_domain": COGNITO_ALLOWED_EMAIL_DOMAIN,
        }
        try:
            path = Path(__file__).with_name("_build_info.json")
            if path.exists():
                info.update(json.loads(path.read_text()))
        except Exception as exc:
            _log("warn", "build_info_load_failed", error=str(exc))
        _build_info_cache = info
    return _build_info_cache


def _build_stamp(info: dict | None = None) -> str:
    data = info or _build_info()
    version = (data.get("version") or "unknown").strip() or "unknown"
    built_at = (data.get("built_at") or "").strip()
    region = (data.get("region") or HOME_REGION).strip() or HOME_REGION
    parts = [f"Version {version}", f"Region {region}"]
    if built_at:
        parts.append(f"Built {built_at}")
    return " · ".join(parts)


def _embedded_monitor_source_sha() -> str:
    path = Path(__file__).with_name("_monitor_handler.py")
    return hashlib.sha256(path.read_bytes()).hexdigest()


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
    cloudfront_viewer_address = headers.get("cloudfront-viewer-address") or headers.get("CloudFront-Viewer-Address") or ""
    if cloudfront_viewer_address:
        return cloudfront_viewer_address.split(",")[0].split(":")[0].strip()
    forwarded_for = headers.get("x-forwarded-for") or headers.get("X-Forwarded-For") or ""
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return (((event.get("requestContext") or {}).get("http") or {}).get("sourceIp") or "").strip()


def _request_via_cloudfront(event: dict) -> bool:
    headers = event.get("headers") or {}
    via = str(headers.get("via") or headers.get("Via") or "").lower()
    return bool(
        headers.get("x-amz-cf-id")
        or headers.get("X-Amz-Cf-Id")
        or headers.get("cloudfront-viewer-address")
        or headers.get("CloudFront-Viewer-Address")
        or "cloudfront" in via
    )


def _admin_ip_allowed(event: dict) -> bool:
    if not ADMIN_ALLOWED_IP_CIDRS:
        return True
    if _request_via_cloudfront(event):
        _log("info", "admin_ip_allowlist_skipped_cloudfront", path=(event.get("rawPath") or "/"), client_ip=_client_ip(event))
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


def _extract_bearer_token(event: dict) -> str:
    headers = event.get("headers") or {}
    auth = headers.get("authorization") or headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    qs = event.get("rawQueryString") or ""
    return (parse_qs(qs).get("key", [""])[0] or "").strip()


def _matches_admin_key(token: str) -> bool:
    if not token:
        return False
    try:
        return hmac.compare_digest(token, _get_admin_key().strip())
    except Exception as exc:
        _log("warn", "admin_key_match_failed", error=str(exc))
        return False


def _cache_cognito_identity(token: str, username: str, attrs: dict, ttl_seconds: int = 240) -> None:
    if token:
        _cognito_access_token_cache[token] = {
            "username": username,
            "attributes": attrs,
            "expires_at": time.time() + ttl_seconds,
        }


def _get_cached_cognito_identity(token: str) -> dict | None:
    entry = _cognito_access_token_cache.get(token)
    if not entry:
        return None
    if entry["expires_at"] <= time.time():
        _cognito_access_token_cache.pop(token, None)
        return None
    return entry


def _email_domain_allowed(email: str) -> bool:
    if not COGNITO_ALLOWED_EMAIL_DOMAIN:
        return True
    domain = (email or "").split("@")[-1].strip().lower()
    return bool(domain) and domain == COGNITO_ALLOWED_EMAIL_DOMAIN


def _cognito_identity_from_access_token(token: str, *, use_cache: bool = True) -> tuple[bool, dict]:
    if not token or not _is_cognito_enabled():
        return False, {}
    if use_cache:
        cached = _get_cached_cognito_identity(token)
        if cached:
            return True, cached
    try:
        response = _cognito_idp_client().get_user(AccessToken=token)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_get_user_failed", error_code=code)
        return False, {}
    attrs = {item.get("Name"): item.get("Value", "") for item in response.get("UserAttributes", [])}
    email = attrs.get("email", "")
    if not _email_domain_allowed(email):
        _log("warn", "cognito_email_domain_rejected", email=email, allowed_domain=COGNITO_ALLOWED_EMAIL_DOMAIN)
        return False, {}
    identity = {"username": response.get("Username", ""), "attributes": attrs}
    _cache_cognito_identity(token, identity["username"], identity["attributes"])
    return True, identity


def _auth_context(event: dict) -> dict:
    token = _extract_bearer_token(event)
    if not token:
        return {"ok": False, "mode": "missing", "token": ""}
    admin_ok = _matches_admin_key(token)
    if admin_ok:
        return {"ok": True, "mode": "admin_key", "token": token, "identity": {}}
    if _is_cognito_enabled():
        cognito_ok, identity = _cognito_identity_from_access_token(token)
        if cognito_ok:
            return {"ok": True, "mode": "cognito", "token": token, "identity": identity}
    return {"ok": False, "mode": "unknown", "token": token, "identity": {}}


def _auth(event: dict) -> bool:
    ctx = _auth_context(event)
    if not ctx["ok"]:
        if ctx["mode"] == "missing":
            _log("warn", "auth_missing_token")
        else:
            _log("warn", "auth_checked", ok=False, mode=ctx["mode"], token_length=len(ctx.get("token", "")))
        return False
    _log("info", "auth_checked", ok=True, mode=ctx["mode"], username=(ctx.get("identity") or {}).get("username"), token_length=len(ctx.get("token", "")))
    return True


def _is_public_api_path(method: str, path: str) -> bool:
    return method == "POST" and path in {"/api/cognito/login", "/api/cognito/respond"}


def _cognito_auth_response(payload: dict) -> dict:
    result = payload.get("AuthenticationResult") or {}
    if result.get("AccessToken"):
        token = result["AccessToken"]
        ok, identity = _cognito_identity_from_access_token(token, use_cache=False)
        if not ok:
            return _json(403, {"error": "This Cognito account is not allowed to access the admin UI."})
        return _json(200, {
            "ok": True,
            "mode": "cognito",
            "access_token": token,
            "expires_in": result.get("ExpiresIn", 3600),
            "username": identity.get("username", ""),
        })
    challenge_name = payload.get("ChallengeName", "")
    challenge_parameters = payload.get("ChallengeParameters") or {}
    challenge_map = {
        "SOFTWARE_TOKEN_MFA": "SOFTWARE_TOKEN_MFA",
        "SMS_MFA": "SMS_MFA",
        "NEW_PASSWORD_REQUIRED": "NEW_PASSWORD_REQUIRED",
        "MFA_SETUP": "MFA_SETUP",
    }
    if challenge_name in challenge_map:
        return _json(200, {
            "ok": False,
            "mode": "cognito",
            "challenge": challenge_map[challenge_name],
            "session": payload.get("Session", ""),
            "challenge_parameters": challenge_parameters,
        })
    return _json(400, {"error": f"Unsupported Cognito challenge: {challenge_name or 'unknown'}"})


def _cognito_login(body: dict) -> dict:
    if not _is_cognito_enabled():
        return _json(400, {"error": "Cognito admin authentication is not enabled for this deployment."})
    username = (body.get("username") or body.get("email") or "").strip()
    password = body.get("password") or ""
    if not username or not password:
        return _json(400, {"error": "Email/username and password are required."})
    try:
        response = _cognito_idp_client().initiate_auth(
            ClientId=COGNITO_USER_POOL_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_login_failed", error_code=code, username=username)
        if code in {"NotAuthorizedException", "UserNotFoundException"}:
            return _json(401, {"error": "Invalid Cognito credentials."})
        if code == "PasswordResetRequiredException":
            return _json(401, {"error": "Password reset required for this Cognito user."})
        return _json(400, {"error": f"Cognito login failed: {code}"})
    _log("info", "cognito_login_started", username=username, challenge=response.get("ChallengeName"))
    return _cognito_auth_response(response)


def _cognito_respond(body: dict) -> dict:
    if not _is_cognito_enabled():
        return _json(400, {"error": "Cognito admin authentication is not enabled for this deployment."})
    challenge = (body.get("challenge") or "").strip()
    session = (body.get("session") or "").strip()
    username = (body.get("username") or body.get("email") or "").strip()
    if not challenge or not session or not username:
        return _json(400, {"error": "Challenge, session, and username are required."})
    challenge_responses = {"USERNAME": username}
    if challenge == "SOFTWARE_TOKEN_MFA":
        code = (body.get("code") or body.get("mfa_code") or "").strip()
        if not code:
            return _json(400, {"error": "Enter the authenticator code."})
        challenge_responses["SOFTWARE_TOKEN_MFA_CODE"] = code
    elif challenge == "SMS_MFA":
        code = (body.get("code") or "").strip()
        if not code:
            return _json(400, {"error": "Enter the MFA code."})
        challenge_responses["SMS_MFA_CODE"] = code
    elif challenge == "NEW_PASSWORD_REQUIRED":
        new_password = body.get("new_password") or ""
        if not new_password:
            return _json(400, {"error": "Enter a new password to complete sign-in."})
        challenge_responses["NEW_PASSWORD"] = new_password
    else:
        return _json(400, {"error": f"Unsupported Cognito challenge: {challenge}"})
    try:
        response = _cognito_idp_client().respond_to_auth_challenge(
            ClientId=COGNITO_USER_POOL_CLIENT_ID,
            ChallengeName=challenge,
            Session=session,
            ChallengeResponses=challenge_responses,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_challenge_failed", error_code=code, username=username, challenge=challenge)
        if code == "CodeMismatchException":
            return _json(401, {"error": "That MFA code was not accepted."})
        if code == "ExpiredCodeException":
            return _json(401, {"error": "That MFA code expired. Start sign-in again."})
        if code == "InvalidPasswordException":
            return _json(400, {"error": "The new password does not meet the pool policy."})
        return _json(400, {"error": f"Cognito challenge failed: {code}"})
    _log("info", "cognito_challenge_completed", username=username, challenge=challenge, next_challenge=response.get("ChallengeName"))
    return _cognito_auth_response(response)


def _require_cognito_account_context(event: dict) -> tuple[dict | None, dict | None]:
    if not _is_cognito_enabled():
        return None, _json(400, {"error": "Cognito admin authentication is not enabled for this deployment."})
    ctx = _auth_context(event)
    if not ctx.get("ok"):
        return None, _json(401, {"error": "Sign in to continue."})
    if ctx.get("mode") != "cognito":
        return None, _json(400, {"error": "Account details are available only when you are signed in with Cognito. Sign out and use Cognito instead of the emergency admin token."})
    return ctx, None


def _cognito_user_payload(identity: dict) -> dict:
    attrs = identity.get("attributes") or {}
    return {
        "mode": "cognito",
        "username": identity.get("username", ""),
        "email": attrs.get("email", ""),
        "email_verified": attrs.get("email_verified", "").lower() == "true",
        "phone_number": attrs.get("phone_number", ""),
        "phone_verified": attrs.get("phone_number_verified", "").lower() == "true",
        "preferred_mfa": identity.get("preferred_mfa_setting") or "",
        "mfa_methods": identity.get("user_mfa_settings") or [],
        "allowed_email_domain": COGNITO_ALLOWED_EMAIL_DOMAIN,
    }


def _get_account(event: dict) -> dict:
    if not _is_cognito_enabled():
        return _json(200, {
            "mode": "password",
            "note": "This deployment is using the shared admin token flow, so there is no per-user Cognito account profile to manage here.",
        })
    ctx = _auth_context(event)
    if not ctx.get("ok"):
        return _json(401, {"error": "Sign in to continue."})
    if ctx.get("mode") != "cognito":
        return _json(200, {
            "mode": "admin_key",
            "note": "You are using the emergency admin token. Sign out and sign back in with Cognito to manage your own account profile, password, and MFA.",
        })
    ok, identity = _cognito_identity_from_access_token(ctx["token"], use_cache=False)
    if not ok:
        return _json(401, {"error": "Your Cognito session expired. Sign in again."})
    identity["preferred_mfa_setting"] = identity["attributes"].get("preferredMfaSetting", identity.get("preferred_mfa_setting", ""))
    try:
        user_response = _cognito_idp_client().get_user(AccessToken=ctx["token"])
        identity["preferred_mfa_setting"] = user_response.get("PreferredMfaSetting", "")
        identity["user_mfa_settings"] = user_response.get("UserMFASettingList", [])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_account_get_user_failed", error_code=code)
        identity["preferred_mfa_setting"] = ""
        identity["user_mfa_settings"] = []
    return _json(200, _cognito_user_payload(identity))


def _run_account_action(body: dict, event: dict) -> dict:
    action = (body.get("action") or "").strip()
    if action == "update_profile":
        return _account_update_profile(body, event)
    if action == "change_password":
        return _account_change_password(body, event)
    if action == "begin_totp":
        return _account_begin_totp(event)
    if action == "verify_totp":
        return _account_verify_totp(body, event)
    if action == "disable_totp":
        return _account_disable_totp(event)
    return _json(400, {"error": "Unknown account action."})


def _account_update_profile(body: dict, event: dict) -> dict:
    ctx, error = _require_cognito_account_context(event)
    if error:
        return error
    email = (body.get("email") or "").strip()
    phone = (body.get("phone_number") or "").strip()
    attrs = []
    if email:
        if not _email_domain_allowed(email):
            return _json(400, {"error": f"Email must match @{COGNITO_ALLOWED_EMAIL_DOMAIN}."})
        attrs.append({"Name": "email", "Value": email})
    if phone:
        attrs.append({"Name": "phone_number", "Value": phone})
    try:
        if attrs:
            _cognito_idp_client().update_user_attributes(AccessToken=ctx["token"], UserAttributes=attrs)
        delete_attrs = []
        if phone == "":
            delete_attrs.append("phone_number")
            delete_attrs.append("phone_number_verified")
        if delete_attrs:
            _cognito_idp_client().delete_user_attributes(AccessToken=ctx["token"], UserAttributeNames=delete_attrs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_account_update_profile_failed", error_code=code)
        return _json(400, {"error": f"Profile update failed: {code}"})
    _cognito_access_token_cache.pop(ctx["token"], None)
    return _get_account(event)


def _account_change_password(body: dict, event: dict) -> dict:
    ctx, error = _require_cognito_account_context(event)
    if error:
        return error
    current_password = body.get("current_password") or ""
    new_password = body.get("new_password") or ""
    if not current_password or not new_password:
        return _json(400, {"error": "Current password and new password are required."})
    try:
        _cognito_idp_client().change_password(
            AccessToken=ctx["token"],
            PreviousPassword=current_password,
            ProposedPassword=new_password,
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_account_change_password_failed", error_code=code)
        if code == "NotAuthorizedException":
            return _json(401, {"error": "Current password was not accepted."})
        if code == "InvalidPasswordException":
            return _json(400, {"error": "The new password does not meet the Cognito password policy."})
        return _json(400, {"error": f"Password change failed: {code}"})
    return _json(200, {"ok": True, "message": "Password updated."})


def _account_begin_totp(event: dict) -> dict:
    ctx, error = _require_cognito_account_context(event)
    if error:
        return error
    identity = ctx.get("identity") or {}
    issuer = (_SETTINGS_DEFAULTS.get("status_page_brand_name") or "Uptime").strip() or "Uptime"
    label = identity.get("attributes", {}).get("email") or identity.get("username", "admin")
    try:
        response = _cognito_idp_client().associate_software_token(AccessToken=ctx["token"])
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_account_begin_totp_failed", error_code=code)
        return _json(400, {"error": f"Unable to start authenticator setup: {code}"})
    secret_code = response.get("SecretCode", "")
    otpauth_uri = f"otpauth://totp/{quote(issuer)}:{quote(label)}?secret={secret_code}&issuer={quote(issuer)}"
    return _json(200, {
        "ok": True,
        "secret_code": secret_code,
        "otpauth_uri": otpauth_uri,
        "label": label,
        "issuer": issuer,
    })


def _account_verify_totp(body: dict, event: dict) -> dict:
    ctx, error = _require_cognito_account_context(event)
    if error:
        return error
    code = (body.get("code") or "").strip()
    preferred = bool(body.get("preferred", True))
    if not code:
        return _json(400, {"error": "Enter the 6-digit authenticator code."})
    try:
        verify = _cognito_idp_client().verify_software_token(
            AccessToken=ctx["token"],
            UserCode=code,
            FriendlyDeviceName=(body.get("device_name") or "Authenticator").strip() or "Authenticator",
        )
        if verify.get("Status") != "SUCCESS":
            return _json(400, {"error": "Authenticator verification was not accepted."})
        _cognito_idp_client().set_user_mfa_preference(
            AccessToken=ctx["token"],
            SoftwareTokenMfaSettings={"Enabled": True, "PreferredMfa": preferred},
        )
    except ClientError as exc:
        code_name = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_account_verify_totp_failed", error_code=code_name)
        if code_name in {"CodeMismatchException", "EnableSoftwareTokenMFAException"}:
            return _json(400, {"error": "That authenticator code was not accepted. Double-check the secret and current 6-digit code."})
        return _json(400, {"error": f"Authenticator setup failed: {code_name}"})
    return _get_account(event)


def _account_disable_totp(event: dict) -> dict:
    ctx, error = _require_cognito_account_context(event)
    if error:
        return error
    try:
        _cognito_idp_client().set_user_mfa_preference(
            AccessToken=ctx["token"],
            SoftwareTokenMfaSettings={"Enabled": False, "PreferredMfa": False},
        )
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "ClientError")
        _log("warn", "cognito_account_disable_totp_failed", error_code=code)
        return _json(400, {"error": f"Unable to disable authenticator MFA: {code}"})
    return _get_account(event)


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
            return _json(200, {"ok": True, "mode": "cognito" if _is_cognito_enabled() else "password"})

    if resource == "account":
        if method == "GET":
            return _get_account(event)
        if method == "POST":
            return _run_account_action(body, event)

    if resource == "cognito":
        if method == "POST" and rid == "login":
            return _cognito_login(body)
        if method == "POST" and rid == "respond":
            return _cognito_respond(body)

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

    if resource == "logs":
        if method == "GET":
            return _get_logs(qs)

    if resource == "dynamodb":
        if method == "GET":
            return _get_dynamodb_data(qs)

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
        "public_link_enabled":    bool(body.get("public_link_enabled", False)),
        "public_link_url":        body.get("public_link_url", "") or None,
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
        "public_link_enabled", "public_link_url", "expected_status_code", "tags", "target_regions",
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
        "maintenance_scope", "maintenance_starts_at", "maintenance_ends_at",
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


def _audit_event(event_type: str, *, status: str = "ok", actor: str = "system", **fields) -> None:
    now = datetime.now(timezone.utc)
    item = {
        "host_id": f"__audit__{now.strftime('%Y%m%dT%H%M%S%fZ')}#{uuid.uuid4().hex[:8]}",
        "event_type": event_type,
        "status": status,
        "actor": actor,
        "created_at": now.isoformat(),
        "ttl": int((now + timedelta(days=AUDIT_RETENTION_DAYS)).timestamp()),
    }
    item.update({k: v for k, v in fields.items() if v not in (None, "")})
    try:
        _db().Table(HOSTS_TABLE).put_item(Item=item)
    except Exception as exc:
        _log("warn", "audit_event_write_failed", event_type=event_type, error=str(exc))


def _list_audit_events(limit: int = 50) -> list[dict]:
    result = _db().Table(HOSTS_TABLE).scan(
        FilterExpression="begins_with(host_id, :p)",
        ExpressionAttributeValues={":p": "__audit__"},
    )
    rows = [dict(item) for item in result.get("Items", [])]
    rows.sort(key=lambda row: row.get("created_at", ""), reverse=True)
    for row in rows:
        row.pop("host_id", None)
    return rows[:limit]


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
        _audit_event(
            "worker_add",
            actor="admin",
            region=region,
            memory_mb=memory_mb,
            supported_tiers=supported_tiers,
            monitor_build_version=info.get("monitor_build_version", ""),
        )
        return _json(200, info)
    except Exception as e:
        _audit_event("worker_add", status="error", actor="admin", region=region, error=str(e))
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
        _audit_event(
            "worker_update",
            actor="admin",
            region=region,
            memory_mb=memory_mb,
            supported_tiers=supported_tiers,
            monitor_build_version=info.get("monitor_build_version", ""),
        )
        return _json(200, info)
    except Exception as e:
        _audit_event("worker_update", status="error", actor="admin", region=region, error=str(e))
        return _json(500, {"error": str(e)})

def _remove_region(region: str) -> dict:
    try:
        reg.teardown_region(region)
        reg.delete_region_record(_db(), region)
        # If no regions remain, remove the shared IAM role too
        remaining = reg.list_regions(_db())
        if not remaining:
            reg.delete_monitor_role()
        _audit_event("worker_delete", actor="admin", region=region, remaining_regions=len(remaining))
        return _json(200, {"removed": region})
    except Exception as e:
        _audit_event("worker_delete", status="error", actor="admin", region=region, error=str(e))
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
        "build": _build_info(),
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
    _audit_event("management_action_requested", actor="admin", action=action)
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
    if action == "force_update_probes":
        return _force_update_probes()
    return _json(400, {"error": "Unknown management action"})


def _force_update_probes() -> dict:
    region_records = reg.list_regions(_db())
    if not region_records:
        return _json(200, {"ok": True, "updated": 0, "regions": []})

    updated = []
    failed = []
    for region_info in region_records:
        region_name = region_info.get("region", "")
        memory_mb = int(region_info.get("memory_mb", 256) or 256)
        supported_tiers = _normalize_monitor_tiers(region_info.get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS)
        try:
            info = reg.deploy_region(region_name, memory_mb, supported_tiers)
            reg.save_region_record(_db(), info)
            _audit_event(
                "worker_force_update",
                actor="system",
                region=region_name,
                memory_mb=memory_mb,
                supported_tiers=supported_tiers,
                monitor_build_version=info.get("monitor_build_version", ""),
            )
            updated.append({
                "region": region_name,
                "monitor_build_version": info.get("monitor_build_version", ""),
                "monitor_source_sha": info.get("monitor_source_sha", ""),
                "deployed_at": info.get("deployed_at", ""),
            })
        except Exception as exc:
            _audit_event("worker_force_update", status="error", actor="system", region=region_name, error=str(exc))
            failed.append({"region": region_name, "error": str(exc)})

    status = 200 if not failed else 500
    return _json(status, {
        "ok": not failed,
        "updated": len(updated),
        "failed": failed,
        "regions": updated,
        "expected_worker_build": _build_info().get("version", "unknown"),
        "expected_worker_source_sha": _embedded_monitor_source_sha(),
    })


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
    summary = _lambda_metrics_snapshot(
        function_name=function_name,
        region_name=HOME_REGION,
        deployed_at=config.get("LastModified"),
        memory_mb=int(config.get("MemorySize", 0) or 0),
        runtime=config.get("Runtime"),
    )
    summary["version"] = _build_info().get("version", "unknown")
    summary["expected_monitor_source_sha"] = _embedded_monitor_source_sha()
    return summary


def _worker_lambda_summary(region_info: dict) -> dict:
    function_name = region_info.get("function_name", f"{os.environ.get('PROJECT', 'uptime')}-monitor-{region_info.get('region')}")
    region_name = region_info.get("region", HOME_REGION)
    deployed_at = region_info.get("deployed_at")
    memory_mb = int(region_info.get("memory_mb", 0) or 0)
    runtime = "python3.12"
    summary = _lambda_metrics_snapshot(
        function_name=function_name,
        region_name=region_name,
        deployed_at=deployed_at,
        memory_mb=memory_mb,
        runtime=runtime,
    )
    expected_sha = _embedded_monitor_source_sha()
    expected_version = _build_info().get("version", "unknown")
    summary["expected_monitor_source_sha"] = expected_sha
    summary["expected_monitor_build_version"] = expected_version
    summary["recorded_monitor_source_sha"] = region_info.get("monitor_source_sha", "")
    summary["recorded_monitor_build_version"] = region_info.get("monitor_build_version", "")
    summary["recorded_lambda_last_modified"] = region_info.get("lambda_last_modified", "")
    try:
        config = _lambda_client(region_name).get_function_configuration(FunctionName=function_name)
        env = (config.get("Environment") or {}).get("Variables", {})
        running_sha = env.get("MONITOR_SOURCE_SHA", "")
        running_version = env.get("MONITOR_BUILD_VERSION", "")
        summary["running_monitor_source_sha"] = running_sha
        summary["running_monitor_build_version"] = running_version
        summary["lambda_last_modified"] = config.get("LastModified")
        summary["lambda_revision_id"] = config.get("RevisionId")
        summary["runtime"] = config.get("Runtime") or runtime
        summary["memory_mb"] = int(config.get("MemorySize", memory_mb) or 0)
        summary["version_status"] = "match" if running_sha == expected_sha and running_version == expected_version else "mismatch"
    except Exception as exc:
        summary["error"] = str(exc)
        summary["version_status"] = "unknown"
    return summary


def _safe_int(value, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _iso_from_epoch_ms(value: int | None) -> str:
    if value in (None, ""):
        return ""
    return datetime.fromtimestamp(value / 1000, tz=timezone.utc).isoformat()


def _infer_log_level(message: str, parsed: dict | None = None) -> str:
    if parsed and parsed.get("level"):
        return str(parsed.get("level")).strip().lower()
    text = (message or "").lower()
    if any(token in text for token in ["exception", "traceback", "error", "failed"]):
        return "error"
    if any(token in text for token in ["warn", "forbidden", "unauthorized", "throttle"]):
        return "warn"
    return "info"


def _classify_log_issue(level: str, event_name: str, raw_message: str, parsed: dict | None = None) -> tuple[str, str]:
    text = f"{event_name} {raw_message}".lower()
    if event_name == "handler_exception" or "traceback" in text:
        return "error", "Unhandled exception"
    if "worker invoke failed" in text or event_name == "worker_invoke_failed":
        return "error", "Probe invoke failed"
    if "unauthorized" in text or "forbidden" in text or event_name in {"api_request_unauthorized", "admin_ip_blocked", "api_ip_blocked"}:
        return "warn", "Access rejected"
    if "timeout" in text:
        return "error", "Timeout"
    if "route_not_found" in text:
        return "warn", "Unknown route"
    if event_name in {"orchestration_started", "orchestration_completed", "scheduled_event_received"}:
        return "info", "Orchestration event"
    if event_name in {"purge_checks_started", "purge_checks_completed"}:
        return "info", "Maintenance action"
    if level == "error":
        return "error", "Error event"
    if level == "warn":
        return "warn", "Warning"
    return "info", "Informational"


def _normalize_log_entry(event: dict) -> dict:
    raw_message = (event.get("message") or "").rstrip()
    parsed = None
    try:
        parsed = json.loads(raw_message)
    except Exception:
        parsed = None
    event_name = str((parsed or {}).get("message") or "").strip()
    level = _infer_log_level(raw_message, parsed)
    severity, issue = _classify_log_issue(level, event_name, raw_message, parsed)
    details = {}
    if isinstance(parsed, dict):
        details = {k: v for k, v in parsed.items() if k not in {"level", "message", "time"}}
    summary = event_name or (raw_message.splitlines()[0][:220] if raw_message else "Log event")
    return {
        "timestamp": _safe_int(event.get("timestamp"), 0),
        "time": _iso_from_epoch_ms(event.get("timestamp")),
        "ingestion_time": _iso_from_epoch_ms(event.get("ingestionTime")),
        "level": level,
        "severity": severity,
        "issue": issue,
        "summary": summary,
        "event_name": event_name,
        "details": details,
        "raw_message": raw_message,
    }


def _log_group_for_scope(scope: str, region_name: str) -> tuple[str, str]:
    if scope == "worker":
        function_name = f"{os.environ.get('PROJECT', 'uptime')}-monitor-{region_name}"
        return function_name, f"/aws/lambda/{function_name}"
    function_name = os.environ.get("AWS_LAMBDA_FUNCTION_NAME", "uptime-management")
    return function_name, f"/aws/lambda/{function_name}"


def _get_logs(qs: dict) -> dict:
    scope = (qs.get("scope", ["management"])[0] or "management").strip().lower()
    requested_region = (qs.get("region", [""])[0] or "").strip()
    limit = max(20, min(200, _safe_int(qs.get("limit", ["80"])[0], 80)))
    lookback_hours = max(1, min(168, _safe_int(qs.get("hours", ["24"])[0], 24)))

    if scope not in {"management", "worker"}:
        return _json(400, {"error": "scope must be management or worker"})

    regions = reg.list_regions(_db())
    available_regions = [item.get("region", "") for item in regions if item.get("region")]
    if scope == "worker":
        if not available_regions:
            return _json(200, {
                "scope": scope,
                "region": "",
                "available_regions": [],
                "entries": [],
                "issues": [],
                "summary": {"error": 0, "warn": 0, "info": 0},
                "message": "No worker regions are deployed yet.",
            })
        region_name = requested_region or available_regions[0]
        if region_name not in available_regions:
            return _json(400, {"error": "Unknown worker region", "available_regions": available_regions})
    else:
        region_name = HOME_REGION

    function_name, log_group_name = _log_group_for_scope(scope, region_name)
    start_time_ms = int((datetime.now(timezone.utc) - timedelta(hours=lookback_hours)).timestamp() * 1000)
    try:
        client = _logs_client(region_name)
        events = []
        next_token = None
        seen_tokens = set()
        page_count = 0
        while page_count < 12:
            kwargs = {
                "logGroupName": log_group_name,
                "startTime": start_time_ms,
                "limit": min(100, limit),
                "interleaved": True,
            }
            if next_token:
                kwargs["nextToken"] = next_token
            response = client.filter_log_events(**kwargs)
            events.extend(response.get("events", []))
            if len(events) > limit * 3:
                events = events[-(limit * 3):]
            page_count += 1
            next_token = response.get("nextToken")
            if not next_token or next_token in seen_tokens:
                break
            seen_tokens.add(next_token)
    except ClientError as exc:
        error_code = ((exc.response or {}).get("Error") or {}).get("Code", "ClientError")
        return _json(200, {
            "scope": scope,
            "region": region_name,
            "function_name": function_name,
            "log_group_name": log_group_name,
            "available_regions": available_regions,
            "entries": [],
            "issues": [],
            "summary": {"error": 0, "warn": 0, "info": 0},
            "message": f"Unable to read logs: {error_code}",
        })

    raw_events = sorted(events, key=lambda item: item.get("timestamp", 0), reverse=True)[:limit]
    entries = [_normalize_log_entry(item) for item in raw_events]
    summary = {"error": 0, "warn": 0, "info": 0}
    for entry in entries:
        summary[entry["severity"]] = summary.get(entry["severity"], 0) + 1
    issues = [entry for entry in entries if entry["severity"] in {"error", "warn"}][:12]
    return _json(200, {
        "scope": scope,
        "region": region_name,
        "function_name": function_name,
        "log_group_name": log_group_name,
        "lookback_hours": lookback_hours,
        "limit": limit,
        "available_regions": available_regions,
        "summary": summary,
        "issues": issues,
        "entries": entries,
    })


def _get_dynamodb_data(qs: dict) -> dict:
    from boto3.dynamodb.conditions import Key as DKey

    db = _db()
    view = (qs.get("view", ["overview"])[0] or "overview").strip().lower()
    host_filter = (qs.get("host_id", [""])[0] or "").strip()
    region_filter = (qs.get("region", ["all"])[0] or "all").strip()
    checks_limit = max(10, min(100, _safe_int(qs.get("checks_limit", ["50"])[0], 50)))

    hosts_rows = sorted(_list_host_items(), key=lambda item: item.get("name", ""))
    settings_item = _load_settings_item()
    settings_item.pop("host_id", None)
    region_rows = reg.list_regions(db)

    selected_host = host_filter or (hosts_rows[0]["host_id"] if hosts_rows else "")
    checks_rows = []
    if selected_host:
        checks_rows = db.Table(CHECKS_TABLE).query(
            KeyConditionExpression=DKey("host_id").eq(selected_host),
            ScanIndexForward=False,
            Limit=checks_limit,
        ).get("Items", [])
    if region_filter != "all":
        checks_rows = [item for item in checks_rows if str(item.get("region", "")) == region_filter]

    audit_rows = _list_audit_events(limit=checks_limit)
    if region_filter != "all":
        audit_rows = [item for item in audit_rows if str(item.get("region", "")) == region_filter]

    def compact_host(item: dict) -> dict:
        return {
            "host_id": item.get("host_id", ""),
            "name": item.get("name", ""),
            "enabled": bool(item.get("enabled", False)),
            "url": item.get("url", ""),
            "monitor_tier_seconds": int(item.get("monitor_tier_seconds", item.get("check_interval_seconds", 60)) or 60),
            "target_regions": item.get("target_regions") or [],
            "current_status": item.get("current_status", "unknown"),
            "last_checked_at": item.get("last_checked_at", ""),
        }

    def compact_check(item: dict) -> dict:
        return {
            "checked_at": item.get("checked_at", ""),
            "run_id": item.get("run_id", ""),
            "region": item.get("region", ""),
            "status": item.get("status", "unknown"),
            "latency_ms": item.get("latency_ms"),
            "status_code": item.get("status_code"),
            "error": item.get("error", ""),
        }

    settings_preview = {
        "status_page_title": settings_item.get("status_page_title", _SETTINGS_DEFAULTS["status_page_title"]),
        "brand_name": settings_item.get("status_page_brand_name", _SETTINGS_DEFAULTS["status_page_brand_name"]),
        "custom_domain_name": settings_item.get("custom_domain_name", ""),
        "retention_days": settings_item.get("retention_days", RETENTION_DAYS),
        "default_check_interval": settings_item.get("default_check_interval", 60),
    }

    return _json(200, {
        "view": view,
        "hosts_table": {
            "name": HOSTS_TABLE,
            "hosts": [compact_host(item) for item in hosts_rows],
            "settings": settings_preview,
            "regions": [
                {
                    "region": row.get("region", ""),
                    "memory_mb": row.get("memory_mb"),
                    "supported_tiers": row.get("supported_tiers") or [],
                    "status": row.get("status", "unknown"),
                    "deployed_at": row.get("deployed_at", ""),
                }
                for row in region_rows
            ],
        },
        "checks_table": {
            "name": CHECKS_TABLE,
            "selected_host_id": selected_host,
            "selected_host_name": next((item.get("name", "") for item in hosts_rows if item.get("host_id") == selected_host), ""),
            "rows": [compact_check(item) for item in checks_rows],
            "limit": checks_limit,
        },
        "audit": {
            "rows": audit_rows,
            "limit": checks_limit,
        },
    })


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


def _parse_iso_datetime(value: str) -> datetime | None:
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _maintenance_state(settings: dict) -> dict:
    now = datetime.now(timezone.utc)
    enabled = bool(settings.get("maintenance_enabled"))
    message = (settings.get("maintenance_message") or "").strip()
    window = (settings.get("maintenance_window") or "").strip()
    scope = (settings.get("maintenance_scope") or "").strip()
    starts_at = _parse_iso_datetime(settings.get("maintenance_starts_at", ""))
    ends_at = _parse_iso_datetime(settings.get("maintenance_ends_at", ""))

    if ends_at and starts_at and ends_at < starts_at:
        ends_at = None

    if enabled and message:
        if ends_at and now > ends_at:
            state = "expired"
        elif starts_at and now < starts_at:
            state = "scheduled"
        elif starts_at or ends_at:
            state = "live"
        else:
            state = "enabled"
    elif message or window or scope or starts_at or ends_at:
        state = "draft"
    else:
        state = "off"

    if window:
        display_window = window
    elif starts_at and ends_at:
        display_window = f"{starts_at.strftime('%Y-%m-%d %H:%M UTC')} - {ends_at.strftime('%Y-%m-%d %H:%M UTC')}"
    elif starts_at:
        display_window = f"Starts {starts_at.strftime('%Y-%m-%d %H:%M UTC')}"
    elif ends_at:
        display_window = f"Ends {ends_at.strftime('%Y-%m-%d %H:%M UTC')}"
    else:
        display_window = ""

    return {
        "state": state,
        "public_visible": state in {"scheduled", "live", "enabled"},
        "title": "Maintenance in progress" if state == "live" else "Scheduled maintenance",
        "message": message,
        "window": display_window,
        "scope": scope,
        "starts_at": starts_at.isoformat() if starts_at else "",
        "ends_at": ends_at.isoformat() if ends_at else "",
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
    maintenance = _maintenance_state(settings)

    host_data = _build_public_host_data(db, _list_public_hosts(), history_limit=300)
    incident_summary = _build_public_incident_summary(host_data)
    return _html(
        200,
        _render_status_page(
            title,
            desc,
            brand_name,
            logo_url,
            theme,
            host_data,
            incident_summary,
            {
                "subscribe_intro": subscribe_intro,
                "subscribe_email_url": subscribe_email_url,
                "subscribe_sms_url": subscribe_sms_url,
                "subscribe_webhook_url": subscribe_webhook_url,
                "maintenance": maintenance,
            },
        ),
    )


def _build_public_incident_summary(host_data: list[dict]) -> dict:
    events = []
    seen = set()
    for host_entry in host_data:
        host_meta = host_entry.get("host", {})
        host_id = host_meta.get("host_id") or ""
        host_name = host_meta.get("name") or host_id or "Host"
        for point in host_entry.get("history_points", []):
            status = point.get("status", "unknown")
            if status not in {"down", "degraded"}:
                continue
            run_id = point.get("run_id") or point.get("checked_at") or ""
            dedupe_key = (host_id or host_name, run_id, status)
            if dedupe_key in seen:
                continue
            seen.add(dedupe_key)
            checked_at = point.get("checked_at") or run_id
            checked_dt = _parse_aws_timestamp(checked_at) or _parse_aws_timestamp(run_id)
            events.append({
                "host_id": host_id,
                "host_name": host_name,
                "status": status,
                "checked_at": checked_at,
                "sort_key": checked_dt.isoformat() if checked_dt else checked_at,
            })

    events.sort(key=lambda item: item.get("sort_key", ""), reverse=True)
    latest = events[0] if events else None
    return {
        "count": len(events),
        "latest": latest,
        "history_href": "/history",
    }


def _format_relative_age(iso_value: str) -> str:
    if not iso_value:
        return "unknown"
    dt = _parse_aws_timestamp(iso_value)
    if not dt:
        return iso_value.replace("T", " ")[:16]
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = datetime.now(timezone.utc) - dt.astimezone(timezone.utc)
    seconds = max(int(delta.total_seconds()), 0)
    if seconds < 60:
        return f"{seconds}s ago"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 24:
        return f"{hours}h ago"
    days = hours // 24
    return f"{days}d ago"


def _format_percent(value) -> str:
    if value is None:
        return "—"
    pct = float(value)
    if pct.is_integer():
        return f"{int(pct)}%"
    return f"{pct:.1f}%"


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
            uptime_pct, avg_latency = None, 0

        region_summary = []
        for region_name, region_info in sorted((host.get("region_statuses") or {}).items()):
            region_summary.append({
                "region": region_name,
                "status": region_info.get("status", "unknown"),
                "latency_ms": region_info.get("latency_ms"),
            })
        incident_points = [point for point in run_points if point.get("status") in {"down", "degraded"}]
        latest_incident = incident_points[0] if incident_points else None
        last_checked_at = host.get("last_checked_at", "")
        current_status = host.get("current_status", "unknown")
        if current_status == "unknown" and run_statuses:
            current_status = run_statuses[0]
        host_data.append({
            "host": host,
            "uptime_pct": uptime_pct,
            "avg_latency": avg_latency,
            "latest_latency": host.get("last_latency_ms"),
            "region_summary": region_summary,
            "target_regions": host.get("target_regions") or [],
            "history": list(reversed(run_statuses)),
            "history_points": list(reversed(run_points)),
            "history_available": bool(run_statuses),
            "current_status": current_status,
            "last_checked_at": last_checked_at,
            "last_checked_label": _format_relative_age(last_checked_at),
            "incident_count": len(incident_points),
            "latest_incident": latest_incident,
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
    build = _build_info()
    hosts = _list_public_hosts()
    query = parse_qs(event.get("rawQueryString") or "")
    selected_host = (query.get("host", ["all"])[0] or "all").strip()
    selected_region = (query.get("region", ["all"])[0] or "all").strip()
    selected_status = (query.get("status", ["all"])[0] or "all").strip()

    history_rows = _collect_public_history_rows(db, hosts)
    regions = sorted({row["region"] for row in history_rows if row.get("region")})
    statuses = sorted({row["status"] for row in history_rows if row.get("status")})

    filtered_rows = history_rows
    if selected_host != "all":
        filtered_rows = [row for row in filtered_rows if row["host_id"] == selected_host]
    if selected_region != "all":
        filtered_rows = [row for row in filtered_rows if row["region"] == selected_region]
    if selected_status != "all":
        filtered_rows = [row for row in filtered_rows if row["status"] == selected_status]

    return _html(
        200,
        _render_history_page(
            title=title,
            brand_name=brand_name,
            logo_url=logo_url,
            theme=theme,
            hosts=hosts,
            regions=regions,
            statuses=statuses,
            selected_host=selected_host,
            selected_region=selected_region,
            selected_status=selected_status,
            rows=filtered_rows[:250],
            build=build,
        ),
    )


def _render_status_page(title: str, desc: str, brand_name: str, logo_url: str, theme: str, host_data: list, incident_summary: dict, page_options: dict) -> str:
    overall, ocls = "All systems operational", "operational"
    for h in host_data:
        if h["current_status"] == "down":
            overall, ocls = "Some systems are experiencing issues", "down"; break
        if h["current_status"] == "degraded":
            overall, ocls = "Some systems are degraded", "degraded"

    theme_class = theme if theme in {"clean", "midnight", "sunrise", "forest"} else "clean"
    maintenance_data = page_options.get("maintenance") or {}
    build_stamp = _build_stamp(page_options.get("build") or {})
    maintenance_block = ""
    if maintenance_data.get("public_visible") and maintenance_data.get("message"):
        window = maintenance_data.get("window", "").strip()
        scope = maintenance_data.get("scope", "").strip()
        maintenance_state = maintenance_data.get("state", "enabled")
        maintenance_meta = []
        if window:
            maintenance_meta.append(f"<span>Window: {window}</span>")
        if scope:
            maintenance_meta.append(f"<span>Affected: {scope}</span>")
        state_badge = "Scheduled" if maintenance_state == "scheduled" else "Live now" if maintenance_state == "live" else "Notice"
        state_class = "pending" if maintenance_state == "scheduled" else "live" if maintenance_state == "live" else "generic"
        fallback_copy = "We will post updates here during the maintenance window." if maintenance_state == "scheduled" else "We are posting updates here while maintenance is in progress."
        maintenance_block = f"""<div class="maintenance {state_class}">
  <div class="maintenance-head">
    <div class="maintenance-title">{maintenance_data.get("title", "Scheduled maintenance")}</div>
    <span class="maintenance-state {state_class}">{state_badge}</span>
  </div>
  <div class="maintenance-copy">{maintenance_data["message"]}</div>
  <div class="maintenance-meta">{' · '.join(maintenance_meta) if maintenance_meta else fallback_copy}</div>
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
    maintenance_summary = "1 scheduled window" if maintenance_data.get("public_visible") and maintenance_data.get("message") else "None"
    maintenance_items = ""
    if maintenance_data.get("public_visible") and maintenance_data.get("message"):
        maintenance_meta = []
        if maintenance_data.get("window"):
            maintenance_meta.append(maintenance_data["window"])
        if maintenance_data.get("scope"):
            maintenance_meta.append(maintenance_data["scope"])
        maintenance_items = f"""<div class="maintenance-list-item">
  <div class="maintenance-list-copy">{maintenance_data["message"]}</div>
  <div class="maintenance-list-meta">{' · '.join(maintenance_meta) if maintenance_meta else 'Scheduled window details will appear here.'}</div>
</div>"""
    else:
        maintenance_items = '<div class="maintenance-list-empty">None</div>'
    maintenance_list_block = f"""<details class="maintenance-list">
  <summary class="section-summary">
    <span class="section-summary-title">Upcoming maintenance</span>
    <span class="section-summary-meta">{maintenance_summary}</span>
  </summary>
  {maintenance_items}
</details>"""

    cards = ""
    for h in host_data:
        s     = h["current_status"]
        badge = {"up": "Operational", "down": "Down", "degraded": "Degraded"}.get(s, "Unknown")
        bars  = "".join(f'<span class="b {c}"></span>' for c in h["history"]) \
                or '<span class="b unknown"></span>' * 10
        summary_bits = []
        if h["uptime_pct"] is not None:
            summary_bits.append(f"{_format_percent(h['uptime_pct'])} uptime")
        if h["avg_latency"]:
            summary_bits.append(f"{h['avg_latency']} ms avg")
        elif h["latest_latency"] is not None:
            summary_bits.append(f"{h['latest_latency']} ms latest")
        target_pills = "".join(
            f'<span class="pill">{region}</span>'
            for region in h["target_regions"]
        )
        region_pills = "".join(
            f'<span class="pill {r["status"]}">{r["region"]} · {r["latency_ms"] if r["latency_ms"] is not None else "—"} ms</span>'
            for r in h["region_summary"]
        )
        public_link = ""
        if h["host"].get("public_link_enabled") and h["host"].get("public_link_url"):
            public_link = f'<div class="svc-actions"><a class="ghost-link svc-history-link" href="{h["host"]["public_link_url"]}" target="_blank" rel="noopener noreferrer">Open service</a></div>'
        history_note = "" if h["history_available"] else ""
        host_history_href = f'/history?host={quote(h["host"]["host_id"])}'
        host_incident_count = int(h.get("incident_count", 0) or 0)
        latest_incident = h.get("latest_incident") or {}
        if host_incident_count:
            incident_label = "incident" if host_incident_count == 1 else "incidents"
            latest_incident_at = (latest_incident.get("checked_at") or "").replace("T", " ")[:16]
            incident_hint = (
                f'<div class="incident-hint">'
                f'<span>{host_incident_count} past {incident_label}'
                f'{f" · latest {latest_incident_at}" if latest_incident_at else ""}</span>'
                f'<a class="ghost-link incident-link" href="{host_history_href}">Full history</a>'
                f'</div>'
            )
        else:
            incident_hint = (
                f'<div class="incident-hint quiet">'
                f'<span>No past incidents recorded</span>'
                f'<a class="ghost-link incident-link" href="{host_history_href}">Full history</a>'
                f'</div>'
            )
        cards += f"""<details class="card svc-card">
  <summary class="svc-summary">
    <div>
      <div class="row" style="margin-bottom:2px"><span class="svc">{h['host']['name']}</span><span class="badge {s}">{badge}</span></div>
      <div class="meta" style="margin-bottom:0">{' &nbsp;·&nbsp; '.join(summary_bits) if summary_bits else 'No recent measurements yet'}</div>
      {incident_hint}
    </div>
    <span class="summary-hint">Details</span>
  </summary>
  <div class="history-title">Recent history</div>
  {history_note}
  <div class="bars">{bars}</div>
  <div class="bar-lbl"><span>90 checks ago</span><span>Latest</span></div>
  <div class="detail-row" style="margin-top:16px">
    <div class="detail-col">
      <div class="history-title">Check locations</div>
      <div class="regions">{target_pills or '<span class="pill unknown">All active check locations</span>'}</div>
    </div>
    <div class="detail-col">
      <div class="history-title">Latest probe results</div>
      <div class="regions">{region_pills or '<span class="pill unknown">No probe results yet</span>'}</div>
    </div>
  </div>
  <div class="meta" style="margin-top:14px">
    Latest latency: {f"{h['latest_latency']} ms" if h["latest_latency"] is not None else "—"} &nbsp;·&nbsp;
    Average latency: {f"{h['avg_latency']} ms" if h["avg_latency"] else "—"}
  </div>
  {public_link}
</details>"""

    if not host_data:
        cards = '<p class="empty">No services configured for the status page yet.</p>'

    history_href = "/history"
    brand = ""
    if brand_name or logo_url:
        logo = f'<img src="{logo_url}" alt="{brand_name}" class="brand-logo">' if logo_url else ""
        brand = f'<div class="brand">{logo}<span>{brand_name or title}</span></div>'
    build_stamp = ""
    return f"""<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="refresh" content="30">
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
.maintenance{{flex-direction:column;background:linear-gradient(135deg, var(--wash), var(--hero));border-color:color-mix(in srgb, var(--ring) 18%, var(--border))}}
.maintenance.pending{{background:linear-gradient(135deg, #fffbeb, var(--hero));border-color:#fcd34d}}
.maintenance.live{{background:linear-gradient(135deg, #fef2f2, var(--hero));border-color:#fca5a5}}
.maintenance-head{{display:flex;justify-content:space-between;align-items:center;gap:12px;width:100%}}
.maintenance-title,.subscribe-title{{font-size:.78rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;margin-bottom:8px;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.maintenance-copy,.subscribe-copy{{font-size:.99rem;line-height:1.6}}
.maintenance-meta{{margin-top:8px;color:var(--muted);font-size:.82rem}}
.maintenance-state{{display:inline-flex;align-items:center;justify-content:center;padding:6px 10px;border-radius:999px;font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.maintenance-state.pending{{background:#fffbeb;color:#b45309;border:1px solid #fcd34d}}
.maintenance-state.live{{background:#fef2f2;color:#b91c1c;border:1px solid #fca5a5}}
.maintenance-state.generic{{background:var(--wash);color:var(--ring);border:1px solid color-mix(in srgb, var(--ring) 20%, var(--border))}}
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
.incident-copy{{font-size:1rem;line-height:1.55;font-weight:600}}
.incident-meta{{margin-top:8px;color:var(--muted);font-size:.84rem;line-height:1.6}}
.incident-actions{{margin-top:14px}}
.incident-link{{padding:9px 13px;font-size:.82rem}}
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
.incident-hint{{margin-top:10px;padding-top:8px;border-top:1px solid rgba(148,163,184,.16);display:flex;justify-content:space-between;align-items:center;gap:12px;font-size:.76rem;color:var(--muted);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.incident-hint.quiet{{opacity:.88}}
.history-title{{font-size:.76rem;color:var(--soft);text-transform:uppercase;letter-spacing:.16em;margin-bottom:8px;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.history-note{{font-size:.78rem;color:var(--muted);margin-bottom:8px}}
.detail-row{{display:grid;grid-template-columns:1fr 1fr;gap:14px;align-items:start}}
.detail-col{{min-width:0}}
.bars{{display:flex;gap:4px;height:28px}}
.b{{flex:1;border-radius:4px;min-width:3px}}
.b.up{{background:#22c55e}}.b.down{{background:#ef4444}}.b.degraded{{background:#f59e0b}}.b.unknown{{background:#e2e8f0}}
.bar-lbl{{display:flex;justify-content:space-between;font-size:.72rem;color:var(--soft);margin-top:6px;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.regions{{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}}
.svc-actions{{margin-top:12px}}
.svc-history-link{{padding:8px 12px;font-size:.78rem}}
.incident-link{{padding:7px 11px;font-size:.72rem;white-space:nowrap}}
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
  .incident-hint{{flex-direction:column;align-items:flex-start}}
  .detail-row{{grid-template-columns:1fr}}
}}
</style></head><body class="theme-{theme_class}">
<div class="wrap">
  {brand}
  <div class="hero">
    <div class="hero-copy"><div><h1>{title}</h1><p class="sub">{desc}</p></div><div class="hero-actions"><a class="ghost-link" href="{history_href}">Explore full history</a></div></div>
    <div class="overall {ocls}"><div class="dot"></div><span>{overall}</span></div>
  </div>
  {maintenance_block}
  {maintenance_list_block}
  <div class="section-heading">Services</div>
  {cards}
  {subscribe_block}
<footer>
  <div>Built for calm operations. Open source on <a class="ghost-link svc-history-link" href="{PROJECT_GITHUB_URL}" target="_blank" rel="noopener noreferrer">GitHub</a>.</div>
</footer>
</div></body></html>"""


def _render_history_page(title: str, brand_name: str, logo_url: str, theme: str, hosts: list[dict], regions: list[str], statuses: list[str], selected_host: str, selected_region: str, selected_status: str, rows: list[dict], build: dict) -> str:
    theme_class = theme if theme in {"clean", "midnight", "sunrise", "forest"} else "clean"
    build_stamp = _build_stamp(build)
    brand = ""
    if brand_name or logo_url:
        logo = f'<img src="{logo_url}" alt="{brand_name}" class="brand-logo">' if logo_url else ""
        brand = f'<div class="brand">{logo}<span>{brand_name or title}</span></div>'

    host_options = ['<option value="all">All hosts</option>'] + [
        f'<option value="{host["host_id"]}"{" selected" if selected_host == host["host_id"] else ""}>{host.get("name", host["host_id"])}</option>'
        for host in hosts
    ]
    region_options = ['<option value="all">All regions</option>'] + [
        f'<option value="{region}"{" selected" if selected_region == region else ""}>{region}</option>'
        for region in regions
    ]
    status_options = ['<option value="all">All statuses</option>'] + [
        f'<option value="{status}"{" selected" if selected_status == status else ""}>{status.title()}</option>'
        for status in statuses
    ]
    row_markup = "".join(
        f"""<tr>
  <td>{row["host_name"]}</td>
  <td><span class="pill {row["status"]}">{row["status"].title()}</span></td>
  <td>{row["latency_ms"] if row["latency_ms"] is not None else "—"} ms</td>
  <td>{row["status_code"] if row.get("status_code") is not None else "—"}</td>
  <td>{row["checked_at"].replace("T", " ")[:19]}</td>
  <td>{(row.get("error") or "—")[:120]}</td>
</tr>"""
        for row in rows
    ) or '<tr><td colspan="6" class="empty-cell">No checks matched the selected filters.</td></tr>'

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
.build-flag{{display:inline-flex;align-items:center;gap:8px;padding:8px 12px;border-radius:999px;border:1px solid var(--hero-border);background:rgba(255,255,255,.58);box-shadow:var(--shadow);font-size:.74rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase;font-family:"IBM Plex Mono","SFMono-Regular",monospace;color:var(--soft);margin-bottom:18px}}
.hero{{display:flex;justify-content:space-between;gap:18px;align-items:flex-end;margin-bottom:20px}}
h1{{font-family:"Space Grotesk","IBM Plex Sans",sans-serif;font-size:clamp(2rem,4vw,3rem);line-height:1.02;font-weight:700;letter-spacing:-.04em;margin-bottom:8px}}
.sub{{color:var(--muted);line-height:1.65;max-width:64ch}}
.hero-actions{{display:flex;gap:10px;flex-wrap:wrap}}
.ghost-link{{display:inline-flex;align-items:center;justify-content:center;padding:11px 14px;border-radius:999px;border:1px solid var(--border);background:rgba(255,255,255,.5);color:var(--text);text-decoration:none;font-weight:700}}
.panel{{background:var(--hero);border:1px solid var(--hero-border);border-radius:14px;padding:18px 18px 16px;box-shadow:var(--shadow);margin-bottom:16px;backdrop-filter:blur(14px)}}
.filters{{display:grid;grid-template-columns:1fr 1fr 1fr auto;gap:12px;align-items:end}}
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
  <div class="build-flag">Running {build_stamp}</div>
  <div class="hero">
    <div>
      <h1>Check History</h1>
      <p class="sub">Browse recent public checks across services. Use filters to narrow the timeline without crowding the main status page.</p>
    </div>
    <div class="hero-actions"><a class="ghost-link" href="/status">Back to status</a></div>
  </div>
  <form class="panel filters" method="GET" action="/history">
    <div>
      <label for="host">Host</label>
      <select id="host" name="host">{''.join(host_options)}</select>
    </div>
    <div>
      <label for="status">Status</label>
      <select id="status" name="status">{''.join(status_options)}</select>
    </div>
    <button class="filter-btn" type="submit">Apply filters</button>
  </form>
  <div class="panel summary">
    <span>Showing <strong>{len(rows)}</strong> recent checks</span>
    <span>Theme: <strong>{theme_class}</strong> · {build_stamp}</span>
  </div>
  <div class="table-wrap">
    <table>
      <thead><tr><th>Host</th><th>Status</th><th>Latency</th><th>HTTP</th><th>Checked</th><th>Detail</th></tr></thead>
      <tbody>{row_markup}</tbody>
    </table>
  </div>
</div></body></html>"""


# ── Admin SPA ─────────────────────────────────────────────────────────────────

def _admin_page() -> str:
    # All AWS regions available for monitor deployment
    build = _build_info()
    cognito_enabled = _is_cognito_enabled()
    auth_config = {
        "mode": "cognito" if cognito_enabled else "password",
        "cognito_enabled": cognito_enabled,
        "cognito_domain": COGNITO_USER_POOL_DOMAIN,
        "allowed_email_domain": COGNITO_ALLOWED_EMAIL_DOMAIN,
    }
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
    if cognito_enabled:
        auth_intro = "Sign in with your Cognito operator account. The access token stays only in this browser session."
        auth_fields = f"""
    <div class="form-group" style="margin-bottom:10px">
      <label>Email / Username</label>
      <input id="auth-username" type="text" autocomplete="username" placeholder="you@{COGNITO_ALLOWED_EMAIL_DOMAIN or 'company.com'}">
    </div>
    <div class="form-group" style="margin-bottom:10px">
      <label>Password</label>
      <input id="auth-password" type="password" autocomplete="current-password" placeholder="Enter your Cognito password">
    </div>
    <div class="form-group" id="auth-new-password-wrap" style="margin-bottom:10px;display:none">
      <label>New Password</label>
      <input id="auth-new-password" type="password" autocomplete="new-password" placeholder="Set a new password">
      <div class="hint">Shown when Cognito requires a first-time password change.</div>
    </div>
    <div class="form-group" id="auth-mfa-wrap" style="margin-bottom:10px;display:none">
      <label>Authenticator Code</label>
      <input id="auth-mfa" type="text" inputmode="numeric" autocomplete="one-time-code" placeholder="123456">
      <div class="hint" id="auth-mfa-hint">Shown when Cognito requests MFA.</div>
    </div>
    <div style="display:flex;gap:10px;flex-wrap:wrap">
      <button class="btn btn-primary" onclick="loginAdmin()">Sign in with Cognito</button>
      <button class="btn btn-ghost" type="button" onclick="toggleTokenLogin()">Use emergency admin token</button>
    </div>
    <div id="auth-token-wrap" style="display:none;margin-top:14px">
      <div class="form-group" style="margin-bottom:10px">
        <label>Emergency Admin Token</label>
        <input id="auth-key" type="password" placeholder="Paste the break-glass admin token">
        <div class="hint">This keeps the legacy admin-key path available while Cognito is being rolled out.</div>
      </div>
      <button class="btn btn-ghost" onclick="loginWithAdminKey()">Unlock with token</button>
    </div>"""
        auth_footer = ""
        if COGNITO_ALLOWED_EMAIL_DOMAIN:
            auth_footer = f'<p style="margin-top:18px">Only <strong>@{COGNITO_ALLOWED_EMAIL_DOMAIN}</strong> accounts are accepted for admin access.</p>'
    else:
        auth_intro = "Enter the admin password/token for this deployment. It stays in this browser session and is sent as a bearer token to the admin API."
        auth_fields = """
    <div class="form-group" style="margin-bottom:10px">
      <label>Admin Password / Token</label>
      <input id="auth-key" type="password" placeholder="Paste the admin key">
    </div>
    <div style="display:flex;gap:10px">
      <button class="btn btn-primary" onclick="loginAdmin()">Unlock Admin</button>
    </div>"""
        auth_footer = f"""<p style="margin-top:18px">If the stack generated the token for you, retrieve it with:</p>
    <pre>aws secretsmanager get-secret-value \\
  --secret-id uptime/admin-key \\
  --query SecretString \\
  --output text \\
  --region {HOME_REGION}</pre>"""

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
.menu-wrap{{position:relative;display:flex;align-items:center;height:64px}}
.menu-btn{{height:40px;padding:0 14px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.02);color:var(--muted);display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-size:.85rem;font-weight:600;transition:color .18s ease,border-color .18s ease,transform .16s ease}}
.menu-btn:hover{{color:#f8fafc;border-color:#4a6288;transform:translateY(-1px)}}
.menu-panel{{position:absolute;top:54px;right:0;min-width:220px;background:linear-gradient(180deg, rgba(23,34,53,.98), rgba(11,18,32,.98));border:1px solid var(--line);border-radius:18px;padding:8px;box-shadow:0 28px 60px rgba(0,0,0,.34);display:none;z-index:60}}
.menu-panel.open{{display:block}}
.menu-item{{display:flex;align-items:center;width:100%;padding:11px 12px;border-radius:12px;background:transparent;border:none;color:var(--text);cursor:pointer;text-align:left;font-size:.85rem;font-weight:600}}
.menu-item:hover{{background:rgba(255,255,255,.05)}}
.menu-item.danger{{color:#fecaca}}
.menu-sep{{height:1px;background:var(--line-soft);margin:6px 0}}
.doc-hero{{display:grid;grid-template-columns:1.3fr .9fr;gap:16px;margin-bottom:18px}}
.doc-card{{background:rgba(23,34,53,.92);border:1px solid var(--line-soft);border-radius:24px;padding:22px;box-shadow:0 24px 60px rgba(2,6,23,.18)}}
.doc-kicker{{font-size:.72rem;color:#7dd3fc;letter-spacing:.16em;text-transform:uppercase;font-weight:700;font-family:"IBM Plex Mono","SFMono-Regular",monospace;margin-bottom:10px}}
.doc-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}}
.doc-list{{display:flex;flex-direction:column;gap:8px;margin-top:10px;color:#d7e4f5}}
.doc-list li{{margin-left:18px;line-height:1.55}}
.doc-mini{{font-size:.8rem;color:var(--soft);line-height:1.6}}
.doc-badges{{display:flex;gap:8px;flex-wrap:wrap;margin-top:12px}}
.doc-badge{{display:inline-flex;align-items:center;padding:6px 10px;border-radius:999px;border:1px solid var(--line);background:#0e1828;color:#c7d2fe;font-size:.74rem;font-weight:700}}
.doc-columns{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-top:12px}}
.doc-subtitle{{font-size:.84rem;font-weight:700;color:#f8fafc;margin-bottom:6px}}
.doc-note{{background:linear-gradient(135deg, rgba(14,165,233,.12), rgba(15,118,110,.08));border:1px solid rgba(14,165,233,.22);padding:14px 16px;border-radius:18px;font-size:.82rem;color:#d2f0ff;line-height:1.6;margin-top:14px}}
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
.log-summary-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}}
.log-summary-card{{background:#0e1828;border:1px solid var(--line);border-radius:18px;padding:14px}}
.log-summary-card .label{{font-size:.74rem;letter-spacing:.12em;text-transform:uppercase;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.log-summary-card .value{{font-size:1.25rem;font-weight:700;margin-top:8px}}
.log-issue-list{{display:flex;flex-direction:column;gap:10px}}
.log-issue{{background:#0e1828;border:1px solid var(--line);border-radius:18px;padding:14px}}
.log-issue-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:6px}}
.log-entry{{background:#0d1624;border:1px solid var(--line-soft);border-radius:18px;padding:14px;margin-bottom:10px}}
.log-entry-head{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:8px}}
.log-entry-meta{{font-size:.76rem;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.log-entry pre{{margin-top:10px;margin-bottom:0;white-space:pre-wrap;word-break:break-word}}
.choice-grid{{display:grid;grid-template-columns:1fr 1fr;gap:12px}}
.choice-card{{display:flex;align-items:flex-start;gap:12px;padding:16px 18px;border-radius:18px;border:1px solid var(--line);background:#0e1828;cursor:pointer;transition:border-color .16s ease,background .16s ease,transform .16s ease,box-shadow .16s ease}}
.choice-card:hover{{border-color:#4a6288;transform:translateY(-1px)}}
.choice-card input{{width:auto;margin-top:3px;accent-color:var(--sky)}}
.choice-card.active{{border-color:rgba(14,165,233,.55);background:linear-gradient(180deg, rgba(14,165,233,.12), rgba(15,118,110,.08));box-shadow:0 18px 36px rgba(2,6,23,.18)}}
.choice-card-title{{font-size:.88rem;font-weight:700;color:#f8fafc;font-family:"Space Grotesk","IBM Plex Sans",sans-serif;letter-spacing:-.01em}}
.choice-card-copy{{font-size:.8rem;color:var(--soft);line-height:1.55;margin-top:4px}}
.probe-scope-panel{{margin-top:12px;padding:14px 16px;border-radius:18px;border:1px solid var(--line);background:#0e1828;transition:border-color .16s ease,background .16s ease,opacity .16s ease}}
.probe-scope-panel.inactive{{opacity:.72}}
.probe-scope-header{{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:10px}}
.probe-scope-title{{font-size:.82rem;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:#cbd5e1;font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.probe-region-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}}
.probe-region-pill{{display:flex;align-items:center;gap:10px;padding:12px 14px;border-radius:16px;border:1px solid var(--line);background:#111c2d;transition:border-color .16s ease,background .16s ease,transform .16s ease}}
.probe-region-pill:hover{{border-color:#44617f;transform:translateY(-1px)}}
.probe-region-pill input{{width:auto;accent-color:var(--sky)}}
.probe-region-pill-name{{font-size:.86rem;font-weight:700;color:#e5eef8}}
.probe-region-pill-meta{{font-size:.74rem;color:var(--soft);margin-top:2px}}
.coverage-grid{{display:flex;flex-direction:column;gap:12px}}
.coverage-card{{background:#0e1828;border:1px solid var(--line);border-radius:18px;padding:14px 16px}}
.coverage-head{{display:flex;justify-content:space-between;align-items:flex-start;gap:12px;margin-bottom:10px}}
.coverage-title{{font-size:.94rem;font-weight:700;color:#f8fafc}}
.coverage-subtitle{{font-size:.78rem;color:var(--soft);margin-top:4px}}
.coverage-pills{{display:flex;flex-wrap:wrap;gap:8px}}
.coverage-pill{{display:inline-flex;align-items:center;gap:6px;padding:7px 10px;border-radius:999px;border:1px solid var(--line);background:#111c2d;font-size:.76rem;color:#dbe7f3}}
.coverage-pill.ok{{border-color:rgba(34,197,94,.35);background:rgba(22,101,52,.18);color:#bbf7d0}}
.coverage-pill.warn{{border-color:rgba(245,158,11,.3);background:rgba(120,53,15,.18);color:#fde68a}}
.coverage-pill.off{{opacity:.68}}
.diag-kv{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px}}
.diag-kv-card{{background:#0e1828;border:1px solid var(--line);border-radius:18px;padding:14px}}
.diag-kv-card .label{{font-size:.74rem;letter-spacing:.12em;text-transform:uppercase;color:var(--soft);font-family:"IBM Plex Mono","SFMono-Regular",monospace}}
.diag-kv-card .value{{margin-top:8px;font-size:.96rem;font-weight:700;color:#f8fafc}}
.diag-stack{{display:flex;flex-direction:column;gap:10px}}
.diag-row{{background:#0e1828;border:1px solid var(--line);border-radius:18px;padding:14px}}
.diag-row-title{{font-size:.88rem;font-weight:700;color:#f8fafc}}
.diag-row-meta{{font-size:.78rem;color:var(--soft);margin-top:5px;line-height:1.5}}
.diag-table{{margin-top:12px}}
.badge.error{{background:#7f1d1d;color:#fecaca}}
.badge.warn{{background:#713f12;color:#fde68a}}
.badge.info{{background:#16314b;color:#93c5fd}}
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
  .doc-hero,.doc-grid,.doc-columns{{grid-template-columns:1fr}}
}}
@media (max-width: 760px) {{
  .grid2{{grid-template-columns:1fr}}
  .choice-grid{{grid-template-columns:1fr}}
  .section-header,.region-card{{flex-direction:column;align-items:flex-start}}
}}
@keyframes spin{{to{{transform:rotate(360deg)}}}}
</style>
</head><body>
<nav>
  <span class="logo"><span class="logo-mark">UP</span><span>Uptime Control</span><span class="logo-version">v{build.get("version", "unknown")}</span></span>
  <span class="tab active" data-tab="hosts" onclick="show('hosts')">Hosts</span>
  <span class="tab" data-tab="regions" onclick="show('regions')">Regions</span>
  <span class="tab" data-tab="status-page" onclick="show('status-page')">Status Page</span>
  <span class="tab" data-tab="notifications" onclick="show('notifications')">Notifications</span>
  <span class="tab" data-tab="management" onclick="show('management')">Management</span>
  <span class="tab" data-tab="diagnostics" onclick="show('diagnostics')">Diagnostics</span>
  <span class="tab" data-tab="cost" onclick="show('cost')">Cost</span>
  <span class="nav-spacer"></span>
  <div class="menu-wrap">
    <button class="menu-btn" id="more-menu-btn" type="button" onclick="toggleMoreMenu()">General ▾</button>
    <div class="menu-panel" id="more-menu">
      <button class="menu-item" type="button" onclick="openMenuTab('account')">Account</button>
      <button class="menu-item" type="button" onclick="openMenuTab('settings')">Settings</button>
      <button class="menu-item" type="button" onclick="openMenuTab('guides')">Docs</button>
      <div class="menu-sep"></div>
      <button class="menu-item danger" type="button" onclick="logoutAdmin()">Sign out</button>
    </div>
  </div>
</nav>
<div class="auth-gate" id="auth-gate">
  <div class="auth-card">
    <h1>Admin access</h1>
    <p><strong>Running { _build_stamp(build) }</strong></p>
    <p>{auth_intro}</p>
    {auth_fields}
    <div class="auth-msg" id="auth-msg"></div>
    {auth_footer}
  </div>
</div>
<div class="main">
{read_only_banner}
<div class="hint" style="margin-bottom:16px">Running { _build_stamp(build) } · Function: <strong>{build.get("function_name", "uptime-management")}</strong></div>

<div id="pane-hosts">
  <div class="section-header">
    <h2>Hosts</h2>
    <button class="btn btn-primary" onclick="openAddHost()">+ Add Host</button>
  </div>
  <table>
    <thead><tr>
      <th>Name</th><th>URL</th><th>Type</th><th>Status</th>
      <th>Uptime</th><th>Latency</th><th>SSL</th><th>Page</th><th>Alert</th><th></th>
    </tr></thead>
    <tbody id="hosts-body">
      <tr><td colspan="10" style="text-align:center;color:#64748b;padding:32px">Loading…</td></tr>
    </tbody>
  </table>
  <div class="panel" style="margin-top:18px">
    <div class="section-header" style="margin-bottom:10px">
      <div>
        <h3 style="margin:0">Probe Routing</h3>
        <div class="hint">See where each host can run right now, and why a probe would skip it.</div>
      </div>
    </div>
    <div id="host-coverage" style="color:#94a3b8">Loading host coverage…</div>
  </div>
</div>

<div id="pane-regions" style="display:none">
  <div class="section-header">
    <h2>Probes</h2>
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
    <h3 style="margin-top:0">Brand & layout</h3>
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
    <div class="tip">
      Themes now change the whole atmosphere, not just the colors:
      <strong>Clean Control</strong> is crisp and editorial, <strong>Midnight Ops</strong> is sharper and denser,
      <strong>Sunrise Briefing</strong> is warmer and softer, and <strong>Forest Calm</strong> is quieter and more grounded.
    </div>
  </div>

  <div class="panel">
    <div class="section-header" style="margin-bottom:12px">
      <div>
        <h3 style="margin:0">Maintenance</h3>
        <div class="hint">Separate, time-bound notice block for scheduled work.</div>
      </div>
      <div id="sp-maintenance-state"></div>
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
        <div class="hint">Optional display label if you want to override the generated UTC range.</div>
      </div>
      <div class="form-group">
        <label>Affected Scope</label>
        <input id="sp-maintenance-scope" placeholder="eu-west-1, us-east-1, Payments API">
      </div>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Start Time</label>
        <input id="sp-maintenance-start" type="datetime-local">
        <div class="hint">Before start: Pending. Inside window: Live. After end: auto-hidden on the public page.</div>
      </div>
      <div class="form-group">
        <label>End Time</label>
        <input id="sp-maintenance-end" type="datetime-local">
        <div class="hint">If end passes, the public notice turns off automatically without deleting the saved draft.</div>
      </div>
    </div>
  </div>

  <div class="panel">
    <h3 style="margin-top:0">Subscribe links</h3>
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
    <pre id="cd-status" style="margin-top:14px">No custom domain configured.</pre>
    <div id="cd-records" style="margin-top:14px"></div>
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

<div id="pane-account" style="display:none">
  <h2>Account</h2>
  <p class="desc">
    Review the current signed-in operator, update contact details, change your password, and manage authenticator MFA.
  </p>
  <div class="panel">
    <div id="account-summary" style="color:#94a3b8">Loading…</div>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Profile</h3>
    <div class="grid2">
      <div class="form-group">
        <label>Email</label>
        <input id="acct-email" type="email" placeholder="you@example.com">
        <div class="hint">If an allowed email domain is configured, the updated email must still match it.</div>
      </div>
      <div class="form-group">
        <label>Phone Number</label>
        <input id="acct-phone" placeholder="+15551234567">
        <div class="hint">Use E.164 format for the best Cognito compatibility. Leave blank to remove the phone number.</div>
      </div>
    </div>
    <button class="btn btn-primary" onclick="saveAccountProfile()">Save Profile</button>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Password</h3>
    <div class="grid2">
      <div class="form-group">
        <label>Current Password</label>
        <input id="acct-current-password" type="password" autocomplete="current-password">
      </div>
      <div class="form-group">
        <label>New Password</label>
        <input id="acct-new-password" type="password" autocomplete="new-password">
        <div class="hint">Cognito currently requires at least 14 characters, plus uppercase, lowercase, number, and symbol.</div>
      </div>
    </div>
    <button class="btn btn-primary" onclick="changeAccountPassword()">Change Password</button>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Authenticator MFA</h3>
    <div id="acct-mfa-summary" class="hint" style="margin-bottom:12px">Loading MFA status…</div>
    <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px">
      <button class="btn btn-primary" onclick="beginTotpSetup()">Set Up Authenticator</button>
      <button class="btn btn-ghost" onclick="disableTotp()">Disable Authenticator</button>
    </div>
    <div id="acct-totp-setup" style="display:none">
      <div class="form-group">
        <label>Authenticator Secret</label>
        <input id="acct-totp-secret" readonly>
      </div>
      <div class="form-group">
        <label>OTPAuth URI</label>
        <textarea id="acct-totp-uri" rows="3" readonly></textarea>
        <div class="hint">Paste the secret into your authenticator app manually, or use the full URI in a QR-code tool if you prefer.</div>
      </div>
      <div class="grid2">
        <div class="form-group">
          <label>Authenticator Code</label>
          <input id="acct-totp-code" inputmode="numeric" autocomplete="one-time-code" placeholder="123456">
        </div>
        <div class="form-group">
          <label>Preferred MFA</label>
          <select id="acct-totp-preferred">
            <option value="true" selected>Yes</option>
            <option value="false">No</option>
          </select>
        </div>
      </div>
      <button class="btn btn-primary" onclick="verifyTotp()">Verify Authenticator</button>
    </div>
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

<div id="pane-diagnostics" style="display:none">
  <h2>Diagnostics</h2>
  <p class="desc">
    Inspect recent runtime signals in two ways: CloudWatch logs for behavior and DynamoDB views for what the system is storing.
  </p>
  <details class="panel" open>
    <summary class="section-summary">
      <span class="section-summary-title">CloudWatch Logs</span>
      <span class="section-summary-meta">Management and worker runtime output</span>
    </summary>
    <h3 style="margin-top:0">CloudWatch Logs</h3>
    <div class="hint" style="margin-bottom:14px">Times are shown in your browser timezone for easier debugging.</div>
    <div class="grid2">
      <div class="form-group">
        <label>Source</label>
        <select id="logs-scope" onchange="handleLogsScopeChange()">
          <option value="management">Management Lambda</option>
          <option value="worker">Probe worker</option>
        </select>
      </div>
      <div class="form-group">
        <label>Worker Region</label>
        <select id="logs-region" onchange="loadLogs()" disabled>
          <option value="">Select a deployed region</option>
        </select>
        <div class="hint">Only used when the source is set to Probe worker.</div>
      </div>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Lookback Window</label>
        <select id="logs-hours" onchange="loadLogs()">
          <option value="6">Last 6 hours</option>
          <option value="24" selected>Last 24 hours</option>
          <option value="72">Last 3 days</option>
          <option value="168">Last 7 days</option>
        </select>
      </div>
      <div class="form-group">
        <label>Entry Limit</label>
        <select id="logs-limit" onchange="loadLogs()">
          <option value="40">40 entries</option>
          <option value="80" selected>80 entries</option>
          <option value="120">120 entries</option>
          <option value="200">200 entries</option>
        </select>
      </div>
    </div>
    <div class="actions">
      <button class="btn btn-primary" onclick="loadLogs()">Refresh Logs</button>
      <button class="btn btn-ghost" onclick="copyLogsSummary()">Copy Summary</button>
    </div>
    <div class="hint" id="logs-source-note" style="margin-top:10px">Reading the management Lambda log group in the home region.</div>
  </div>
  <div class="panel">
    <div id="logs-summary" style="color:#94a3b8">Loading log summary…</div>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Likely Issues</h3>
    <div id="logs-issues" style="color:#94a3b8">No log scan has run yet.</div>
  </div>
  <div class="panel">
    <h3 style="margin-top:0">Recent Entries</h3>
    <div id="logs-entries" style="color:#94a3b8">No log scan has run yet.</div>
  </div>
  </details>
  <details class="panel" open>
    <summary class="section-summary">
      <span class="section-summary-title">DynamoDB</span>
      <span class="section-summary-meta">Hosts, checks, region records, and audit history</span>
    </summary>
    <div class="section-header" style="margin-bottom:12px">
      <div>
        <h3 style="margin:0">DynamoDB</h3>
        <div class="hint">Formatted snapshots of hosts, settings, region records, and recent checks.</div>
      </div>
      <button class="btn btn-ghost" onclick="loadDynamoData()">Refresh Data</button>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Table View</label>
        <select id="ddb-view-select" onchange="loadDynamoData()">
          <option value="overview">Overview</option>
          <option value="hosts">Hosts</option>
          <option value="checks">Checks</option>
          <option value="audit">Audit</option>
        </select>
      </div>
      <div class="form-group">
        <label>Checks Host</label>
        <select id="ddb-host-filter" onchange="loadDynamoData()">
          <option value="">Auto-select first host</option>
        </select>
      </div>
    </div>
    <div class="grid2">
      <div class="form-group">
        <label>Region Filter</label>
        <select id="ddb-region-filter" onchange="loadDynamoData()">
          <option value="all">All regions</option>
        </select>
      </div>
      <div class="form-group">
        <label>Row Limit</label>
        <select id="ddb-check-limit" onchange="loadDynamoData()">
          <option value="20">20 rows</option>
          <option value="50" selected>50 rows</option>
          <option value="100">100 rows</option>
        </select>
      </div>
    </div>
    <div id="ddb-summary" style="color:#94a3b8">Loading DynamoDB data…</div>
    <div id="ddb-hosts" style="margin-top:16px;color:#94a3b8"></div>
    <div id="ddb-checks" style="margin-top:16px;color:#94a3b8"></div>
  </details>
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
    Defaults are filled from your live deployment: enabled hosts, active probes, default interval, and retention.
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
  <h2>Operator Docs</h2>
  <p class="desc">
    This page is the practical runbook for operating the stack: what to deploy, how to secure admin access, which scripts are worth keeping nearby, and what to watch for in corporate-network environments.
  </p>

  <div class="doc-hero">
    <div class="doc-card">
      <div class="doc-kicker">Quick Start</div>
      <h3 style="margin-top:0">Recommended first production shape</h3>
      <ul class="doc-list">
        <li>Keep one home region for the management Lambda and add at least two probe regions for coverage.</li>
        <li>Use a custom domain through CloudFront instead of sending operators to the raw Lambda Function URL.</li>
        <li>Turn on Cognito if you want named users and MFA; keep the emergency admin token only as a break-glass path.</li>
        <li>If you stay on password-only admin without CloudFront, restrict `/admin` and `/api/*` with `AdminAllowedIpCidrs`.</li>
      </ul>
      <div class="doc-badges">
        <span class="doc-badge">Home region: {HOME_REGION}</span>
        <span class="doc-badge">1-minute orchestrator heartbeat</span>
        <span class="doc-badge">Regional worker fan-out</span>
      </div>
    </div>
    <div class="doc-card">
      <div class="doc-kicker">Useful Endpoints</div>
      <div class="doc-subtitle">Admin</div>
      <p class="doc-mini">`/admin` is the private control plane. In Cognito mode, operators should sign in with Cognito and use the Account page for password and MFA work.</p>
      <div class="doc-subtitle" style="margin-top:12px">Public status</div>
      <p class="doc-mini">`/` or `/status` is the public landing page. `/history` is the detailed timeline and should be the main path for past incidents.</p>
      <div class="doc-subtitle" style="margin-top:12px">Version check</div>
      <pre>GET /api/debug/version
Authorization: Bearer &lt;admin-token-or-cognito-access-token&gt;</pre>
    </div>
  </div>

  <div class="doc-grid">
    <div class="doc-card">
      <div class="doc-kicker">Authentication</div>
      <h3 style="margin-top:0">Password-only vs Cognito</h3>
      <div class="doc-columns">
        <div>
          <div class="doc-subtitle">Password-only</div>
          <ul class="doc-list">
            <li>Fastest setup and easiest to bootstrap.</li>
            <li>Good for a very small trusted team.</li>
            <li>Shared secret means weaker accountability.</li>
            <li>Behind CloudFront, prefer WAF or CloudFront rules for viewer IP allowlisting.</li>
          </ul>
        </div>
        <div>
          <div class="doc-subtitle">Cognito</div>
          <ul class="doc-list">
            <li>Per-user identities, password policy, and MFA support.</li>
            <li>Better for auditability and operator separation.</li>
            <li>More moving parts: user setup, MFA enrollment, and IAM calls from the management Lambda.</li>
            <li>For this project, Cognito is the better long-term admin story.</li>
          </ul>
        </div>
      </div>
      <div class="doc-note">
        If you use Cognito, keep the old admin token hidden behind the emergency sign-in path only. It is useful for recovery, but it should not be the default operator path once Cognito is working.
      </div>
    </div>

    <div class="doc-card">
      <div class="doc-kicker">Hardening</div>
      <h3 style="margin-top:0">IP restrictions and network policy</h3>
      <ul class="doc-list">
        <li>`AdminAllowedIpCidrs` protects the raw Lambda URL admin path without affecting the public status page.</li>
        <li>Use it when the operator IP range is stable, especially if you are still on password-only auth.</li>
        <li>When using Cognito, IP allowlisting is still a good extra control for office/VPN traffic.</li>
      </ul>
      <pre>AdminAllowedIpCidrs=203.0.113.10/32,198.51.100.0/24</pre>
      <div class="doc-note">
        If your operators work from multiple networks, consider allowing only trusted VPN or office CIDRs rather than broad home ISP ranges.
      </div>
    </div>

    <div class="doc-card">
      <div class="doc-kicker">Monitoring Model</div>
      <h3 style="margin-top:0">What the workers actually do</h3>
      <ul class="doc-list">
        <li>The management Lambda runs on a shared one-minute heartbeat.</li>
        <li>It invokes every deployed probe region that is due for the selected monitor tiers.</li>
        <li>Hosts do not create their own Lambda schedules. They choose from shared tiers like 60s or 300s.</li>
        <li>HTTP checks verify status code, latency, and SSL expiry for HTTPS. TCP checks only verify socket reachability.</li>
      </ul>
    </div>

    <div class="doc-card">
      <div class="doc-kicker">Corporate Networks</div>
      <h3 style="margin-top:0">Split tunnel and firewall notes</h3>
      <ul class="doc-list">
        <li>If operators use a split-tunnel VPN, make sure the browser can still resolve and reach the admin endpoint they use: custom status/admin domain, CloudFront domain, or raw `*.lambda-url.{HOME_REGION}.on.aws` host.</li>
        <li>If you use Cognito, also allow the Cognito domain and login flows to pass through the user firewall path. That includes the managed domain under `*.auth.{HOME_REGION}.amazoncognito.com` if you enabled it.</li>
        <li>DNS failures can look like a broken admin app even when Lambda itself is healthy. Check local DNS resolution first before debugging the stack.</li>
      </ul>
      <pre># Useful local checks on the operator machine
nslookup your-admin-domain.example.com
nslookup my-uptime-admin.auth.{HOME_REGION}.amazoncognito.com
curl -I https://your-admin-domain.example.com/admin</pre>
    </div>
  </div>

  <div class="doc-grid" style="margin-top:16px">
    <div class="doc-card">
      <div class="doc-kicker">Admin Scripts</div>
      <h3 style="margin-top:0">Common operator actions</h3>
      <div class="doc-subtitle">Deploy new management code</div>
      <pre>./scripts/deploy-new-version.sh {HOME_REGION}</pre>
      <div class="doc-subtitle" style="margin-top:12px">Publish artifacts only</div>
      <pre>./scripts/publish-artifacts.sh</pre>
      <div class="doc-subtitle" style="margin-top:12px">Enable or disable read-only mode</div>
      <pre>./scripts/set-management-readonly.sh enable {HOME_REGION}
./scripts/set-management-readonly.sh disable {HOME_REGION}</pre>
      <div class="doc-subtitle" style="margin-top:12px">Prepare a Cognito CloudFormation command</div>
      <pre>./scripts/prepare-cognito-cf.sh {HOME_REGION} uptime my-uptime-admin maimons.dev OPTIONAL 203.0.113.10/32</pre>
      <div class="doc-subtitle" style="margin-top:12px">Create a Cognito admin user</div>
      <pre>./scripts/create-cognito-admin-user.sh {HOME_REGION} uptime you@maimons.dev 'StrongTempPass123!'</pre>
    </div>

    <div class="doc-card">
      <div class="doc-kicker">Operational Notes</div>
      <h3 style="margin-top:0">Useful one-off tasks</h3>
      <div class="doc-subtitle">Set up SNS alerts</div>
      <pre>aws sns create-topic --name uptime-alerts --region {HOME_REGION}
aws sns subscribe \\
  --topic-arn arn:aws:sns:{HOME_REGION}:ACCOUNT_ID:uptime-alerts \\
  --protocol email \\
  --notification-endpoint you@example.com</pre>
      <div class="doc-subtitle" style="margin-top:12px">Rotate the emergency admin key</div>
      <pre>NEW_KEY=$(openssl rand -hex 20)
aws secretsmanager put-secret-value \\
  --secret-id uptime/admin-key \\
  --secret-string "$NEW_KEY" \\
  --region {HOME_REGION}</pre>
      <div class="doc-subtitle" style="margin-top:12px">Back up check history</div>
      <pre>aws dynamodb create-backup \\
  --table-name uptime-checks \\
  --backup-name uptime-backup-$(date +%Y%m%d)</pre>
    </div>
  </div>
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
      Current scheduler: every 60 seconds. This host will be checked about 1,440 times/day per probe region and does not create one Lambda invocation per check by itself.
    </div>
    <div class="form-group">
      <label>Expected HTTP Status Code</label>
      <input id="m-code" type="number" value="200">
    </div>
    <div class="grid2">
      <div class="form-group">
        <label class="toggle"><input type="checkbox" id="m-public-link-enabled" onchange="togglePublicLink()"> Show public host link</label>
      </div>
      <div class="form-group" id="m-public-link-group" style="display:none">
        <label>Public Link URL</label>
        <input id="m-public-link-url" placeholder="https://status.example.com/app">
      </div>
    </div>
    <div class="form-group">
      <label>Probes</label>
      <div class="choice-grid">
        <label class="choice-card" id="m-region-card-all">
          <input type="radio" name="m-region-mode" id="m-region-mode-all" value="all" checked onchange="toggleTargetRegionMode()">
          <span>
            <div class="choice-card-title">Run on all deployed probes</div>
            <div class="choice-card-copy">Best when you want broad coverage by default. New probes will pick this host up automatically.</div>
          </span>
        </label>
        <label class="choice-card" id="m-region-card-selected">
          <input type="radio" name="m-region-mode" id="m-region-mode-selected" value="selected" onchange="toggleTargetRegionMode()">
          <span>
            <div class="choice-card-title">Run only on selected probes</div>
            <div class="choice-card-copy">Use this when a host should stay scoped to specific regions, networks, or customer edges.</div>
          </span>
        </label>
      </div>
      <div class="probe-scope-panel inactive" id="m-target-regions-panel">
        <div class="probe-scope-header">
          <div class="probe-scope-title">Probe selection</div>
          <div class="hint" id="m-target-regions-hint">All deployed probes will run this host unless you switch to selected probes.</div>
        </div>
        <div id="m-target-regions" class="probe-region-grid"></div>
      </div>
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
    <p class="desc" style="margin-bottom:16px">This deploys a new probe Lambda in the selected AWS region.</p>
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
      <div class="hint">Each probe can support one or more shared schedules. Hosts will choose from these tiers.</div>
      <div id="r-supported-tiers" class="checklist"></div>
      <div class="hint" id="r-tier-cost-note" style="margin-top:10px"></div>
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
const AUTH_CONFIG = {json.dumps(auth_config)};
let KEY = sessionStorage.getItem('uptime_admin_key') || '';
let COGNITO_TOKEN = sessionStorage.getItem('uptime_admin_cognito_access_token') || '';
let COGNITO_CHALLENGE = '';
let COGNITO_SESSION = '';
let COGNITO_USERNAME = '';
let ACCOUNT_CACHE = null;
const queryKey = new URLSearchParams(location.search).get('key') || '';
let REGIONS_CACHE = [];
let HOSTS_CACHE = [];
const RECOMMENDED_MONITOR_TIERS = {json.dumps(RECOMMENDED_MONITOR_TIERS)};
const CLOUDFRONT_PLAN_COSTS = {json.dumps(_CLOUDFRONT_PLAN_COSTS)};
if (queryKey) {{
  KEY = queryKey;
  sessionStorage.setItem('uptime_admin_key', KEY);
  history.replaceState(null, '', location.pathname);
}}

function api(path, opts={{}}) {{
  const authToken = COGNITO_TOKEN || KEY;
  return fetch(path, {{
    ...opts,
    headers: {{ ...(authToken ? {{ Authorization: 'Bearer ' + authToken }} : {{}}), 'Content-Type': 'application/json', ...(opts.headers||{{}}) }}
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
  if (!COGNITO_TOKEN && !KEY) {{
    showAuthGate(AUTH_CONFIG.cognito_enabled ? 'Sign in with Cognito to continue.' : 'Enter the admin token to continue.');
    return false;
  }}
  const probe = await api('/api/auth');
  if (probe.unauthorized || probe.error) {{
    showAuthGate(AUTH_CONFIG.cognito_enabled ? 'Your sign-in expired or was rejected. Sign in again.' : 'That token was rejected. Check the value and try again.');
    return false;
  }}
  hideAuthGate();
  return true;
}}

function clearCognitoChallenge() {{
  COGNITO_CHALLENGE = '';
  COGNITO_SESSION = '';
  const mfaWrap = document.getElementById('auth-mfa-wrap');
  const mfaInput = document.getElementById('auth-mfa');
  const mfaHint = document.getElementById('auth-mfa-hint');
  const newPasswordWrap = document.getElementById('auth-new-password-wrap');
  const newPasswordInput = document.getElementById('auth-new-password');
  if (mfaWrap) mfaWrap.style.display = 'none';
  if (mfaInput) mfaInput.value = '';
  if (mfaHint) mfaHint.textContent = 'Shown when Cognito requests MFA.';
  if (newPasswordWrap) newPasswordWrap.style.display = 'none';
  if (newPasswordInput) newPasswordInput.value = '';
}}

function toggleTokenLogin() {{
  const wrap = document.getElementById('auth-token-wrap');
  if (!wrap) return;
  wrap.style.display = wrap.style.display === 'none' ? '' : 'none';
}}

function rememberCognitoToken(token) {{
  COGNITO_TOKEN = token || '';
  if (COGNITO_TOKEN) sessionStorage.setItem('uptime_admin_cognito_access_token', COGNITO_TOKEN);
  else sessionStorage.removeItem('uptime_admin_cognito_access_token');
}}

async function finishCognitoAuth(res) {{
  if (res.ok && res.access_token) {{
    KEY = '';
    sessionStorage.removeItem('uptime_admin_key');
    rememberCognitoToken(res.access_token);
    clearCognitoChallenge();
    const password = document.getElementById('auth-password');
    const username = document.getElementById('auth-username');
    if (password) password.value = '';
    if (username) username.value = '';
    hideAuthGate();
    boot();
    return;
  }}
  if (!res.challenge) {{
    showAuthGate(res.error || 'Cognito sign-in failed.');
    return;
  }}
  COGNITO_CHALLENGE = res.challenge;
  COGNITO_SESSION = res.session || '';
  const mfaWrap = document.getElementById('auth-mfa-wrap');
  const mfaHint = document.getElementById('auth-mfa-hint');
  const newPasswordWrap = document.getElementById('auth-new-password-wrap');
  if (res.challenge === 'SOFTWARE_TOKEN_MFA' || res.challenge === 'SMS_MFA') {{
    if (mfaWrap) mfaWrap.style.display = '';
    if (mfaHint) mfaHint.textContent = res.challenge === 'SOFTWARE_TOKEN_MFA' ? 'Enter the 6-digit code from your authenticator app.' : 'Enter the MFA code sent by Cognito.';
    showAuthGate('Complete the MFA challenge to finish signing in.');
    return;
  }}
  if (res.challenge === 'NEW_PASSWORD_REQUIRED') {{
    if (newPasswordWrap) newPasswordWrap.style.display = '';
    showAuthGate('Set a new password to complete your first Cognito sign-in.');
    return;
  }}
  if (res.challenge === 'MFA_SETUP') {{
    showAuthGate('This Cognito user still needs MFA setup. Finish initial setup in Cognito before using the admin UI.');
    return;
  }}
  showAuthGate('Cognito requested an unsupported sign-in challenge.');
}}

async function loginWithCognito() {{
  const username = document.getElementById('auth-username')?.value.trim() || '';
  const password = document.getElementById('auth-password')?.value || '';
  if (!username || !password) {{
    showAuthGate('Enter your Cognito username/email and password first.');
    return;
  }}
  COGNITO_USERNAME = username;
  if (COGNITO_CHALLENGE) {{
    const body = {{ username: COGNITO_USERNAME, challenge: COGNITO_CHALLENGE, session: COGNITO_SESSION }};
    if (COGNITO_CHALLENGE === 'SOFTWARE_TOKEN_MFA' || COGNITO_CHALLENGE === 'SMS_MFA') {{
      body.code = document.getElementById('auth-mfa')?.value.trim() || '';
    }} else if (COGNITO_CHALLENGE === 'NEW_PASSWORD_REQUIRED') {{
      body.new_password = document.getElementById('auth-new-password')?.value || '';
    }}
    const res = await api('/api/cognito/respond', {{ method:'POST', body: JSON.stringify(body), headers: {{}} }});
    return finishCognitoAuth(res);
  }}
  const res = await api('/api/cognito/login', {{ method:'POST', body: JSON.stringify({{ username, password }}), headers: {{}} }});
  return finishCognitoAuth(res);
}}

async function loginWithAdminKey() {{
  KEY = document.getElementById('auth-key')?.value.trim() || '';
  if (!KEY) {{
    showAuthGate('Enter the admin token first.');
    return;
  }}
  sessionStorage.setItem('uptime_admin_key', KEY);
  rememberCognitoToken('');
  clearCognitoChallenge();
  if (await ensureAuthed()) {{
    const keyInput = document.getElementById('auth-key');
    if (keyInput) keyInput.value = '';
    boot();
  }}
}}

async function loginAdmin() {{
  if (AUTH_CONFIG.cognito_enabled) return loginWithCognito();
  return loginWithAdminKey();
}}

function logoutAdmin() {{
  KEY = '';
  rememberCognitoToken('');
  sessionStorage.removeItem('uptime_admin_key');
  ACCOUNT_CACHE = null;
  clearCognitoChallenge();
  closeMoreMenu();
  showAuthGate('Signed out.');
}}

function toggleMoreMenu() {{
  document.getElementById('more-menu').classList.toggle('open');
}}

function closeMoreMenu() {{
  document.getElementById('more-menu').classList.remove('open');
}}

function openMenuTab(tab) {{
  closeMoreMenu();
  show(tab);
}}

function renderAccountModeNote(message, warn=false) {{
  const summary = document.getElementById('account-summary');
  const mfa = document.getElementById('acct-mfa-summary');
  summary.innerHTML = `<div class="tip" style="margin:0;${{warn ? 'background:#3f2a16;border-color:#d97706;color:#fde68a' : ''}}">${{message}}</div>`;
  mfa.textContent = 'Authenticator MFA controls are unavailable in the current auth mode.';
  ['acct-email','acct-phone','acct-current-password','acct-new-password','acct-totp-secret','acct-totp-uri','acct-totp-code'].forEach(id => {{
    const el = document.getElementById(id);
    if (el) el.value = '';
  }});
  document.getElementById('acct-totp-setup').style.display = 'none';
}}

function renderAccount(data) {{
  ACCOUNT_CACHE = data || null;
  if (!AUTH_CONFIG.cognito_enabled) {{
    renderAccountModeNote('This deployment is using the shared admin token flow, so there is no per-user Cognito account profile to manage here.');
    return;
  }}
  if ((data || {{}}).mode === 'admin_key') {{
    renderAccountModeNote(data.note || 'Sign out and sign back in with Cognito to manage your own account profile.', true);
    return;
  }}
  if ((data || {{}}).mode !== 'cognito') {{
    renderAccountModeNote((data || {{}}).note || 'Account details are unavailable right now.', true);
    return;
  }}
  const summary = document.getElementById('account-summary');
  const methods = (data.mfa_methods || []).length ? data.mfa_methods.join(', ') : 'None configured';
  summary.innerHTML = `
    <div class="grid2">
      <div><strong>Username</strong><div class="hint">${{data.username || '—'}}</div></div>
      <div><strong>Email</strong><div class="hint">${{data.email || '—'}} ${{data.email_verified ? '· verified' : '· unverified'}}</div></div>
      <div><strong>Phone</strong><div class="hint">${{data.phone_number || '—'}} ${{data.phone_verified ? '· verified' : data.phone_number ? '· unverified' : ''}}</div></div>
      <div><strong>Preferred MFA</strong><div class="hint">${{data.preferred_mfa || 'None'}}</div></div>
    </div>
  `;
  document.getElementById('acct-email').value = data.email || '';
  document.getElementById('acct-phone').value = data.phone_number || '';
  document.getElementById('acct-mfa-summary').textContent = `Enabled methods: ${{methods}}. Preferred: ${{data.preferred_mfa || 'None'}}.`;
  document.getElementById('acct-totp-setup').style.display = 'none';
}}

async function loadAccount() {{
  if (!AUTH_CONFIG.cognito_enabled) {{
    renderAccountModeNote('This deployment is using the shared admin token flow, so there is no per-user Cognito account profile to manage here.');
    return;
  }}
  if (!COGNITO_TOKEN) {{
    renderAccountModeNote('Sign out and sign back in with Cognito to see your account details, change your password, or manage authenticator MFA.', true);
    return;
  }}
  const data = await api('/api/account');
  if (data.unauthorized) {{
    showAuthGate('Your Cognito session expired. Sign in again.');
    return;
  }}
  if (data.error) {{
    renderAccountModeNote(data.error, true);
    return;
  }}
  renderAccount(data);
}}

async function saveAccountProfile() {{
  if (!COGNITO_TOKEN) {{
    toast('Sign in with Cognito to update your profile.', true);
    return;
  }}
  const res = await api('/api/account', {{
    method:'POST',
    body: JSON.stringify({{
      action:'update_profile',
      email: document.getElementById('acct-email').value.trim(),
      phone_number: document.getElementById('acct-phone').value.trim()
    }})
  }});
  if (res.error) {{ toast(res.error, true); return; }}
  renderAccount(res);
  toast('Account profile updated');
}}

async function changeAccountPassword() {{
  if (!COGNITO_TOKEN) {{
    toast('Sign in with Cognito to change your password.', true);
    return;
  }}
  const res = await api('/api/account', {{
    method:'POST',
    body: JSON.stringify({{
      action:'change_password',
      current_password: document.getElementById('acct-current-password').value,
      new_password: document.getElementById('acct-new-password').value
    }})
  }});
  if (res.error) {{ toast(res.error, true); return; }}
  document.getElementById('acct-current-password').value = '';
  document.getElementById('acct-new-password').value = '';
  toast(res.message || 'Password updated');
}}

async function beginTotpSetup() {{
  if (!COGNITO_TOKEN) {{
    toast('Sign in with Cognito to set up authenticator MFA.', true);
    return;
  }}
  const res = await api('/api/account', {{method:'POST', body: JSON.stringify({{action:'begin_totp'}})}});
  if (res.error) {{ toast(res.error, true); return; }}
  document.getElementById('acct-totp-secret').value = res.secret_code || '';
  document.getElementById('acct-totp-uri').value = res.otpauth_uri || '';
  document.getElementById('acct-totp-code').value = '';
  document.getElementById('acct-totp-setup').style.display = '';
  toast('Authenticator secret generated');
}}

async function verifyTotp() {{
  if (!COGNITO_TOKEN) {{
    toast('Sign in with Cognito to verify authenticator MFA.', true);
    return;
  }}
  const res = await api('/api/account', {{
    method:'POST',
    body: JSON.stringify({{
      action:'verify_totp',
      code: document.getElementById('acct-totp-code').value.trim(),
      preferred: document.getElementById('acct-totp-preferred').value === 'true'
    }})
  }});
  if (res.error) {{ toast(res.error, true); return; }}
  renderAccount(res);
  toast('Authenticator MFA enabled');
}}

async function disableTotp() {{
  if (!COGNITO_TOKEN) {{
    toast('Sign in with Cognito to disable authenticator MFA.', true);
    return;
  }}
  const res = await api('/api/account', {{method:'POST', body: JSON.stringify({{action:'disable_totp'}})}});
  if (res.error) {{ toast(res.error, true); return; }}
  renderAccount(res);
  toast('Authenticator MFA disabled');
}}

const PANES = ['hosts','regions','status-page','notifications','account','management','diagnostics','settings','cost','guides'];
function show(tab) {{
  PANES.forEach((t,i) => {{
    document.getElementById('pane-'+t).style.display = t===tab ? '' : 'none';
  }});
  document.querySelectorAll('.tab').forEach(el => el.classList.toggle('active', el.dataset.tab === tab));
  closeMoreMenu();
  if (tab === 'hosts') loadHosts();
  if (tab === 'regions') loadRegions();
  if (tab === 'status-page') loadStatusPage();
  if (tab === 'notifications') loadNotificationSettings();
  if (tab === 'account') loadAccount();
  if (tab === 'management') loadManagement();
  if (tab === 'diagnostics') loadDiagnostics();
  if (tab === 'settings') loadSettings();
  if (tab === 'cost') loadCostDefaults();
}}
document.addEventListener('click', (event) => {{
  const menu = document.getElementById('more-menu');
  const btn = document.getElementById('more-menu-btn');
  if (!menu || !btn) return;
  if (!menu.contains(event.target) && !btn.contains(event.target)) closeMoreMenu();
}});

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
      <input type="checkbox" value="${{tier}}" ${{selectedTiers.includes(tier) ? 'checked' : ''}} onchange="renderRegionTierCostNote()">
      <span>${{formatTierLabel(tier)}}</span>
    </label>
  `).join('');
  renderRegionTierCostNote();
}}

function selectedRegionTiers() {{
  return Array.from(document.querySelectorAll('#r-supported-tiers input[type=checkbox]:checked')).map(el => +el.value).sort((a, b) => a - b);
}}

function renderRegionTierCostNote() {{
  const note = document.getElementById('r-tier-cost-note');
  if (!note) return;
  const tiers = selectedRegionTiers();
  const tierBits = tiers.length
    ? tiers.map(tier => `${{formatTierLabel(tier)}} = ${{Math.round(86400 / Math.max(60, tier)).toLocaleString()}} host-region checks/day`).join(' · ')
    : 'Select at least one tier.';
  note.innerHTML = `Cost note: each deployed worker is still invoked every <strong>1 minute</strong> today, which is about <strong>1,440 runs/day</strong> or <strong>43,200 runs/month</strong> per worker. That is roughly <strong>$0.01/month in Lambda request charges after the free tier</strong>, and usually still $0 while free-tier headroom remains. Slower host tiers reduce checks, DynamoDB rows, and logs for hosts assigned to them, but they do not change the worker's base wake-up cadence.<br><span style="display:block;margin-top:6px">${{tierBits}}</span>`;
}}

function renderTargetRegions(selected=[]) {{
  const wrap = document.getElementById('m-target-regions');
  if (!REGIONS_CACHE.length) {{
    wrap.innerHTML = '<div class="hint">No worker regions deployed yet.</div>';
    return;
  }}
  wrap.innerHTML = REGIONS_CACHE.map(r => `
    <label class="probe-region-pill">
      <input type="checkbox" value="${{r.region}}" ${{selected.includes(r.region) ? 'checked' : ''}} onchange="updateHostImpact()">
      <span>
        <div class="probe-region-pill-name">${{r.region}}</div>
        <div class="probe-region-pill-meta">${{(r.supported_tiers || [60,300]).map(t => formatTierLabel(t)).join(' · ')}}</div>
      </span>
    </label>
  `).join('');
  toggleTargetRegionMode();
}}

function selectedTargetRegions() {{
  return Array.from(document.querySelectorAll('#m-target-regions input[type=checkbox]:checked')).map(el => el.value);
}}

function targetRegionMode() {{
  return document.getElementById('m-region-mode-selected').checked ? 'selected' : 'all';
}}

function toggleTargetRegionMode() {{
  const selectedMode = targetRegionMode() === 'selected';
  const hint = document.getElementById('m-target-regions-hint');
  const panel = document.getElementById('m-target-regions-panel');
  const allCard = document.getElementById('m-region-card-all');
  const selectedCard = document.getElementById('m-region-card-selected');
  const checkboxes = Array.from(document.querySelectorAll('#m-target-regions input[type=checkbox]'));
  if (allCard) allCard.classList.toggle('active', !selectedMode);
  if (selectedCard) selectedCard.classList.toggle('active', selectedMode);
  if (panel) panel.classList.toggle('inactive', !selectedMode);
  checkboxes.forEach(el => {{
    el.disabled = !selectedMode;
    if (!selectedMode) el.checked = false;
  }});
  if (hint) {{
    hint.textContent = selectedMode
      ? 'Only the checked probes will run this host. Choose the exact regions below.'
      : 'This host will run on every deployed probe. The list below is shown for reference.';
  }}
  updateHostImpact();
}}

function describeHostScope(host) {{
  const targets = Array.isArray(host.target_regions) ? host.target_regions : [];
  return targets.length ? `Selected probes: ${{targets.join(', ')}}` : 'All deployed probes';
}}

function hostTierSeconds(host) {{
  return +(host.monitor_tier_seconds || host.check_interval_seconds || 60);
}}

function computeHostProbeCoverage(host) {{
  const targets = Array.isArray(host.target_regions) ? host.target_regions : [];
  const tier = hostTierSeconds(host);
  const regions = REGIONS_CACHE.map(region => {{
    const scopedOut = targets.length > 0 && !targets.includes(region.region);
    const supportsTier = (region.supported_tiers || [60,300]).includes(tier);
    const eligible = !scopedOut && supportsTier;
    let reason = '';
    if (scopedOut) reason = 'Not selected for this host';
    else if (!supportsTier) reason = `Does not support ${{formatTierLabel(tier)}}`;
    else reason = `Supports ${{formatTierLabel(tier)}}`;
    return {{
      region: region.region,
      eligible,
      reason,
    }};
  }});
  return {{
    tier,
    eligible: regions.filter(region => region.eligible),
    blocked: regions.filter(region => !region.eligible),
    regions,
  }};
}}

function renderHostCoverage() {{
  const wrap = document.getElementById('host-coverage');
  if (!wrap) return;
  if (!HOSTS_CACHE.length) {{
    wrap.innerHTML = '<div class="hint">Add a host to see probe coverage.</div>';
    return;
  }}
  if (!REGIONS_CACHE.length) {{
    wrap.innerHTML = '<div class="hint">Deploy at least one probe region to see coverage.</div>';
    return;
  }}
  wrap.innerHTML = `<div class="coverage-grid">${{HOSTS_CACHE.map(host => {{
    const coverage = computeHostProbeCoverage(host);
    const eligibleHtml = coverage.eligible.length
      ? coverage.eligible.map(region => `<span class="coverage-pill ok">${{region.region}}</span>`).join('')
      : '<span class="coverage-pill warn">No eligible probes</span>';
    const blockedHtml = coverage.blocked.length
      ? coverage.blocked.map(region => `<span class="coverage-pill off" title="${{region.reason}}">${{region.region}} · ${{region.reason}}</span>`).join('')
      : '<span class="coverage-pill ok">No exclusions</span>';
    return `
      <div class="coverage-card">
        <div class="coverage-head">
          <div>
            <div class="coverage-title">${{host.name}}</div>
            <div class="coverage-subtitle">${{describeHostScope(host)}} · Interval: ${{formatTierLabel(coverage.tier)}} · ${{host.enabled === false ? 'Disabled host' : 'Enabled host'}}</div>
          </div>
          <span class="badge ${{host.enabled === false ? 'inactive' : coverage.eligible.length ? 'active' : 'warn'}}">${{host.enabled === false ? 'disabled' : coverage.eligible.length ? coverage.eligible.length + ' routes' : 'blocked'}}</span>
        </div>
        <div class="hint" style="margin-bottom:8px">Will run from</div>
        <div class="coverage-pills" style="margin-bottom:10px">${{eligibleHtml}}</div>
        <div class="hint" style="margin-bottom:8px">Skipped by</div>
        <div class="coverage-pills">${{blockedHtml}}</div>
      </div>
    `;
  }}).join('')}}</div>`;
}}

async function loadHosts() {{
  await ensureRegionsLoaded();
  const hosts = await api('/api/hosts');
  if (hosts.unauthorized) {{
    showAuthGate('Enter the admin token to load hosts.');
    return;
  }}
  HOSTS_CACHE = Array.isArray(hosts) ? hosts : [];
  const tbody = document.getElementById('hosts-body');
  if (!HOSTS_CACHE.length) {{
    tbody.innerHTML = '<tr><td colspan="10" style="text-align:center;color:#64748b;padding:32px">No hosts yet.</td></tr>';
    renderHostCoverage();
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
      <td>${{renderSslCell(h)}}</td>
      <td style="text-align:center">${{h.show_on_status_page ? '✓' : '—'}}</td>
      <td style="text-align:center">${{h.alert_enabled ? '✓' : '—'}}</td>
      <td><div class="actions">
        <button class="btn btn-ghost btn-sm" onclick="openEditHostById('${{h.host_id}}')">Edit</button>
        <button class="btn btn-danger btn-sm" onclick="deleteHost('${{h.host_id}}','${{h.name}}')">Del</button>
      </div></td>
    </tr>`).join('');
  renderHostCoverage();
}}

function renderSslCell(host) {{
  const url = (host.url || '').toLowerCase();
  const isHttps = url.startsWith('https://');
  if (!isHttps) return '<span style="color:#64748b">—</span>';
  const regionStatuses = Object.values(host.region_statuses || {{}});
  const sslDays = regionStatuses
    .map(region => region && typeof region.ssl_days_remaining === 'number' ? region.ssl_days_remaining : null)
    .filter(days => days != null);
  if (sslDays.length) {{
    const minDays = Math.min(...sslDays);
    return `<span title="Certificate currently verifies. Lowest observed days remaining across workers: ${{minDays}}">✓</span>`;
  }}
  return '<span title="No recent successful SSL verification was recorded.">×</span>';
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
  ['m-id','m-name','m-url','m-sns','m-public-link-url'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('m-type').value = 'http';
  renderHostTierOptions(60);
  document.getElementById('m-timeout').value = 10;
  document.getElementById('m-code').value = 200;
  document.getElementById('m-page').checked = true;
  document.getElementById('m-public-link-enabled').checked = false;
  document.getElementById('m-alert').checked = false;
  document.getElementById('m-enabled').checked = true;
  document.getElementById('m-region-mode-all').checked = true;
  document.getElementById('m-region-mode-selected').checked = false;
  document.getElementById('m-sns-group').style.display = 'none';
  document.getElementById('m-public-link-group').style.display = 'none';
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
  renderHostTierOptions(h.monitor_tier_seconds || h.check_interval_seconds || 60);
  document.getElementById('m-timeout').value = h.timeout_seconds || 10;
  document.getElementById('m-code').value = h.expected_status_code || 200;
  document.getElementById('m-page').checked = !!h.show_on_status_page;
  document.getElementById('m-public-link-enabled').checked = !!h.public_link_enabled;
  document.getElementById('m-public-link-url').value = h.public_link_url || '';
  document.getElementById('m-alert').checked = !!h.alert_enabled;
  document.getElementById('m-sns').value = h.alert_sns_arn || '';
  document.getElementById('m-enabled').checked = h.enabled !== false;
  const hasScopedRegions = Array.isArray(h.target_regions) && h.target_regions.length > 0;
  document.getElementById('m-region-mode-all').checked = !hasScopedRegions;
  document.getElementById('m-region-mode-selected').checked = hasScopedRegions;
  document.getElementById('m-sns-group').style.display = h.alert_enabled ? '' : 'none';
  document.getElementById('m-public-link-group').style.display = h.public_link_enabled ? '' : 'none';
  renderTargetRegions(h.target_regions || []);
  document.getElementById('host-modal').classList.add('open');
}}

function toggleSNS() {{
  document.getElementById('m-sns-group').style.display = document.getElementById('m-alert').checked ? '' : 'none';
}}

function togglePublicLink() {{
  document.getElementById('m-public-link-group').style.display = document.getElementById('m-public-link-enabled').checked ? '' : 'none';
}}

function updateHostImpact() {{
  const requestedInterval = Math.max(60, +(document.getElementById('m-tier').value || 60));
  const effectiveInterval = 60;
  const selectedRegions = targetRegionMode() === 'selected' ? selectedTargetRegions() : [];
  const eligibleRegions = (selectedRegions.length ? REGIONS_CACHE.filter(region => selectedRegions.includes(region.region)) : REGIONS_CACHE)
    .filter(region => (region.supported_tiers || [60,300]).includes(requestedInterval));
  const regionCount = eligibleRegions.length;
  const requestedChecksPerDayPerRegion = Math.round(86400 / requestedInterval);
  const effectiveChecksPerDayPerRegion = Math.round(86400 / effectiveInterval);
  const effectiveChecksPerDayTotal = effectiveChecksPerDayPerRegion * regionCount;
  const targetLabel = regionCount ? (regionCount + ' probe region(s) currently support this tier') : 'no probe regions currently support this tier';
  document.getElementById('m-impact').innerHTML =
    `Chosen tier: <strong>${{formatTierLabel(requestedInterval)}}</strong>, which is about <strong>${{requestedChecksPerDayPerRegion.toLocaleString()}}</strong> checks/day per supporting region.<br>` +
    `Current scheduler heartbeat: every <strong>${{effectiveInterval}}s</strong>. This host is currently eligible for about <strong>${{effectiveChecksPerDayTotal.toLocaleString()}}</strong> checks/day across ${{targetLabel}}.<br>` +
    `Lambda invocations are driven by the shared management + worker schedule. Adding this host mainly increases checks and DynamoDB writes, not one Lambda invoke per check.`;
}}

function closeHostModal() {{ document.getElementById('host-modal').classList.remove('open'); }}

async function saveHost() {{
  const id = document.getElementById('m-id').value;
  const chosenTier = +document.getElementById('m-tier').value;
  const mode = targetRegionMode();
  const targets = mode === 'selected' ? selectedTargetRegions() : [];
  const scopedRegions = targets.length ? REGIONS_CACHE.filter(region => targets.includes(region.region)) : REGIONS_CACHE;
  const unsupportedRegions = scopedRegions.filter(region => !(region.supported_tiers || [60,300]).includes(chosenTier)).map(region => region.region);
  if (!scopedRegions.length) {{
    toast('Deploy at least one probe region before saving a host.', true);
    return;
  }}
  if (mode === 'selected' && !targets.length) {{
    toast('Choose at least one probe, or switch this host to all deployed probes.', true);
    return;
  }}
  if (!targets.length && !scopedRegions.some(region => (region.supported_tiers || [60,300]).includes(chosenTier))) {{
    toast('No deployed probe region currently supports that monitor tier.', true);
    return;
  }}
  if (targets.length && unsupportedRegions.length) {{
    toast('These selected probes do not support that tier: ' + unsupportedRegions.join(', '), true);
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
    public_link_enabled: document.getElementById('m-public-link-enabled').checked,
    public_link_url: document.getElementById('m-public-link-url').value,
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
    showAuthGate('Enter the admin token to load probes.');
    return;
  }}
  REGIONS_CACHE = Array.isArray(list) ? list : [];
  const el = document.getElementById('regions-list');
  if (!REGIONS_CACHE.length) {{
    el.innerHTML = '<div style="color:#64748b;padding:20px 0">No probes deployed yet.</div>';
    return;
  }}
  const expectedProbeVersion = {json.dumps(build.get("version", "unknown"))};
  const expectedProbeSha = {json.dumps(_embedded_monitor_source_sha())};
  el.innerHTML = REGIONS_CACHE.map(r => `
    <div class="region-card">
      <div class="region-info">
        <div class="name">${{r.region}} <span class="badge active" style="margin-left:6px">${{r.status||'active'}}</span></div>
        <div class="meta">Memory: ${{r.memory_mb||256}}MB · Tiers: ${{(r.supported_tiers || [60,300]).map(formatTierLabel).join(', ')}} · Deployed: ${{r.deployed_at ? new Date(r.deployed_at).toLocaleDateString() : '—'}}</div>
        <div class="meta">Worker build: <strong>${{r.monitor_build_version || 'unknown'}}</strong>${{r.monitor_source_sha ? ' · ' + r.monitor_source_sha.slice(0, 8) : ''}}</div>
        <div class="meta">Expected now: <strong>${{expectedProbeVersion}}</strong>${{expectedProbeSha ? ' · ' + expectedProbeSha.slice(0, 8) : ''}} · ${{r.monitor_build_version === expectedProbeVersion && r.monitor_source_sha === expectedProbeSha ? 'matches current bundle' : 'update recommended'}}</div>
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

function isoToLocalInput(value) {{
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  const offset = date.getTimezoneOffset();
  const local = new Date(date.getTime() - offset * 60000);
  return local.toISOString().slice(0, 16);
}}

function localInputToIso(value) {{
  if (!value) return '';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return '';
  return date.toISOString();
}}

function refreshMaintenanceEditorState() {{
  const enabled = document.getElementById('sp-maintenance-enabled').checked;
  const message = document.getElementById('sp-maintenance-message').value.trim();
  const startRaw = document.getElementById('sp-maintenance-start').value;
  const endRaw = document.getElementById('sp-maintenance-end').value;
  const start = startRaw ? new Date(startRaw) : null;
  const end = endRaw ? new Date(endRaw) : null;
  const now = new Date();
  let label = 'Off';
  let badge = 'unknown';
  let hint = 'No maintenance notice will be shown.';

  if (enabled && message) {{
    if (end && now > end) {{
      label = 'Expired';
      badge = 'inactive';
      hint = 'The public notice is auto-hidden because the window already passed.';
    }} else if (start && now < start) {{
      label = 'Pending';
      badge = 'active';
      hint = 'The notice is queued and will become active when the start time arrives.';
    }} else if (start || end) {{
      label = 'Live';
      badge = 'degraded';
      hint = 'The maintenance notice is currently visible on the public status page.';
    }} else {{
      label = 'Enabled';
      badge = 'active';
      hint = 'The notice is visible until you turn it off.';
    }}
  }} else if (message || startRaw || endRaw || document.getElementById('sp-maintenance-window').value.trim() || document.getElementById('sp-maintenance-scope').value.trim()) {{
    label = 'Draft';
    badge = 'http';
    hint = 'Details are saved in the editor, but the public notice is still off.';
  }}

  document.getElementById('sp-maintenance-state').innerHTML = `<span class="badge ${{badge}}">${{label}}</span>`;
  document.getElementById('sp-maintenance-state').title = hint;
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
  document.getElementById('sp-maintenance-start').value = isoToLocalInput(settings.maintenance_starts_at || '');
  document.getElementById('sp-maintenance-end').value = isoToLocalInput(settings.maintenance_ends_at || '');
  document.getElementById('sp-subscribe-intro').value = settings.status_page_subscribe_intro || 'Subscribe for status updates.';
  document.getElementById('sp-subscribe-email').value = settings.status_page_subscribe_email_url || '';
  document.getElementById('sp-subscribe-sms').value = settings.status_page_subscribe_sms_url || '';
  document.getElementById('sp-subscribe-webhook').value = settings.status_page_subscribe_webhook_url || '';
  document.getElementById('cd-domain').value = settings.custom_domain_name || '';
  refreshMaintenanceEditorState();
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
    maintenance_starts_at: localInputToIso(document.getElementById('sp-maintenance-start').value),
    maintenance_ends_at: localInputToIso(document.getElementById('sp-maintenance-end').value),
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
    lines.push('Use the DNS record copy boxes below for the next setup step.');
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
  const build = data.build || {{}};
  const workerRows = workers.map(worker => `
    <tr>
      <td>${{worker.region || '—'}}</td>
      <td>${{worker.function_name || '—'}}</td>
      <td><span class="badge ${{worker.version_status === 'match' ? 'active' : worker.version_status === 'mismatch' ? 'warn' : 'unknown'}}">${{worker.version_status || 'unknown'}}</span></td>
      <td title="${{worker.running_monitor_source_sha || ''}}">${{worker.running_monitor_build_version || '—'}}${{worker.running_monitor_source_sha ? ' · ' + worker.running_monitor_source_sha.slice(0, 8) : ''}}</td>
      <td>${{worker.memory_mb || '—'}} MB</td>
      <td>${{worker.age_human || '—'}}</td>
      <td>${{worker.last_24h?.invocations ?? '—'}}</td>
      <td>${{worker.last_24h?.avg_duration_ms != null ? worker.last_24h.avg_duration_ms + ' ms' : '—'}}</td>
      <td>${{worker.last_24h?.errors ?? '—'}}</td>
    </tr>`).join('') || `<tr><td colspan="9" style="text-align:center;color:#64748b;padding:16px">No probe regions deployed yet.</td></tr>`;
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
        <h3 style="margin-top:0">Running Build</h3>
        <div class="hint">Version: ${{build.version || '—'}}</div>
        <div class="hint">Built at: ${{build.built_at || '—'}}</div>
        <div class="hint">Home region: ${{build.region || data.home_region || '—'}}</div>
        <div class="hint">Function: ${{build.function_name || managementLambda.function_name || 'uptime-management'}}</div>
      </div>
      <div>
        <h3 style="margin-top:0">Management Lambda</h3>
        <div class="hint">Function: ${{managementLambda.function_name || 'uptime-management'}}</div>
        <div class="hint">Memory: ${{managementLambda.memory_mb || '—'}} MB</div>
        <div class="hint">Age: ${{managementLambda.age_human || '—'}}</div>
        <div class="hint">Invocations (24h): ${{managementLambda.last_24h?.invocations ?? '—'}}</div>
        <div class="hint">Avg runtime (24h): ${{managementLambda.last_24h?.avg_duration_ms != null ? managementLambda.last_24h.avg_duration_ms + ' ms' : '—'}}</div>
      </div>
    </div>
    <div class="grid2" style="margin-top:16px">
      <div>
        <h3 style="margin-top:0">Probe Fleet</h3>
        <div class="hint">Deployed probe regions: ${{data.worker_regions}}</div>
        <div class="hint">Home region: ${{data.home_region}}</div>
        <div class="hint">Probe invocations (24h): ${{workerInvocations24h}}</div>
        <div class="hint">Probe errors (24h): ${{workerErrors24h}}</div>
        <div class="hint">Expected embedded build: ${{managementLambda.version || '—'}}${{managementLambda.expected_monitor_source_sha ? ' · ' + managementLambda.expected_monitor_source_sha.slice(0, 8) : ''}}</div>
      </div>
    </div>
    <div style="margin-top:16px">
      <div class="hint" style="margin-bottom:10px">Version state compares the running probe against the current embedded probe source in the management Lambda. Use Update Code when a probe shows mismatch.</div>
      <table>
        <thead><tr><th>Region</th><th>Function</th><th>Version</th><th>Running Build</th><th>Memory</th><th>Age</th><th>Invocations (24h)</th><th>Avg runtime</th><th>Errors</th></tr></thead>
        <tbody>${{workerRows}}</tbody>
      </table>
    </div>
    <div style="margin-top:16px" class="hint">
      Hosts: ${{data.hosts.total}} total, ${{data.hosts.enabled}} enabled, ${{data.hosts.on_status_page}} on status page, ${{data.hosts.alerts_enabled}} with alerts.
      Probe regions: ${{data.worker_regions}}. Home region: ${{data.home_region}}.
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

function formatLogTime(value) {{
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString();
}}

function escapeHtml(value) {{
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}}

function renderLogs(data) {{
  const summaryEl = document.getElementById('logs-summary');
  const issuesEl = document.getElementById('logs-issues');
  const entriesEl = document.getElementById('logs-entries');
  const noteEl = document.getElementById('logs-source-note');
  if (!data || data.error) {{
    const text = (data && data.error) || 'Unable to load logs.';
    summaryEl.innerHTML = `<div style="color:#ef4444">${{escapeHtml(text)}}</div>`;
    issuesEl.innerHTML = `<div style="color:#ef4444">${{escapeHtml(text)}}</div>`;
    entriesEl.innerHTML = `<div style="color:#ef4444">${{escapeHtml(text)}}</div>`;
    return;
  }}
  const scopeName = data.scope === 'worker' ? 'probe worker' : 'management Lambda';
  noteEl.textContent = `Reading the ${{scopeName}} log group in ${{data.region || '—'}}: ${{data.log_group_name || '—'}}`;
  summaryEl.innerHTML = `
    <div class="log-summary-grid">
      <div class="log-summary-card"><div class="label">Source</div><div class="value" style="font-size:1rem">${{escapeHtml(data.function_name || '—')}}</div></div>
      <div class="log-summary-card"><div class="label">Errors</div><div class="value" style="color:#fca5a5">${{data.summary?.error ?? 0}}</div></div>
      <div class="log-summary-card"><div class="label">Warnings</div><div class="value" style="color:#fde68a">${{data.summary?.warn ?? 0}}</div></div>
      <div class="log-summary-card"><div class="label">Info</div><div class="value" style="color:#93c5fd">${{data.summary?.info ?? 0}}</div></div>
      <div class="log-summary-card"><div class="label">Window</div><div class="value" style="font-size:1rem">Last ${{data.lookback_hours || 24}}h</div></div>
    </div>
  `;
  const issues = Array.isArray(data.issues) ? data.issues : [];
  issuesEl.innerHTML = issues.length ? `<div class="log-issue-list">${{issues.map(item => `
    <div class="log-issue">
      <div class="log-issue-head">
        <div>
          <div style="font-weight:700">${{escapeHtml(item.issue || item.summary || 'Issue')}}</div>
          <div class="hint">${{escapeHtml(item.summary || '')}}</div>
        </div>
        <div style="text-align:right">
          <span class="badge ${{item.severity || 'info'}}">${{escapeHtml(item.severity || 'info')}}</span>
          <div class="log-entry-meta" style="margin-top:6px">${{escapeHtml(formatLogTime(item.time))}}</div>
        </div>
      </div>
      <pre>${{escapeHtml(item.raw_message || '')}}</pre>
    </div>`).join('')}}</div>` : '<div class="hint">No warnings or errors were found in the selected window.</div>';

  const entries = Array.isArray(data.entries) ? data.entries : [];
  entriesEl.innerHTML = entries.length ? entries.map(item => `
    <details class="log-entry">
      <summary class="log-entry-head" style="list-style:none;cursor:pointer">
        <div>
          <div style="font-weight:700">${{escapeHtml(item.summary || 'Log event')}}</div>
          <div class="hint">${{escapeHtml(item.issue || '')}}</div>
        </div>
        <div style="text-align:right">
          <span class="badge ${{item.severity || 'info'}}">${{escapeHtml(item.level || 'info')}}</span>
          <div class="log-entry-meta" style="margin-top:6px">${{escapeHtml(formatLogTime(item.time))}}</div>
        </div>
      </summary>
      ${{item.details && Object.keys(item.details).length ? `<pre>${{escapeHtml(JSON.stringify(item.details, null, 2))}}</pre>` : ''}}
      <pre>${{escapeHtml(item.raw_message || '')}}</pre>
    </details>
  `).join('') : '<div class="hint">No log entries matched the current filter.</div>';
  window.LAST_LOGS_DATA = data;
}}

async function loadDiagnostics() {{
  await Promise.all([loadLogs(), loadDynamoData()]);
}}

function populateDynamoHostFilter(hosts, selectedHostId='') {{
  const select = document.getElementById('ddb-host-filter');
  if (!select) return;
  const current = selectedHostId || select.value || '';
  const options = ['<option value="">Auto-select first host</option>'].concat(
    (hosts || []).map(host => `<option value="${{host.host_id}}" ${{host.host_id === current ? 'selected' : ''}}>${{host.name || host.host_id}}</option>`)
  );
  select.innerHTML = options.join('');
}}

function populateDynamoRegionFilter(regions, selectedRegion='all') {{
  const select = document.getElementById('ddb-region-filter');
  if (!select) return;
  const values = ['<option value="all">All regions</option>'].concat(
    (regions || []).map(region => `<option value="${{region.region}}" ${{region.region === selectedRegion ? 'selected' : ''}}>${{region.region}}</option>`)
  );
  select.innerHTML = values.join('');
}}

function renderDynamoData(data) {{
  const summaryEl = document.getElementById('ddb-summary');
  const hostsEl = document.getElementById('ddb-hosts');
  const checksEl = document.getElementById('ddb-checks');
  if (!data || data.error) {{
    const text = (data && data.error) || 'Unable to load DynamoDB data.';
    summaryEl.innerHTML = `<div style="color:#ef4444">${{escapeHtml(text)}}</div>`;
    hostsEl.innerHTML = '';
    checksEl.innerHTML = '';
    return;
  }}
  const hostsTable = data.hosts_table || {{}};
  const checksTable = data.checks_table || {{}};
  const hosts = Array.isArray(hostsTable.hosts) ? hostsTable.hosts : [];
  const regions = Array.isArray(hostsTable.regions) ? hostsTable.regions : [];
  const checks = Array.isArray(checksTable.rows) ? checksTable.rows : [];
  const auditRows = Array.isArray(data.audit?.rows) ? data.audit.rows : [];
  const view = data.view || 'overview';
  populateDynamoHostFilter(hosts, checksTable.selected_host_id || '');
  populateDynamoRegionFilter(regions, document.getElementById('ddb-region-filter')?.value || 'all');
  summaryEl.innerHTML = `
    <div class="diag-kv">
      <div class="diag-kv-card"><div class="label">Hosts Table</div><div class="value">${{escapeHtml(hostsTable.name || '—')}}</div></div>
      <div class="diag-kv-card"><div class="label">Host Rows</div><div class="value">${{hosts.length}}</div></div>
      <div class="diag-kv-card"><div class="label">Region Records</div><div class="value">${{regions.length}}</div></div>
      <div class="diag-kv-card"><div class="label">Checks Table</div><div class="value">${{escapeHtml(checksTable.name || '—')}}</div></div>
    </div>
  `;
  const overviewHtml = `
    <div class="diag-stack">
      <div class="diag-row">
        <div class="diag-row-title">Settings row</div>
        <div class="diag-row-meta">Brand: ${{escapeHtml(hostsTable.settings?.brand_name || '—')}} · Title: ${{escapeHtml(hostsTable.settings?.status_page_title || '—')}} · Default interval: ${{hostsTable.settings?.default_check_interval ?? '—'}}s · Retention: ${{hostsTable.settings?.retention_days ?? '—'}} days</div>
      </div>
      <div class="diag-row">
        <div class="diag-row-title">Worker regions</div>
        <div class="coverage-pills" style="margin-top:10px">${{regions.length ? regions.map(region => `<span class="coverage-pill ok">${{region.region}} · ${{(region.supported_tiers || []).map(t => formatTierLabel(t)).join(', ') || 'No tiers'}}</span>`).join('') : '<span class="coverage-pill warn">No deployed worker regions</span>'}}</div>
      </div>
      <div class="diag-row">
        <div class="diag-row-title">Hosts table view</div>
        <div class="diag-table">
          <table>
            <thead><tr><th>Name</th><th>Status</th><th>Tier</th><th>Scope</th><th>Last Check</th></tr></thead>
            <tbody>${{hosts.length ? hosts.map(host => `<tr><td>${{escapeHtml(host.name || host.host_id)}}</td><td><span class="badge ${{host.current_status || 'unknown'}}">${{escapeHtml(host.current_status || 'unknown')}}</span></td><td>${{host.monitor_tier_seconds}}s</td><td>${{host.target_regions && host.target_regions.length ? escapeHtml(host.target_regions.join(', ')) : 'All probes'}}</td><td>${{escapeHtml(formatLogTime(host.last_checked_at))}}</td></tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:18px">No hosts found.</td></tr>'}}</tbody>
          </table>
        </div>
      </div>
    </div>
  `;
  const checksHtml = `
    <div class="diag-row">
      <div class="diag-row-title">Recent checks for ${{escapeHtml(checksTable.selected_host_name || 'selected host')}}</div>
      <div class="diag-row-meta">Showing the latest ${{checksTable.limit || checks.length}} rows from ${{escapeHtml(checksTable.name || 'uptime-checks')}}.</div>
      <div class="diag-table">
        <table>
          <thead><tr><th>When</th><th>Region</th><th>Status</th><th>Latency</th><th>HTTP</th><th>Error</th></tr></thead>
          <tbody>${{checks.length ? checks.map(row => `<tr><td>${{escapeHtml(formatLogTime(row.checked_at))}}</td><td>${{escapeHtml(row.region || '—')}}</td><td><span class="badge ${{row.status || 'unknown'}}">${{escapeHtml(row.status || 'unknown')}}</span></td><td>${{row.latency_ms != null ? row.latency_ms + ' ms' : '—'}}</td><td>${{row.status_code != null ? row.status_code : '—'}}</td><td title="${{escapeHtml(row.error || '')}}">${{escapeHtml((row.error || '').slice(0, 96) || '—')}}</td></tr>`).join('') : '<tr><td colspan="6" style="text-align:center;color:#64748b;padding:18px">No checks found for the selected host.</td></tr>'}}</tbody>
        </table>
      </div>
    </div>
  `;
  const hostsHtml = `
    <div class="diag-row">
      <div class="diag-row-title">Hosts table view</div>
      <div class="diag-row-meta">Current host rows with interval, scope, and last aggregate status.</div>
      <div class="diag-table">
        <table>
          <thead><tr><th>Name</th><th>Status</th><th>Tier</th><th>Scope</th><th>Last Check</th></tr></thead>
          <tbody>${{hosts.length ? hosts.map(host => `<tr><td>${{escapeHtml(host.name || host.host_id)}}</td><td><span class="badge ${{host.current_status || 'unknown'}}">${{escapeHtml(host.current_status || 'unknown')}}</span></td><td>${{host.monitor_tier_seconds}}s</td><td>${{host.target_regions && host.target_regions.length ? escapeHtml(host.target_regions.join(', ')) : 'All probes'}}</td><td>${{escapeHtml(formatLogTime(host.last_checked_at))}}</td></tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:18px">No hosts found.</td></tr>'}}</tbody>
        </table>
      </div>
    </div>
  `;
  const auditHtml = `
    <div class="diag-row">
      <div class="diag-row-title">Management audit log</div>
      <div class="diag-row-meta">Recent admin and system actions like worker add, update, delete, and force-update.</div>
      <div class="diag-table">
        <table>
          <thead><tr><th>When</th><th>Action</th><th>Status</th><th>Region</th><th>Details</th></tr></thead>
          <tbody>${{auditRows.length ? auditRows.map(row => `<tr><td>${{escapeHtml(formatLogTime(row.created_at))}}</td><td>${{escapeHtml(row.event_type || '—')}}</td><td><span class="badge ${{row.status === 'error' ? 'error' : 'active'}}">${{escapeHtml(row.status || 'ok')}}</span></td><td>${{escapeHtml(row.region || '—')}}</td><td>${{escapeHtml(row.error || row.monitor_build_version || row.action || '') || '—'}}</td></tr>`).join('') : '<tr><td colspan="5" style="text-align:center;color:#64748b;padding:18px">No audit rows found.</td></tr>'}}</tbody>
        </table>
      </div>
    </div>
  `;
  hostsEl.innerHTML = view === 'hosts' ? hostsHtml : view === 'checks' ? '' : view === 'audit' ? '' : overviewHtml;
  checksEl.innerHTML = view === 'checks' ? checksHtml : view === 'audit' ? auditHtml : '';
  if (view === 'hosts') checksEl.innerHTML = '';
  if (view === 'audit') hostsEl.innerHTML = '';
}}

async function loadDynamoData() {{
  await ensureRegionsLoaded();
  const view = document.getElementById('ddb-view-select')?.value || 'overview';
  const hostId = document.getElementById('ddb-host-filter')?.value || '';
  const region = document.getElementById('ddb-region-filter')?.value || 'all';
  const checksLimit = document.getElementById('ddb-check-limit')?.value || '50';
  const summaryEl = document.getElementById('ddb-summary');
  const hostsEl = document.getElementById('ddb-hosts');
  const checksEl = document.getElementById('ddb-checks');
  summaryEl.innerHTML = '<span class="spinner"></span> Loading DynamoDB summary…';
  hostsEl.innerHTML = '<span class="spinner"></span> Loading hosts table…';
  checksEl.innerHTML = '<span class="spinner"></span> Loading checks table…';
  const qs = new URLSearchParams({{checks_limit: checksLimit, view, region}});
  if (hostId) qs.set('host_id', hostId);
  const data = await api('/api/dynamodb?'+qs.toString());
  renderDynamoData(data);
}}

async function ensureLogsRegions() {{
  if (!REGIONS_CACHE.length) {{
    await ensureRegionsLoaded();
  }}
  const select = document.getElementById('logs-region');
  if (!select) return;
  const current = select.value;
  const regions = REGIONS_CACHE.map(item => item.region).filter(Boolean);
  select.innerHTML = regions.length
    ? regions.map(region => `<option value="${{region}}" ${{region === current ? 'selected' : ''}}>${{region}}</option>`).join('')
    : '<option value="">No deployed probe regions</option>';
  if (!select.value && regions.length) select.value = regions[0];
}}

async function handleLogsScopeChange() {{
  const worker = document.getElementById('logs-scope').value === 'worker';
  document.getElementById('logs-region').disabled = !worker;
  if (worker) await ensureLogsRegions();
  loadLogs();
}}

async function loadLogs() {{
  const scope = document.getElementById('logs-scope').value;
  const limit = document.getElementById('logs-limit').value;
  const hours = document.getElementById('logs-hours').value;
  if (scope === 'worker') {{
    await ensureLogsRegions();
  }}
  const region = scope === 'worker' ? document.getElementById('logs-region').value : '';
  const summaryEl = document.getElementById('logs-summary');
  const issuesEl = document.getElementById('logs-issues');
  const entriesEl = document.getElementById('logs-entries');
  summaryEl.innerHTML = '<span class="spinner"></span> Loading log summary…';
  issuesEl.innerHTML = '<span class="spinner"></span> Looking for likely issues…';
  entriesEl.innerHTML = '<span class="spinner"></span> Loading entries…';
  const qs = new URLSearchParams({{scope, limit, hours}});
  if (scope === 'worker' && region) qs.set('region', region);
  const data = await api('/api/logs?'+qs.toString());
  renderLogs(data);
}}

async function copyLogsSummary() {{
  const data = window.LAST_LOGS_DATA;
  if (!data) {{
    toast('Load logs first', true);
    return;
  }}
  const lines = [
    `Source: ${{data.function_name || '—'}}`,
    `Region: ${{data.region || '—'}}`,
    `Log group: ${{data.log_group_name || '—'}}`,
    `Window: last ${{data.lookback_hours || 24}} hours`,
    `Errors: ${{data.summary?.error ?? 0}}`,
    `Warnings: ${{data.summary?.warn ?? 0}}`,
    `Info: ${{data.summary?.info ?? 0}}`,
  ];
  (data.issues || []).slice(0, 5).forEach((item, index) => {{
    lines.push(`${{index + 1}}. [${{item.severity}}] ${{item.issue}} — ${{item.summary}} @ ${{formatLogTime(item.time)}}`);
  }});
  try {{
    await navigator.clipboard.writeText(lines.join('\\n'));
    toast('Summary copied');
  }} catch (err) {{
    toast('Copy failed', true);
  }}
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
  if (data.error) {{
    const fallbackDefaults = {{
      hosts: HOSTS_CACHE.filter(h => h.enabled !== false).length,
      regions: REGIONS_CACHE.length,
      interval_sec: 60,
      retention_days: 90,
      cloudfront_plan: 'payg',
      cognito_admin_mau: 0,
    }};
    fillCostInputs(fallbackDefaults);
    renderCostEstimate(estimateCostLocal(fallbackDefaults), 'Calculated locally because /api/cost failed.');
    toast(data.error, true);
    return;
  }}
  const defaults = data.defaults || data.inputs || {{}};
  fillCostInputs(defaults);
  await calcCost();
}}

function costNumber(value) {{
  const n = Number(value);
  return Number.isFinite(n) ? n : 0;
}}

function fillCostInputs(defaults={{}}) {{
  document.getElementById('c-hosts').value = defaults.hosts ?? 0;
  document.getElementById('c-regions').value = defaults.regions ?? 0;
  document.getElementById('c-interval').value = defaults.interval_sec ?? 300;
  document.getElementById('c-days').value = defaults.retention_days ?? 90;
  document.getElementById('c-cloudfront-plan').value = defaults.cloudfront_plan ?? 'payg';
  document.getElementById('c-cognito-mau').value = defaults.cognito_admin_mau ?? 0;
}}

function getCostInputs() {{
  const customDomainInput = document.getElementById('cd-domain');
  const customDomainEnabled = !!(customDomainInput && customDomainInput.value);
  const cognitoMau = costNumber(document.getElementById('c-cognito-mau').value);
  return {{
    hosts: costNumber(document.getElementById('c-hosts').value),
    regions: costNumber(document.getElementById('c-regions').value),
    interval_sec: Math.max(60, costNumber(document.getElementById('c-interval').value) || 60),
    retention_days: Math.max(1, costNumber(document.getElementById('c-days').value) || 90),
    cloudfront_plan: document.getElementById('c-cloudfront-plan').value || 'payg',
    custom_domain: customDomainEnabled,
    cognito_enabled: cognitoMau > 0,
    cognito_admin_mau: cognitoMau,
  }};
}}

function estimateCostLocal(inputs) {{
  const hosts = Math.max(0, costNumber(inputs.hosts));
  const regions = Math.max(0, costNumber(inputs.regions));
  const requestedInterval = Math.max(60, costNumber(inputs.interval_sec) || 60);
  const effectiveInterval = 60;
  const days = Math.max(1, costNumber(inputs.retention_days) || 90);
  const customDomainEnabled = !!inputs.custom_domain;
  const cloudfrontPlan = (inputs.cloudfront_plan || 'payg').toLowerCase();
  const cognitoEnabled = !!inputs.cognito_enabled;
  const cognitoAdminMau = Math.max(0, costNumber(inputs.cognito_admin_mau));
  const runsPerMonth = Math.round((30 * 24 * 3600) / effectiveInterval);
  const checksPerDayPerRegion = Math.round(86400 / effectiveInterval);
  const requestedChecksPerDayPerRegion = Math.round(86400 / requestedInterval);
  const checksPerMonth = runsPerMonth * hosts * regions;
  const managementInvocations = runsPerMonth;
  const workerInvocations = runsPerMonth * regions;
  const invocations = managementInvocations + workerInvocations;
  const gbSec = workerInvocations * 2.0 * (256 / 1024);
  const lambdaCost = Math.max(0, (invocations - 1000000) / 1000000 * 0.20) + Math.max(0, (gbSec - 400000) * 0.00001667);
  const ddbWrites = checksPerMonth * 2;
  const ddbReads = checksPerMonth * 0.1;
  const ddbWritesCost = Math.max(0, (ddbWrites - 1000000) / 1000000 * 1.25);
  const ddbReadsCost = Math.max(0, (ddbReads - 1000000) / 1000000 * 0.25);
  const items = checksPerMonth * (days / 30);
  const storageGb = (items * 500) / (1024 ** 3);
  const storageCost = Math.max(0, (storageGb - 25) * 0.25);
  const logGb = (checksPerMonth * 100) / (1024 ** 3);
  const logCost = Math.max(0, (logGb - 5) * 0.50);
  const cloudfrontCost = customDomainEnabled ? (CLOUDFRONT_PLAN_COSTS[cloudfrontPlan] ?? 0) : 0;
  const cognitoBillableMau = Math.max(0, cognitoAdminMau - 10000);
  const cognitoCost = cognitoEnabled ? cognitoBillableMau * 0.015 : 0;
  const total = lambdaCost + ddbWritesCost + ddbReadsCost + storageCost + logCost + cloudfrontCost + cognitoCost;
  return {{
    inputs: {{
      hosts,
      regions,
      interval_sec: requestedInterval,
      retention_days: days,
      cloudfront_plan: cloudfrontPlan,
      cognito_admin_mau: cognitoAdminMau,
    }},
    scheduler: {{
      requested_interval_sec: requestedInterval,
      effective_interval_sec: effectiveInterval,
    }},
    checks_per_day_per_region: checksPerDayPerRegion,
    requested_checks_per_day_per_region: requestedChecksPerDayPerRegion,
    monthly_invocations: {{
      management: managementInvocations,
      workers: workerInvocations,
      total: invocations,
    }},
    breakdown: {{
      lambda_usd: +lambdaCost.toFixed(4),
      dynamodb_writes_usd: +ddbWritesCost.toFixed(4),
      dynamodb_reads_usd: +ddbReadsCost.toFixed(4),
      dynamodb_storage_usd: +storageCost.toFixed(4),
      cloudfront_custom_domain_usd: +cloudfrontCost.toFixed(4),
      cognito_auth_usd: +cognitoCost.toFixed(4),
      cloudwatch_logs_usd: +logCost.toFixed(4),
    }},
    total_usd_per_month: +total.toFixed(4),
    note: 'Local estimate using the same pricing assumptions as the backend. The current scheduler runs once per minute, so worker-region count drives Lambda wake-ups; slower host tiers mainly reduce checks, DynamoDB growth, and logs.',
  }};
}}

function renderCostEstimate(data, prefixNote='') {{
  const b = data.breakdown || {{}};
  const el = document.getElementById('cost-result');
  el.style.display = '';
  const month = costNumber(data.total_usd_per_month);
  const day = month / 30;
  document.getElementById('cost-summary').innerHTML =
    `Current scheduler: every <strong>${{costNumber(data.scheduler?.effective_interval_sec || 60).toLocaleString()}}s</strong>. ` +
    `Requested interval: every <strong>${{costNumber(data.scheduler?.requested_interval_sec || 60).toLocaleString()}}s</strong>. ` +
    `Checks/day per region at current scheduler: <strong>${{costNumber(data.checks_per_day_per_region).toLocaleString()}}</strong>. ` +
    `If hosts actually run every ${{costNumber(data.scheduler?.requested_interval_sec || 60).toLocaleString()}}s, that is about <strong>${{costNumber(data.requested_checks_per_day_per_region).toLocaleString()}}</strong> checks/day per host-region. ` +
    `Estimated total: <strong>$${{day.toFixed(4)}}/day</strong> · <strong>$${{month.toFixed(4)}}/month</strong>. ` +
    `Monthly Lambda invocations: <strong>${{costNumber(data.monthly_invocations?.total).toLocaleString()}}</strong> ` +
    `(management ${{costNumber(data.monthly_invocations?.management).toLocaleString()}}, workers ${{costNumber(data.monthly_invocations?.workers).toLocaleString()}}). ` +
    `Cognito admin MAUs: <strong>${{costNumber(data.inputs?.cognito_admin_mau).toLocaleString()}}</strong>.`;
  document.getElementById('cost-rows').innerHTML =
    [['Lambda (workers + orchestrator)', b.lambda_usd], ['DynamoDB writes', b.dynamodb_writes_usd], ['DynamoDB reads', b.dynamodb_reads_usd], ['DynamoDB storage', b.dynamodb_storage_usd], ['CloudFront / custom domain', b.cloudfront_custom_domain_usd], ['Cognito auth', b.cognito_auth_usd], ['CloudWatch Logs', b.cloudwatch_logs_usd], ['Total / month', data.total_usd_per_month]]
    .map(([l,v]) => `<div class="cost-row"><span>${{l}}</span><span>$${{costNumber(v).toFixed(4)}}</span></div>`)
    .join('') + `<div style="color:#64748b;font-size:.75rem;margin-top:10px">${{prefixNote ? prefixNote + ' ' : ''}}${{data.note||''}}</div>`;
}}

async function calcCost() {{
  const inputs = getCostInputs();
  const data = await api('/api/cost?hosts='+inputs.hosts+'&regions='+inputs.regions+'&interval='+inputs.interval_sec+'&days='+inputs.retention_days+'&custom_domain='+(inputs.custom_domain ? '1' : '0')+'&cloudfront_plan='+encodeURIComponent(inputs.cloudfront_plan)+'&cognito_enabled='+(inputs.cognito_enabled ? '1' : '0')+'&cognito_admin_mau='+inputs.cognito_admin_mau);
  if (data.unauthorized) {{
    showAuthGate('Enter the admin token to calculate costs.');
    return;
  }}
  if (data.error) {{
    toast(data.error, true);
    renderCostEstimate(estimateCostLocal(inputs), 'Calculated locally because /api/cost failed.');
    return;
  }}
  renderCostEstimate(data);
}}

async function boot() {{
  ['c-hosts','c-regions','c-interval','c-days','c-cloudfront-plan','c-cognito-mau'].forEach(id => {{
    const el = document.getElementById(id);
    if (!el || el.dataset.costBound === '1') return;
    el.addEventListener('input', () => {{
      if (document.getElementById('pane-cost').style.display !== 'none') calcCost();
    }});
    el.addEventListener('change', () => {{
      if (document.getElementById('pane-cost').style.display !== 'none') calcCost();
    }});
    el.dataset.costBound = '1';
  }});
  ['sp-maintenance-enabled','sp-maintenance-message','sp-maintenance-window','sp-maintenance-scope','sp-maintenance-start','sp-maintenance-end'].forEach(id => {{
    const el = document.getElementById(id);
    if (!el || el.dataset.maintenanceBound === '1') return;
    el.addEventListener('input', refreshMaintenanceEditorState);
    el.addEventListener('change', refreshMaintenanceEditorState);
    el.dataset.maintenanceBound = '1';
  }});
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
