"""
Regional worker Lambda invoked by the management Lambda.
Runs checks for all enabled hosts in its region, stores raw check rows in DynamoDB,
and returns the per-host results to the orchestrator for aggregation.
"""

import os
import ssl
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from decimal import Decimal

import boto3

# ── AWS clients (module-level for Lambda reuse across invocations) ────────────
_dynamodb = None


def _get_dynamodb():
    global _dynamodb
    if _dynamodb is None:
        _dynamodb = boto3.resource("dynamodb", region_name=HOME_REGION)
    return _dynamodb


# ── Config from environment ───────────────────────────────────────────────────
HOSTS_TABLE = os.environ["HOSTS_TABLE"]
CHECKS_TABLE = os.environ["CHECKS_TABLE"]
HOME_REGION = os.environ["HOME_REGION"]
MONITOR_REGION = os.environ.get("MONITOR_REGION", os.environ.get("AWS_REGION", "us-east-1"))
RETENTION_DAYS = int(os.environ.get("RETENTION_DAYS", "90"))

MAX_WORKERS = 20


def handler(event, context):
    run_id = (event or {}).get("run_id") or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    supported_tiers = _normalize_monitor_tiers((event or {}).get("supported_tiers"), fallback=[60, 300])
    force_check = bool((event or {}).get("force_check"))
    target_host_id = str((event or {}).get("host_id") or "").strip()
    now = datetime.now(timezone.utc)

    db = _get_dynamodb()
    hosts_table = db.Table(HOSTS_TABLE)
    resp = hosts_table.scan(
        FilterExpression="enabled = :t AND host_id <> :s AND NOT begins_with(host_id, :r)",
        ExpressionAttributeValues={":t": True, ":s": "__settings__", ":r": "__region__"},
    )
    enabled_hosts = resp.get("Items", [])
    if target_host_id:
        enabled_hosts = [host for host in enabled_hosts if host.get("host_id") == target_host_id]
    region_hosts = [host for host in enabled_hosts if _host_runs_in_region(host, MONITOR_REGION)]
    supported_hosts = [host for host in region_hosts if _host_tier_supported(host, supported_tiers)]
    due_hosts = supported_hosts if force_check else [host for host in supported_hosts if _host_due_now(host, MONITOR_REGION, now)]
    hosts = due_hosts

    if not hosts:
        print(
            f"[{MONITOR_REGION}] no runnable hosts "
            f"(enabled={len(enabled_hosts)}, "
            f"region_matched={len(region_hosts)}, "
            f"tier_supported={len(supported_hosts)}, "
            f"due_now={len(due_hosts)}, "
            f"force_check={force_check}, "
            f"target_host_id={target_host_id or 'all'}, "
            f"supported_tiers={supported_tiers}, "
            f"run_time={now.isoformat()})"
        )
        return {"checked": 0, "region": MONITOR_REGION, "run_id": run_id, "results": []}

    print(f"[{MONITOR_REGION}] checking {len(hosts)} hosts for run {run_id}")

    results = []
    with ThreadPoolExecutor(max_workers=min(len(hosts), MAX_WORKERS)) as pool:
        futures = {pool.submit(_check_and_record, host, run_id): host for host in hosts}
        for fut in as_completed(futures):
            host = futures[fut]
            try:
                results.append(fut.result())
            except Exception as exc:
                print(f"[{MONITOR_REGION}] unhandled error for {host.get('name')}: {exc}")
                results.append({
                    "host_id": host["host_id"],
                    "name": host.get("name"),
                    "region": MONITOR_REGION,
                    "run_id": run_id,
                    "checked_at": datetime.now(timezone.utc).isoformat(),
                    "status": "down",
                    "latency_ms": 0,
                    "error": str(exc),
                })

    up = sum(1 for r in results if r.get("status") == "up")
    degraded = sum(1 for r in results if r.get("status") == "degraded")
    down = sum(1 for r in results if r.get("status") == "down")
    print(f"[{MONITOR_REGION}] done - {up} up, {degraded} degraded, {down} down")
    return {
        "checked": len(results),
        "up": up,
        "degraded": degraded,
        "down": down,
        "region": MONITOR_REGION,
        "run_id": run_id,
        "force_check": force_check,
        "host_id": target_host_id,
        "results": results,
    }


def _normalize_monitor_tiers(value, fallback=None) -> list[int]:
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
    return sorted(tiers) if tiers else list(fallback or [60, 300])


def _host_monitor_tier_seconds(host: dict) -> int:
    value = host.get("monitor_tier_seconds", host.get("check_interval_seconds", 60))
    try:
        tier = int(value)
    except (TypeError, ValueError):
        return 60
    if tier < 60 or tier % 60 != 0:
        return 60
    return tier


def _host_runs_in_region(host: dict, region: str) -> bool:
    targets = host.get("target_regions") or []
    if not targets:
        return True
    return region in targets


def _host_tier_supported(host: dict, supported_tiers: list[int]) -> bool:
    tier = _host_monitor_tier_seconds(host)
    return tier in supported_tiers


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if not text:
        return None
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _host_due_now(host: dict, region: str, now: datetime) -> bool:
    tier = _host_monitor_tier_seconds(host)
    region_status = ((host.get("region_statuses") or {}).get(region) or {})
    last_checked = _parse_timestamp(region_status.get("checked_at"))
    if last_checked is None:
        last_checked = _parse_timestamp(host.get("last_checked_at"))
    if last_checked is None:
        return True
    elapsed = (now - last_checked).total_seconds()
    # Small slack avoids minute-boundary jitter from skipping an otherwise-due host.
    return elapsed >= max(0, tier - 5)


def _check_and_record(host: dict, run_id: str) -> dict:
    host_id = host["host_id"]
    check_type = host.get("check_type", "http")
    result = _check_tcp(host) if check_type == "tcp" else _check_http(host)

    now = datetime.now(timezone.utc)
    checked_at = now.isoformat()
    ttl = int((now + timedelta(days=RETENTION_DAYS)).timestamp())

    item = {
        "host_id": host_id,
        "checked_at": checked_at,
        "run_id": run_id,
        "status": result["status"],
        "latency_ms": Decimal(str(result.get("latency_ms", 0))),
        "region": MONITOR_REGION,
        "ttl": ttl,
    }
    if result.get("status_code") is not None:
        item["status_code"] = result["status_code"]
    if result.get("error"):
        item["error"] = result["error"][:500]
    if result.get("ssl_days_remaining") is not None:
        item["ssl_days_remaining"] = result["ssl_days_remaining"]

    _get_dynamodb().Table(CHECKS_TABLE).put_item(Item=item)

    return {
        "host_id": host_id,
        "name": host.get("name"),
        "region": MONITOR_REGION,
        "run_id": run_id,
        "checked_at": checked_at,
        "status": result["status"],
        "latency_ms": result.get("latency_ms", 0),
        "status_code": result.get("status_code"),
        "error": result.get("error"),
        "ssl_days_remaining": result.get("ssl_days_remaining"),
    }


def _check_http(host: dict) -> dict:
    url = host["url"]
    timeout = int(host.get("timeout_seconds", 10))
    expected_code = int(host.get("expected_status_code", 200))

    start = time.monotonic()
    try:
        ctx = ssl.create_default_context()
        req = urllib.request.Request(url, headers={"User-Agent": "UptimeMonitor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            latency_ms = round((time.monotonic() - start) * 1000)
            status_code = resp.status

            ssl_days = None
            if url.lower().startswith("https://"):
                ssl_days = _ssl_days_remaining(url)

            if status_code == expected_code:
                status = "up"
            elif 200 <= status_code < 300:
                status = "degraded"
            else:
                status = "down"

            if ssl_days is not None and ssl_days < 7:
                status = "degraded"

            out = {"status": status, "status_code": status_code, "latency_ms": latency_ms}
            if ssl_days is not None:
                out["ssl_days_remaining"] = ssl_days
            return out
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.monotonic() - start) * 1000)
        return {"status": "down", "status_code": exc.code, "latency_ms": latency_ms, "error": str(exc)}
    except Exception as exc:
        latency_ms = round((time.monotonic() - start) * 1000)
        return {"status": "down", "latency_ms": latency_ms, "error": str(exc)}


def _check_tcp(host: dict) -> dict:
    url = host["url"]
    timeout = int(host.get("timeout_seconds", 10))

    if "://" not in url:
        url = "tcp://" + url
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname
    port = parsed.port or 80

    start = time.monotonic()
    try:
        with socket.create_connection((hostname, port), timeout=timeout):
            pass
        latency_ms = round((time.monotonic() - start) * 1000)
        return {"status": "up", "latency_ms": latency_ms}
    except Exception as exc:
        latency_ms = round((time.monotonic() - start) * 1000)
        return {"status": "down", "latency_ms": latency_ms, "error": str(exc)}


def _ssl_days_remaining(url: str) -> int | None:
    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname
        port = parsed.port or 443

        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname=hostname) as wrapped:
                cert = wrapped.getpeercert()
        expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        return max(0, (expiry - datetime.now(timezone.utc)).days)
    except Exception:
        return None
