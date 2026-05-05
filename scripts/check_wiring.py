#!/usr/bin/env python3
"""
Diagnostic checker for the live Uptime deployment wiring.

Checks:
 - local worker-source wiring
 - management Lambda config, function URL, and CloudFormation stack
 - EventBridge schedule targets
 - DynamoDB tables and deployment records
 - host-to-worker assignment eligibility
 - worker Lambda config per region
 - custom-domain CloudFront wiring
 - expected S3 artifact buckets/objects
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import warnings
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

warnings.filterwarnings(
    "ignore",
    message=r"Boto3 will no longer support Python 3\.9.*",
    category=Warning,
)

import boto3
from boto3.dynamodb.conditions import Attr
from botocore.exceptions import BotoCoreError, ClientError


ARTIFACT_BUCKETS = {
    "us-east-1": "uptime-artifacts-us-east-1.maimons.dev",
    "eu-west-1": "uptime-artifacts-eu-west-1.maimons.dev",
    "eu-central-1": "uptime-artifacts-eu-central-1.maimons.dev",
    "ap-southeast-1": "uptime-artifacts-ap-southeast-1.maimons.dev",
}

DEFAULT_MONITOR_TIERS = [60, 300]
SETTINGS_KEY = "__settings__"
REGION_PREFIX = "__region__"


@dataclass
class Check:
    status: str
    name: str
    detail: str


class Recorder:
    def __init__(self) -> None:
        self.checks: list[Check] = []

    def add(self, status: str, name: str, detail: str) -> None:
        self.checks.append(Check(status=status, name=name, detail=detail))

    def ok(self, name: str, detail: str) -> None:
        self.add("OK", name, detail)

    def warn(self, name: str, detail: str) -> None:
        self.add("WARN", name, detail)

    def fail(self, name: str, detail: str) -> None:
        self.add("FAIL", name, detail)

    def counts(self) -> dict[str, int]:
        out = {"OK": 0, "WARN": 0, "FAIL": 0}
        for check in self.checks:
            out[check.status] = out.get(check.status, 0) + 1
        return out


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize_tiers(value: Any, fallback: list[int] | None = None) -> list[int]:
    tiers: list[int] = []
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
    return sorted(tiers) if tiers else list(fallback or DEFAULT_MONITOR_TIERS)


def host_tier_seconds(host: dict[str, Any]) -> int:
    try:
        tier = int(host.get("monitor_tier_seconds", host.get("check_interval_seconds", 60)))
    except (TypeError, ValueError):
        return 60
    return tier if tier >= 60 and tier % 60 == 0 else 60


def scan_all(table, **kwargs) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    response = table.scan(**kwargs)
    items.extend(response.get("Items", []))
    while "LastEvaluatedKey" in response:
        response = table.scan(ExclusiveStartKey=response["LastEvaluatedKey"], **kwargs)
        items.extend(response.get("Items", []))
    return items


def detect_stack_name(cfn, function_name: str) -> str | None:
    try:
        resources = cfn.describe_stack_resources(PhysicalResourceId=function_name).get("StackResources", [])
    except ClientError:
        return None
    for resource in resources:
        if resource.get("PhysicalResourceId") == function_name:
            return resource.get("StackName")
    return None


def safe_client(service: str, region: str | None = None):
    return boto3.client(service, region_name=region) if region else boto3.client(service)


def parse_iso8601(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def count_recent_log_events(logs, log_group_name: str, start_ms: int, pattern: str | None = None) -> tuple[int, list[str]]:
    kwargs: dict[str, Any] = {
        "logGroupName": log_group_name,
        "startTime": start_ms,
        "limit": 50,
    }
    if pattern:
        kwargs["filterPattern"] = pattern
    count = 0
    samples: list[str] = []
    paginator = logs.get_paginator("filter_log_events")
    for page in paginator.paginate(**kwargs):
        events = page.get("events", [])
        count += len(events)
        for event in events[:3]:
            message = (event.get("message") or "").strip().replace("\n", " | ")
            if message:
                samples.append(message[:220])
        if count and len(samples) >= 3:
            break
    return count, samples[:3]


def classify_worker_logs(logs, log_group_name: str, start_ms: int) -> list[str]:
    hints: list[str] = []
    patterns = [
        ('"no enabled hosts"', "worker reported 'no enabled hosts'"),
        ('"checking "', "worker started host checks"),
        ('"done -"', "worker completed host checks"),
        ('"Traceback"', "worker logged a traceback"),
        ('"unhandled error"', "worker logged an unhandled error"),
        ('"Task timed out"', "worker timed out"),
    ]
    for pattern, label in patterns:
        try:
            count, samples = count_recent_log_events(logs, log_group_name, start_ms, pattern)
        except ClientError:
            continue
        if count:
            sample = f" ({samples[0]})" if samples else ""
            hints.append(f"{label}: {count}{sample}")
    return hints


def local_source_checks(repo_root: Path, rec: Recorder) -> None:
    embedded = repo_root / "src" / "management" / "_monitor_handler.py"
    standalone = repo_root / "src" / "monitor" / "handler.py"
    regions_py = repo_root / "src" / "management" / "regions.py"

    if not embedded.exists() or not standalone.exists() or not regions_py.exists():
        rec.fail("local worker sources", "Expected worker source files are missing.")
        return

    embedded_text = embedded.read_text()
    standalone_text = standalone.read_text()
    regions_text = regions_py.read_text()
    embedded_hash = sha256_file(embedded)[:12]
    standalone_hash = sha256_file(standalone)[:12]
    zip_path_ok = '_monitor_handler.py' in regions_text
    supports_due_tiers = "_host_due_for_tier" in embedded_text and "due_tiers" in embedded_text

    if zip_path_ok:
        rec.ok(
            "worker deployment source",
            "Admin-driven worker deploys package src/management/_monitor_handler.py at deploy time."
        )
    else:
        rec.warn("worker deployment source", "Could not confirm which local worker file regions.py packages.")

    if embedded_hash != standalone_hash:
        rec.warn(
            "worker source mismatch",
            f"src/management/_monitor_handler.py ({embedded_hash}) differs from src/monitor/handler.py ({standalone_hash})."
        )
    else:
        rec.ok("worker source mismatch", "Embedded and standalone worker sources currently match.")

    if supports_due_tiers:
        rec.ok("embedded worker tier support", "Embedded worker source includes tier-based scheduling filters.")
    else:
        rec.warn(
            "embedded worker tier support",
            "Embedded worker source does not appear to support due_tiers/supported_tiers filtering."
        )


def management_checks(args, rec: Recorder) -> dict[str, Any]:
    lam = safe_client("lambda", args.home_region)
    events = safe_client("events", args.home_region)
    cfn = safe_client("cloudformation", args.home_region)

    function_name = args.function_name
    try:
        mgmt = lam.get_function(FunctionName=function_name)
    except ClientError as exc:
        rec.fail("management lambda", f"Unable to load {function_name} in {args.home_region}: {exc}")
        return {}

    cfg = mgmt["Configuration"]
    env = (cfg.get("Environment") or {}).get("Variables", {})
    resolved = {
        "function_name": function_name,
        "function_arn": cfg["FunctionArn"],
        "runtime": cfg.get("Runtime"),
        "role": cfg.get("Role"),
        "timeout": cfg.get("Timeout"),
        "memory": cfg.get("MemorySize"),
        "state": cfg.get("State"),
        "last_modified": cfg.get("LastModified"),
        "home_region": env.get("HOME_REGION", args.home_region),
        "hosts_table": env.get("HOSTS_TABLE"),
        "checks_table": env.get("CHECKS_TABLE"),
        "project": env.get("PROJECT", args.project or "uptime"),
        "retention_days": env.get("RETENTION_DAYS"),
        "env": env,
    }
    rec.ok(
        "management lambda",
        f"{function_name} is {resolved['state']} in {args.home_region}, runtime={resolved['runtime']}, memory={resolved['memory']}MB, timeout={resolved['timeout']}s."
    )

    try:
        function_url = lam.get_function_url_config(FunctionName=function_name).get("FunctionUrl")
        rec.ok("management function URL", function_url)
        resolved["function_url"] = function_url
    except ClientError as exc:
        rec.warn("management function URL", f"Could not read function URL config: {exc.response['Error']['Code']}")

    stack_name = detect_stack_name(cfn, function_name)
    if stack_name:
        try:
            stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
            rec.ok("cloudformation stack", f"{stack_name} status={stack['StackStatus']}")
            resolved["stack_name"] = stack_name
        except ClientError as exc:
            rec.warn("cloudformation stack", f"Detected stack {stack_name} but could not describe it: {exc}")
    else:
        rec.warn("cloudformation stack", "Could not infer a CloudFormation stack for the management Lambda.")

    try:
        target_rules = events.list_rule_names_by_target(TargetArn=cfg["FunctionArn"]).get("RuleNames", [])
    except ClientError as exc:
        rec.fail("eventbridge target wiring", f"Could not list EventBridge targets: {exc}")
        target_rules = []

    if not target_rules:
        rec.fail("eventbridge target wiring", "No EventBridge rules target the management Lambda.")
    else:
        for rule_name in target_rules:
            rule = events.describe_rule(Name=rule_name)
            rec.ok(
                f"eventbridge rule {rule_name}",
                f"state={rule.get('State')} schedule={rule.get('ScheduleExpression') or 'n/a'}"
            )

    return resolved


def dynamodb_and_host_checks(home_region: str, hosts_table_name: str, checks_table_name: str, rec: Recorder) -> dict[str, Any]:
    ddb_client = safe_client("dynamodb", home_region)
    ddb = boto3.resource("dynamodb", region_name=home_region)
    hosts_table = ddb.Table(hosts_table_name)
    checks_table = ddb.Table(checks_table_name)

    out: dict[str, Any] = {}

    for table_name, label in [(hosts_table_name, "hosts"), (checks_table_name, "checks")]:
        try:
            desc = ddb_client.describe_table(TableName=table_name)["Table"]
            rec.ok(
                f"dynamodb {label} table",
                f"{table_name} status={desc['TableStatus']} item_count={desc.get('ItemCount', 0)} region={home_region}"
            )
        except ClientError as exc:
            rec.fail(f"dynamodb {label} table", f"Could not describe {table_name}: {exc}")

    settings = hosts_table.get_item(Key={"host_id": SETTINGS_KEY}).get("Item", {})
    if settings:
        rec.ok("settings item", f"Loaded {SETTINGS_KEY} from {hosts_table_name}.")
    else:
        rec.warn("settings item", f"No {SETTINGS_KEY} item found in {hosts_table_name}.")

    region_rows = scan_all(
        hosts_table,
        FilterExpression=Attr("host_id").begins_with(REGION_PREFIX),
    )
    regions = []
    for row in region_rows:
        cleaned = dict(row)
        cleaned.pop("host_id", None)
        regions.append(cleaned)
    regions.sort(key=lambda item: item.get("region", ""))

    if regions:
        rec.ok("worker region records", f"Found {len(regions)} worker-region records in {hosts_table_name}.")
    else:
        rec.warn("worker region records", "No worker-region records found.")

    host_rows = scan_all(
        hosts_table,
        FilterExpression=Attr("host_id").ne(SETTINGS_KEY) & ~Attr("host_id").begins_with(REGION_PREFIX),
    )
    enabled_hosts = [host for host in host_rows if host.get("enabled", True)]
    rec.ok("host inventory", f"Found {len(host_rows)} hosts total, {len(enabled_hosts)} enabled.")

    region_map = {region["region"]: region for region in regions if region.get("region")}
    for host in enabled_hosts:
        targets = host.get("target_regions") or []
        tier = host_tier_seconds(host)
        missing_targets = [region for region in targets if region not in region_map]
        if missing_targets:
            rec.fail(
                f"host {host.get('name') or host['host_id']} missing regions",
                f"Target regions not present in deployment records: {', '.join(sorted(missing_targets))}"
            )

        eligible = []
        scoped_regions = targets if targets else sorted(region_map)
        for region_name in scoped_regions:
            region = region_map.get(region_name)
            if not region:
                continue
            tiers = normalize_tiers(region.get("supported_tiers"), fallback=DEFAULT_MONITOR_TIERS)
            if tier in tiers:
                eligible.append(region_name)

        if not eligible:
            scope = "all workers" if not targets else ", ".join(targets)
            rec.fail(
                f"host {host.get('name') or host['host_id']} eligibility",
                f"Tier {tier}s has no eligible workers in scope [{scope}]."
            )
        elif targets:
            rec.ok(
                f"host {host.get('name') or host['host_id']} eligibility",
                f"Scoped to {', '.join(targets)}; eligible workers after tier filter: {', '.join(eligible)}."
            )

    out["settings"] = settings
    out["regions"] = regions
    out["hosts"] = host_rows
    return out


def worker_lambda_checks(home_region: str, hosts_table_name: str, checks_table_name: str, retention_days: str | None, regions: list[dict[str, Any]], rec: Recorder) -> None:
    for region in regions:
        region_name = region.get("region")
        function_name = region.get("function_name")
        if not region_name or not function_name:
            rec.fail("worker lambda record", f"Incomplete region record: {json.dumps(region, default=str)}")
            continue

        lam = safe_client("lambda", region_name)
        try:
            cfg = lam.get_function_configuration(FunctionName=function_name)
        except ClientError as exc:
            rec.fail(f"worker lambda {region_name}", f"Could not load {function_name}: {exc}")
            continue

        env = (cfg.get("Environment") or {}).get("Variables", {})
        problems = []
        if env.get("HOME_REGION") != home_region:
            problems.append(f"HOME_REGION={env.get('HOME_REGION')} expected {home_region}")
        if env.get("MONITOR_REGION") != region_name:
            problems.append(f"MONITOR_REGION={env.get('MONITOR_REGION')} expected {region_name}")
        if env.get("HOSTS_TABLE") != hosts_table_name:
            problems.append(f"HOSTS_TABLE={env.get('HOSTS_TABLE')} expected {hosts_table_name}")
        if env.get("CHECKS_TABLE") != checks_table_name:
            problems.append(f"CHECKS_TABLE={env.get('CHECKS_TABLE')} expected {checks_table_name}")
        if retention_days and env.get("RETENTION_DAYS") != str(retention_days):
            problems.append(f"RETENTION_DAYS={env.get('RETENTION_DAYS')} expected {retention_days}")
        if int(cfg.get("MemorySize", 0)) != int(region.get("memory_mb", 0) or 0):
            problems.append(f"memory={cfg.get('MemorySize')} record={region.get('memory_mb')}")

        dry_run_ok = True
        try:
            lam.invoke(FunctionName=function_name, InvocationType="DryRun")
        except ClientError as exc:
            dry_run_ok = False
            problems.append(f"DryRun invoke failed: {exc.response['Error']['Code']}")

        detail = (
            f"{function_name} state={cfg.get('State')} runtime={cfg.get('Runtime')} "
            f"memory={cfg.get('MemorySize')}MB last_modified={cfg.get('LastModified')}"
        )
        if problems:
            rec.fail(f"worker lambda {region_name}", detail + " | " + "; ".join(problems))
        else:
            suffix = " | DryRun invoke ok." if dry_run_ok else ""
            rec.ok(f"worker lambda {region_name}", detail + suffix)


def reporting_path_checks(
    home_region: str,
    function_name: str,
    checks_table_name: str,
    regions: list[dict[str, Any]],
    lookback_minutes: int,
    rec: Recorder,
) -> None:
    start_dt = datetime.now(timezone.utc) - timedelta(minutes=lookback_minutes)
    start_ms = int(start_dt.timestamp() * 1000)
    logs_home = safe_client("logs", home_region)
    checks_table = boto3.resource("dynamodb", region_name=home_region).Table(checks_table_name)

    management_log_group = f"/aws/lambda/{function_name}"
    try:
        mgmt_events, _ = count_recent_log_events(logs_home, management_log_group, start_ms)
        rec.ok(
            "management recent logs",
            f"{mgmt_events} log events in the last {lookback_minutes} minutes from {management_log_group}."
        )
    except ClientError as exc:
        rec.warn("management recent logs", f"Could not read {management_log_group}: {exc.response['Error']['Code']}")

    try:
        fail_count, samples = count_recent_log_events(
            logs_home,
            management_log_group,
            start_ms,
            '"worker invoke failed"'
        )
        if fail_count:
            rec.fail(
                "management worker invoke failures",
                f"{fail_count} recent worker invoke failure log(s). Sample: {samples[0] if samples else 'see CloudWatch logs'}"
            )
        else:
            rec.ok(
                "management worker invoke failures",
                f"No worker invoke failure logs in the last {lookback_minutes} minutes."
            )
    except ClientError as exc:
        rec.warn("management worker invoke failures", f"Could not search management logs: {exc.response['Error']['Code']}")

    try:
        recent_rows = scan_all(
            checks_table,
            FilterExpression=Attr("checked_at").gte(start_dt.isoformat()),
        )
    except ClientError as exc:
        rec.warn("recent check rows", f"Could not scan recent check rows: {exc.response['Error']['Code']}")
        recent_rows = []

    region_row_counts: dict[str, int] = {}
    latest_by_region: dict[str, datetime] = {}
    for row in recent_rows:
        region_name = row.get("region")
        if not region_name:
            continue
        region_row_counts[region_name] = region_row_counts.get(region_name, 0) + 1
        checked_dt = parse_iso8601(row.get("checked_at"))
        if checked_dt and (region_name not in latest_by_region or checked_dt > latest_by_region[region_name]):
            latest_by_region[region_name] = checked_dt

    for region in regions:
        region_name = region.get("region")
        function_name = region.get("function_name") or f"uptime-monitor-{region_name}"
        if not region_name:
            continue
        worker_logs = safe_client("logs", region_name)
        worker_log_group = f"/aws/lambda/{function_name}"
        log_issue = None
        worker_event_count = 0
        try:
            worker_event_count, samples = count_recent_log_events(worker_logs, worker_log_group, start_ms)
        except ClientError as exc:
            log_issue = f"Could not read {worker_log_group}: {exc.response['Error']['Code']}"
            samples = []

        recent_count = region_row_counts.get(region_name, 0)
        latest_dt = latest_by_region.get(region_name)
        latest_text = latest_dt.isoformat() if latest_dt else "none"

        if log_issue:
            rec.warn(f"worker reporting {region_name}", log_issue)
            continue

        if worker_event_count == 0:
            rec.fail(
                f"worker reporting {region_name}",
                f"No worker log events in the last {lookback_minutes} minutes. Recent check rows from this region: {recent_count}."
            )
            continue

        if recent_count == 0:
            hints = classify_worker_logs(worker_logs, worker_log_group, start_ms)
            hint_text = f" Hints: {'; '.join(hints)}." if hints else ""
            sample_text = f" Sample log: {samples[0]}" if samples else ""
            rec.fail(
                f"worker reporting {region_name}",
                f"Worker produced {worker_event_count} recent log event(s) but no check rows were written in the last {lookback_minutes} minutes.{hint_text}{sample_text}"
            )
            continue

        rec.ok(
            f"worker reporting {region_name}",
            f"{worker_event_count} worker log event(s) and {recent_count} recent check row(s) in the last {lookback_minutes} minutes. Latest check_at={latest_text}."
        )


def cloudfront_checks(home_region: str, settings: dict[str, Any], rec: Recorder) -> None:
    distribution_id = settings.get("custom_domain_distribution_id")
    domain_name = settings.get("custom_domain_name")

    if not distribution_id and not domain_name:
        rec.ok("cloudfront wiring", "No custom domain is configured.")
        return

    if domain_name:
        rec.ok("custom domain setting", f"custom_domain_name={domain_name}")

    if not distribution_id:
        rec.warn("cloudfront wiring", "Custom domain settings exist, but no distribution id is stored yet.")
        return

    cf = safe_client("cloudfront")
    try:
        dist = cf.get_distribution(Id=distribution_id)["Distribution"]
    except ClientError as exc:
        rec.fail("cloudfront distribution", f"Could not load distribution {distribution_id}: {exc}")
        return

    aliases = dist["DistributionConfig"].get("Aliases", {}).get("Items", [])
    origins = dist["DistributionConfig"].get("Origins", {}).get("Items", [])
    rec.ok(
        "cloudfront distribution",
        f"id={distribution_id} status={dist.get('Status')} domain={dist.get('DomainName')} aliases={aliases or ['-']} origins={[origin.get('DomainName') for origin in origins]}"
    )


def s3_checks(home_region: str, artifact_prefix: str, rec: Recorder) -> None:
    s3 = safe_client("s3", home_region)
    prefix = artifact_prefix.strip("/") if artifact_prefix else "uptime"
    object_key = f"{prefix}/releases/management.zip"
    template_key = f"{prefix}/cloudformation/uptime-bootstrap.yaml"
    home_bucket = ARTIFACT_BUCKETS.get(home_region)

    if not home_bucket:
        rec.warn("artifact bucket mapping", f"No known artifact bucket mapping for home region {home_region}.")
        return

    for label, key in [("management artifact", object_key), ("bootstrap template", template_key)]:
        try:
            s3.head_object(Bucket=home_bucket, Key=key)
            rec.ok(f"s3 {label}", f"s3://{home_bucket}/{key} exists.")
        except ClientError as exc:
            rec.fail(f"s3 {label}", f"s3://{home_bucket}/{key} missing or inaccessible: {exc.response['Error']['Code']}")

    for region_name, bucket in ARTIFACT_BUCKETS.items():
        try:
            s3.head_bucket(Bucket=bucket)
            rec.ok(f"s3 bucket {region_name}", f"{bucket} is reachable.")
        except ClientError as exc:
            rec.warn(f"s3 bucket {region_name}", f"{bucket} not reachable from current credentials: {exc.response['Error']['Code']}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check the live uptime deployment wiring.")
    parser.add_argument("--home-region", default="eu-central-1", help="Home region of the management Lambda.")
    parser.add_argument("--function-name", default="uptime-management", help="Management Lambda function name.")
    parser.add_argument("--project", default="uptime", help="Project prefix used for worker functions.")
    parser.add_argument("--artifact-prefix", default="uptime", help="Artifact prefix inside S3 buckets.")
    parser.add_argument("--lookback-minutes", type=int, default=30, help="Lookback window for recent logs and check rows.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable text.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    repo_root = Path(__file__).resolve().parents[1]
    rec = Recorder()

    local_source_checks(repo_root, rec)
    mgmt = management_checks(args, rec)
    if not mgmt:
        return emit(rec, args.json)

    hosts_table_name = mgmt.get("hosts_table")
    checks_table_name = mgmt.get("checks_table")
    if not hosts_table_name or not checks_table_name:
        rec.fail("management lambda env", "HOSTS_TABLE or CHECKS_TABLE is missing from the management Lambda environment.")
        return emit(rec, args.json)

    wiring = dynamodb_and_host_checks(
        home_region=mgmt["home_region"],
        hosts_table_name=hosts_table_name,
        checks_table_name=checks_table_name,
        rec=rec,
    )
    worker_lambda_checks(
        home_region=mgmt["home_region"],
        hosts_table_name=hosts_table_name,
        checks_table_name=checks_table_name,
        retention_days=mgmt.get("retention_days"),
        regions=wiring.get("regions", []),
        rec=rec,
    )
    reporting_path_checks(
        home_region=mgmt["home_region"],
        function_name=mgmt["function_name"],
        checks_table_name=checks_table_name,
        regions=wiring.get("regions", []),
        lookback_minutes=max(1, args.lookback_minutes),
        rec=rec,
    )
    cloudfront_checks(mgmt["home_region"], wiring.get("settings", {}), rec)
    s3_checks(mgmt["home_region"], args.artifact_prefix, rec)
    return emit(rec, args.json)


def emit(rec: Recorder, as_json_output: bool) -> int:
    counts = rec.counts()
    if as_json_output:
        print(json.dumps({
            "summary": counts,
            "checks": [asdict(check) for check in rec.checks],
        }, indent=2))
    else:
        print("Uptime Wiring Check")
        print(f"OK={counts['OK']} WARN={counts['WARN']} FAIL={counts['FAIL']}")
        for check in rec.checks:
            print(f"[{check.status}] {check.name}: {check.detail}")
    return 1 if counts["FAIL"] else 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BotoCoreError, ClientError) as exc:
        print(f"fatal AWS error: {exc}", file=sys.stderr)
        raise SystemExit(2)
