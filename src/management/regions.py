"""
Programmatic deployment and teardown of regional worker Lambdas.
Called by the management Lambda when users add/remove regions via the admin UI.

Strategy:
  - IAM role (${project}-monitor) is global and shared across all regions.
  - One worker Lambda per region, invoked by the management orchestrator.
  - Monitor code is bundled inside this package as _monitor_handler.py,
    zipped in-memory and uploaded directly to Lambda (no S3 needed).
  - State is stored as __region__<name> pseudo-items in the hosts DynamoDB table.
"""

import io
import json
import os
import hashlib
import time
import zipfile
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

PROJECT        = os.environ.get("PROJECT", "uptime")
HOME_REGION    = os.environ["HOME_REGION"]
HOSTS_TABLE    = os.environ["HOSTS_TABLE"]
CHECKS_TABLE   = os.environ["CHECKS_TABLE"]
RETENTION_DAYS = os.environ.get("RETENTION_DAYS", "90")

MONITOR_ROLE_NAME = f"{PROJECT}-monitor"
FUNCTION_PREFIX   = f"{PROJECT}-monitor"

_account_id: str | None = None


# ── Helpers ───────────────────────────────────────────────────────────────────

def _log_dynamodb_write(operation: str, table_name: str, *, key: dict | None = None, item: dict | None = None, context: str = "") -> None:
    fields = {
        "level": "info",
        "message": "dynamodb_write",
        "time": datetime.now(timezone.utc).isoformat(),
        "operation": operation,
        "table": table_name,
    }
    if context:
        fields["context"] = context
    if key is not None:
        fields["key"] = key
    if item is not None:
        fields["item"] = item
        fields["item_keys"] = sorted(str(k) for k in item.keys())
    print(json.dumps(fields, default=str))


def _account() -> str:
    global _account_id
    if _account_id is None:
        _account_id = boto3.client("sts").get_caller_identity()["Account"]
    return _account_id

def _monitor_zip() -> bytes:
    """Zip _monitor_handler.py in memory and return the bytes."""
    src = os.path.join(os.path.dirname(__file__), "_monitor_handler.py")
    with open(src) as f:
        code = f.read()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("handler.py", code)
    return buf.getvalue()

def _monitor_source_sha() -> str:
    src = os.path.join(os.path.dirname(__file__), "_monitor_handler.py")
    return hashlib.sha256(open(src, "rb").read()).hexdigest()

def _monitor_build_version() -> str:
    info_path = os.path.join(os.path.dirname(__file__), "_build_info.json")
    try:
        with open(info_path) as f:
            data = json.load(f)
    except Exception:
        data = {}
    version = str(data.get("version") or os.environ.get("APP_VERSION") or "unknown").strip()
    return version or "unknown"

def _monitor_env(region: str) -> dict:
    return {
        "HOSTS_TABLE":    HOSTS_TABLE,
        "CHECKS_TABLE":   CHECKS_TABLE,
        "HOME_REGION":    HOME_REGION,
        "MONITOR_REGION": region,
        "RETENTION_DAYS": RETENTION_DAYS,
        "MONITOR_SOURCE_SHA": _monitor_source_sha(),
        "MONITOR_BUILD_VERSION": _monitor_build_version(),
    }


# ── IAM role (global, shared by all monitor regions) ─────────────────────────

def _ensure_monitor_role() -> str:
    """Return ARN of the monitor IAM role, creating it if necessary."""
    iam = boto3.client("iam")
    try:
        return iam.get_role(RoleName=MONITOR_ROLE_NAME)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        pass

    acct = _account()
    trust = json.dumps({
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    })
    role_arn = iam.create_role(
        RoleName=MONITOR_ROLE_NAME,
        AssumeRolePolicyDocument=trust,
        Description=f"{PROJECT} monitor Lambda execution role",
    )["Role"]["Arn"]

    iam.put_role_policy(
        RoleName=MONITOR_ROLE_NAME,
        PolicyName=f"{MONITOR_ROLE_NAME}-policy",
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "Logs",
                    "Effect": "Allow",
                    "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                    "Resource": f"arn:aws:logs:*:{acct}:log-group:/aws/lambda/{FUNCTION_PREFIX}-*:*",
                },
                {
                    "Sid": "DynamoDB",
                    "Effect": "Allow",
                    # Cross-region: monitors write to DynamoDB in the home region over HTTPS.
                    "Action": [
                        "dynamodb:GetItem", "dynamodb:PutItem",
                        "dynamodb:UpdateItem", "dynamodb:Scan",
                    ],
                    "Resource": [
                        f"arn:aws:dynamodb:{HOME_REGION}:{acct}:table/{HOSTS_TABLE}",
                        f"arn:aws:dynamodb:{HOME_REGION}:{acct}:table/{CHECKS_TABLE}",
                    ],
                },
                {
                    "Sid": "SNS",
                    "Effect": "Allow",
                    # Monitors publish to per-host SNS topics (user-specified ARNs).
                    "Action": ["sns:Publish"],
                    "Resource": f"arn:aws:sns:{HOME_REGION}:{acct}:*",
                },
            ],
        }),
    )

    # IAM propagation delay — Lambda CreateFunction will fail without this.
    print(f"IAM role created ({MONITOR_ROLE_NAME}), waiting 12s for propagation...")
    time.sleep(12)
    return role_arn


# ── Deploy ────────────────────────────────────────────────────────────────────

def deploy_region(region: str, memory_mb: int = 256, supported_tiers: list[int] | None = None) -> dict:
    """
    Deploy (or update) a regional worker Lambda in the given region.
    Idempotent — safe to call multiple times; updates code/config on existing deployments.
    Returns a dict describing the deployed state.
    """
    fname    = f"{FUNCTION_PREFIX}-{region}"
    role_arn = _ensure_monitor_role()
    zip_data = _monitor_zip()
    source_sha = _monitor_source_sha()
    build_version = _monitor_build_version()
    lam  = boto3.client("lambda", region_name=region)
    logs = boto3.client("logs",   region_name=region)

    # ── CloudWatch log group ─────────────────────────────────────────────────
    try:
        logs.create_log_group(logGroupName=f"/aws/lambda/{fname}")
    except logs.exceptions.ResourceAlreadyExistsException:
        pass
    try:
        logs.put_retention_policy(logGroupName=f"/aws/lambda/{fname}", retentionInDays=7)
    except Exception:
        pass

    # ── Lambda function ──────────────────────────────────────────────────────
    existing = None
    try:
        existing = lam.get_function_configuration(FunctionName=fname)
    except lam.exceptions.ResourceNotFoundException:
        pass

    if existing is None:
        print(f"Creating Lambda {fname} in {region}...")
        lam.create_function(
            FunctionName=fname,
            Runtime="python3.12",
            Role=role_arn,
            Handler="handler.handler",
            Code={"ZipFile": zip_data},
            Timeout=60,
            MemorySize=memory_mb,
            Environment={"Variables": _monitor_env(region)},
            Description=f"{PROJECT} uptime monitor — {region}",
        )
        # Wait for Active state before the orchestrator invokes the worker.
        for _ in range(30):
            state = lam.get_function_configuration(FunctionName=fname).get("State", "")
            if state == "Active":
                break
            time.sleep(2)
    else:
        print(f"Updating Lambda {fname} in {region}...")
        lam.update_function_code(FunctionName=fname, ZipFile=zip_data)
        time.sleep(3)  # wait for code update before config update
        lam.update_function_configuration(
            FunctionName=fname,
            Environment={"Variables": _monitor_env(region)},
            MemorySize=memory_mb,
        )

    current = lam.get_function_configuration(FunctionName=fname)
    func_arn = current["FunctionArn"]

    print(f"Worker deployed in {region}")
    return {
        "region": region,
        "function_arn": func_arn,
        "function_name": fname,
        "memory_mb": memory_mb,
        "supported_tiers": sorted(supported_tiers or [60, 300]),
        "status": "active",
        "deployed_at": datetime.now(timezone.utc).isoformat(),
        "monitor_source_sha": source_sha,
        "monitor_build_version": build_version,
        "lambda_last_modified": current.get("LastModified"),
        "lambda_revision_id": current.get("RevisionId"),
    }


# ── Teardown ──────────────────────────────────────────────────────────────────

def teardown_region(region: str) -> None:
    """Remove a worker Lambda and log group from a region."""
    fname     = f"{FUNCTION_PREFIX}-{region}"

    lam  = boto3.client("lambda", region_name=region)
    logs = boto3.client("logs",   region_name=region)

    try:
        lam.delete_function(FunctionName=fname)
    except Exception as e:
        print(f"delete_function: {e}")

    try:
        logs.delete_log_group(logGroupName=f"/aws/lambda/{fname}")
    except Exception as e:
        print(f"delete_log_group: {e}")

    print(f"Worker torn down in {region}")


def delete_monitor_role() -> None:
    """Delete the shared IAM role (only call when removing ALL regions)."""
    iam = boto3.client("iam")
    try:
        iam.delete_role_policy(RoleName=MONITOR_ROLE_NAME, PolicyName=f"{MONITOR_ROLE_NAME}-policy")
    except Exception:
        pass
    try:
        iam.delete_role(RoleName=MONITOR_ROLE_NAME)
    except Exception:
        pass


# ── DynamoDB region records ───────────────────────────────────────────────────

def list_regions(db) -> list[dict]:
    result = db.Table(HOSTS_TABLE).scan(
        FilterExpression="begins_with(host_id, :p)",
        ExpressionAttributeValues={":p": "__region__"},
    )
    rows = [dict(i) for i in result.get("Items", [])]
    for r in rows:
        r.pop("host_id", None)
    return sorted(rows, key=lambda r: r.get("region", ""))


def save_region_record(db, info: dict) -> None:
    key = {"host_id": f"__region__{info['region']}"}
    existing = db.Table(HOSTS_TABLE).get_item(Key=key).get("Item") or {}
    now = datetime.now(timezone.utc).isoformat()
    created_at = existing.get("created_at") or existing.get("first_deployed_at") or info.get("deployed_at") or now
    item = {
        "host_id": key["host_id"],
        **info,
        "created_at": created_at,
        "first_deployed_at": created_at,
        "last_deployed_at": info.get("deployed_at") or now,
    }
    _log_dynamodb_write("put_item", HOSTS_TABLE, key={"host_id": item["host_id"]}, item=item, context="region_save")
    db.Table(HOSTS_TABLE).put_item(Item=item)


def delete_region_record(db, region: str) -> None:
    _log_dynamodb_write("delete_item", HOSTS_TABLE, key={"host_id": f"__region__{region}"}, context="region_delete")
    db.Table(HOSTS_TABLE).delete_item(Key={"host_id": f"__region__{region}"})
