#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/deploy-cf-template.sh <region> [stack-name]
  ./scripts/deploy-cf-template.sh help

Arguments:
  region
    AWS region where the uptime CloudFormation stack already exists or should be created.

  stack-name
    CloudFormation stack name.
    Default: uptime

Environment overrides:
  CF_TEMPLATE_BUCKET
    Public bucket holding uptime-bootstrap.yaml when CF_TEMPLATE_SOURCE=remote.
    Default: www.maimons.dev

  CF_ARTIFACT_PREFIX
    Prefix inside the template bucket when CF_TEMPLATE_SOURCE=remote.
    Default: uptime

  CF_TEMPLATE_SOURCE
    Template source to apply.
    Allowed values: local, remote
    Default: local

  CF_ADMIN_API_KEY
    Optional admin password/token override. Usually leave unset on stack updates.

  CF_ADMIN_AUTH_MODE
    Optional admin auth mode override.
    Example: password or cognito

  CF_ADMIN_ALLOWED_IP_CIDRS
    Optional comma-separated IP allowlist for /admin and /api.

  CF_COGNITO_MANAGED_DOMAIN_PREFIX
    Optional Cognito managed domain prefix override.

  CF_COGNITO_ALLOWED_EMAIL_DOMAIN
    Optional Cognito allowed email domain hint.

  CF_COGNITO_MFA_MODE
    Optional Cognito MFA mode override.
    Allowed values: OFF, OPTIONAL, ON

What it does:
  - Uses the local bootstrap template by default.
  - Can optionally fetch the published template from S3 instead.
  - Updates the named stack in-place, or creates it if missing.
  - Preserves existing parameter values unless you explicitly override them above.
  - Applies IAM/template changes such as new Lambda permissions or policy updates.

Examples:
  ./scripts/deploy-cf-template.sh eu-central-1
  ./scripts/deploy-cf-template.sh eu-central-1 uptime
  CF_ADMIN_ALLOWED_IP_CIDRS=203.0.113.10/32 ./scripts/deploy-cf-template.sh eu-central-1
EOF
}

if [[ "${1:-}" == "" || "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

REGION="${1:?region is required}"
STACK_NAME="${2:-uptime}"
TEMPLATE_BUCKET="${CF_TEMPLATE_BUCKET:-www.maimons.dev}"
PREFIX="${CF_ARTIFACT_PREFIX:-uptime}"
TEMPLATE_SOURCE="${CF_TEMPLATE_SOURCE:-local}"
TMP_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptime-cf.XXXXXX")"
TEMPLATE_FILE="${TMP_DIR}/uptime-bootstrap.yaml"
PARAMS_FILE="${TMP_DIR}/parameters.json"

cleanup_tmp() {
  rm -rf "$TMP_DIR"
}
trap cleanup_tmp EXIT

[[ "$PREFIX" == /* ]] && { echo "error: CF_ARTIFACT_PREFIX must be relative (no leading /)"; exit 1; }
PREFIX_ROOT="${PREFIX%/}"
TEMPLATE_URL="https://s3.amazonaws.com/${TEMPLATE_BUCKET}/${PREFIX_ROOT}/cloudformation/uptime-bootstrap.yaml"
LOCAL_TEMPLATE_FILE="$(cd "$(dirname "$0")/.." && pwd)/cloudformation/uptime-bootstrap.yaml"

STACK_EXISTS=0
if aws cloudformation describe-stacks --region "$REGION" --stack-name "$STACK_NAME" >/dev/null 2>&1; then
  STACK_EXISTS=1
fi

echo "→ CloudFormation template deploy"
echo "  Region: ${REGION}"
echo "  Stack: ${STACK_NAME}"
echo "  Mode: $([[ "$STACK_EXISTS" -eq 1 ]] && echo update || echo create)"
case "$TEMPLATE_SOURCE" in
  local)
    cp "$LOCAL_TEMPLATE_FILE" "$TEMPLATE_FILE"
    echo "  Template: ${LOCAL_TEMPLATE_FILE}"
    ;;
  remote)
    curl -fsSL "$TEMPLATE_URL" -o "$TEMPLATE_FILE"
    echo "  Template: ${TEMPLATE_URL}"
    ;;
  *)
    echo "error: CF_TEMPLATE_SOURCE must be local or remote"
    exit 1
    ;;
esac

python3 - "$PARAMS_FILE" "$STACK_EXISTS" <<'PY'
import json
import os
import sys

path = sys.argv[1]
stack_exists = sys.argv[2] == "1"

mapping = [
    ("AdminApiKey", "CF_ADMIN_API_KEY"),
    ("AdminAuthMode", "CF_ADMIN_AUTH_MODE"),
    ("AdminAllowedIpCidrs", "CF_ADMIN_ALLOWED_IP_CIDRS"),
    ("CognitoManagedDomainPrefix", "CF_COGNITO_MANAGED_DOMAIN_PREFIX"),
    ("CognitoAllowedEmailDomain", "CF_COGNITO_ALLOWED_EMAIL_DOMAIN"),
    ("CognitoMfaMode", "CF_COGNITO_MFA_MODE"),
]

params = []
for key, env_name in mapping:
    value = os.environ.get(env_name)
    if value is not None and value != "":
        params.append({"ParameterKey": key, "ParameterValue": value})
    elif stack_exists:
        params.append({"ParameterKey": key, "UsePreviousValue": True})

with open(path, "w", encoding="utf-8") as handle:
    json.dump(params, handle)
PY

if [[ -s "$PARAMS_FILE" ]]; then
  echo "  Overrides:"
  python3 - "$PARAMS_FILE" <<'PY'
import json
import sys

params = json.load(open(sys.argv[1], encoding="utf-8"))
for item in params:
    key = item["ParameterKey"]
    if item.get("UsePreviousValue"):
        print(f"    - {key}=<previous>")
    elif key == "AdminApiKey":
        print(f"    - {key}=***")
    else:
        print(f"    - {key}={item.get('ParameterValue', '')}")
PY
else
  echo "  Overrides: none"
fi
echo ""

common_args=(
  --region "$REGION"
  --stack-name "$STACK_NAME"
  --template-body "file://${TEMPLATE_FILE}"
  --capabilities CAPABILITY_NAMED_IAM
  --parameters "file://${PARAMS_FILE}"
)

if [[ "$STACK_EXISTS" -eq 1 ]]; then
  set +e
  update_output="$(
    aws cloudformation update-stack \
      "${common_args[@]}" \
      2>&1
  )"
  update_status=$?
  set -e

  if [[ "$update_status" -ne 0 ]]; then
    if [[ "$update_output" == *"No updates are to be performed"* ]]; then
      echo "✓ CloudFormation template already up to date"
      echo "  Region: ${REGION}"
      echo "  Stack: ${STACK_NAME}"
      exit 0
    fi
    echo "$update_output" >&2
    exit "$update_status"
  fi

  echo "$update_output"
  aws cloudformation wait stack-update-complete --region "$REGION" --stack-name "$STACK_NAME"
else
  aws cloudformation create-stack "${common_args[@]}"
  aws cloudformation wait stack-create-complete --region "$REGION" --stack-name "$STACK_NAME"
fi

echo ""
echo "✓ CloudFormation template applied"
echo "  Region: ${REGION}"
echo "  Stack: ${STACK_NAME}"
echo "  Template source: ${TEMPLATE_SOURCE}"
