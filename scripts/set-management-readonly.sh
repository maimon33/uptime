#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/set-management-readonly.sh enable <home-region>
  ./scripts/set-management-readonly.sh disable <home-region>
  ./scripts/set-management-readonly.sh help

Arguments:
  enable | disable
    enable:
      turns on read-only mode
    disable:
      turns off read-only mode

  home-region
    AWS region where the live uptime-management Lambda is deployed.

Notes:
  - Sets or unsets the READ_ONLY_MODE Lambda environment variable.
  - Adds or removes an explicit deny inline policy on the management role.
  - Reads remain available; writes are explicitly denied while enabled.

Examples:
  ./scripts/set-management-readonly.sh enable eu-central-1
  ./scripts/set-management-readonly.sh disable eu-central-1
EOF
}

if [[ "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ $# -ne 2 ]]; then
  usage
  exit 0
fi

MODE="$1"
HOME_REGION="$2"
FUNCTION_NAME="${DEPLOY_FUNCTION_NAME:-uptime-management}"
DENY_POLICY_NAME="${READ_ONLY_DENY_POLICY_NAME:-${FUNCTION_NAME}-readonly-deny}"

if [[ "$MODE" != "enable" && "$MODE" != "disable" ]]; then
  echo "error: mode must be 'enable' or 'disable'"
  exit 1
fi

CONFIG_JSON="$(aws lambda get-function-configuration \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME" \
  --output json)"

ROLE_ARN="$(python3 - <<'PY' "$CONFIG_JSON"
import json, sys
cfg = json.loads(sys.argv[1])
print(cfg["Role"])
PY
)"

ROLE_NAME="${ROLE_ARN##*/}"
ENV_PAYLOAD="$(python3 - <<'PY' "$CONFIG_JSON" "$MODE"
import json, sys
cfg = json.loads(sys.argv[1])
mode = sys.argv[2]
vars = dict((cfg.get("Environment") or {}).get("Variables") or {})
if mode == "enable":
    vars["READ_ONLY_MODE"] = "true"
else:
    vars.pop("READ_ONLY_MODE", None)
print(json.dumps({"Variables": vars}, separators=(",", ":")))
PY
)"

echo "→ Updating Lambda environment for ${FUNCTION_NAME} in ${HOME_REGION}..."
aws lambda update-function-configuration \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME" \
  --environment "$ENV_PAYLOAD" >/tmp/uptime-readonly-update.json

echo "→ Waiting for Lambda configuration update..."
aws lambda wait function-updated \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME"

if [[ "$MODE" == "enable" ]]; then
  echo "→ Applying explicit deny policy to role ${ROLE_NAME}..."
  POLICY_DOC="$(cat <<'JSON'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyStateChanges",
      "Effect": "Deny",
      "Action": [
        "dynamodb:BatchWriteItem",
        "dynamodb:DeleteItem",
        "dynamodb:PutItem",
        "dynamodb:UpdateItem",
        "dynamodb:UpdateTable",
        "sns:Publish",
        "lambda:CreateFunction",
        "lambda:DeleteFunction",
        "lambda:InvokeFunction",
        "lambda:RemovePermission",
        "lambda:UpdateFunctionCode",
        "lambda:UpdateFunctionConfiguration",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:PassRole",
        "iam:PutRolePolicy",
        "acm:AddTagsToCertificate",
        "acm:DeleteCertificate",
        "acm:RequestCertificate",
        "cloudfront:CreateDistribution",
        "cloudfront:DeleteDistribution",
        "cloudfront:TagResource",
        "cloudfront:UntagResource",
        "cloudfront:UpdateDistribution",
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:DeleteLogGroup",
        "logs:PutLogEvents",
        "logs:PutRetentionPolicy"
      ],
      "Resource": "*"
    }
  ]
}
JSON
)"
  aws iam put-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "$DENY_POLICY_NAME" \
    --policy-document "$POLICY_DOC"
  echo "✓ Read-only mode enabled"
  echo "  Function: ${FUNCTION_NAME}"
  echo "  Region: ${HOME_REGION}"
  echo "  Role: ${ROLE_NAME}"
  echo "  Deny policy: ${DENY_POLICY_NAME}"
else
  echo "→ Removing explicit deny policy from role ${ROLE_NAME}..."
  aws iam delete-role-policy \
    --role-name "$ROLE_NAME" \
    --policy-name "$DENY_POLICY_NAME" 2>/dev/null || true
  echo "✓ Read-only mode disabled"
  echo "  Function: ${FUNCTION_NAME}"
  echo "  Region: ${HOME_REGION}"
  echo "  Role: ${ROLE_NAME}"
fi
