#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/deploy-new-version.sh <home-region> [notify-topic-arn]

Examples:
  ./scripts/deploy-new-version.sh eu-central-1
  ./scripts/deploy-new-version.sh eu-central-1 arn:aws:sns:eu-central-1:123456789012:uptime-deploys

Notes:
  - Publishes the latest artifacts to the template bucket and all supported regional artifact buckets.
  - Updates the management Lambda code in the chosen home region.
  - Optionally sends an SNS notification after a successful deploy.
EOF
}

if [[ "${1:-}" == "" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

HOME_REGION="$1"
NOTIFY_TOPIC_ARN="${2:-${DEPLOY_NOTIFY_SNS_ARN:-}}"
FUNCTION_NAME="${DEPLOY_FUNCTION_NAME:-uptime-management}"
PREFIX="${DEPLOY_ARTIFACT_PREFIX:-uptime}"
TEMPLATE_BUCKET="${DEPLOY_TEMPLATE_BUCKET:-www.maimons.dev}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REGIONAL_BUCKETS=(
  "uptime-artifacts-us-east-1.maimons.dev"
  "uptime-artifacts-eu-west-1.maimons.dev"
  "uptime-artifacts-eu-central-1.maimons.dev"
  "uptime-artifacts-ap-southeast-1.maimons.dev"
)

case "$HOME_REGION" in
  us-east-1) ARTIFACT_BUCKET="uptime-artifacts-us-east-1.maimons.dev" ;;
  eu-west-1) ARTIFACT_BUCKET="uptime-artifacts-eu-west-1.maimons.dev" ;;
  eu-central-1) ARTIFACT_BUCKET="uptime-artifacts-eu-central-1.maimons.dev" ;;
  ap-southeast-1) ARTIFACT_BUCKET="uptime-artifacts-ap-southeast-1.maimons.dev" ;;
  *)
    echo "error: unsupported home region: $HOME_REGION"
    echo "supported regions: us-east-1, eu-west-1, eu-central-1, ap-southeast-1"
    exit 1
    ;;
esac

ARTIFACT_KEY="${PREFIX%/}/releases/management.zip"
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M%S)"

echo "→ Publishing latest artifacts..."
bash "$REPO_ROOT/scripts/publish-artifacts.sh" "$TEMPLATE_BUCKET" "$PREFIX"
declare -a PIDS=()
declare -a PID_BUCKETS=()
for bucket in "${REGIONAL_BUCKETS[@]}"; do
  if [[ "$bucket" == "$TEMPLATE_BUCKET" ]]; then
    continue
  fi
  echo "→ Publishing regional artifact bundle to ${bucket} in parallel..."
  (
    bash "$REPO_ROOT/scripts/publish-artifacts.sh" "$bucket" "$PREFIX"
  ) &
  PIDS+=("$!")
  PID_BUCKETS+=("$bucket")
done

for i in "${!PIDS[@]}"; do
  if ! wait "${PIDS[$i]}"; then
    echo "error: publish failed for ${PID_BUCKETS[$i]}"
    exit 1
  fi
done

echo ""
echo "→ Updating ${FUNCTION_NAME} in ${HOME_REGION} from s3://${ARTIFACT_BUCKET}/${ARTIFACT_KEY}"
aws lambda update-function-code \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME" \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --s3-key "$ARTIFACT_KEY" \
  --publish >/tmp/uptime-deploy-update.json

echo "→ Waiting for Lambda update to finish..."
aws lambda wait function-updated \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME"

FUNCTION_URL="$(
  aws lambda get-function-url-config \
    --region "$HOME_REGION" \
    --function-name "$FUNCTION_NAME" \
    --query FunctionUrl \
    --output text 2>/dev/null || true
)"

cat > "$REPO_ROOT/dist/deploy-last.json" <<EOF
{
  "version": "$VERSION",
  "home_region": "$HOME_REGION",
  "function_name": "$FUNCTION_NAME",
  "template_bucket": "$TEMPLATE_BUCKET",
  "published_regional_buckets": ["${REGIONAL_BUCKETS[0]}", "${REGIONAL_BUCKETS[1]}", "${REGIONAL_BUCKETS[2]}", "${REGIONAL_BUCKETS[3]}"],
  "artifact_bucket": "$ARTIFACT_BUCKET",
  "artifact_key": "$ARTIFACT_KEY",
  "function_url": "$FUNCTION_URL",
  "deployed_at": "$DEPLOYED_AT"
}
EOF

if [[ -n "$NOTIFY_TOPIC_ARN" ]]; then
  echo "→ Sending deployment notification to SNS..."
  aws sns publish \
    --region "$HOME_REGION" \
    --topic-arn "$NOTIFY_TOPIC_ARN" \
    --subject "Uptime deployed: ${VERSION}" \
    --message "Uptime deployment completed.

Version: ${VERSION}
Region: ${HOME_REGION}
Function: ${FUNCTION_NAME}
URL: ${FUNCTION_URL:-not configured}
Time: ${DEPLOYED_AT}"
fi

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Uptime deploy completed"
    echo ""
    echo "- Version: \`${VERSION}\`"
    echo "- Home region: \`${HOME_REGION}\`"
    echo "- Function: \`${FUNCTION_NAME}\`"
    echo "- Template bucket: \`s3://${TEMPLATE_BUCKET}/${PREFIX%/}/cloudformation/uptime-bootstrap.yaml\`"
    echo "- Regional buckets:"
    for bucket in "${REGIONAL_BUCKETS[@]}"; do
      echo "  - \`s3://${bucket}/${ARTIFACT_KEY}\`"
    done
    echo "- Artifact: \`s3://${ARTIFACT_BUCKET}/${ARTIFACT_KEY}\`"
    if [[ -n "$FUNCTION_URL" ]]; then
      echo "- Status page: ${FUNCTION_URL}"
    fi
    if [[ -n "$NOTIFY_TOPIC_ARN" ]]; then
      echo "- Notification topic: \`${NOTIFY_TOPIC_ARN}\`"
    fi
  } >> "$GITHUB_STEP_SUMMARY"
fi

echo ""
echo "✓ Deployment complete"
echo "  Version: ${VERSION}"
echo "  Region: ${HOME_REGION}"
echo "  Function: ${FUNCTION_NAME}"
echo "  Template bucket: s3://${TEMPLATE_BUCKET}/${PREFIX%/}/cloudformation/uptime-bootstrap.yaml"
echo "  Published regional buckets:"
for bucket in "${REGIONAL_BUCKETS[@]}"; do
  echo "    - s3://${bucket}/${ARTIFACT_KEY}"
done
echo "  Artifact: s3://${ARTIFACT_BUCKET}/${ARTIFACT_KEY}"
if [[ -n "$FUNCTION_URL" ]]; then
  echo "  Status page: ${FUNCTION_URL}"
fi
echo "  Summary: $REPO_ROOT/dist/deploy-last.json"
