#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/deploy-new-version.sh <home-region> [notify-topic-arn]
  ./scripts/deploy-new-version.sh help

Arguments:
  home-region
    AWS region where the live uptime-management Lambda is deployed.
    Supported values:
      us-east-1
      eu-west-1
      eu-central-1
      ap-southeast-1

  notify-topic-arn
    Optional SNS topic ARN to notify after a successful deploy.
    If omitted, the script also checks DEPLOY_NOTIFY_SNS_ARN.

Notes:
  - Publishes the latest artifacts to the template bucket and all supported regional artifact buckets.
  - Updates the management Lambda code in the chosen home region.
  - Can optionally force-update all deployed probes to the same worker build.
  - Optionally sends an SNS notification after a successful deploy.

Examples:
  ./scripts/deploy-new-version.sh eu-central-1
  ./scripts/deploy-new-version.sh eu-central-1 arn:aws:sns:eu-central-1:123456789012:uptime-deploys
EOF
}

if [[ "${1:-}" == "" || "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
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
INTERACTIVE=0
[[ -t 1 ]] && INTERACTIVE=1
LOG_DIR="$(mktemp -d "${TMPDIR:-/tmp}/uptime-deploy.XXXXXX")"

cleanup_tmp() {
  rm -rf "$LOG_DIR"
}
trap cleanup_tmp EXIT

render_progress() {
  local current="$1"
  local total="$2"
  local label="$3"

  if [[ "$INTERACTIVE" -eq 1 ]]; then
    local width=28
    local filled=$(( current * width / total ))
    local empty=$(( width - filled ))
    local filled_bar
    local empty_bar
    filled_bar="$(printf '%*s' "$filled" '' | tr ' ' '#')"
    empty_bar="$(printf '%*s' "$empty" '' | tr ' ' '.')"
    printf "\r["
    printf "%s%s] %d/%d %s" "$filled_bar" "$empty_bar" "$current" "$total" "$label"
  else
    echo "→ ${label}"
  fi
}

prompt_force_update_probes() {
  if [[ "${FORCE_UPDATE_PROBES:-}" == "1" || "${FORCE_UPDATE_PROBES:-}" == "true" || "${FORCE_UPDATE_PROBES:-}" == "yes" ]]; then
    return 0
  fi
  if [[ "${FORCE_UPDATE_PROBES:-}" == "0" || "${FORCE_UPDATE_PROBES:-}" == "false" || "${FORCE_UPDATE_PROBES:-}" == "no" ]]; then
    return 1
  fi
  if [[ "$INTERACTIVE" -ne 1 ]]; then
    return 1
  fi
  echo ""
  read -r -p "Force update all deployed probes to worker build ${VERSION}? [y/N] " reply
  case "${reply}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

finish_progress_line() {
  [[ "$INTERACTIVE" -eq 1 ]] && printf "\n"
}

show_log_excerpt() {
  local log_file="$1"
  if [[ -f "$log_file" ]]; then
    echo ""
    echo "Last log lines from ${log_file}:"
    tail -n 20 "$log_file" || true
  fi
}

run_step() {
  local current="$1"
  local total="$2"
  local label="$3"
  local log_file="$4"
  shift 4

  render_progress "$current" "$total" "$label"
  if ! "$@" >"$log_file" 2>&1; then
    finish_progress_line
    echo "error: ${label}"
    show_log_excerpt "$log_file"
    exit 1
  fi
}

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

[[ "$PREFIX" == /* ]] && { echo "error: prefix must be relative (no leading /)"; exit 1; }
PREFIX_ROOT="${PREFIX%/}"
ARTIFACT_KEY="${PREFIX_ROOT}/releases/management.zip"
DEPLOYED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSION="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M%S)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
VERSIONED_PREFIX="${PREFIX_ROOT}/releases/${VERSION}"
SOURCE_VERSIONED_URI="s3://${TEMPLATE_BUCKET}/${VERSIONED_PREFIX}/"

echo "→ Deploying version specification"
echo "  Version: ${VERSION}"
echo "  Built at: ${BUILT_AT}"
echo "  Home region: ${HOME_REGION}"
echo "  Expected worker build: ${VERSION}"
echo "  Pinned artifact path: ${SOURCE_VERSIONED_URI}management.zip"
echo ""

replicate_bucket() {
  local bucket="$1"
  local log_file="$2"
  local stage_uri="s3://${bucket}/${PREFIX_ROOT}/staging/${VERSION}/"
  local versioned_uri="s3://${bucket}/${VERSIONED_PREFIX}/"

  {
  aws s3 rm "${stage_uri}" --recursive --quiet 2>/dev/null || true
  aws s3 sync "${SOURCE_VERSIONED_URI}" "${stage_uri}" --delete

  aws s3 cp "${stage_uri}management.zip" "s3://${bucket}/${PREFIX_ROOT}/releases/management.zip"
  aws s3 cp "${stage_uri}uptime-bootstrap.yaml" "s3://${bucket}/${PREFIX_ROOT}/cloudformation/uptime-bootstrap.yaml"
  aws s3 cp "${stage_uri}uptime-artifacts.yaml" "s3://${bucket}/${PREFIX_ROOT}/cloudformation/uptime-artifacts.yaml"

  aws s3 mv "${stage_uri}management.zip" "${versioned_uri}management.zip"
  aws s3 mv "${stage_uri}uptime-bootstrap.yaml" "${versioned_uri}uptime-bootstrap.yaml"
  aws s3 mv "${stage_uri}uptime-artifacts.yaml" "${versioned_uri}uptime-artifacts.yaml"
  } >"$log_file" 2>&1 || {
    aws s3 rm "${stage_uri}" --recursive --quiet 2>/dev/null || true
    return 1
  }
}

TOTAL_STEPS=3
WILL_FORCE_UPDATE_PROBES=0
if prompt_force_update_probes; then
  WILL_FORCE_UPDATE_PROBES=1
  TOTAL_STEPS=$((TOTAL_STEPS + 1))
fi
[[ -n "$NOTIFY_TOPIC_ARN" ]] && TOTAL_STEPS=4
if [[ -n "$NOTIFY_TOPIC_ARN" && "$WILL_FORCE_UPDATE_PROBES" -eq 1 ]]; then
  TOTAL_STEPS=5
fi
CURRENT_STEP=1

run_step "$CURRENT_STEP" "$TOTAL_STEPS" "Publishing source artifacts to ${TEMPLATE_BUCKET}" "$LOG_DIR/publish-source.log" \
  bash "$REPO_ROOT/scripts/publish-artifacts.sh" "$TEMPLATE_BUCKET" "$PREFIX_ROOT"

CURRENT_STEP=$((CURRENT_STEP + 1))
declare -a PIDS=()
declare -a PID_BUCKETS=()
declare -a PID_LOGS=()
declare -a PID_DONE=()
for bucket in "${REGIONAL_BUCKETS[@]}"; do
  if [[ "$bucket" == "$TEMPLATE_BUCKET" ]]; then
    continue
  fi
  log_file="$LOG_DIR/replicate-${bucket}.log"
  (
    replicate_bucket "$bucket" "$log_file"
  ) &
  PIDS+=("$!")
  PID_BUCKETS+=("$bucket")
  PID_LOGS+=("$log_file")
  PID_DONE+=(0)
done

COMPLETED_BUCKETS=0
TOTAL_BUCKETS="${#PIDS[@]}"
render_progress "$CURRENT_STEP" "$TOTAL_STEPS" "Replicating artifacts to ${COMPLETED_BUCKETS}/${TOTAL_BUCKETS} regional buckets"

while (( COMPLETED_BUCKETS < TOTAL_BUCKETS )); do
  for i in "${!PIDS[@]}"; do
    if [[ "${PID_DONE[$i]}" -eq 1 ]]; then
      continue
    fi

    if ! kill -0 "${PIDS[$i]}" 2>/dev/null; then
      if ! wait "${PIDS[$i]}"; then
        finish_progress_line
        echo "error: replication failed for ${PID_BUCKETS[$i]}"
        show_log_excerpt "${PID_LOGS[$i]}"
        exit 1
      fi
      PID_DONE[$i]=1
      COMPLETED_BUCKETS=$((COMPLETED_BUCKETS + 1))
      render_progress "$CURRENT_STEP" "$TOTAL_STEPS" "Replicating artifacts to ${COMPLETED_BUCKETS}/${TOTAL_BUCKETS} regional buckets"
    fi
  done
  sleep 0.2
done

CURRENT_STEP=$((CURRENT_STEP + 1))
render_progress "$CURRENT_STEP" "$TOTAL_STEPS" "Updating ${FUNCTION_NAME} in ${HOME_REGION}"
if ! aws lambda update-function-code \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME" \
  --s3-bucket "$ARTIFACT_BUCKET" \
  --s3-key "$ARTIFACT_KEY" \
  --publish >"$LOG_DIR/lambda-update.log" 2>&1; then
  finish_progress_line
  echo "error: Updating ${FUNCTION_NAME} in ${HOME_REGION}"
  show_log_excerpt "$LOG_DIR/lambda-update.log"
  exit 1
fi
render_progress "$CURRENT_STEP" "$TOTAL_STEPS" "Waiting for ${FUNCTION_NAME} update to finish"
if ! aws lambda wait function-updated \
  --region "$HOME_REGION" \
  --function-name "$FUNCTION_NAME" >"$LOG_DIR/lambda-wait.log" 2>&1; then
  finish_progress_line
  echo "error: Waiting for ${FUNCTION_NAME} update to finish"
  show_log_excerpt "$LOG_DIR/lambda-wait.log"
  exit 1
fi

FUNCTION_URL="$(
  aws lambda get-function-url-config \
    --region "$HOME_REGION" \
    --function-name "$FUNCTION_NAME" \
    --query FunctionUrl \
    --output text 2>/dev/null || true
)"

if [[ "$WILL_FORCE_UPDATE_PROBES" -eq 1 ]]; then
  CURRENT_STEP=$((CURRENT_STEP + 1))
  render_progress "$CURRENT_STEP" "$TOTAL_STEPS" "Force updating all deployed probes"
  if ! aws lambda invoke \
    --region "$HOME_REGION" \
    --function-name "$FUNCTION_NAME" \
    --cli-binary-format raw-in-base64-out \
    --payload '{"action":"force_update_probes"}' \
    "$LOG_DIR/force-update-probes.json" >"$LOG_DIR/force-update-probes.log" 2>&1; then
    finish_progress_line
    echo "error: Force updating all deployed probes"
    show_log_excerpt "$LOG_DIR/force-update-probes.log"
    exit 1
  fi
  if ! python3 - <<'PY' "$LOG_DIR/force-update-probes.json"
import json, sys
path = sys.argv[1]
with open(path) as f:
    payload = json.load(f)
body = payload.get("body")
data = json.loads(body) if isinstance(body, str) else payload
ok = data.get("ok", False)
if not ok:
    raise SystemExit(1)
PY
  then
    finish_progress_line
    echo "error: Force updating all deployed probes"
    show_log_excerpt "$LOG_DIR/force-update-probes.json"
    exit 1
  fi
fi

cat > "$REPO_ROOT/dist/deploy-last.json" <<EOF
{
  "version": "$VERSION",
  "built_at": "$BUILT_AT",
  "home_region": "$HOME_REGION",
  "function_name": "$FUNCTION_NAME",
  "template_bucket": "$TEMPLATE_BUCKET",
  "published_regional_buckets": ["${REGIONAL_BUCKETS[0]}", "${REGIONAL_BUCKETS[1]}", "${REGIONAL_BUCKETS[2]}", "${REGIONAL_BUCKETS[3]}"],
  "artifact_bucket": "$ARTIFACT_BUCKET",
  "artifact_key": "$ARTIFACT_KEY",
  "force_updated_probes": $([[ "$WILL_FORCE_UPDATE_PROBES" -eq 1 ]] && echo true || echo false),
  "function_url": "$FUNCTION_URL",
  "deployed_at": "$DEPLOYED_AT"
}
EOF

if [[ -n "$NOTIFY_TOPIC_ARN" ]]; then
  CURRENT_STEP=$((CURRENT_STEP + 1))
  run_step "$CURRENT_STEP" "$TOTAL_STEPS" "Sending deployment notification" "$LOG_DIR/sns-publish.log" \
    aws sns publish \
      --region "$HOME_REGION" \
      --topic-arn "$NOTIFY_TOPIC_ARN" \
      --subject "Uptime deployed: ${VERSION}" \
      --message "Uptime deployment completed.

Version: ${VERSION}
Built at: ${BUILT_AT}
Region: ${HOME_REGION}
Function: ${FUNCTION_NAME}
URL: ${FUNCTION_URL:-not configured}
Time: ${DEPLOYED_AT}"
fi

render_progress "$TOTAL_STEPS" "$TOTAL_STEPS" "Deployment complete"
finish_progress_line

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    echo "### Uptime deploy completed"
    echo ""
    echo "- Version: \`${VERSION}\`"
    echo "- Built at: \`${BUILT_AT}\`"
    echo "- Home region: \`${HOME_REGION}\`"
    echo "- Function: \`${FUNCTION_NAME}\`"
    echo "- Force-updated probes: \`$([[ "$WILL_FORCE_UPDATE_PROBES" -eq 1 ]] && echo yes || echo no)\`"
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
echo "  Built at: ${BUILT_AT}"
echo "  Region: ${HOME_REGION}"
echo "  Function: ${FUNCTION_NAME}"
echo "  Force-updated probes: $([[ "$WILL_FORCE_UPDATE_PROBES" -eq 1 ]] && echo yes || echo no)"
echo "  Expected worker build: ${VERSION}"
echo "  Pinned artifact path: ${SOURCE_VERSIONED_URI}management.zip"
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
