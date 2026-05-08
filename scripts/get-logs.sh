#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/get-logs.sh <home-region> [options]
  ./scripts/get-logs.sh help

Arguments:
  home-region
    AWS region where uptime-management is deployed.

Options:
  --function-name <name>
    Lambda function name for management logs.
    Default: DEPLOY_FUNCTION_NAME or uptime-management.

  --scope <management|worker>
    Which log group to read.
    Default: management.

  --worker-region <region>
    Worker/probe region when --scope worker is used.

  --project <name>
    Project prefix for worker functions.
    Default: PROJECT or uptime.

  --since <duration>
    CloudWatch lookback duration accepted by aws logs tail, such as 10m, 2h, 1d.
    Default: 1h.

  --request-id <id>
    Filter for a Lambda request id from a 500 response.

  --filter <pattern>
    Raw CloudWatch Logs filter pattern. Ignored when --request-id is set.

  --follow
    Continue streaming new log lines.

  --format <short|detailed|json>
    Output format passed to aws logs tail.
    Default: short.

Examples:
  ./scripts/get-logs.sh eu-central-1
  ./scripts/get-logs.sh eu-central-1 --since 30m --request-id 4c1bf183-4599-472d-a142-b03280f0687d
  ./scripts/get-logs.sh eu-central-1 --scope worker --worker-region il-central-1 --since 2h
EOF
}

if [[ "${1:-}" == "" || "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

HOME_REGION="$1"
shift

FUNCTION_NAME="${DEPLOY_FUNCTION_NAME:-uptime-management}"
PROJECT_NAME="${PROJECT:-uptime}"
SCOPE="management"
WORKER_REGION=""
SINCE="1h"
FILTER_PATTERN=""
REQUEST_ID=""
FOLLOW=0
FORMAT="short"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --function-name)
      FUNCTION_NAME="${2:-}"
      shift 2
      ;;
    --scope)
      SCOPE="${2:-}"
      shift 2
      ;;
    --worker-region)
      WORKER_REGION="${2:-}"
      shift 2
      ;;
    --project)
      PROJECT_NAME="${2:-}"
      shift 2
      ;;
    --since)
      SINCE="${2:-}"
      shift 2
      ;;
    --request-id)
      REQUEST_ID="${2:-}"
      shift 2
      ;;
    --filter)
      FILTER_PATTERN="${2:-}"
      shift 2
      ;;
    --follow)
      FOLLOW=1
      shift
      ;;
    --format)
      FORMAT="${2:-}"
      shift 2
      ;;
    *)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

if [[ "$SCOPE" != "management" && "$SCOPE" != "worker" ]]; then
  echo "error: --scope must be management or worker" >&2
  exit 2
fi

if [[ "$FORMAT" != "short" && "$FORMAT" != "detailed" && "$FORMAT" != "json" ]]; then
  echo "error: --format must be short, detailed, or json" >&2
  exit 2
fi

REGION="$HOME_REGION"
if [[ "$SCOPE" == "worker" ]]; then
  if [[ -z "$WORKER_REGION" ]]; then
    echo "error: --worker-region is required with --scope worker" >&2
    exit 2
  fi
  REGION="$WORKER_REGION"
  FUNCTION_NAME="${PROJECT_NAME}-monitor-${WORKER_REGION}"
fi

LOG_GROUP="/aws/lambda/${FUNCTION_NAME}"
if [[ -n "$REQUEST_ID" ]]; then
  FILTER_PATTERN="\"${REQUEST_ID}\""
fi

echo "Reading CloudWatch logs"
echo "  Region: ${REGION}"
echo "  Log group: ${LOG_GROUP}"
echo "  Since: ${SINCE}"
if [[ -n "$FILTER_PATTERN" ]]; then
  echo "  Filter: ${FILTER_PATTERN}"
fi
echo ""

cmd=(aws logs tail "$LOG_GROUP" --region "$REGION" --since "$SINCE" --format "$FORMAT")
if [[ -n "$FILTER_PATTERN" ]]; then
  cmd+=(--filter-pattern "$FILTER_PATTERN")
fi
if [[ "$FOLLOW" -eq 1 ]]; then
  cmd+=(--follow)
fi

"${cmd[@]}"
