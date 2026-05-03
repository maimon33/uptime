#!/usr/bin/env bash
set -euo pipefail

REGION="${1:-eu-central-1}"
STACK_NAME="${2:-uptime}"
DOMAIN_PREFIX="${3:-}"
ALLOWED_EMAIL_DOMAIN="${4:-}"
MFA_MODE="${5:-OPTIONAL}"
ADMIN_ALLOWED_IP_CIDRS="${6:-}"

TEMPLATE_URL="https://www.maimons.dev.s3.amazonaws.com/uptime/cloudformation/uptime-bootstrap.yaml"

usage() {
  cat <<EOF
Usage:
  ./scripts/prepare-cognito-cf.sh <region> <stack-name> <cognito-domain-prefix> [allowed-email-domain] [mfa-mode] [admin-allowed-ip-cidrs]
  ./scripts/prepare-cognito-cf.sh help

Arguments:
  region
    AWS region where the uptime stack will be deployed.

  stack-name
    CloudFormation stack name.

  cognito-domain-prefix
    Managed Cognito login prefix.
    This must be unique in the target region.
    Example:
      my-uptime-admin

  allowed-email-domain
    Optional email domain hint for future Cognito login filtering.
    Example:
      maimons.dev

  mfa-mode
    Optional Cognito MFA mode.
    Allowed values:
      OFF
      OPTIONAL
      ON
    Default:
      OPTIONAL

  admin-allowed-ip-cidrs
    Optional comma-separated CIDR allowlist for /admin and /api.
    Example:
      203.0.113.10/32
      203.0.113.0/24,198.51.100.0/24

Example:
  ./scripts/prepare-cognito-cf.sh eu-central-1 uptime my-uptime-admin maimons.dev OPTIONAL 203.0.113.10/32

Notes:
  - The Cognito managed domain prefix must be globally unique in the target region.
  - Allowed email domain is optional and is stored for the future app-side Cognito auth flow.
  - MFA mode defaults to OPTIONAL.
  - Admin IP allowlisting is optional.
EOF
}

if [[ "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$DOMAIN_PREFIX" ]]; then
  usage
  exit 1
fi

cat <<EOF
aws cloudformation deploy \\
  --region ${REGION} \\
  --stack-name ${STACK_NAME} \\
  --template-url ${TEMPLATE_URL} \\
  --capabilities CAPABILITY_NAMED_IAM \\
  --parameter-overrides \\
    AdminAuthMode=cognito \\
    CognitoManagedDomainPrefix=${DOMAIN_PREFIX} \\
    CognitoAllowedEmailDomain=${ALLOWED_EMAIL_DOMAIN} \\
    CognitoMfaMode=${MFA_MODE} \\
    AdminAllowedIpCidrs=${ADMIN_ALLOWED_IP_CIDRS}
EOF
