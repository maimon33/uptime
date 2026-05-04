#!/usr/bin/env bash
set -euo pipefail

REGION="${1:-}"
STACK_NAME="${2:-}"
EMAIL="${3:-}"
TEMP_PASSWORD="${4:-}"

usage() {
  cat <<EOF
Usage:
  ./scripts/create-cognito-admin-user.sh <region> <stack-name> <email> [temporary-password]
  ./scripts/create-cognito-admin-user.sh help

Arguments:
  region
    AWS region where the uptime CloudFormation stack was deployed.

  stack-name
    CloudFormation stack name.

  email
    Email address for the Cognito admin user to create.

  temporary-password
    Optional temporary password to set explicitly.
    If omitted, Cognito chooses the invite flow behavior.

Example:
  ./scripts/create-cognito-admin-user.sh eu-central-1 uptime you@maimons.dev
EOF
}

if [[ "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ -z "$REGION" || -z "$STACK_NAME" || -z "$EMAIL" ]]; then
  usage
  exit 1
fi

USER_POOL_ID="$(
  aws cloudformation describe-stacks \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolId'].OutputValue" \
    --output text
)"

CLIENT_ID="$(
  aws cloudformation describe-stacks \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='CognitoUserPoolClientId'].OutputValue" \
    --output text
)"

MANAGED_LOGIN_DOMAIN="$(
  aws cloudformation describe-stacks \
    --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --query "Stacks[0].Outputs[?OutputKey=='CognitoManagedLoginDomain'].OutputValue" \
    --output text
)"

if [[ -z "$USER_POOL_ID" || "$USER_POOL_ID" == "None" ]]; then
  echo "No CognitoUserPoolId output found. Was the stack deployed with AdminAuthMode=cognito?"
  exit 1
fi

CREATE_ARGS=(
  cognito-idp admin-create-user
  --region "$REGION"
  --user-pool-id "$USER_POOL_ID"
  --username "$EMAIL"
  --user-attributes "Name=email,Value=$EMAIL" "Name=email_verified,Value=true"
)

if [[ -n "$TEMP_PASSWORD" ]]; then
  CREATE_ARGS+=(--temporary-password "$TEMP_PASSWORD")
fi

aws "${CREATE_ARGS[@]}"

cat <<EOF

Created Cognito admin user:
  email: ${EMAIL}
  user-pool-id: ${USER_POOL_ID}
  client-id: ${CLIENT_ID}
EOF

if [[ -n "$MANAGED_LOGIN_DOMAIN" && "$MANAGED_LOGIN_DOMAIN" != "None" ]]; then
  cat <<EOF
  managed-login-domain: ${MANAGED_LOGIN_DOMAIN}
EOF
fi

cat <<EOF

Notes:
  - Open /admin and sign in with this Cognito user.
  - If the user is in FORCE_CHANGE_PASSWORD, the admin login screen will ask for the new password during first sign-in.
  - If MFA is OPTIONAL or ON, the admin login screen will ask for the authenticator code when Cognito challenges for it.
  - If you configured CognitoAllowedEmailDomain, make sure this email matches that domain.
EOF
