#!/usr/bin/env bash
# Publishes release artifacts to S3 atomically.
#
# Strategy:
#   1. Build the zip locally.
#   2. Upload all 3 files to a versioned staging path.
#   3. Only if all 3 succeed: server-side copy to the live paths.
#   4. Move staging files to a permanent versioned archive (for pinning).
#   5. On any failure before step 3: delete staging, leave live paths untouched.
#
# Live paths (what the CFN template defaults point to):
#   s3://BUCKET/PREFIX/releases/management.zip
#   s3://BUCKET/PREFIX/cloudformation/uptime-bootstrap.yaml
#   s3://BUCKET/PREFIX/cloudformation/uptime-artifacts.yaml
#
# Versioned archive (immutable, safe to pin):
#   s3://BUCKET/PREFIX/releases/VERSION/management.zip
#   s3://BUCKET/PREFIX/releases/VERSION/uptime-bootstrap.yaml
#   s3://BUCKET/PREFIX/releases/VERSION/uptime-artifacts.yaml
#
# Usage:
#   ./scripts/publish-artifacts.sh                        # official release → www.maimons.dev
#   ./scripts/publish-artifacts.sh my-bucket my-prefix   # fork → your own bucket

set -euo pipefail

BUCKET="${1:-www.maimons.dev}"
PREFIX="${2:-uptime}"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

[[ "$PREFIX" == /* ]] && { echo "error: prefix must be relative (no leading /)"; exit 1; }
[[ "$PREFIX" != */ ]] && PREFIX="${PREFIX}/"

# Version: git short hash if available, else UTC timestamp
VERSION="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M%S)"

STAGE="s3://${BUCKET}/${PREFIX}staging/${VERSION}"

LIVE_ZIP="${PREFIX}releases/management.zip"
LIVE_BOOTSTRAP="${PREFIX}cloudformation/uptime-bootstrap.yaml"
LIVE_ARTIFACTS="${PREFIX}cloudformation/uptime-artifacts.yaml"

VERSIONED="${PREFIX}releases/${VERSION}"

# ── Cleanup on failure ────────────────────────────────────────────────────────
_cleanup() {
  echo ""
  echo "error: publish failed — rolling back staging upload..."
  aws s3 rm "${STAGE}/" --recursive --quiet 2>/dev/null || true
  echo "Live paths are unchanged."
  exit 1
}
trap _cleanup ERR

# ── 1. Build ──────────────────────────────────────────────────────────────────
echo "→ Packaging (version: ${VERSION})..."
bash "$REPO_ROOT/scripts/package.sh"

# ── 2. Stage all three files ──────────────────────────────────────────────────
# Any failure here triggers _cleanup — live paths are never touched.
echo "→ Staging to ${STAGE}/"
aws s3 cp "$REPO_ROOT/dist/management.zip"                   "${STAGE}/management.zip"
aws s3 cp "$REPO_ROOT/cloudformation/uptime-bootstrap.yaml"  "${STAGE}/uptime-bootstrap.yaml"
aws s3 cp "$REPO_ROOT/cloudformation/uptime-artifacts.yaml"  "${STAGE}/uptime-artifacts.yaml"

# ── 3. Promote to live (server-side copy, no local network involved) ──────────
echo "→ Promoting to live..."
aws s3 cp "${STAGE}/management.zip"          "s3://${BUCKET}/${LIVE_ZIP}"
aws s3 cp "${STAGE}/uptime-bootstrap.yaml"   "s3://${BUCKET}/${LIVE_BOOTSTRAP}"
aws s3 cp "${STAGE}/uptime-artifacts.yaml"   "s3://${BUCKET}/${LIVE_ARTIFACTS}"

# ── 4. Archive versioned copy (move staging → permanent; staging now empty) ───
aws s3 mv "${STAGE}/management.zip"          "s3://${BUCKET}/${VERSIONED}/management.zip"
aws s3 mv "${STAGE}/uptime-bootstrap.yaml"   "s3://${BUCKET}/${VERSIONED}/uptime-bootstrap.yaml"
aws s3 mv "${STAGE}/uptime-artifacts.yaml"   "s3://${BUCKET}/${VERSIONED}/uptime-artifacts.yaml"

trap - ERR

# ── Summary ───────────────────────────────────────────────────────────────────
TEMPLATE_URL="https://${BUCKET}.s3.amazonaws.com/${LIVE_BOOTSTRAP}"

echo ""
echo "✓ Published version: ${VERSION}"
echo ""
echo "Live (CFN template defaults):"
echo "  s3://${BUCKET}/${LIVE_ZIP}"
echo "  s3://${BUCKET}/${LIVE_BOOTSTRAP}"
echo ""
echo "Versioned archive (pin with LambdaCodeS3Key=${VERSIONED}/management.zip):"
echo "  s3://${BUCKET}/${VERSIONED}/"
echo ""
echo "One-click deploy:"
echo "  https://console.aws.amazon.com/cloudformation/home?region=us-east-1#/stacks/quickcreate?templateURL=${TEMPLATE_URL}"
