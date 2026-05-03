#!/usr/bin/env bash
# Packages the management Lambda into dist/management.zip.
#
# The zip contains:
#   handler.py          — management API + admin UI + status page
#   regions.py          — programmatic region deploy/teardown via boto3
#   _monitor_handler.py — worker code to be deployed to remote regions
#
# Run this before 'terraform apply' and after any src/ changes.
#
# Usage:
#   ./scripts/package.sh

set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  ./scripts/package.sh
  ./scripts/package.sh help

What it does:
  Builds dist/management.zip from the current repo contents.

Arguments:
  This script takes no positional arguments.

Notes:
  - Copies src/monitor/handler.py into the management package as _monitor_handler.py.
  - Writes build metadata into the zip.
  - Does not talk to AWS.
EOF
}

if [[ "${1:-}" == "help" || "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/src/management"
DIST="$REPO_ROOT/dist"
VERSION="$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || date -u +%Y%m%d%H%M%S)"
BUILT_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
TMPDIR="$(mktemp -d "${TMPDIR:-/tmp}/uptime-package.XXXXXX")"

cleanup() {
  rm -rf "$TMPDIR"
}
trap cleanup EXIT

mkdir -p "$DIST"

echo "→ Preparing isolated build workspace..."
cp "$SRC/handler.py" "$TMPDIR/handler.py"
cp "$SRC/regions.py" "$TMPDIR/regions.py"

echo "→ Syncing worker code into management package..."
cp "$REPO_ROOT/src/monitor/handler.py" "$TMPDIR/_monitor_handler.py"

echo "→ Writing build metadata..."
cat > "$TMPDIR/_build_info.json" <<EOF
{"version":"$VERSION","built_at":"$BUILT_AT"}
EOF

echo "→ Packaging management Lambda..."
OUT="$DIST/management.zip"
rm -f "$OUT"

cd "$TMPDIR"
zip -qr "$OUT" handler.py regions.py _monitor_handler.py _build_info.json

SIZE=$(du -sh "$OUT" | cut -f1)
echo "  ✓ $OUT ($SIZE)"
echo ""
echo "Contents:"
unzip -l "$OUT" | awk '$2 ~ /^[0-9-]+$/ && $3 ~ /^[0-9:]+$/ {print "  " $NF " (" $1 " bytes)"}'
echo ""
echo "Next: cd terraform && terraform apply"
