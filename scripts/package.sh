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

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="$REPO_ROOT/src/management"
DIST="$REPO_ROOT/dist"

mkdir -p "$DIST"

echo "→ Syncing worker code into management package..."
cp "$REPO_ROOT/src/monitor/handler.py" "$SRC/_monitor_handler.py"

echo "→ Packaging management Lambda..."
OUT="$DIST/management.zip"
rm -f "$OUT"

cd "$SRC"
zip -qr "$OUT" handler.py regions.py _monitor_handler.py

SIZE=$(du -sh "$OUT" | cut -f1)
echo "  ✓ $OUT ($SIZE)"
echo ""
echo "Contents:"
unzip -l "$OUT" | awk '$2 ~ /^[0-9-]+$/ && $3 ~ /^[0-9:]+$/ {print "  " $NF " (" $1 " bytes)"}'
echo ""
echo "Next: cd terraform && terraform apply"
