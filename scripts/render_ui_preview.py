#!/usr/bin/env python3
"""Render static preview HTML for the inline Lambda UI."""

from __future__ import annotations

import os
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
MANAGEMENT_DIR = ROOT / "src" / "management"
OUTPUT_DIR = ROOT / "dist" / "preview"


def _load_handler():
    os.environ.setdefault("HOSTS_TABLE", "preview-hosts")
    os.environ.setdefault("CHECKS_TABLE", "preview-checks")
    os.environ.setdefault("HOME_REGION", "eu-central-1")
    os.environ.setdefault("AWS_REGION", "eu-central-1")
    if "boto3" not in sys.modules:
        boto3_stub = types.ModuleType("boto3")

        def _unavailable(*args, **kwargs):
            raise RuntimeError("boto3 is unavailable in preview mode")

        boto3_stub.client = _unavailable
        boto3_stub.resource = _unavailable
        sys.modules["boto3"] = boto3_stub
    if "regions" not in sys.modules:
        sys.modules["regions"] = types.ModuleType("regions")
    sys.path.insert(0, str(MANAGEMENT_DIR))
    import handler  # type: ignore

    return handler


def main() -> int:
    handler = _load_handler()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    host_data = [
        {
            "host": {"name": "Marketing Site"},
            "uptime_pct": 100.0,
            "avg_latency": 142,
            "latest_latency": 133,
            "region_summary": [
                {"region": "us-east-1", "status": "up", "latency_ms": 128},
                {"region": "eu-west-1", "status": "up", "latency_ms": 154},
                {"region": "ap-southeast-1", "status": "up", "latency_ms": 177},
            ],
            "history": ["up"] * 12,
            "history_points": [],
            "history_available": True,
            "current_status": "up",
        },
        {
            "host": {"name": "Payments API"},
            "uptime_pct": 98.9,
            "avg_latency": 236,
            "latest_latency": 301,
            "region_summary": [
                {"region": "us-east-1", "status": "degraded", "latency_ms": 294},
                {"region": "eu-west-1", "status": "up", "latency_ms": 201},
                {"region": "ap-southeast-1", "status": "degraded", "latency_ms": 312},
            ],
            "history": ["up", "up", "degraded", "up", "up", "degraded", "up", "up", "up", "up", "degraded", "up"],
            "history_points": [],
            "history_available": True,
            "current_status": "degraded",
        },
        {
            "host": {"name": "Auth Cluster"},
            "uptime_pct": 96.7,
            "avg_latency": 418,
            "latest_latency": 0,
            "region_summary": [
                {"region": "us-east-1", "status": "down", "latency_ms": 0},
                {"region": "eu-west-1", "status": "degraded", "latency_ms": 442},
                {"region": "ap-southeast-1", "status": "up", "latency_ms": 286},
            ],
            "history": ["up", "up", "down", "down", "degraded", "up", "up", "up", "degraded", "up", "up", "down"],
            "history_points": [],
            "history_available": True,
            "current_status": "down",
        },
    ]

    events = [
        {
            "month": "May 2026",
            "count": 3,
            "items": [
                {"host_name": "Auth Cluster", "status": "down", "checked_at": "2026-05-03T08:15:00+00:00"},
                {"host_name": "Payments API", "status": "degraded", "checked_at": "2026-05-03T08:10:00+00:00"},
                {"host_name": "Payments API", "status": "degraded", "checked_at": "2026-05-02T22:42:00+00:00"},
            ],
        }
    ]

    status_html = handler._render_status_page(
        "Uptime Command Center",
        "Live health across regions, with maintenance and incident context kept clear at a glance.",
        "Uptime",
        "",
        "clean",
        host_data,
        events,
        {
            "subscribe_intro": "Subscribe for email, SMS, or webhook updates when incidents or maintenance windows change.",
            "subscribe_email_url": "mailto:status@example.com?subject=Subscribe",
            "subscribe_sms_url": "https://example.com/status/sms",
            "subscribe_webhook_url": "https://example.com/status/feed.xml",
            "maintenance_enabled": True,
            "maintenance_message": "Database failover rehearsal for the payments path.",
            "maintenance_window": "Sun 02:00-03:00 UTC",
            "maintenance_scope": "Payments API, eu-west-1",
        },
    )
    (OUTPUT_DIR / "status-preview.html").write_text(status_html, encoding="utf-8")

    history_html = handler._render_history_page(
        title="Uptime Command Center",
        brand_name="Uptime",
        logo_url="",
        theme="clean",
        hosts=[
            {"host_id": "marketing-site", "name": "Marketing Site"},
            {"host_id": "payments-api", "name": "Payments API"},
            {"host_id": "auth-cluster", "name": "Auth Cluster"},
        ],
        regions=["ap-southeast-1", "eu-west-1", "us-east-1"],
        selected_host="all",
        selected_region="all",
        rows=[
            {"host_id": "auth-cluster", "host_name": "Auth Cluster", "region": "us-east-1", "status": "down", "latency_ms": 0, "status_code": 503, "checked_at": "2026-05-03T08:15:00+00:00", "error": "upstream timeout"},
            {"host_id": "payments-api", "host_name": "Payments API", "region": "ap-southeast-1", "status": "degraded", "latency_ms": 312, "status_code": 200, "checked_at": "2026-05-03T08:10:00+00:00", "error": ""},
            {"host_id": "marketing-site", "host_name": "Marketing Site", "region": "eu-west-1", "status": "up", "latency_ms": 154, "status_code": 200, "checked_at": "2026-05-03T08:09:00+00:00", "error": ""},
            {"host_id": "payments-api", "host_name": "Payments API", "region": "us-east-1", "status": "degraded", "latency_ms": 294, "status_code": 200, "checked_at": "2026-05-03T08:08:00+00:00", "error": "high latency"},
        ],
    )
    (OUTPUT_DIR / "history-preview.html").write_text(history_html, encoding="utf-8")

    admin_html = handler._admin_page()
    (OUTPUT_DIR / "admin-preview.html").write_text(admin_html, encoding="utf-8")

    print(f"Wrote previews to {OUTPUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
