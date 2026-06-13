"""Vercel serverless entrypoint for ICSMOG.

This module exports `handler`, `app`, and `application` so Vercel's Python
runtime can discover the function entrypoint.
"""

from __future__ import annotations

import os

from src.api.cybersecurity import build_handler
from src.services.cybersecurity import CybersecurityMonitoringService, seed_mvp_demo_data
from src.storage import CybersecurityEventStore


def _default_storage_path() -> str:
    configured = os.environ.get("ICSMOG_STORAGE_PATH")
    if configured:
        return configured

    # Vercel serverless file system is ephemeral; /tmp is writable per instance.
    if os.environ.get("VERCEL"):
        return "/tmp/cybersecurity.db"

    return "data/cybersecurity.db"


def _should_seed_demo_data() -> bool:
    raw = os.environ.get("ICSMOG_SEED_DEMO_DATA", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


_service = CybersecurityMonitoringService(
    store=CybersecurityEventStore(_default_storage_path())
)

if _should_seed_demo_data():
    seed_mvp_demo_data(_service)

# Vercel expects one of these top-level names.
handler = build_handler(_service)
app = handler
application = handler
