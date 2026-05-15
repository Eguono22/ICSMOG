"""Shared datetime helpers for timezone-aware UTC timestamps."""

from __future__ import annotations

import datetime

UTC = getattr(datetime, "UTC", datetime.timezone.utc)


def utc_now() -> datetime.datetime:
    """Return the current time as a timezone-aware UTC datetime."""
    return datetime.datetime.now(UTC)
