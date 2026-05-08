"""Shared timezone helpers for Unified ThreatLens."""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone, tzinfo
from zoneinfo import ZoneInfo

DEFAULT_TIMEZONE = "Asia/Kuala_Lumpur"


def configured_timezone_name() -> str:
    """Resolve timezone from env with safe fallback."""
    raw = (
        os.environ.get("TIMEZONE", "").strip()
        or os.environ.get("TZ", "").strip()
        or DEFAULT_TIMEZONE
    )
    return raw


def configured_timezone() -> tzinfo:
    """Return ZoneInfo for configured timezone."""
    name = configured_timezone_name()
    try:
        return ZoneInfo(name)
    except Exception:
        # Windows hosts may not ship IANA tzdata in local Python.
        return timezone(timedelta(hours=8), name=DEFAULT_TIMEZONE)


def now_tz() -> datetime:
    """Return current datetime in configured timezone."""
    return datetime.now(configured_timezone())


def now_utc() -> datetime:
    """Return current datetime in UTC."""
    return datetime.now(timezone.utc)


def to_configured_tz(value: datetime) -> datetime:
    """Convert datetime to configured timezone, assuming UTC for naive values."""
    dt = value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(configured_timezone())


def iso_now_tz() -> str:
    """Current time in ISO-8601 with configured timezone offset."""
    return now_tz().isoformat()


def format_now_tz(fmt: str) -> str:
    """Format current datetime in configured timezone."""
    return now_tz().strftime(fmt)


def format_dt_tz(value: datetime, fmt: str) -> str:
    """Format any datetime in configured timezone."""
    return to_configured_tz(value).strftime(fmt)

