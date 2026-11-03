"""Constants for the Argus integration."""
from __future__ import annotations

from datetime import timedelta

DOMAIN = "argus"

CONF_SCAN_INTERVAL = "scan_interval"
DEFAULT_SCAN_INTERVAL = 300  # seconds — Argus data changes slowly
MIN_SCAN_INTERVAL = 60

DEFAULT_TIMEOUT = 30

MANUFACTURER = "Argus"


def interval(seconds: float | None) -> timedelta:
    return timedelta(seconds=max(MIN_SCAN_INTERVAL, int(seconds or DEFAULT_SCAN_INTERVAL)))
