"""End-of-life / latest-version lookups via endoflife.date (read-only, cached).

Answers "is this OS still supported, and what's the latest feature version?"
for Windows and common Linux distributions. A feature upgrade (e.g. Windows
20H2 -> 24H2, Ubuntu 20.04 -> 24.04) is NOT reported as a pending patch by the
OS itself, so this cross-checks the installed version against the public
end-of-life calendar. Network access is outbound-only; failures degrade
gracefully to "unknown".
"""
from __future__ import annotations

import datetime
import logging
import re
import time

import httpx

log = logging.getLogger(__name__)

_API = "https://endoflife.date/api/{product}.json"
_TTL = 6 * 3600
_CACHE: dict[str, tuple[float, list]] = {}

# os-release ID -> endoflife.date product slug
_DISTRO_MAP = {
    "ubuntu": "ubuntu", "debian": "debian", "raspbian": "debian", "fedora": "fedora",
    "rhel": "rhel", "centos": "centos", "almalinux": "almalinux", "rocky": "rockylinux",
    "opensuse-leap": "opensuse", "opensuse": "opensuse", "sles": "sles",
    "alpine": "alpine", "amzn": "amazon-linux", "linuxmint": "linuxmint",
}


def _fetch(product: str, timeout: int) -> list | None:
    now = time.time()
    hit = _CACHE.get(product)
    if hit and now - hit[0] < _TTL:
        return hit[1]
    try:
        resp = httpx.get(_API.format(product=product), timeout=timeout)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:  # network/parse failure -> unknown
        log.info("eol fetch %s failed: %s", product, exc)
        return None
    _CACHE[product] = (now, data)
    return data


def _is_eol(eol) -> bool | None:
    if isinstance(eol, bool):
        return eol
    try:
        return datetime.date.fromisoformat(str(eol)) < datetime.date.today()
    except (ValueError, TypeError):
        return None


def _win_build(entry: dict) -> int:
    m = re.match(r"10\.0\.(\d+)", str(entry.get("latest", "")))
    return int(m.group(1)) if m else -1


def windows_status(build: int, edition_id: str | None, timeout: int = 15) -> dict | None:
    """EOL/latest status for a Windows build (e.g. 22621) + edition."""
    data = _fetch("windows", timeout)
    if not data:
        return None
    is_win11 = build >= 22000
    # Consumer (Home/Pro) tracks the "-w" cycle; Enterprise/Education the "-e".
    variant = "-e" if (edition_id or "").lower() in {
        "enterprise", "enterprises", "education", "enterprisen"
    } else "-w"

    def label(entry: dict | None) -> str | None:
        if not entry:
            return None
        text = (entry.get("releaseLabel") or entry.get("cycle") or "").replace(
            " (W)", ""
        ).replace(" (E)", "").strip()
        # Drop a leading product number ("11 26H1" -> "26H1"); product is shown separately.
        return re.sub(r"^\d+\s+", "", text)

    prefix = f"10.0.{build}"
    candidates = [e for e in data if str(e.get("latest", "")) == prefix]
    current = next((e for e in candidates if str(e.get("cycle", "")).endswith(variant)), None)
    if current is None and candidates:
        current = candidates[0]

    family = [
        e for e in data
        if (_win_build(e) >= 22000) == is_win11
        and str(e.get("cycle", "")).endswith(variant)
        and "iot" not in str(e.get("cycle", ""))
    ]
    latest = max(family, key=_win_build) if family else None
    latest_build = _win_build(latest) if latest else -1
    return {
        "current_label": label(current),
        "eol": current.get("eol") if current else None,
        "is_eol": _is_eol(current.get("eol")) if current else None,
        "latest_label": label(latest),
        "outdated": bool(latest and latest_build > build),
    }


def distro_status(distro_id: str | None, version_id: str | None, timeout: int = 15) -> dict | None:
    """EOL/latest status for a Linux distro from os-release ID + VERSION_ID."""
    product = _DISTRO_MAP.get((distro_id or "").lower())
    if not product or not version_id:
        return None
    data = _fetch(product, timeout)
    if not data:
        return None
    vid = str(version_id).strip()
    current = next((e for e in data if str(e.get("cycle")) == vid), None)
    if current is None:
        major = vid.split(".")[0]
        current = next((e for e in data if str(e.get("cycle")) == major), None)
    latest = data[0] if data else None  # endoflife.date lists newest cycle first
    return {
        "product": product,
        "current_label": f"{product} {vid}",
        "eol": current.get("eol") if current else None,
        "is_eol": _is_eol(current.get("eol")) if current else None,
        "latest_label": f"{product} {latest.get('cycle')}" if latest else None,
        "outdated": bool(current and latest and str(current.get("cycle")) != str(latest.get("cycle"))),
    }
