"""Server-side latest-firmware lookup for device families (cached, centralised).

Rationale: the agent must NOT force every device to phone its vendor's update
server on each scan (that would hammer the vendor). So:

* devices that already cache their own update status (e.g. Shelly) report it to
  the agent locally — that value is used as-is;
* for families with a single public release feed (e.g. Tasmota on GitHub), the
  SERVER looks up the latest version **once per product, cached with a TTL**, and
  compares it to every device. One request per product per TTL — not per device.

Any failure degrades to "unknown" (no false "up to date").
"""
from __future__ import annotations

import logging
import re
import time

import httpx

log = logging.getLogger(__name__)

_TTL = 6 * 3600
_CACHE: dict[str, tuple[float, str | None]] = {}

# product family -> a resolver that returns the latest version string (or None).
_GITHUB_LATEST = "https://api.github.com/repos/{repo}/releases/latest"


def _github_latest(repo: str, timeout: int) -> str | None:
    try:
        r = httpx.get(_GITHUB_LATEST.format(repo=repo), timeout=timeout,
                      headers={"Accept": "application/vnd.github+json"})
        r.raise_for_status()
        tag = r.json().get("tag_name") or ""
    except Exception as exc:
        log.info("github latest %s failed: %s", repo, exc)
        return None
    return tag.lstrip("v") or None


# Families whose latest release lives in one feed. Shelly is intentionally absent:
# each Shelly reports its own cached available_updates locally.
_FEEDS = {
    "tasmota": lambda t: _github_latest("arendst/Tasmota", t),
}


def _family(product: str) -> str | None:
    p = (product or "").lower()
    for fam in _FEEDS:
        if fam in p:
            return fam
    return None


def latest_for(product: str, timeout: int = 10) -> str | None:
    """Latest version for a product family, cached once per family per TTL."""
    fam = _family(product)
    if fam is None:
        return None
    now = time.time()
    hit = _CACHE.get(fam)
    if hit and now - hit[0] < _TTL:
        return hit[1]
    value = _FEEDS[fam](timeout)
    _CACHE[fam] = (now, value)
    return value


_NUM = re.compile(r"\d+")


def _nums(v: str | None) -> list[int]:
    return [int(n) for n in _NUM.findall(v or "")]


def is_outdated(current: str | None, latest: str | None) -> bool:
    """True if `current` is clearly older than `latest` (numeric comparison)."""
    if not current or not latest:
        return False
    c, l = _nums(current), _nums(latest)
    return bool(c and l and c < l)
