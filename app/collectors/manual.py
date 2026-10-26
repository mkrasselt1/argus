"""Manual collector — for systems inventoried by hand.

Produces no automatic data; the system's documentation (access_notes, web_url)
and any packages are maintained manually. Useful for routers, appliances or
anything without a programmatic read-only interface.
"""
from __future__ import annotations

from app.collectors.base import CollectResult, register


class ManualCollector:
    name = "manual"

    def collect(self, config: dict) -> CollectResult:
        return CollectResult(summary={"note": "manual system — no automatic collection"})


register(ManualCollector())
