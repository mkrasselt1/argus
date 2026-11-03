"""Small async client for the Argus JSON API (read-only + rescan requests)."""
from __future__ import annotations

from typing import Any

import aiohttp

from .const import DEFAULT_TIMEOUT


class ArgusError(Exception):
    """Generic communication error."""


class ArgusAuthError(ArgusError):
    """The API token was rejected (or is required but missing)."""


class ArgusClient:
    def __init__(self, session: aiohttp.ClientSession, url: str, token: str,
                 verify_ssl: bool = True) -> None:
        self._session = session
        self._base = url.rstrip("/")
        self._token = token
        self._ssl = None if verify_ssl else False

    async def _request(self, method: str, path: str) -> Any:
        headers = {"Accept": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        try:
            async with self._session.request(
                method, f"{self._base}{path}", headers=headers, ssl=self._ssl,
                allow_redirects=False,
                timeout=aiohttp.ClientTimeout(total=DEFAULT_TIMEOUT),
            ) as resp:
                if resp.status in (401, 403):
                    raise ArgusAuthError(f"authentication failed ({resp.status})")
                if resp.status >= 400:
                    text = (await resp.text())[:200]
                    raise ArgusError(f"HTTP {resp.status} on {path}: {text}")
                return await resp.json(content_type=None)
        except (TimeoutError, aiohttp.ClientError, ValueError) as err:
            raise ArgusError(f"cannot reach Argus at {self._base}: {err}") from err

    async def overview(self) -> dict[str, Any]:
        data = await self._request("GET", "/api/overview")
        if not isinstance(data, dict) or "systems" not in data:
            raise ArgusError("unexpected /api/overview response (Argus server too old?)")
        return data

    async def scan_system(self, system_id: int) -> None:
        await self._request("POST", f"/api/systems/{system_id}/scan")

    async def scan_all(self) -> None:
        await self._request("POST", "/api/scan-all")
