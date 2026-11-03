"""DataUpdateCoordinator polling /api/overview."""
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import ArgusAuthError, ArgusClient, ArgusError
from .const import CONF_SCAN_INTERVAL, DOMAIN, interval

_LOGGER = logging.getLogger(__name__)


class ArgusData:
    """Parsed overview: totals + systems keyed by id."""

    def __init__(self, raw: dict[str, Any]) -> None:
        self.version: str | None = raw.get("version")
        self.totals: dict[str, Any] = raw.get("totals") or {}
        self.systems: dict[int, dict[str, Any]] = {
            int(s["id"]): s for s in raw.get("systems") or [] if s.get("id") is not None
        }


class ArgusCoordinator(DataUpdateCoordinator[ArgusData]):
    config_entry: ConfigEntry

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry, client: ArgusClient) -> None:
        super().__init__(
            hass,
            _LOGGER,
            config_entry=entry,
            name=DOMAIN,
            update_interval=interval(entry.options.get(CONF_SCAN_INTERVAL)),
        )
        self.client = client

    async def _async_update_data(self) -> ArgusData:
        try:
            return ArgusData(await self.client.overview())
        except ArgusAuthError as err:
            raise ConfigEntryAuthFailed(str(err)) from err
        except ArgusError as err:
            raise UpdateFailed(str(err)) from err
