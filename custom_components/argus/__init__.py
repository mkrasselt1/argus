"""Argus integration for Home Assistant.

Polls the Argus server's read-only /api/overview and exposes server totals and
one device per monitored system (updates, CVEs, OS end-of-life, scan state).
"""
from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_TOKEN, CONF_URL, CONF_VERIFY_SSL, Platform
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import ArgusClient
from .const import DOMAIN
from .coordinator import ArgusCoordinator
from .entity import hub_device

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON]

ArgusConfigEntry = ConfigEntry  # runtime_data: ArgusCoordinator


async def async_setup_entry(hass: HomeAssistant, entry: ArgusConfigEntry) -> bool:
    verify = entry.data.get(CONF_VERIFY_SSL, True)
    client = ArgusClient(
        async_get_clientsession(hass, verify_ssl=verify),
        entry.data[CONF_URL], entry.data.get(CONF_TOKEN, ""), verify,
    )
    coordinator = ArgusCoordinator(hass, entry, client)
    await coordinator.async_config_entry_first_refresh()
    entry.runtime_data = coordinator
    # Register the server hub first: per-system devices point to it via
    # via_device, and platforms may set up in any order.
    dr.async_get(hass).async_get_or_create(config_entry_id=entry.entry_id,
                                           **hub_device(coordinator))
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    entry.async_on_unload(entry.add_update_listener(_async_reload))
    return True


async def _async_reload(hass: HomeAssistant, entry: ArgusConfigEntry) -> None:
    await hass.config_entries.async_reload(entry.entry_id)


async def async_unload_entry(hass: HomeAssistant, entry: ArgusConfigEntry) -> bool:
    return await hass.config_entries.async_unload_platforms(entry, PLATFORMS)


async def async_remove_config_entry_device(
    hass: HomeAssistant, entry: ArgusConfigEntry, device: dr.DeviceEntry
) -> bool:
    """Allow deleting devices of systems that no longer exist in Argus."""
    prefix = f"{entry.entry_id}_system_"
    data = entry.runtime_data.data
    for domain, ident in device.identifiers:
        if domain != DOMAIN:
            continue
        if ident == entry.entry_id:
            return False  # the server hub itself
        if ident.startswith(prefix):
            try:
                return int(ident[len(prefix):]) not in data.systems
            except ValueError:
                return True
    return True
