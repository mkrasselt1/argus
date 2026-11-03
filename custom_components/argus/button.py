"""Buttons: request a rescan of one system or of all systems.

Argus never changes a monitored system — a rescan only re-reads it (push
systems get a rescan command on the agent's next poll).
"""
from __future__ import annotations

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .api import ArgusError
from .coordinator import ArgusCoordinator
from .entity import ArgusHubEntity, ArgusSystemEntity


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator: ArgusCoordinator = entry.runtime_data
    async_add_entities([ArgusScanAllButton(coordinator)])
    known: set[int] = set()

    @callback
    def _add_new_systems() -> None:
        new = [sid for sid in coordinator.data.systems if sid not in known]
        if not new:
            return
        known.update(new)
        async_add_entities(ArgusScanButton(coordinator, sid) for sid in new)

    _add_new_systems()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_systems))


class ArgusScanAllButton(ArgusHubEntity, ButtonEntity):
    _attr_translation_key = "scan_all"
    _attr_icon = "mdi:radar"

    def __init__(self, coordinator: ArgusCoordinator) -> None:
        super().__init__(coordinator, "scan_all")

    async def async_press(self) -> None:
        try:
            await self.coordinator.client.scan_all()
        except ArgusError as err:
            raise HomeAssistantError(str(err)) from err


class ArgusScanButton(ArgusSystemEntity, ButtonEntity):
    _attr_translation_key = "scan"
    _attr_icon = "mdi:radar"

    def __init__(self, coordinator: ArgusCoordinator, system_id: int) -> None:
        super().__init__(coordinator, system_id, "scan")

    async def async_press(self) -> None:
        try:
            await self.coordinator.client.scan_system(self.system_id)
        except ArgusError as err:
            raise HomeAssistantError(str(err)) from err
