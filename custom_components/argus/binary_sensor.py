"""Binary sensors per system: updates pending, vulnerable, OS end-of-life."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
    BinarySensorEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .coordinator import ArgusCoordinator
from .entity import ArgusSystemEntity


@dataclass(frozen=True, kw_only=True)
class ArgusBinaryDescription(BinarySensorEntityDescription):
    value_fn: Callable[[dict[str, Any]], bool]


SYSTEM_BINARY: tuple[ArgusBinaryDescription, ...] = (
    ArgusBinaryDescription(key="update_available", translation_key="update_available",
                           device_class=BinarySensorDeviceClass.UPDATE,
                           value_fn=lambda d: bool(d.get("updates"))),
    ArgusBinaryDescription(key="vulnerable", translation_key="vulnerable",
                           device_class=BinarySensorDeviceClass.PROBLEM,
                           icon="mdi:shield-bug",
                           value_fn=lambda d: bool(d.get("critical") or d.get("high"))),
    ArgusBinaryDescription(key="eol", translation_key="eol",
                           device_class=BinarySensorDeviceClass.PROBLEM,
                           icon="mdi:calendar-remove",
                           value_fn=lambda d: bool(d.get("eol"))),
    ArgusBinaryDescription(key="scan_error", translation_key="scan_error",
                           device_class=BinarySensorDeviceClass.PROBLEM,
                           value_fn=lambda d: d.get("status") == "error"),
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator: ArgusCoordinator = entry.runtime_data
    known: set[int] = set()

    @callback
    def _add_new_systems() -> None:
        new = [sid for sid in coordinator.data.systems if sid not in known]
        if not new:
            return
        known.update(new)
        async_add_entities(
            ArgusSystemBinary(coordinator, sid, d) for sid in new for d in SYSTEM_BINARY
        )

    _add_new_systems()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_systems))


class ArgusSystemBinary(ArgusSystemEntity, BinarySensorEntity):
    entity_description: ArgusBinaryDescription

    def __init__(self, coordinator: ArgusCoordinator, system_id: int,
                 description: ArgusBinaryDescription) -> None:
        super().__init__(coordinator, system_id, description.key)
        self.entity_description = description

    @property
    def is_on(self) -> bool | None:
        s = self.system
        return self.entity_description.value_fn(s) if s else None
