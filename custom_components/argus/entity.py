"""Base entities: one hub device for the server, one device per Argus system."""
from __future__ import annotations

from typing import Any

from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN, MANUFACTURER
from .coordinator import ArgusCoordinator

KIND_MODEL = {
    "linux": "Linux",
    "windows": "Windows",
    "synology": "Synology NAS",
    "router": "Router",
    "docker_host": "Docker-Host",
    "other": "Gerät",
}


def hub_device(coordinator: ArgusCoordinator) -> DeviceInfo:
    entry = coordinator.config_entry
    return DeviceInfo(
        identifiers={(DOMAIN, entry.entry_id)},
        name=entry.title,
        manufacturer=MANUFACTURER,
        model="Argus Server",
        sw_version=coordinator.data.version if coordinator.data else None,
        configuration_url=entry.data.get("url"),
    )


class ArgusHubEntity(CoordinatorEntity[ArgusCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: ArgusCoordinator, key: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{coordinator.config_entry.entry_id}_{key}"
        self._attr_device_info = hub_device(coordinator)


class ArgusSystemEntity(CoordinatorEntity[ArgusCoordinator]):
    _attr_has_entity_name = True

    def __init__(self, coordinator: ArgusCoordinator, system_id: int, key: str) -> None:
        super().__init__(coordinator)
        self.system_id = system_id
        entry_id = coordinator.config_entry.entry_id
        self._attr_unique_id = f"{entry_id}_system_{system_id}_{key}"
        s = self.system or {}
        base = (coordinator.config_entry.data.get("url") or "").rstrip("/")
        self._attr_device_info = DeviceInfo(
            identifiers={(DOMAIN, f"{entry_id}_system_{system_id}")},
            name=s.get("name") or f"System {system_id}",
            manufacturer=MANUFACTURER,
            model=KIND_MODEL.get(s.get("kind") or "", s.get("kind")),
            via_device=(DOMAIN, entry_id),
            configuration_url=f"{base}/systems/{system_id}" if base else None,
        )

    @property
    def system(self) -> dict[str, Any] | None:
        data = self.coordinator.data
        return data.systems.get(self.system_id) if data else None

    @property
    def available(self) -> bool:
        return super().available and self.system is not None
