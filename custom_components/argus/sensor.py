"""Sensors: server-wide totals + per-system counts."""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import (
    SensorDeviceClass,
    SensorEntity,
    SensorEntityDescription,
    SensorStateClass,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import EntityCategory
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.util import dt as dt_util

from .coordinator import ArgusCoordinator
from .entity import ArgusHubEntity, ArgusSystemEntity


@dataclass(frozen=True, kw_only=True)
class ArgusSensorDescription(SensorEntityDescription):
    value_fn: Callable[[dict[str, Any]], Any]


def _count(key: str) -> Callable[[dict[str, Any]], Any]:
    return lambda d: int(d.get(key) or 0)


HUB_SENSORS: tuple[ArgusSensorDescription, ...] = (
    ArgusSensorDescription(key="systems", translation_key="systems", icon="mdi:server-network",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("systems")),
    ArgusSensorDescription(key="systems_with_updates", translation_key="systems_with_updates",
                           icon="mdi:update", state_class=SensorStateClass.MEASUREMENT,
                           value_fn=_count("systems_with_updates")),
    ArgusSensorDescription(key="updates", translation_key="updates", icon="mdi:package-up",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("updates")),
    ArgusSensorDescription(key="critical", translation_key="critical", icon="mdi:shield-alert",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("critical")),
    ArgusSensorDescription(key="high", translation_key="high", icon="mdi:shield-half-full",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("high")),
    ArgusSensorDescription(key="eol", translation_key="eol", icon="mdi:calendar-remove",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("eol")),
    ArgusSensorDescription(key="scan_errors", translation_key="scan_errors",
                           icon="mdi:alert-circle-outline",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("scan_errors")),
    ArgusSensorDescription(key="agents", translation_key="agents", icon="mdi:robot",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("agents")),
    ArgusSensorDescription(key="agents_pending", translation_key="agents_pending",
                           icon="mdi:robot-confused", state_class=SensorStateClass.MEASUREMENT,
                           value_fn=_count("agents_pending")),
)


def _ts(d: dict[str, Any]):
    raw = d.get("last_scan_at")
    return dt_util.parse_datetime(raw) if raw else None


SYSTEM_SENSORS: tuple[ArgusSensorDescription, ...] = (
    ArgusSensorDescription(key="updates", translation_key="system_updates", icon="mdi:package-up",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("updates")),
    ArgusSensorDescription(key="critical", translation_key="system_critical",
                           icon="mdi:shield-alert", state_class=SensorStateClass.MEASUREMENT,
                           value_fn=_count("critical")),
    ArgusSensorDescription(key="high", translation_key="system_high", icon="mdi:shield-half-full",
                           state_class=SensorStateClass.MEASUREMENT, value_fn=_count("high")),
    ArgusSensorDescription(key="packages", translation_key="system_packages",
                           icon="mdi:package-variant-closed",
                           state_class=SensorStateClass.MEASUREMENT,
                           entity_category=EntityCategory.DIAGNOSTIC, value_fn=_count("packages")),
    ArgusSensorDescription(key="last_scan", translation_key="system_last_scan",
                           device_class=SensorDeviceClass.TIMESTAMP,
                           entity_category=EntityCategory.DIAGNOSTIC, value_fn=_ts),
    ArgusSensorDescription(key="scan_status", translation_key="system_scan_status",
                           device_class=SensorDeviceClass.ENUM,
                           options=["pending", "running", "ok", "error", "none"],
                           entity_category=EntityCategory.DIAGNOSTIC,
                           value_fn=lambda d: d.get("status") or "none"),
    ArgusSensorDescription(key="os_support", translation_key="system_os_support",
                           icon="mdi:calendar-check",
                           value_fn=lambda d: d.get("os_support")),
)


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry,
                            async_add_entities: AddEntitiesCallback) -> None:
    coordinator: ArgusCoordinator = entry.runtime_data
    async_add_entities(ArgusHubSensor(coordinator, d) for d in HUB_SENSORS)

    known: set[int] = set()

    @callback
    def _add_new_systems() -> None:
        new = [sid for sid in coordinator.data.systems if sid not in known]
        if not new:
            return
        known.update(new)
        async_add_entities(
            ArgusSystemSensor(coordinator, sid, d) for sid in new for d in SYSTEM_SENSORS
        )

    _add_new_systems()
    entry.async_on_unload(coordinator.async_add_listener(_add_new_systems))


class ArgusHubSensor(ArgusHubEntity, SensorEntity):
    entity_description: ArgusSensorDescription

    def __init__(self, coordinator: ArgusCoordinator, description: ArgusSensorDescription) -> None:
        super().__init__(coordinator, description.key)
        self.entity_description = description

    @property
    def native_value(self):
        return self.entity_description.value_fn(self.coordinator.data.totals)

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        key = self.entity_description.key
        field = {"systems_with_updates": "updates", "critical": "critical",
                 "high": "high", "eol": "eol", "scan_errors": "status"}.get(key)
        if not field:
            return None
        systems = self.coordinator.data.systems.values()
        if field == "status":
            names = [s["name"] for s in systems if s.get("status") == "error"]
        else:
            names = [s["name"] for s in systems if s.get(field)]
        return {"systems": sorted(names)}


class ArgusSystemSensor(ArgusSystemEntity, SensorEntity):
    entity_description: ArgusSensorDescription

    def __init__(self, coordinator: ArgusCoordinator, system_id: int,
                 description: ArgusSensorDescription) -> None:
        super().__init__(coordinator, system_id, description.key)
        self.entity_description = description

    @property
    def native_value(self):
        s = self.system
        return self.entity_description.value_fn(s) if s else None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        s = self.system
        if not s or self.entity_description.key != "updates":
            return None
        return {k: s.get(k) for k in ("hostname", "ip_address", "kind", "group", "tags",
                                      "collector", "os_latest") if s.get(k) not in (None, [])}
