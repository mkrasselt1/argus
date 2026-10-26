"""Collector framework.

A collector connects to a system **read-only** and returns the components and
vulnerabilities it observed. It must never modify the target. Collectors are
registered by name and selected per-system via `System.collector`.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Protocol

from app.models import Severity


@dataclass
class PackageResult:
    name: str
    version: str | None = None
    type: str | None = None
    source: str | None = None
    purl: str | None = None
    latest_version: str | None = None
    extra: dict = field(default_factory=dict)


@dataclass
class VulnResult:
    cve_id: str
    severity: Severity = Severity.unknown
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    title: str | None = None
    source: str | None = None


@dataclass
class CollectResult:
    packages: list[PackageResult] = field(default_factory=list)
    vulnerabilities: list[VulnResult] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    # --- JSON (de)serialisation, used by the agent/relay transport ---------

    def to_dict(self) -> dict:
        return {
            "packages": [asdict(p) for p in self.packages],
            "vulnerabilities": [
                {**asdict(v), "severity": v.severity.value} for v in self.vulnerabilities
            ],
            "summary": self.summary,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "CollectResult":
        packages = [PackageResult(**p) for p in data.get("packages", []) or []]
        vulns = []
        for v in data.get("vulnerabilities", []) or []:
            v = dict(v)
            sev = v.pop("severity", "unknown")
            try:
                v["severity"] = Severity(sev)
            except ValueError:
                v["severity"] = Severity.unknown
            vulns.append(VulnResult(severity=v.pop("severity"), **v))
        return cls(packages=packages, vulnerabilities=vulns, summary=data.get("summary", {}) or {})


class Collector(Protocol):
    name: str

    def collect(self, config: dict) -> CollectResult:
        """Gather read-only data for a system using its collector_config."""
        ...


_REGISTRY: dict[str, Collector] = {}


def register(collector: Collector) -> Collector:
    _REGISTRY[collector.name] = collector
    return collector


def get_collector(name: str) -> Collector | None:
    return _REGISTRY.get(name)


def available() -> list[str]:
    return sorted(_REGISTRY)


def run_collector(name: str, config: dict) -> CollectResult:
    """Execute a registered collector by name. Raises if unknown."""
    collector = get_collector(name)
    if collector is None:
        raise ValueError(f"Unknown collector '{name}'")
    return collector.collect(config or {})


def load_builtin_collectors() -> None:
    """Import modules so their collectors self-register. Safe if deps missing."""
    import importlib

    for mod in (
        "docker_local", "ssh_linux", "windows", "manual", "relay", "network_discovery"
    ):
        try:
            importlib.import_module(f"app.collectors.{mod}")
        except Exception as exc:  # pragma: no cover - optional deps
            import logging

            logging.getLogger(__name__).warning("Collector %s unavailable: %s", mod, exc)
