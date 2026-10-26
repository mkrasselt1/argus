"""Run collectors and persist their results as immutable scan records."""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlmodel import Session, select

from app.collectors.base import CollectResult, PackageResult, get_collector
from app.db import engine
from app.models import (
    AgentCommand,
    CommandStatus,
    ComponentChange,
    Package,
    Scan,
    ScanStatus,
    Severity,
    Snooze,
    System,
    SystemKind,
    SystemSummary,
    Vulnerability,
    utcnow,
)

log = logging.getLogger(__name__)


def _store_findings(session: Session, scan: Scan, result: CollectResult) -> None:
    """Persist a collector result's packages and vulnerabilities for a scan."""
    for p in result.packages:
        session.add(
            Package(
                scan_id=scan.id,
                name=p.name,
                version=p.version,
                type=p.type,
                source=p.source,
                purl=p.purl,
                latest_version=p.latest_version,
                extra=p.extra,
            )
        )
    for v in result.vulnerabilities:
        session.add(
            Vulnerability(
                scan_id=scan.id,
                cve_id=v.cve_id,
                severity=v.severity,
                package_name=v.package_name,
                installed_version=v.installed_version,
                fixed_version=v.fixed_version,
                title=v.title,
                source=v.source,
            )
        )
    scan.status = ScanStatus.ok
    scan.finished_at = utcnow()
    scan.summary = result.summary


def _record_changes(session: Session, system_id: int, scan: Scan, result: CollectResult) -> int:
    """Diff this scan against the previous OK scan and log component changes.

    Records *when* a component changed — most importantly when an update was
    applied (an available update vanished because the installed version rose).
    The first scan of a system establishes a baseline and logs nothing.
    """
    prev = session.exec(
        select(Scan)
        .where(
            Scan.system_id == system_id,
            Scan.status == ScanStatus.ok,
            Scan.id != scan.id,
        )
        .order_by(Scan.started_at.desc())
    ).first()
    if prev is None:
        return 0  # baseline scan, nothing to diff

    prev_pkgs = session.exec(select(Package).where(Package.scan_id == prev.id)).all()
    prev_by_key = {(p.name, p.type): p for p in prev_pkgs}
    seen: set[tuple] = set()
    count = 0

    def add(name, ptype, change_type, old, new):
        nonlocal count
        session.add(
            ComponentChange(
                system_id=system_id, scan_id=scan.id, name=name, type=ptype,
                change_type=change_type, old_value=old, new_value=new,
            )
        )
        count += 1

    for np in result.packages:
        key = (np.name, np.type)
        seen.add(key)
        op = prev_by_key.get(key)
        if op is None:
            add(np.name, np.type, "added", None, np.version)
            continue
        if np.type == "service":
            if (np.version or "") != (op.version or ""):
                add(np.name, np.type, "status_changed", op.version, np.version)
            continue
        if (np.version or "") != (op.version or ""):
            # An update was applied if the previous scan had flagged one available.
            prev_had_update = op.latest_version and op.latest_version != op.version
            change = "update_applied" if prev_had_update else "version_changed"
            add(np.name, np.type, change, op.version, np.version)

    for key, op in prev_by_key.items():
        if key not in seen:
            add(op.name, op.type, "removed", op.version, None)

    return count


def run_scan(system_id: int) -> Scan:
    """Execute the system's collector and store a new Scan with its findings."""
    with Session(engine) as session:
        system = session.get(System, system_id)
        if system is None:
            raise ValueError(f"System {system_id} not found")

        scan = Scan(system_id=system.id, collector=system.collector, status=ScanStatus.running)
        session.add(scan)
        session.commit()
        session.refresh(scan)

        collector = get_collector(system.collector)
        if collector is None:
            scan.status = ScanStatus.error
            scan.error = f"Unknown collector '{system.collector}'"
            scan.finished_at = utcnow()
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan

        try:
            result = collector.collect(dict(system.collector_config or {}))
        except Exception as exc:  # collector failure must not crash the app
            log.exception("Scan failed for system %s", system_id)
            scan.status = ScanStatus.error
            scan.error = f"{type(exc).__name__}: {exc}"
            scan.finished_at = utcnow()
            session.add(scan)
            session.commit()
            session.refresh(scan)
            return scan

        _store_findings(session, scan, result)
        _record_changes(session, system.id, scan, result)
        if any(p.type == "iot-device" for p in result.packages):
            _materialize_discovered_devices(session, system, result)
        system.updated_at = utcnow()
        session.add(scan)
        session.add(system)
        session.commit()
        recompute_summary(session, system.id)
        session.refresh(scan)  # reload after recompute's commit expired it
        return scan


def ingest_result(
    system_name: str,
    collector: str,
    result: CollectResult,
    kind: str | None = None,
    hostname: str | None = None,
    ip_address: str | None = None,
    auto_register: bool = True,
) -> Scan:
    """Store a result **pushed by a client** (client -> server).

    The client runs a collector locally and POSTs the result here, so the
    server never needs an inbound path to the client. The system is matched by
    name; unknown systems are created when auto_register is enabled.
    """
    with Session(engine) as session:
        system = session.exec(select(System).where(System.name == system_name)).first()
        if system is None:
            if not auto_register:
                raise ValueError(f"Unknown system '{system_name}' and auto-register is off")
            try:
                system_kind = SystemKind(kind) if kind else SystemKind.other
            except ValueError:
                system_kind = SystemKind.other
            system = System(
                name=system_name,
                kind=system_kind,
                hostname=hostname,
                collector=collector,
                collector_config={"mode": "push"},
            )
            session.add(system)
            session.commit()
            session.refresh(system)

        scan = Scan(system_id=system.id, collector=collector, status=ScanStatus.running)
        session.add(scan)
        session.commit()
        session.refresh(scan)

        _store_findings(session, scan, result)
        _record_changes(session, system.id, scan, result)
        if any(p.type == "iot-device" for p in result.packages):
            _materialize_discovered_devices(session, system, result)
        if hostname and not system.hostname:
            system.hostname = hostname
        if ip_address:
            system.ip_address = ip_address  # refresh each push
        system.updated_at = utcnow()
        session.add(scan)
        session.add(system)
        session.commit()
        recompute_summary(session, system.id)
        session.refresh(scan)  # reload after recompute's commit expired it
        return scan


def latest_scan(session: Session, system_id: int) -> Scan | None:
    return session.exec(
        select(Scan)
        .where(Scan.system_id == system_id, Scan.status == ScanStatus.ok)
        .order_by(Scan.started_at.desc())
    ).first()


def _materialize_discovered_devices(
    session: Session, agent: System, result: CollectResult
) -> int:
    """Turn module-identified devices from a discovery scan into their own systems.

    Only hosts a device module recognised (iot-device packages) become systems.
    They are recognised by MAC (stable across IP changes), grouped under the
    discovering agent, and get their own scan (firmware + services) so their
    version is tracked and changes show up in their history. Returns the count.
    """
    # Collect, per host, the identified device and its open ports.
    devices: dict[str, PackageResult] = {}
    ports_by_host: dict[str, list[PackageResult]] = {}
    for p in result.packages:
        if p.type == "iot-device":
            devices[p.source] = p
        elif p.type == "open-port":
            ports_by_host.setdefault(p.source, []).append(p)

    count = 0
    for ip, dev in devices.items():
        extra = dev.extra or {}
        mac = extra.get("mac")
        hostname = extra.get("hostname")
        dev_name = extra.get("device_name")
        display = dev_name or dev.name  # friendly name wins, else product

        system = None
        if mac:
            system = session.exec(select(System).where(System.mac == mac)).first()
        if system is None:
            system = session.exec(
                select(System).where(System.ip_address == ip, System.discovered == True)  # noqa: E712
            ).first()
        if system is None:
            system = System(name=display or f"{dev.name} ({ip})", kind=SystemKind.other,
                            discovered=True, collector="discovered")
            session.add(system)
            session.commit()
            session.refresh(system)
            count += 1

        system.ip_address = ip
        system.hostname = hostname or system.hostname
        system.mac = mac or system.mac
        system.discovered = True
        system.discovered_via = agent.name
        system.collector = "discovered"
        if not system.group:
            system.group = agent.name
        # Inherit the agent's tags (customer/site/network assignment), additively.
        if agent.tags:
            current = list(system.tags or [])
            system.tags = current + [t for t in agent.tags if t not in current]
        if dev_name and (not system.name or system.name.startswith(dev.name)):
            system.name = dev_name
        system.updated_at = utcnow()
        session.add(system)
        session.commit()
        session.refresh(system)

        # Determine the latest firmware: the device's own cached value if it
        # reported one, otherwise a cached server-side release lookup. We never
        # make the device phone its vendor on our behalf.
        from app.services import firmware

        latest = extra.get("latest") or firmware.latest_for(dev.name)
        fw_latest = latest if (latest and latest != dev.version) else dev.version

        # Build a per-device scan: firmware row + its open services.
        pkgs = [PackageResult(name=dev.name, version=dev.version, type="firmware",
                              source=ip, latest_version=fw_latest, extra=extra)]
        pkgs.extend(
            PackageResult(name=sp.name, version=sp.version, type="open-port",
                          source=ip, extra=sp.extra)
            for sp in ports_by_host.get(ip, [])
        )
        dev_result = CollectResult(
            packages=pkgs,
            summary={"firmware": dev.version, "device": dev.name,
                     "via": agent.name, "mac": mac, "name": dev_name},
        )
        dev_scan = Scan(system_id=system.id, collector="discovered", status=ScanStatus.running)
        session.add(dev_scan)
        session.commit()
        session.refresh(dev_scan)
        _store_findings(session, dev_scan, dev_result)
        _record_changes(session, system.id, dev_scan, dev_result)
        session.add(dev_scan)
        session.commit()
        recompute_summary(session, system.id)
    return count


def propagate_agent_to_devices(old_name: str, new_name: str, tags: list) -> int:
    """Push an agent's tags (and a rename) down to the devices it discovered.

    Tags are unioned (device-specific tags are preserved). Used when an agent
    system is edited, so assignment tags (customer/site) flow to its devices
    immediately instead of only on the next scan. Returns the device count.
    """
    with Session(engine) as session:
        devices = session.exec(
            select(System).where(System.discovered_via == old_name)
        ).all()
        for d in devices:
            if tags:
                current = list(d.tags or [])
                d.tags = current + [t for t in tags if t not in current]
            if new_name != old_name:
                d.discovered_via = new_name
                if d.group == old_name:
                    d.group = new_name
            d.updated_at = utcnow()
            session.add(d)
        if devices:
            session.commit()
        return len(devices)


def recompute_summary(session: Session, system_id: int) -> None:
    """Rebuild the denormalised SystemSummary row for a system."""
    last = latest_scan(session, system_id)
    summary = session.get(SystemSummary, system_id) or SystemSummary(system_id=system_id)
    if last is None:
        summary.last_scan_id = None
        summary.last_scan_at = None
        summary.packages = summary.updates = summary.critical = summary.high = 0
    else:
        pkgs = session.exec(select(Package).where(Package.scan_id == last.id)).all()
        snoozed = {s.component for s in session.exec(
            select(Snooze).where(Snooze.system_id == system_id, Snooze.until > utcnow())
        ).all()}
        vulns = session.exec(select(Vulnerability).where(Vulnerability.scan_id == last.id)).all()
        summary.last_scan_id = last.id
        summary.last_scan_at = last.started_at
        summary.status = last.status.value
        summary.packages = len(pkgs)
        summary.updates = sum(
            1 for p in pkgs
            if p.latest_version and p.latest_version != p.version and p.name not in snoozed
        )
        summary.critical = sum(1 for v in vulns if v.severity == Severity.critical)
        summary.high = sum(1 for v in vulns if v.severity == Severity.high)
    summary.updated_at = utcnow()
    session.add(summary)
    session.commit()


def active_snoozes(session: Session, system_id: int) -> dict[str, "Snooze"]:
    """Return {component: Snooze} for snoozes that are still in effect."""
    rows = session.exec(
        select(Snooze).where(Snooze.system_id == system_id, Snooze.until > utcnow())
    ).all()
    return {s.component: s for s in rows}


def snooze_component(system_id: int, component: str, days: int, reason: str | None = None) -> None:
    """Snooze (or re-snooze) a component's update for `days` days."""
    with Session(engine) as session:
        existing = session.exec(
            select(Snooze).where(Snooze.system_id == system_id, Snooze.component == component)
        ).first()
        until = utcnow() + timedelta(days=max(1, days))
        if existing:
            existing.until = until
            existing.reason = reason
            session.add(existing)
        else:
            session.add(Snooze(system_id=system_id, component=component, until=until, reason=reason))
        session.commit()
        recompute_summary(session, system_id)


def unsnooze_component(system_id: int, component: str) -> None:
    with Session(engine) as session:
        row = session.exec(
            select(Snooze).where(Snooze.system_id == system_id, Snooze.component == component)
        ).first()
        if row:
            session.delete(row)
            session.commit()
            recompute_summary(session, system_id)


def recent_changes(session: Session, system_id: int, limit: int = 50) -> list[ComponentChange]:
    """Most recent component changes for a system (newest first)."""
    return session.exec(
        select(ComponentChange)
        .where(ComponentChange.system_id == system_id)
        .order_by(ComponentChange.detected_at.desc())
    ).all()[:limit]


def enqueue_command(system_id: int, cmd_type: str, payload: dict | None = None) -> int:
    """Queue a control command to hand to the client on its next push."""
    with Session(engine) as session:
        cmd = AgentCommand(system_id=system_id, type=cmd_type, payload=payload or {})
        session.add(cmd)
        session.commit()
        session.refresh(cmd)
        return cmd.id  # type: ignore[return-value]


def take_pending_commands(session: Session, system_id: int) -> list[dict]:
    """Return pending commands for a system and mark them delivered (once)."""
    cmds = session.exec(
        select(AgentCommand).where(
            AgentCommand.system_id == system_id,
            AgentCommand.status == CommandStatus.pending,
        )
    ).all()
    out = []
    for c in cmds:
        out.append({"id": c.id, "type": c.type, "payload": c.payload})
        c.status = CommandStatus.delivered
        c.delivered_at = utcnow()
        session.add(c)
    if cmds:
        session.commit()
    return out


def prune_old_scans(keep_per_system: int) -> int:
    """Delete scans beyond the newest `keep_per_system` per system (+ their rows).

    Bounds DB growth at scale. The newest scans are always kept. Returns the
    number of scans deleted.
    """
    if keep_per_system <= 0:
        return 0
    deleted = 0
    with Session(engine) as session:
        system_ids = [s.id for s in session.exec(select(System)).all()]
        for sid in system_ids:
            scans = session.exec(
                select(Scan).where(Scan.system_id == sid).order_by(Scan.started_at.desc())
            ).all()
            for old in scans[keep_per_system:]:
                for p in session.exec(select(Package).where(Package.scan_id == old.id)).all():
                    session.delete(p)
                for v in session.exec(
                    select(Vulnerability).where(Vulnerability.scan_id == old.id)
                ).all():
                    session.delete(v)
                session.delete(old)
                deleted += 1
        if deleted:
            session.commit()
    if deleted:
        log.info("pruned %d old scans (keep %d/system)", deleted, keep_per_system)
    return deleted


def backfill_summaries() -> None:
    """Compute SystemSummary for any system that lacks one (after a migration)."""
    with Session(engine) as session:
        have = {s.system_id for s in session.exec(select(SystemSummary)).all()}
        ids = [s.id for s in session.exec(select(System)).all() if s.id not in have]
    for sid in ids:
        with Session(engine) as session:
            recompute_summary(session, sid)


def run_all_enabled() -> list[int]:
    """Scan every enabled system (used by the scheduler). Returns scan ids."""
    with Session(engine) as session:
        systems = session.exec(select(System).where(System.enabled == True)).all()  # noqa: E712
        ids = [s.id for s in systems if s.id is not None]
    scan_ids: list[int] = []
    for sid in ids:
        try:
            scan_ids.append(run_scan(sid).id)  # type: ignore[arg-type]
        except Exception:
            log.exception("run_all_enabled: system %s failed", sid)
    return scan_ids
