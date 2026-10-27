"""Database models.

Design notes
------------
The tool is *read-only* towards the systems it monitors: it never changes a
target, it only records what it observed. To stay revision-safe, observations
are stored **per scan run** rather than overwritten. The "current" state of a
system is simply the newest finished scan; older scans remain for diffing and
audit history.

Note: this module intentionally does *not* use ``from __future__ import
annotations``; that turns relationship annotations into plain strings and
breaks SQLAlchemy mapper configuration.
"""
import enum
from datetime import datetime, timezone

from sqlalchemy import Column, UniqueConstraint
from sqlalchemy.types import JSON
from sqlmodel import Field, Relationship, SQLModel


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SystemKind(str, enum.Enum):
    linux = "linux"
    windows = "windows"
    synology = "synology"
    router = "router"
    docker_host = "docker_host"
    other = "other"


class ScanStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    ok = "ok"
    error = "error"


class Severity(str, enum.Enum):
    unknown = "unknown"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class System(SQLModel, table=True):
    """A monitored asset and how to reach it (documentation lives here)."""

    id: int | None = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    kind: SystemKind = Field(default=SystemKind.other)
    hostname: str | None = None  # IP or DNS name
    ip_address: str | None = None  # last reported primary IP of the device
    mac: str | None = Field(default=None, index=True)  # stable id for discovered devices

    # Provenance: devices found by a discovery agent become their own systems,
    # recognised by MAC and linked back to the agent that found them.
    discovered: bool = Field(default=False)
    discovered_via: str | None = None  # name of the discovering agent

    # Organisation: free-form group (e.g. customer/site) and tags.
    group: str | None = Field(default=None, index=True)
    tags: list = Field(default_factory=list, sa_column=Column(JSON))

    # Free-form documentation: how do I reach this box?
    access_notes: str | None = None  # e.g. "SSH :22 as admin, web UI https://..."
    web_url: str | None = None

    # Which collector gathers data and its (read-only) connection config.
    collector: str = Field(default="manual")  # see app/collectors
    collector_config: dict = Field(default_factory=dict, sa_column=Column(JSON))

    enabled: bool = Field(default=True)
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)

    scans: list["Scan"] = Relationship(back_populates="system")


class Scan(SQLModel, table=True):
    """One execution of a collector against a system."""

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(foreign_key="system.id", index=True)
    collector: str
    status: ScanStatus = Field(default=ScanStatus.pending)
    started_at: datetime = Field(default_factory=utcnow)
    finished_at: datetime | None = None
    error: str | None = None
    summary: dict = Field(default_factory=dict, sa_column=Column(JSON))

    system: System | None = Relationship(back_populates="scans")
    packages: list["Package"] = Relationship(back_populates="scan")
    vulnerabilities: list["Vulnerability"] = Relationship(back_populates="scan")


class Package(SQLModel, table=True):
    """A single software component observed in a scan (SBOM entry)."""

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    name: str = Field(index=True)
    version: str | None = None
    type: str | None = None  # os/deb/apk/rpm/pip/npm/docker-image/firmware/...
    source: str | None = None  # image:tag, container name, layer, path, ...
    purl: str | None = None  # package URL if known
    latest_version: str | None = None  # if the collector can determine it
    extra: dict = Field(default_factory=dict, sa_column=Column(JSON))

    scan: Scan | None = Relationship(back_populates="packages")


class ClientStatus(str, enum.Enum):
    pending = "pending"    # enrolled, awaiting approval (manual-approve mode)
    approved = "approved"  # may push data
    revoked = "revoked"    # blocked


class EnrollmentCode(SQLModel, table=True):
    """A short-lived code that lets a new agent enroll itself (frictionless).

    The code is handed out as part of a one-line install/join command. It is
    stored only as a hash, is single- or limited-use, and expires. Enrolling
    with it exchanges it for a durable per-client secret.
    """

    id: int | None = Field(default=None, primary_key=True)
    code_hash: str = Field(index=True)
    label: str | None = None  # e.g. "Kunde-A Rollout"
    auto_approve: bool = True  # approve enrolled clients immediately
    max_uses: int = 1
    uses: int = 0
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None
    # Optional defaults applied to systems created by clients from this code.
    group: str | None = None
    tags: list = Field(default_factory=list, sa_column=Column(JSON))


class Client(SQLModel, table=True):
    """An enrolled agent with its own durable credential and approval status."""

    id: int | None = Field(default=None, primary_key=True)
    client_id: str = Field(index=True, unique=True)
    secret_hash: str
    name: str
    status: ClientStatus = Field(default=ClientStatus.approved)
    system_id: int | None = Field(default=None, foreign_key="system.id")
    enrolled_at: datetime = Field(default_factory=utcnow)
    last_seen: datetime | None = None
    last_ip: str | None = None
    agent_version: str | None = None  # reported by the agent on each push
    # Zero-knowledge credential crypto: the agent's X25519 public key (secrets
    # are sealed to it) and the passphrase that unlocks the agent's own private
    # key, delivered to the authenticated agent at runtime (split knowledge).
    pubkey: str | None = None
    key_passphrase: str | None = None


class CommandStatus(str, enum.Enum):
    pending = "pending"
    delivered = "delivered"
    done = "done"


class AgentCommand(SQLModel, table=True):
    """A control command queued for a push-mode client.

    The server never connects to the client. Instead the client POSTs its data
    on a schedule (push), and the server returns any pending commands in that
    response. The client acts on them and reports back on its next push. This
    keeps all traffic client-initiated — no inbound path to the client.

    Commands only steer the agent's own read-only behaviour (rescan now, change
    interval, change what it collects). They never mutate the monitored system.
    """

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(foreign_key="system.id", index=True)
    type: str  # rescan | set_interval | set_config
    payload: dict = Field(default_factory=dict, sa_column=Column(JSON))
    status: CommandStatus = Field(default=CommandStatus.pending)
    created_at: datetime = Field(default_factory=utcnow)
    delivered_at: datetime | None = None


class ComponentChange(SQLModel, table=True):
    """A detected change in a component between two scans of a system.

    Computed by diffing each scan against the previous one, so Argus records
    *when* something changed — in particular when an update was actually
    applied (an available update disappeared because the version went up).
    """

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(foreign_key="system.id", index=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    detected_at: datetime = Field(default_factory=utcnow, index=True)
    name: str
    type: str | None = None
    change_type: str  # update_applied | version_changed | added | removed | status_changed
    old_value: str | None = None
    new_value: str | None = None


class Credential(SQLModel, table=True):
    """A module credential, stored **encrypted at rest** (envelope).

    The secret is Fernet-encrypted; it is decrypted only in memory and handed to
    an authenticated agent in its push response, so the agent can let a module
    (e.g. Home Assistant, OctoPrint) read a version/details that sit behind login.
    The agent keeps it in RAM only — never on disk.
    """

    id: int | None = Field(default=None, primary_key=True)
    label: str | None = None
    module: str = Field(index=True)   # which device module this credential is for
    username: str | None = None       # optional metadata (not the secret)
    match: str | None = None          # optional scope (MAC/IP) — None = any host
    created_at: datetime = Field(default_factory=utcnow)
    # v2 (zero-knowledge): the secret is SEALED to a specific agent's public key;
    # the server stores only this blob and cannot read it.
    client_id: int | None = Field(default=None, foreign_key="client.id", index=True)
    sealed: str | None = None         # ECIES blob, decryptable only by that agent
    secret_enc: str | None = None     # legacy v1 symmetric ciphertext (unused in v2)


class SystemSummary(SQLModel, table=True):
    """Denormalised per-system rollup for a fast dashboard (no N+1 at scale).

    Recomputed after each scan and when snoozes change, so listing hundreds of
    systems reads one small table instead of querying packages per system.
    """

    system_id: int = Field(foreign_key="system.id", primary_key=True)
    last_scan_id: int | None = None
    last_scan_at: datetime | None = None
    status: str | None = None
    packages: int = 0
    updates: int = 0  # pending, excluding snoozed components
    critical: int = 0
    high: int = 0
    updated_at: datetime = Field(default_factory=utcnow)


class Snooze(SQLModel, table=True):
    """Temporarily suppress a component's 'update available' flag.

    Lets you postpone a specific update (per system + component name) until a
    date — the component then counts as not-pending until the snooze expires.
    """

    __table_args__ = (UniqueConstraint("system_id", "component", name="uq_snooze"),)

    id: int | None = Field(default=None, primary_key=True)
    system_id: int = Field(foreign_key="system.id", index=True)
    component: str  # package/component name being snoozed
    until: datetime = Field(index=True)
    reason: str | None = None
    created_at: datetime = Field(default_factory=utcnow)


class Vulnerability(SQLModel, table=True):
    """A known vulnerability affecting a component (from trivy/grype/etc.)."""

    __table_args__ = (UniqueConstraint("scan_id", "cve_id", "package_name", name="uq_vuln"),)

    id: int | None = Field(default=None, primary_key=True)
    scan_id: int = Field(foreign_key="scan.id", index=True)
    cve_id: str = Field(index=True)
    severity: Severity = Field(default=Severity.unknown)
    package_name: str | None = None
    installed_version: str | None = None
    fixed_version: str | None = None
    title: str | None = None
    source: str | None = None

    scan: Scan | None = Relationship(back_populates="vulnerabilities")
