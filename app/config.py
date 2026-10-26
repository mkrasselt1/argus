"""Application configuration, loaded from environment / .env."""
from __future__ import annotations

import logging
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

log = logging.getLogger("argus.config")

_LOOPBACK_HOSTS = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SECSCAN_", env_file=".env", extra="ignore")

    # Where the SQLite database lives (mount this as a volume in Docker).
    data_dir: Path = DATA_DIR
    database_url: str | None = None

    # Web server
    host: str = "0.0.0.0"
    port: int = 8080
    # Auto-reload on source changes (watches files, reloads itself). Dev only —
    # keep off in production/containers. Enable with SECSCAN_RELOAD=1.
    reload: bool = False

    # Web UI login. Set a password to require login for the dashboard and all
    # management routes (ingest/enroll/agent APIs keep their own tokens and stay
    # open). Empty = no login (local/dev). secret_key signs the session cookie;
    # if empty it is derived from admin_password so sessions survive restarts.
    admin_password: str = ""
    secret_key: str = ""
    # Key for encrypting stored module credentials at rest. If empty it is
    # derived from the secret/password; set an explicit Fernet key in production.
    crypto_key: str = ""
    # Opt-out guard: start even with no admin password on a non-loopback host.
    allow_no_auth: bool = False
    # Mark the session cookie Secure (HTTPS-only). Disable only for local/dev
    # or test setups that run over plain HTTP.
    secure_cookies: bool = True

    # Public base URL of this server (e.g. https://argus.example.com). Used to
    # build install scripts and join tokens instead of trusting the Host header.
    # Empty = fall back to the request's base URL.
    public_url: str = ""

    # /agent/collect allow-list: collectors a remote caller may run through this
    # agent. Comma-separated. "relay" is intentionally excluded by default so an
    # agent cannot be abused as an open scan/SSRF proxy or looped back on itself.
    agent_allowed_collectors: str = "docker,ssh_linux,network_discovery,manual"

    # Ingest hardening: reject oversized payloads (defense against resource
    # exhaustion from a compromised/misbehaving agent).
    ingest_max_packages: int = 50000
    ingest_max_vulnerabilities: int = 50000
    # Maximum accepted request body size in bytes (checked via Content-Length).
    max_body_bytes: int = 33554432  # 32 MiB

    def auth_enabled(self) -> bool:
        return bool(self.admin_password)

    def host_is_loopback(self) -> bool:
        return (self.host or "").strip().lower() in _LOOPBACK_HOSTS

    def allowed_agent_collectors(self) -> set[str]:
        return {c.strip() for c in self.agent_allowed_collectors.split(",") if c.strip()}

    def public_base_url(self, fallback: str) -> str:
        """Return the configured public URL (trailing slash) or the fallback."""
        base = (self.public_url or fallback or "").strip()
        if base and not base.endswith("/"):
            base += "/"
        return base

    def session_secret(self) -> str:
        if self.secret_key:
            return self.secret_key
        import hashlib

        return hashlib.sha256(f"argus::{self.admin_password}".encode()).hexdigest()

    # Scheduler: how often (minutes) to re-run all enabled collectors. 0 = off.
    scan_interval_minutes: int = 360
    # Retention: keep at most this many scans per system (older ones are pruned
    # daily). 0 = keep everything. Bounds DB growth at scale.
    scan_retention: int = 20

    # Path to trivy/syft binaries if available (optional, enhances SBOM + CVE data).
    trivy_bin: str = "trivy"
    syft_bin: str = "syft"

    # Agent/relay mode: when a token is set, this instance exposes the read-only
    # /agent/collect endpoint so another argus can collect *through* it
    # (e.g. an edge node reachable via VPN that can see an otherwise isolated
    # internal network). Empty token = endpoint disabled.
    agent_token: str = ""
    # Timeout (seconds) when this instance calls a remote agent via the relay.
    relay_timeout: int = 900

    # Push/ingest mode: clients POST their own scan results here (client ->
    # server), so the server needs no inbound path to clients. Set a strong
    # shared secret to enable the /ingest endpoint. Empty = disabled.
    ingest_token: str = ""
    # Auto-create unknown systems on first push (vs. requiring them pre-defined).
    ingest_auto_register: bool = True

    def agent_enabled(self) -> bool:
        return bool(self.agent_token)

    def ingest_enabled(self) -> bool:
        return bool(self.ingest_token)

    def resolved_database_url(self) -> str:
        if self.database_url:
            return self.database_url
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return f"sqlite:///{self.data_dir / 'argus.db'}"


settings = Settings()


def warn_weak_keys() -> None:
    """Warn (don't fail) when crypto material is derived rather than explicit."""
    if settings.auth_enabled() and not settings.secret_key:
        log.warning(
            "SECSCAN_SECRET_KEY is empty: the session-cookie secret is derived "
            "from the admin password. Set an explicit random SECSCAN_SECRET_KEY "
            "in production so sessions survive a password change."
        )
    if not settings.crypto_key:
        log.warning(
            "SECSCAN_CRYPTO_KEY is empty: the at-rest encryption key is derived "
            "from the session secret. Set an explicit Fernet SECSCAN_CRYPTO_KEY "
            "in production so stored secrets survive a secret/password change."
        )


def enforce_startup_safety() -> None:
    """Refuse to start an unauthenticated UI on a non-loopback interface.

    A missing SECSCAN_ADMIN_PASSWORD means the dashboard and all management
    routes are open. Binding that to 0.0.0.0 (the default) would expose an
    admin UI to the network. Require either a password, a loopback bind, or an
    explicit opt-out (SECSCAN_ALLOW_NO_AUTH=1).
    """
    if settings.auth_enabled() or settings.host_is_loopback() or settings.allow_no_auth:
        return
    raise SystemExit(
        "REFUSING TO START: authentication is disabled (no SECSCAN_ADMIN_PASSWORD) "
        f"and the server is bound to a non-loopback host ({settings.host!r}). "
        "This would expose the admin UI to the network.\n"
        "Fix one of:\n"
        "  * set SECSCAN_ADMIN_PASSWORD=<strong password> (recommended), or\n"
        "  * bind to loopback with SECSCAN_HOST=127.0.0.1, or\n"
        "  * if you really intend an open instance (e.g. behind an auth proxy), "
        "set SECSCAN_ALLOW_NO_AUTH=1."
    )
