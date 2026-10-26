"""Application configuration, loaded from environment / .env."""
from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

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

    def auth_enabled(self) -> bool:
        return bool(self.admin_password)

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
