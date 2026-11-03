"""Integration API (/api/overview + token-only scan triggers) used by Home Assistant."""
import os
import tempfile

os.environ.setdefault("SECSCAN_DATABASE_URL", f"sqlite:///{tempfile.mktemp(suffix='.db')}")
os.environ.setdefault("SECSCAN_SCAN_INTERVAL_MINUTES", "0")
os.environ.setdefault("SECSCAN_SECURE_COOKIES", "0")

from fastapi.testclient import TestClient  # noqa: E402

from app.collectors.base import CollectResult, PackageResult, VulnResult  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Severity  # noqa: E402
from app.services import scanner  # noqa: E402

TOKEN = "ha-test-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


def _seed() -> int:
    result = CollectResult(
        packages=[PackageResult(name="openssl", version="1.0", latest_version="3.0", type="deb")],
        vulnerabilities=[
            VulnResult(cve_id="CVE-1", severity=Severity.critical, package_name="openssl"),
            VulnResult(cve_id="CVE-2", severity=Severity.high, package_name="openssl"),
        ],
        summary={"os_support": "END-OF-LIFE", "os_latest": "Debian 13"},
    )
    scan = scanner.ingest_result("HA-Box", "manual", result)
    return scan.system_id


def test_overview_requires_auth_and_accepts_bearer(monkeypatch):
    monkeypatch.setattr(settings, "admin_password", "geheim")
    monkeypatch.setattr(settings, "api_token", TOKEN)
    with TestClient(app) as client:
        sid = _seed()
        assert client.get("/api/overview").status_code == 401
        assert client.get("/api/overview",
                          headers={"Authorization": "Bearer wrong"}).status_code == 401
        r = client.get("/api/overview", headers=AUTH)
        assert r.status_code == 200
        data = r.json()
        box = next(s for s in data["systems"] if s["id"] == sid)
        assert box["updates"] == 1 and box["critical"] == 1 and box["high"] == 1
        assert box["eol"] is True and box["os_latest"] == "Debian 13"
        assert "access_notes" not in box and "collector_config" not in box
        assert data["totals"]["critical"] >= 1 and data["totals"]["eol"] >= 1
        # the bearer token only opens the JSON API, not the UI
        ui = client.get("/", headers={**AUTH, "accept": "text/html"}, follow_redirects=False)
        assert ui.status_code == 303


def test_api_scan_trigger_is_token_only(monkeypatch):
    monkeypatch.setattr(settings, "api_token", "")
    with TestClient(app) as client:
        sid = _seed()
        assert client.post(f"/api/systems/{sid}/scan").status_code == 404
        monkeypatch.setattr(settings, "api_token", TOKEN)
        calls = []
        monkeypatch.setattr(scanner, "request_scan", lambda i: calls.append(i))
        assert client.post(f"/api/systems/{sid}/scan").status_code == 401
        assert client.post("/api/systems/999999/scan", headers=AUTH).status_code == 404
        r = client.post(f"/api/systems/{sid}/scan", headers=AUTH)
        assert r.status_code == 200 and calls == [sid]
