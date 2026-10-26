"""Smoke tests: app boots, DB initialises, collectors register, parsing works."""
import os
import tempfile

os.environ.setdefault("SECSCAN_DATABASE_URL", f"sqlite:///{tempfile.mktemp(suffix='.db')}")
os.environ.setdefault("SECSCAN_SCAN_INTERVAL_MINUTES", "0")

from fastapi.testclient import TestClient  # noqa: E402

from app.collectors.base import (  # noqa: E402
    CollectResult,
    PackageResult,
    VulnResult,
    available,
    load_builtin_collectors,
)
from app.collectors.ssh_linux import _parse_packages  # noqa: E402
from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Severity  # noqa: E402


def test_collectors_register():
    load_builtin_collectors()
    names = available()
    assert "docker" in names
    assert "manual" in names
    assert "relay" in names


def test_collectresult_roundtrip():
    original = CollectResult(
        packages=[PackageResult(name="bash", version="5.1", type="deb")],
        vulnerabilities=[
            VulnResult(cve_id="CVE-2024-0001", severity=Severity.high, package_name="bash")
        ],
        summary={"mode": "trivy"},
    )
    restored = CollectResult.from_dict(original.to_dict())
    assert restored.packages[0].name == "bash"
    assert restored.vulnerabilities[0].severity == Severity.high
    assert restored.summary == {"mode": "trivy"}


def test_discovery_finds_open_port():
    import socket

    from app.collectors.base import run_collector

    load_builtin_collectors()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    port = srv.getsockname()[1]
    try:
        res = run_collector(
            "network_discovery",
            {"targets": "127.0.0.1", "ports": [port], "timeout": 1.0},
        )
    finally:
        srv.close()
    assert res.summary["hosts_alive"] == 1
    assert any(p.extra.get("port") == port for p in res.packages)


def test_discovery_respects_max_hosts():
    from app.collectors.base import run_collector

    load_builtin_collectors()
    try:
        run_collector("network_discovery", {"targets": "10.0.0.0/16", "max_hosts": 10})
    except ValueError as exc:
        assert "max_hosts" in str(exc)
    else:
        raise AssertionError("expected max_hosts guard to trigger")


def test_winget_list_parser_german_columns():
    from app.collectors.windows import _parse_winget_list

    # German headers; "Edge" has no available update (empty Available column).
    output = (
        "Name                 Id                 Version      Verfügbar    Quelle\n"
        "------------------------------------------------------------------------\n"
        "Git                  Git.Git            2.38.1       2.55.0.5     winget\n"
        "Microsoft Edge       Microsoft.Edge     120.0.0                   winget\n"
        "Docker Desktop       Docker.DockerD     4.77.0       4.96.2       winget\n"
    )
    parsed = _parse_winget_list(output)
    assert parsed["git"]["available"] == "2.55.0.5"
    assert parsed["git"]["id"] == "Git.Git"
    assert parsed["git"]["source"] == "winget"
    # recognized by winget but up to date -> no available, but has a source
    assert parsed["microsoft edge"]["available"] is None
    assert parsed["microsoft edge"]["source"] == "winget"
    assert parsed["docker desktop"]["available"] == "4.96.2"


def test_update_classification():
    from app.collectors.windows import _classify_update

    assert _classify_update("3.95", "4.27") == "major"   # Advanced Renamer case
    assert _classify_update("2.38.1", "2.55.0.5") == "minor"
    assert _classify_update(None, "1.0") == "minor"


def test_device_modules_parse_details(monkeypatch):
    from app.collectors import network_discovery as nd

    responses = {
        "http://1.2.3.4/rpc/Shelly.GetDeviceInfo": {
            "name": "shellyplus1", "id": "shellyplus1-abc", "model": "SNSW-001X16EU",
            "gen": 2, "fw_id": "20240101", "ver": "1.2.3", "app": "Plus1", "mac": "AABBCC",
        },
        "http://5.6.7.8/cm?cmnd=Status%200": {
            "Status": {"DeviceName": "Küche", "Module": 1},
            "StatusFWR": {"Version": "14.2.0(tasmota)", "Hardware": "ESP32", "Core": "3.0"},
            "StatusNET": {"Mac": "11:22:33", "IPAddress": "5.6.7.8"},
        },
    }
    monkeypatch.setattr(nd, "_http_json", lambda url, timeout: responses.get(url))

    shelly = nd._mod_shelly("1.2.3.4", 1.0)
    assert shelly.product.startswith("Shelly") and shelly.version == "1.2.3"
    assert shelly.details.get("gen") == 2 and shelly.details.get("mac") == "AABBCC"

    tas = nd._mod_tasmota("5.6.7.8", 1.0)
    assert tas.product == "Tasmota" and tas.version == "14.2.0(tasmota)"
    assert tas.details.get("Hardware") == "ESP32" and tas.details.get("DeviceName") == "Küche"

    # module registry carries metadata (ports, auth)
    assert nd.DEVICE_MODULES["homeassistant"].needs_auth is True
    assert 8123 in nd.DEVICE_MODULES["homeassistant"].ports


def test_credentials_zero_knowledge():
    """v2: secrets are sealed to an agent key; the server stores only blobs."""
    from sqlmodel import Session

    from app.db import engine, init_db
    from app.models import Client
    from app.services import credentials, crypto

    init_db()
    # agent keypair; secret is sealed to its public key
    priv, pub = crypto.generate_keypair()
    with Session(engine) as session:
        client = Client(client_id="agt_zk", secret_hash="x", name="ZK", pubkey=pub,
                        key_passphrase="pp")
        session.add(client)
        session.commit()
        session.refresh(client)
        cid = client.id

    sealed = crypto.seal(pub, "ha-token-xyz")
    credentials.add_sealed(cid, "homeassistant", sealed, label="HA")

    rows = [r for r in credentials.list_credentials() if r.client_id == cid]
    assert rows and rows[0].sealed == sealed  # server stores the opaque blob
    assert "ha-token-xyz" not in rows[0].sealed  # not plaintext

    # only the agent (its private key) can open the delivered blob
    delivered = credentials.delivery_for_client(cid)
    assert delivered[0]["sealed"] == sealed
    assert crypto.unseal(priv, delivered[0]["sealed"]) == "ha-token-xyz"


def test_snooze_hides_update():
    from app.db import init_db
    from app.services import scanner
    from sqlmodel import Session
    from app.db import engine

    init_db()
    scanner.snooze_component(1, "SomeApp", days=30)
    with Session(engine) as session:
        snz = scanner.active_snoozes(session, 1)
        assert "SomeApp" in snz
    scanner.unsnooze_component(1, "SomeApp")
    with Session(engine) as session:
        assert "SomeApp" not in scanner.active_snoozes(session, 1)


def test_auth_required_when_password_set(monkeypatch):
    monkeypatch.setattr(settings, "admin_password", "geheim")
    with TestClient(app) as client:
        # UI redirects to login when unauthenticated
        r = client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
        assert r.status_code == 303 and "/login" in r.headers["location"]
        # ingest stays open (own token), not behind the UI login
        assert client.post("/ingest", json={}).status_code in (401, 404, 422)
        # login then access
        client.post("/login", data={"password": "geheim", "next": "/"}, follow_redirects=False)
        assert client.get("/", headers={"accept": "text/html"}).status_code == 200


def test_port_presets():
    from app.collectors.network_discovery import DEFAULT_PORTS, _resolve_ports

    assert _resolve_ports(None) == DEFAULT_PORTS
    assert _resolve_ports("common") == DEFAULT_PORTS
    assert _resolve_ports("full") == list(range(1, 65536))
    assert _resolve_ports("web") and 443 in _resolve_ports("web")
    assert _resolve_ports([22, 80, 443]) == [22, 80, 443]
    assert _resolve_ports(22) == [22]
    # unknown preset falls back to common (never empty)
    assert _resolve_ports("bogus") == DEFAULT_PORTS


def test_discovery_multi_subnet():
    from app.collectors.network_discovery import _expand_targets

    hosts = _expand_targets(["192.168.1.0/30", "10.0.0.5"], max_hosts=100)
    # /30 yields 2 usable hosts + 1 literal = 3
    assert "10.0.0.5" in hosts
    assert "192.168.1.1" in hosts and "192.168.1.2" in hosts
    assert len(hosts) == 3


def test_os_release_parse():
    from app.collectors.ssh_linux import _parse_os_release

    info = 'NAME="Ubuntu"\nID=ubuntu\nVERSION_ID="20.04"\nPRETTY_NAME="Ubuntu 20.04.6 LTS"\n'
    f = _parse_os_release(info)
    assert f["ID"] == "ubuntu"
    assert f["VERSION_ID"] == "20.04"


def test_eol_classification_offline(monkeypatch):
    from app.services import eol

    fake = [
        {"cycle": "11-24h2-w", "releaseLabel": "11 24H2 (W)", "eol": "2099-01-01",
         "latest": "10.0.26100"},
        {"cycle": "11-22h2-w", "releaseLabel": "11 22H2 (W)", "eol": "2024-10-08",
         "latest": "10.0.22621"},
    ]
    monkeypatch.setattr(eol, "_fetch", lambda product, timeout: fake)
    st = eol.windows_status(22621, "Professional")
    assert st["is_eol"] is True
    assert st["outdated"] is True
    assert st["latest_label"] == "24H2"


def test_change_history_detects_update_applied(monkeypatch):
    from sqlmodel import Session, select

    from app.collectors.base import CollectResult, PackageResult
    from app.db import engine, init_db
    from app.models import ComponentChange
    from app.services import scanner

    init_db()
    monkeypatch.setattr(settings, "ingest_token", "t")
    monkeypatch.setattr(settings, "ingest_auto_register", True)

    # scan 1: Git 2.38 with an update to 2.55 available
    r1 = CollectResult(packages=[
        PackageResult(name="Git", version="2.38.1", latest_version="2.55.0", type="windows-app")
    ])
    scanner.ingest_result("HistBox", "windows", r1)
    # scan 2: Git now at 2.55 (update was applied), and a new program appeared
    r2 = CollectResult(packages=[
        PackageResult(name="Git", version="2.55.0", latest_version="2.55.0", type="windows-app"),
        PackageResult(name="NewTool", version="1.0", type="windows-app"),
    ])
    scan2 = scanner.ingest_result("HistBox", "windows", r2)

    with Session(engine) as session:
        changes = session.exec(
            select(ComponentChange).where(ComponentChange.scan_id == scan2.id)
        ).all()
    by_name = {c.name: c for c in changes}
    assert by_name["Git"].change_type == "update_applied"
    assert by_name["Git"].old_value == "2.38.1" and by_name["Git"].new_value == "2.55.0"
    assert by_name["NewTool"].change_type == "added"


def test_discovered_devices_become_systems(monkeypatch):
    from sqlmodel import Session, select

    from app.db import engine, init_db
    from app.models import System
    from app.services import scanner

    init_db()
    monkeypatch.setattr(settings, "ingest_token", "t")
    monkeypatch.setattr(settings, "ingest_auto_register", True)

    def scan_result(fw):
        return {
            "packages": [
                {"name": "Shelly Plus 1", "version": fw, "type": "iot-device",
                 "source": "192.168.30.9",
                 "extra": {"mac": "aa:bb:cc:dd:ee:01", "device_name": "Wohnzimmer",
                           "hostname": "shelly1.local"}},
                {"name": "http", "version": "80", "type": "open-port",
                 "source": "192.168.30.9", "extra": {"port": 80}},
                {"name": "unknownhost", "version": "80", "type": "open-port",
                 "source": "192.168.30.50", "extra": {"port": 80}},  # not identified -> no system
            ],
            "vulnerabilities": [], "summary": {},
        }

    from app.collectors.base import CollectResult
    scanner.ingest_result("NetAgent", "network_discovery", CollectResult.from_dict(scan_result("1.0.0")))

    with Session(engine) as session:
        devs = session.exec(select(System).where(System.discovered == True)).all()  # noqa: E712
        names = {d.name: d for d in devs}
        assert "Wohnzimmer" in names  # named after the device's own name
        dev = names["Wohnzimmer"]
        assert dev.mac == "aa:bb:cc:dd:ee:01"
        assert dev.discovered_via == "NetAgent"
        assert dev.group == "NetAgent"
        assert dev.ip_address == "192.168.30.9"
        # the unidentified host did NOT become a system
        assert not any(d.ip_address == "192.168.30.50" for d in devs)

    # re-scan with a new IP but same MAC -> recognised, not duplicated
    scanner.ingest_result("NetAgent", "network_discovery", CollectResult.from_dict({
        "packages": [{"name": "Shelly Plus 1", "version": "1.1.0", "type": "iot-device",
                      "source": "192.168.30.77",
                      "extra": {"mac": "aa:bb:cc:dd:ee:01", "device_name": "Wohnzimmer"}}],
        "vulnerabilities": [], "summary": {}}))
    with Session(engine) as session:
        devs = session.exec(select(System).where(System.mac == "aa:bb:cc:dd:ee:01")).all()
        assert len(devs) == 1 and devs[0].ip_address == "192.168.30.77"


def test_discovered_devices_inherit_agent_tags(monkeypatch):
    from sqlmodel import Session, select

    from app.collectors.base import CollectResult
    from app.db import engine, init_db
    from app.models import System
    from app.services import scanner

    init_db()
    monkeypatch.setattr(settings, "ingest_token", "t")
    monkeypatch.setattr(settings, "ingest_auto_register", True)

    # pre-create the agent system WITH tags, then it discovers a device
    with Session(engine) as session:
        agent = System(name="TagAgent", collector="network_discovery",
                       tags=["kunde-a", "standort-nord"])
        session.add(agent)
        session.commit()

    scanner.ingest_result("TagAgent", "network_discovery", CollectResult.from_dict({
        "packages": [{"name": "Shelly X", "version": "1.0", "type": "iot-device",
                      "source": "10.0.0.5", "extra": {"mac": "de:ad:be:ef:00:01"}}],
        "vulnerabilities": [], "summary": {}}))

    with Session(engine) as session:
        dev = session.exec(select(System).where(System.mac == "de:ad:be:ef:00:01")).first()
        assert set(dev.tags) >= {"kunde-a", "standort-nord"}

    # editing the agent's tags propagates immediately (union, non-destructive)
    moved = scanner.propagate_agent_to_devices("TagAgent", "TagAgent", ["kunde-a", "wichtig"])
    assert moved == 1
    with Session(engine) as session:
        dev = session.exec(select(System).where(System.mac == "de:ad:be:ef:00:01")).first()
        assert set(dev.tags) >= {"kunde-a", "standort-nord", "wichtig"}


def test_join_token_roundtrip():
    from app.services import enrollment

    tok = enrollment.encode_join_token("https://argus.local:8443", "CODE123", "sha256:ab")
    assert tok.startswith("argus-join-")
    info = enrollment.decode_join_token(tok)
    assert info["server"] == "https://argus.local:8443"
    assert info["code"] == "CODE123" and info["fingerprint"] == "sha256:ab"


def test_enrollment_auto_approve_and_manual():
    from app.db import init_db
    from app.services import enrollment

    init_db()
    # auto-approve: enrolled client can authenticate immediately
    code, _ = enrollment.create_code(auto_approve=True)
    creds = enrollment.enroll(code, "AgentA")
    assert creds["status"] == "approved"
    assert enrollment.authenticate(creds["client_id"], creds["client_secret"]) is not None
    # wrong secret -> None
    assert enrollment.authenticate(creds["client_id"], "nope") is None

    # manual approval: pending client is blocked until approved
    code2, _ = enrollment.create_code(auto_approve=False)
    creds2 = enrollment.enroll(code2, "AgentB")
    assert creds2["status"] == "pending"
    try:
        enrollment.authenticate(creds2["client_id"], creds2["client_secret"])
    except PermissionError as exc:
        assert str(exc) == "pending"
    else:
        raise AssertionError("pending client should raise PermissionError")

    # expired/used codes are rejected
    import pytest
    with pytest.raises(ValueError):
        enrollment.enroll(code, "AgentC")  # single-use code already consumed


def test_enroll_endpoint_and_per_client_ingest():
    from app.services import enrollment

    with TestClient(app) as client:
        code, _ = enrollment.create_code(auto_approve=True)
        r = client.post("/enroll", json={"code": code, "name": "PushAgent"})
        assert r.status_code == 200
        creds = r.json()
        # per-client auth works without the shared ingest token
        r2 = client.post(
            "/ingest",
            json={"system": "PushAgent", "collector": "manual",
                  "result": {"packages": [], "vulnerabilities": [], "summary": {}}},
            headers={"X-Client-Id": creds["client_id"], "X-Client-Token": creds["client_secret"]},
        )
        assert r2.status_code == 200 and r2.json()["ok"]
        # bad client credentials are rejected
        r3 = client.post(
            "/ingest",
            json={"system": "X", "collector": "manual",
                  "result": {"packages": [], "vulnerabilities": [], "summary": {}}},
            headers={"X-Client-Id": creds["client_id"], "X-Client-Token": "wrong"},
        )
        assert r3.status_code == 401


def test_ingest_push_and_command_channel(monkeypatch):
    monkeypatch.setattr(settings, "ingest_token", "pushsecret")
    monkeypatch.setattr(settings, "ingest_auto_register", True)
    payload = {
        "system": "PushBox",
        "collector": "windows",
        "kind": "windows",
        "hostname": "pushbox.local",
        "result": {
            "packages": [{"name": "Git", "version": "2.38.1", "latest_version": "2.55.0"}],
            "vulnerabilities": [],
            "summary": {"installed_programs": 1},
        },
    }
    with TestClient(app) as client:
        # wrong token rejected
        assert client.post("/ingest", json=payload).status_code == 401
        # push creates the system and stores the scan
        r = client.post("/ingest", json=payload, headers={"X-Ingest-Token": "pushsecret"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] and body["commands"] == []

        systems = client.get("/api/systems").json()
        sysid = next(s["id"] for s in systems if s["name"] == "PushBox")

        # queue a control command; it is handed back on the next push, once
        client.post(f"/systems/{sysid}/command", data={"cmd_type": "rescan"},
                    follow_redirects=False)
        r2 = client.post("/ingest", json=payload, headers={"X-Ingest-Token": "pushsecret"})
        cmds = r2.json()["commands"]
        assert len(cmds) == 1 and cmds[0]["type"] == "rescan"
        # delivered only once
        r3 = client.post("/ingest", json=payload, headers={"X-Ingest-Token": "pushsecret"})
        assert r3.json()["commands"] == []


def test_agent_disabled_by_default():
    with TestClient(app) as client:
        r = client.post("/agent/collect", json={"collector": "manual", "config": {}})
        assert r.status_code == 404


def test_agent_with_token(monkeypatch):
    monkeypatch.setattr(settings, "agent_token", "s3cret")
    with TestClient(app) as client:
        assert client.post("/agent/collect", json={"collector": "manual"}).status_code == 401
        r = client.post(
            "/agent/collect",
            json={"collector": "manual", "config": {}},
            headers={"X-Agent-Token": "s3cret"},
        )
        assert r.status_code == 200
        assert "summary" in r.json()


def test_parse_deb_packages():
    out = "bash\t5.1-2\nopenssl\t3.0.2-1\n"
    pkgs = _parse_packages(out, "deb")
    assert [p.name for p in pkgs] == ["bash", "openssl"]
    assert pkgs[1].version == "3.0.2-1"


def test_health_and_version():
    with TestClient(app) as client:
        assert client.get("/healthz").json() == {"status": "ok"}
        v = client.get("/version").json()
        assert "version" in v and "schema_revision" in v


def test_create_and_list_system():
    with TestClient(app) as client:
        r = client.post(
            "/systems",
            data={"name": "Test NAS", "kind": "synology", "collector": "manual"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        systems = client.get("/api/systems").json()
        assert any(s["name"] == "Test NAS" for s in systems)
