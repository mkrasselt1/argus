"""Tests for the security hardening fixes (CSRF, agent binding, rate limit, ...)."""
import os
import re
import tempfile

os.environ.setdefault("SECSCAN_DATABASE_URL", f"sqlite:///{tempfile.mktemp(suffix='.db')}")
os.environ.setdefault("SECSCAN_SCAN_INTERVAL_MINUTES", "0")
os.environ.setdefault("SECSCAN_SECURE_COOKIES", "0")

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.config import Settings, enforce_startup_safety, settings  # noqa: E402
from app.main import app  # noqa: E402
from app.services.ratelimit import RateLimiter, enroll_limiter, login_limiter  # noqa: E402


def _csrf(client, path: str = "/systems/new") -> str:
    r = client.get(path, headers={"accept": "text/html"})
    m = re.search(r'name="csrf_token" value="([^"]+)"', r.text)
    assert m, f"no CSRF token found on {path}"
    return m.group(1)


# ---- C1: agent <-> system binding ----------------------------------------

def test_agent_bound_to_one_system():
    from app.services import enrollment

    with TestClient(app) as client:
        code, _ = enrollment.create_code(auto_approve=True)
        creds = client.post("/enroll", json={"code": code, "name": "BindAgent"}).json()
        headers = {"X-Client-Id": creds["client_id"], "X-Client-Token": creds["client_secret"]}
        empty = {"packages": [], "vulnerabilities": [], "summary": {}}

        # first push binds the agent to "Alpha"
        r1 = client.post("/ingest",
                         json={"system": "Alpha", "collector": "manual", "result": empty},
                         headers=headers)
        assert r1.status_code == 200 and r1.json()["ok"]

        # pushing a different system is rejected (403) — no auto-register of others
        r2 = client.post("/ingest",
                         json={"system": "Beta", "collector": "manual", "result": empty},
                         headers=headers)
        assert r2.status_code == 403

        # pushing its own system again still works
        r3 = client.post("/ingest",
                         json={"system": "Alpha", "collector": "manual", "result": empty},
                         headers=headers)
        assert r3.status_code == 200

        # the other system was never created
        names = {s["name"] for s in client.get("/api/systems").json()}
        assert "Alpha" in names and "Beta" not in names


# ---- H1/M3: CSRF ----------------------------------------------------------

def test_csrf_blocks_post_without_token():
    with TestClient(app) as client:
        r = client.post("/systems",
                        data={"name": "NoCSRF", "kind": "other", "collector": "manual"},
                        follow_redirects=False)
        assert r.status_code == 403

        r2 = client.post("/systems",
                         data={"name": "WithCSRF", "kind": "other", "collector": "manual",
                               "csrf_token": _csrf(client)},
                         follow_redirects=False)
        assert r2.status_code == 303


def test_ingest_exempt_from_csrf():
    """Machine endpoint authenticates with a token, not a cookie — no CSRF."""
    from app.services import enrollment

    with TestClient(app) as client:
        code, _ = enrollment.create_code(auto_approve=True)
        creds = client.post("/enroll", json={"code": code, "name": "NoCsrfAgent"}).json()
        r = client.post(
            "/ingest",
            json={"system": "NoCsrfAgent", "collector": "manual",
                  "result": {"packages": [], "vulnerabilities": [], "summary": {}}},
            headers={"X-Client-Id": creds["client_id"], "X-Client-Token": creds["client_secret"]},
        )
        assert r.status_code == 200


# ---- H3: /agent/collect allow-list + relay verify -------------------------

def test_agent_collect_allowlist(monkeypatch):
    monkeypatch.setattr(settings, "agent_token", "s3cret")
    with TestClient(app) as client:
        h = {"X-Agent-Token": "s3cret"}
        # relay is NOT in the default allow-list -> 403 (no SSRF/loop proxy)
        r = client.post("/agent/collect", json={"collector": "relay", "config": {}}, headers=h)
        assert r.status_code == 403
        # manual is allowed
        r2 = client.post("/agent/collect", json={"collector": "manual", "config": {}}, headers=h)
        assert r2.status_code == 200


def test_relay_verify_cannot_be_disabled():
    from app.collectors.relay import _resolve_verify

    assert _resolve_verify(True) is True
    assert _resolve_verify("true") is True
    for bad in (False, "false", "0", "no"):
        with pytest.raises(ValueError):
            _resolve_verify(bad)
    with pytest.raises(ValueError):
        _resolve_verify("/nonexistent/ca-bundle.pem")


# ---- H4: rate limiting + ingest caps --------------------------------------

def test_rate_limiter_unit():
    rl = RateLimiter(max_hits=3, window_seconds=100, lockout_seconds=100)
    assert all(rl.check("ip") for _ in range(3))
    assert rl.check("ip") is False  # 4th blocked
    assert rl.check("ip") is False  # stays locked
    rl.reset("ip")
    assert rl.check("ip") is True


def test_login_rate_limit_locks_out(monkeypatch):
    monkeypatch.setattr(settings, "admin_password", "geheim")
    login_limiter.reset("testclient")
    try:
        with TestClient(app) as client:
            locked = False
            for _ in range(13):
                r = client.post("/login", data={"password": "wrong", "next": "/"},
                                follow_redirects=False)
                if "error=locked" in r.headers.get("location", ""):
                    locked = True
            assert locked
    finally:
        login_limiter.reset("testclient")


def test_ingest_rejects_oversized_payload(monkeypatch):
    from app.services import enrollment

    monkeypatch.setattr(settings, "ingest_max_packages", 2)
    with TestClient(app) as client:
        code, _ = enrollment.create_code(auto_approve=True)
        creds = client.post("/enroll", json={"code": code, "name": "BigAgent"}).json()
        pkgs = [{"name": f"p{i}", "version": "1"} for i in range(5)]
        r = client.post(
            "/ingest",
            json={"system": "BigAgent", "collector": "manual",
                  "result": {"packages": pkgs, "vulnerabilities": [], "summary": {}}},
            headers={"X-Client-Id": creds["client_id"], "X-Client-Token": creds["client_secret"]},
        )
        assert r.status_code == 413


# ---- L1: malformed ingest body -> 400 (not 500) ---------------------------

def test_ingest_malformed_result_is_400(monkeypatch):
    monkeypatch.setattr(settings, "ingest_token", "tok")
    with TestClient(app) as client:
        r = client.post(
            "/ingest",
            json={"system": "X", "collector": "manual", "result": {"packages": [123]}},
            headers={"X-Ingest-Token": "tok"},
        )
        assert r.status_code == 400


# ---- H2: collector_config secret encryption at rest -----------------------

def test_config_secret_encryption_roundtrip():
    from app.services import crypto

    cfg = {"host": "h", "username": "u", "password": "s3cret",
           "via": {"host": "edge", "password": "innerpw"}}
    enc = crypto.encrypt_config(cfg)
    assert enc["password"].startswith(crypto.ENC_PREFIX)
    assert "s3cret" not in enc["password"]
    assert enc["via"]["password"].startswith(crypto.ENC_PREFIX)
    assert enc["host"] == "h" and enc["username"] == "u"  # non-secret untouched

    # idempotent: re-encrypting an already-encrypted config changes nothing
    assert crypto.encrypt_config(enc) == enc

    dec = crypto.decrypt_config(enc)
    assert dec["password"] == "s3cret"
    assert dec["via"]["password"] == "innerpw"


def test_create_system_encrypts_config():
    from sqlmodel import Session, select

    from app.db import engine
    from app.models import System
    from app.services import crypto

    with TestClient(app) as client:
        client.post(
            "/systems",
            data={"name": "SSH Box", "kind": "linux", "collector": "ssh_linux",
                  "collector_config": '{"host": "1.2.3.4", "password": "hunter2"}',
                  "csrf_token": _csrf(client)},
            follow_redirects=False,
        )
    with Session(engine) as session:
        sys = session.exec(select(System).where(System.name == "SSH Box")).first()
        assert sys is not None
        assert sys.collector_config["password"].startswith(crypto.ENC_PREFIX)
        assert crypto.decrypt_config(sys.collector_config)["password"] == "hunter2"


# ---- L2: web_url scheme validation ----------------------------------------

def test_web_url_rejects_non_http():
    with TestClient(app) as client:
        r = client.post(
            "/systems",
            data={"name": "BadURL", "kind": "other", "collector": "manual",
                  "web_url": "javascript:alert(1)", "csrf_token": _csrf(client)},
            follow_redirects=False,
        )
        assert r.status_code == 400


# ---- M6: option injection into trivy/docker -------------------------------

def test_docker_rejects_option_like_refs():
    from app.collectors.docker_local import _reject_option_like

    with pytest.raises(ValueError):
        _reject_option_like("--config=/evil", "image ref")
    _reject_option_like("nginx:latest", "image ref")  # fine


# ---- C2: startup safety guard ---------------------------------------------

def test_startup_safety_refuses_open_ui(monkeypatch):
    monkeypatch.setattr(settings, "admin_password", "")
    monkeypatch.setattr(settings, "host", "0.0.0.0")
    monkeypatch.setattr(settings, "allow_no_auth", False)
    with pytest.raises(SystemExit):
        enforce_startup_safety()

    # loopback is fine without a password
    monkeypatch.setattr(settings, "host", "127.0.0.1")
    enforce_startup_safety()

    # explicit opt-out is fine on any host
    monkeypatch.setattr(settings, "host", "0.0.0.0")
    monkeypatch.setattr(settings, "allow_no_auth", True)
    enforce_startup_safety()

    # a password is always fine
    monkeypatch.setattr(settings, "allow_no_auth", False)
    monkeypatch.setattr(settings, "admin_password", "pw")
    enforce_startup_safety()


def test_allowed_agent_collectors_default():
    s = Settings()
    assert s.allowed_agent_collectors() == {"docker", "ssh_linux", "network_discovery", "manual"}
    assert "relay" not in s.allowed_agent_collectors()
