"""Unit tests for the network_discovery collector — no real network access."""
import os
import socket
import tempfile

os.environ.setdefault("SECSCAN_DATABASE_URL", f"sqlite:///{tempfile.mktemp(suffix='.db')}")
os.environ.setdefault("SECSCAN_SCAN_INTERVAL_MINUTES", "0")

from app.collectors import network_discovery as nd  # noqa: E402


# --- target expansion ------------------------------------------------------

def test_expand_one_cidr_and_host():
    assert nd._expand_one("10.0.0.5") == ["10.0.0.5"]
    assert nd._expand_one("host.example") == ["host.example"]
    cidr = nd._expand_one("192.168.1.0/30")
    assert cidr == ["192.168.1.1", "192.168.1.2"]  # usable hosts only


def test_expand_targets_cidr_host_mix():
    hosts = nd._expand_targets(["192.168.1.0/30", "10.0.0.5", "nas.local"], max_hosts=100)
    assert hosts == ["192.168.1.1", "192.168.1.2", "10.0.0.5", "nas.local"]


def test_expand_targets_dedupes_and_guards_max_hosts():
    # /30 overlaps the literal 192.168.1.1 -> deduped to 2 hosts.
    hosts = nd._expand_targets(["192.168.1.0/30", "192.168.1.1"], max_hosts=100)
    assert hosts == ["192.168.1.1", "192.168.1.2"]
    try:
        nd._expand_targets("10.0.0.0/16", max_hosts=10)
    except ValueError as exc:
        assert "max_hosts" in str(exc)
    else:
        raise AssertionError("expected max_hosts guard to trigger")


# --- HTTP Server-header parsing (pure function) ----------------------------

def test_parse_http_server_extracts_header():
    raw = (
        b"HTTP/1.1 200 OK\r\n"
        b"Date: Wed, 22 Oct 2026 10:00:00 GMT\r\n"
        b"Server: nginx/1.25.3\r\n"
        b"Content-Type: text/html\r\n\r\n"
    )
    assert nd._parse_http_server(raw) == "nginx/1.25.3"
    # case-insensitive header name, str input accepted too
    assert nd._parse_http_server("HTTP/1.0 404\r\nSERVER: Apache/2.4\r\n\r\n") == "Apache/2.4"


def test_parse_http_server_missing_returns_none():
    assert nd._parse_http_server(b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n") is None
    assert nd._parse_http_server(b"") is None


# --- banner cleaning -------------------------------------------------------

def test_clean_banner_strips_control_and_truncates():
    assert nd._clean_banner(b"SSH-2.0-OpenSSH_8.9\r\n") == "SSH-2.0-OpenSSH_8.9"
    assert nd._clean_banner(b"a\x00b\x07c\td") == "a b c d"
    assert nd._clean_banner(b"") is None
    assert nd._clean_banner(None) is None
    long = nd._clean_banner(b"x" * 500)
    assert long is not None and len(long) == 200


# --- reverse DNS handling (monkeypatched; no network) ----------------------

def test_reverse_dns_success(monkeypatch):
    monkeypatch.setattr(
        nd.socket, "gethostbyaddr", lambda host: ("nas.example.lan", [], [host])
    )
    assert nd._reverse_dns("192.168.1.10") == "nas.example.lan"


def test_reverse_dns_handles_errors(monkeypatch):
    def boom(host):
        raise socket.herror("no PTR record")

    monkeypatch.setattr(nd.socket, "gethostbyaddr", boom)
    assert nd._reverse_dns("192.168.1.11") is None


# --- banner grab dispatch (monkeypatched socket; no network) ---------------

class _FakeSock:
    """Minimal socket stand-in recording writes and replaying a canned read."""

    def __init__(self, to_read: bytes = b""):
        self._to_read = to_read
        self.sent: list[bytes] = []

    def sendall(self, data: bytes):
        self.sent.append(data)

    def recv(self, _n: int) -> bytes:
        return self._to_read


def test_grab_banner_http_sends_head_and_parses_server():
    sock = _FakeSock(b"HTTP/1.1 200 OK\r\nServer: lighttpd/1.4\r\n\r\n")
    banner, version = nd._grab_banner(sock, 80, "192.168.1.10")
    assert version == "lighttpd/1.4"
    assert banner and "HTTP/1.1 200 OK" in banner
    assert sock.sent and sock.sent[0].startswith(b"HEAD / HTTP/1.0")


def test_grab_banner_https_notes_tls_without_reading():
    sock = _FakeSock(b"should-not-be-read")
    banner, version = nd._grab_banner(sock, 443, "192.168.1.10")
    assert version == "https"
    assert banner is None
    assert sock.sent == []  # no bytes written to a TLS port


def test_grab_banner_greeting_ports_read_line():
    sock = _FakeSock(b"SSH-2.0-OpenSSH_8.9p1\r\n")
    banner, version = nd._grab_banner(sock, 22, "192.168.1.10")
    assert banner == "SSH-2.0-OpenSSH_8.9p1"
    assert version == "SSH-2.0-OpenSSH_8.9p1"
    assert sock.sent == []  # server speaks first; we send nothing


# --- end-to-end against a local listener (loopback only) -------------------

def test_collect_reports_hostname_and_open_port(monkeypatch):
    from app.collectors.base import run_collector, load_builtin_collectors

    load_builtin_collectors()
    monkeypatch.setattr(nd.socket, "gethostbyaddr", lambda h: ("local.test", [], [h]))

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
    pkg = next(p for p in res.packages if p.extra.get("port") == port)
    assert pkg.extra["hostname"] == "local.test"
    assert res.summary["hosts"]["127.0.0.1"]["hostname"] == "local.test"
    assert res.summary["live_hosts"]["127.0.0.1"] == [port]
