"""Network discovery collector — find reachable devices & open services.

Runs on whichever node can *see* the target network (typically the edge agent
inside a customer LAN, reached via the `relay` collector). It performs a
read-only **TCP connect** sweep: it opens a socket to each (host, port) and
records which services answer. It sends no exploit payloads and changes
nothing; an optional light banner grab reads whatever the service offers first
(and, for HTTP, a benign `HEAD` request) to learn the product/version.

This tells you which devices exist and what they expose, so you can then point
a deeper collector (ssh_linux, docker, …) at them.

collector_config keys:
    targets       CIDR "192.168.1.0/24" | single IP/host | list of IPs/hosts
    ports         preset name ("common"|"web"|"windows"|"top100"|"full") or
                  an explicit list[int] (default: "common")
    timeout       per-connect timeout in seconds (default 0.5)
    concurrency   max parallel connects (default 200)
    grab_banner   read a short banner from open ports (default false)
    arp           also list local ARP neighbours (finds portless devices,
                  default true) — only meaningful for the local subnet
    modules       device-ID modules to run (list; default: all). Available:
                  shelly, tasmota, toshiba, homeassistant, octoprint, smartwb,
                  warp. The server activates a subset per agent.
    max_hosts     safety cap on sweep size (default 1024)
"""
from __future__ import annotations

import ipaddress
import logging
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field

from app.collectors.base import CollectResult, PackageResult, register

log = logging.getLogger(__name__)

_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_MAC_RE = re.compile(r"\b((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})\b")


def _arp_neighbors() -> dict[str, str]:
    """Read the OS ARP/neighbour table -> {ip: mac} (read-only, best-effort).

    ARP finds every device on the local L2 segment regardless of which TCP
    ports it exposes, so IoT/ESP32 devices that answer no scanned port still
    show up. The preceding TCP sweep warms the cache for reachable hosts.
    """
    out: dict[str, str] = {}
    for cmd in (["arp", "-a"], ["ip", "neigh"]):
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        except (FileNotFoundError, subprocess.SubprocessError):
            continue
        if proc.returncode != 0 and not proc.stdout:
            continue
        for line in proc.stdout.splitlines():
            ip_m = _IP_RE.search(line)
            mac_m = _MAC_RE.search(line)
            if ip_m and mac_m:
                mac = mac_m.group(1).replace("-", ":").lower()
                if mac != "00:00:00:00:00:00" and not mac.startswith("ff:ff"):
                    out[ip_m.group(1)] = mac
        if out:
            break
    return out

# port -> service label
COMMON_PORTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 123: "ntp", 135: "msrpc", 139: "netbios",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 514: "syslog", 548: "afp", 587: "submission", 631: "ipp",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1883: "mqtt", 2049: "nfs",
    2375: "docker", 2376: "docker-tls", 3000: "http-alt", 3306: "mysql",
    3389: "rdp", 5000: "upnp/http", 5001: "synology-dsm", 5432: "postgres",
    5900: "vnc", 6379: "redis", 8006: "proxmox", 8080: "http-proxy",
    8443: "https-alt", 8123: "home-assistant", 9000: "http-alt",
    9200: "elasticsearch", 32400: "plex",
}

DEFAULT_PORTS = sorted(COMMON_PORTS)

# Named port presets the server can hand to an agent via the `ports` config
# (as a string) instead of listing numbers. "full" is 1-65535 (slow — pair it
# with a higher max_hosts / tighter targets).
PORT_PRESETS: dict[str, list[int]] = {
    "common": DEFAULT_PORTS,                       # ~42 typical service ports
    "web": [80, 443, 8080, 8443, 3000, 5000, 8000, 8081, 9000, 9090],
    "windows": [135, 139, 445, 3389, 5985, 5986, 1433],
    "top100": sorted({  # nmap-style top ~100 TCP ports
        7, 20, 21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 161, 179, 199,
        389, 443, 445, 465, 514, 515, 548, 554, 587, 631, 646, 873, 990, 993,
        995, 1025, 1026, 1027, 1433, 1720, 1723, 1883, 2000, 2049, 2121, 2375,
        2376, 3000, 3306, 3389, 3690, 4444, 5000, 5001, 5060, 5432, 5631, 5666,
        5900, 5985, 6000, 6379, 6667, 8000, 8006, 8008, 8080, 8081, 8443, 8888,
        9000, 9090, 9100, 9200, 10000, 27017, 32400, 49152,
    }),
    "full": list(range(1, 65536)),                 # exhaustive — use carefully
}


def _resolve_ports(cfg_ports) -> list[int]:
    """Accept a preset name (str), a single int, or an explicit list of ints."""
    if cfg_ports is None:
        return DEFAULT_PORTS
    if isinstance(cfg_ports, str):
        return PORT_PRESETS.get(cfg_ports.lower().strip(), DEFAULT_PORTS)
    if isinstance(cfg_ports, int):
        return [cfg_ports]
    return [int(p) for p in cfg_ports]

# Ports where we speak a benign HTTP HEAD request to read the Server header.
HTTP_PORTS = frozenset({80, 3000, 5000, 8080, 8081, 9000})
# Ports we only note as TLS; we do not parse certificates.
HTTPS_PORTS = frozenset({443, 8443})
# Ports where the server greets first (read-only line read).
GREETING_PORTS = frozenset({21, 22, 25, 110, 143, 587})

# Control chars to strip from banners (keep printable text only).
_CTRL_RE = re.compile(r"[\x00-\x1f\x7f]")


def _expand_one(target: str) -> list[str]:
    """Expand a single target: a CIDR -> its hosts, otherwise a literal host."""
    try:
        net = ipaddress.ip_network(target, strict=False)
        return [str(h) for h in (net.hosts() if net.num_addresses > 1 else [net.network_address])]
    except ValueError:
        return [target]  # a single hostname/IP


def _expand_targets(targets, max_hosts: int) -> list[str]:
    """Accept a CIDR, a host, or a list mixing several subnets and hosts.

    This lets one agent sweep multiple subnets it can reach, e.g.
    targets: ["192.168.1.0/24", "192.168.5.0/24", "10.0.0.10"].
    """
    items = targets if isinstance(targets, list) else [targets]
    hosts: list[str] = []
    seen: set[str] = set()
    for item in items:
        if not item:
            continue
        for h in _expand_one(str(item)):
            if h not in seen:
                seen.add(h)
                hosts.append(h)
    if len(hosts) > max_hosts:
        raise ValueError(
            f"discovery refused: {len(hosts)} hosts exceeds max_hosts={max_hosts}. "
            "Narrow the subnets or raise max_hosts deliberately."
        )
    return hosts


def _clean_banner(raw: bytes | str | None, limit: int = 200) -> str | None:
    """Decode, strip control chars, collapse whitespace, truncate to `limit`."""
    if not raw:
        return None
    text = raw.decode("latin-1", "replace") if isinstance(raw, bytes) else raw
    text = _CTRL_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:limit] or None


def _parse_http_server(raw: bytes | str) -> str | None:
    """Extract the `Server:` header value from a raw HTTP response, if present."""
    if isinstance(raw, bytes):
        raw = raw.decode("latin-1", "replace")
    for line in raw.splitlines():
        if line.lower().startswith("server:"):
            return _clean_banner(line.split(":", 1)[1])
    return None


def _reverse_dns(host: str) -> str | None:
    """Best-effort reverse DNS; returns the hostname or None on any failure."""
    try:
        return socket.gethostbyaddr(host)[0] or None
    except (OSError, UnicodeError):
        return None


def _grab_banner(sock: socket.socket, port: int, ip: str) -> tuple[str | None, str | None]:
    """Read-only, best-effort service probe. Returns (banner, product/version).

    HTTP: benign `HEAD /` then parse the Server header. HTTPS: note "https".
    SSH/FTP/SMTP/… : read the greeting the server sends first. Nothing is ever
    written beyond the benign HTTP HEAD; no auth or exploit payloads are sent.
    """
    try:
        if port in HTTPS_PORTS:
            return None, "https"
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {ip}\r\n\r\n".encode("ascii", "ignore"))
            raw = sock.recv(1024)
            return _clean_banner(raw), _parse_http_server(raw)
        # GREETING_PORTS and anything else: the server speaks first (or not).
        banner = _clean_banner(sock.recv(256))
        return banner, banner
    except OSError:
        return None, None


def _probe(
    host: str, port: int, timeout: float, grab: bool
) -> tuple[str, int, str | None, str | None] | None:
    """Return (host, port, version, banner) for an open port, else None."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = version = None
            if grab:
                sock.settimeout(timeout)
                banner, version = _grab_banner(sock, port, host)
            return host, port, version, banner
    except OSError:
        return None


# ---- device-identification modules ---------------------------------------
# Each module is a benign, read-only probe for a specific device family that
# only the agent can reach. The server activates which modules an agent runs
# via config["modules"] (a list of names); default: all known modules. This is
# the concrete first instance of the planned server-activatable module system
# (next: octoprint, immich, proxmox, …).


def _http_get(url: str, timeout: float):
    try:
        import httpx

        r = httpx.get(url, timeout=timeout, follow_redirects=True)
        if r.status_code == 200:
            return r
    except Exception:
        return None
    return None


def _http_json(url: str, timeout: float) -> dict | None:
    r = _http_get(url, timeout)
    try:
        return r.json() if r is not None else None
    except Exception:
        return None


@dataclass
class DeviceInfo:
    """Result of a device module: identity, firmware, and extra details.

    `details` holds the other important facts a module knows how to read for
    that device family (model, serial, state, uptime, IP config, …), so modules
    are more than a name/version — they encode *how* to reach each fact.
    """

    product: str
    version: str | None = None
    name: str | None = None  # the device's own user-assigned name, if readable
    latest: str | None = None  # newest firmware the device reports as available
    details: dict = field(default_factory=dict)


def _pick(d: dict, *keys) -> dict:
    """Subset of a dict with only the given keys that are present & non-empty."""
    return {k: d[k] for k in keys if isinstance(d, dict) and d.get(k) not in (None, "")}


def _mod_shelly(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    # Gen2+ RPC: {"name","id","model","gen","fw_id","ver","app","mac","auth_en"}
    d = _http_json(f"http://{host}/rpc/Shelly.GetDeviceInfo", timeout)
    if isinstance(d, dict) and (d.get("ver") or d.get("fw_id")):
        # Read the device's *cached* update status (sys.available_updates). The
        # device auto-checks on its own schedule — we never force a fresh cloud
        # check (that would hammer the vendor's update server across many devices).
        stt = _http_json(f"http://{host}/rpc/Shelly.GetStatus", timeout)
        avail = ((stt.get("sys", {}) or {}).get("available_updates", {})
                 if isinstance(stt, dict) else {})
        latest = (avail.get("stable", {}) or {}).get("version") if isinstance(avail, dict) else None
        return DeviceInfo(
            product=f"Shelly {d.get('model') or d.get('app') or ''}".strip(),
            version=d.get("ver") or d.get("fw_id"),
            name=d.get("name"),  # user-assigned device name (Gen2)
            latest=latest,
            details=_pick(d, "gen", "model", "app", "id", "mac", "auth_en", "name"),
        )
    # Gen1: {"type","mac","fw","auth","num_outputs","num_meters"}
    d = _http_json(f"http://{host}/shelly", timeout)
    if isinstance(d, dict) and d.get("fw"):
        # /settings has the name; /status reports whether an update is available.
        settings = _http_json(f"http://{host}/settings", timeout) or {}
        st = _http_json(f"http://{host}/status", timeout) or {}
        upd = st.get("update", {}) if isinstance(st, dict) else {}
        return DeviceInfo(
            product=f"Shelly {d.get('type', '')}".strip(),
            version=d.get("fw"),
            name=settings.get("name") if isinstance(settings, dict) else None,
            latest=upd.get("new_version") if upd.get("has_update") else None,
            details=_pick(d, "type", "mac", "auth", "num_outputs", "num_meters"),
        )
    return None


def _mod_tasmota(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    # Status 0 bundles firmware + network + device facts in one call.
    d = _http_json(f"http://{host}/cm?cmnd=Status%200", timeout)
    fwr = d.get("StatusFWR") if isinstance(d, dict) else None
    if isinstance(fwr, dict) and fwr.get("Version"):
        status = d.get("Status", {}) if isinstance(d.get("Status"), dict) else {}
        net = d.get("StatusNET", {}) if isinstance(d.get("StatusNET"), dict) else {}
        details = _pick(fwr, "Hardware", "Core", "SDK")
        details.update(_pick(status, "DeviceName", "Module", "FriendlyName"))
        details.update(_pick(net, "Mac", "IPAddress"))
        friendly = status.get("FriendlyName")
        dev_name = status.get("DeviceName") or (friendly[0] if isinstance(friendly, list) and friendly else None)
        return DeviceInfo("Tasmota", fwr.get("Version"), name=dev_name, details=details)
    return None


_TOSHIBA_MODEL = re.compile(r"(e-?STUDIO\s*[\w-]+)", re.I)
_TOSHIBA_FW = re.compile(r"(?:firmware|version)[^0-9]{0,12}([0-9][0-9A-Za-z._-]+)", re.I)


def _mod_toshiba(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    """Best-effort Toshiba printer ID via its TopAccess web UI (HTML scrape)."""
    for url in (f"http://{host}/", f"https://{host}/", f"http://{host}/TopAccess"):
        r = _http_get(url, timeout)
        if r is None:
            continue
        text = r.text[:20000]
        if "toshiba" in text.lower() or "e-studio" in text.lower():
            model = _TOSHIBA_MODEL.search(text)
            fw = _TOSHIBA_FW.search(text)
            return DeviceInfo(
                product=f"Toshiba {model.group(1)}" if model else "Toshiba Drucker",
                version=fw.group(1) if fw else None,
                details={"kind": "printer", "detected_via": "web"},
            )
    return None


def _mod_homeassistant(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    # HA frontend on :8123. Full version needs a long-lived token (future:
    # envelope-encrypted credential delivered by the server).
    token = (creds or {}).get("secret")
    for base in (f"http://{host}:8123", f"https://{host}:8123"):
        d = _http_json(f"{base}/manifest.json", timeout)
        is_ha = isinstance(d, dict) and "home assistant" in str(d.get("name", "")).lower()
        if not is_ha:
            r = _http_get(f"{base}/", timeout)
            is_ha = r is not None and "home assistant" in r.text[:5000].lower()
        if not is_ha:
            continue
        # With a long-lived token we can read the exact version via the API.
        if token:
            try:
                import httpx
                cfg = httpx.get(f"{base}/api/config", timeout=timeout,
                                headers={"Authorization": f"Bearer {token}"})
                if cfg.status_code == 200:
                    j = cfg.json()
                    return DeviceInfo("Home Assistant", j.get("version"),
                                      details={k: j.get(k) for k in ("location_name", "country")
                                               if j.get(k)})
            except Exception:
                pass
        return DeviceInfo("Home Assistant", None, {"note": "Version benötigt API-Token"})
    return None


def _mod_octoprint(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    # OctoPrint on :80 or :5000. /api/version needs an API key for the version.
    key = (creds or {}).get("secret")
    for base in (f"http://{host}", f"http://{host}:5000"):
        if key:
            try:
                import httpx
                v = httpx.get(f"{base}/api/version", timeout=timeout,
                              headers={"X-Api-Key": key})
                if v.status_code == 200:
                    j = v.json()
                    return DeviceInfo("OctoPrint", j.get("server"),
                                      details={"api": j.get("api")})
            except Exception:
                pass
        r = _http_get(f"{base}/", timeout)
        if r is None:
            continue
        text = r.text[:8000]
        if "octoprint" in text.lower():
            m = re.search(r"OctoPrint[^0-9]{0,8}([0-9]+\.[0-9][0-9A-Za-z.\-]*)", text)
            return DeviceInfo("OctoPrint", m.group(1) if m else None,
                              {"note": "Version/Job-Details benötigen API-Key"})
    return None


def _mod_smartwb(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    # SmartWB / SmartEVSE ESP charger: GET /getParameters -> JSON.
    d = _http_json(f"http://{host}/getParameters", timeout)
    items = d.get("list") if isinstance(d, dict) else (d if isinstance(d, list) else None)
    if isinstance(items, list) and items and isinstance(items[0], dict):
        rec = items[0]
        fw = rec.get("firmwareVersion") or rec.get("firmware") or rec.get("version")
        return DeviceInfo(
            product="SmartWB Wallbox",
            version=str(fw) if fw else None,
            details=_pick(rec, "currentState", "actualCurrent", "maxCurrent",
                          "temperature", "evseState"),
        )
    return None


def _mod_dahua(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    """Dahua camera/NVR fingerprint via its JSON-RPC login endpoint (read-only).

    /RPC2_Login answers with a Dahua-specific JSON structure even without
    credentials. The firmware version itself needs an authenticated CGI call
    (magicBox.cgi?action=getSoftwareVersion) — deferred until the module can be
    given credentials (see envelope-encryption plan).
    """
    for base in (f"http://{host}", f"https://{host}"):
        d = _http_json(f"{base}/RPC2_Login", timeout)
        if isinstance(d, dict) and ("session" in d or "params" in d or
                                    str(d.get("error", {}).get("code", "")).startswith("268")):
            return DeviceInfo("Dahua Kamera/NVR", None,
                              details={"kind": "camera", "note": "Version benötigt Zugangsdaten"})
    return None


def _mod_warp(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    # Tinkerforge WARP Charger REST: /info/version + /info/name + /info/features.
    d = _http_json(f"http://{host}/info/version", timeout)
    if isinstance(d, dict) and d.get("firmware"):
        name = _http_json(f"http://{host}/info/name", timeout) or {}
        feats = _http_json(f"http://{host}/info/features", timeout)
        label = name.get("display_name") or name.get("name") or "WARP Charger"
        details = _pick(name, "type", "uid", "name")
        details.update(_pick(d, "config_type"))
        if isinstance(feats, list):
            details["features"] = feats
        return DeviceInfo(f"WARP {label}".strip(), d.get("firmware"), details)
    return None


def _mod_supermicro(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    """Supermicro IPMI/BMC: identify via Redfish root or the ATEN login page."""
    d = _http_json(f"https://{host}/redfish/v1/", timeout) or _http_json(
        f"http://{host}/redfish/v1/", timeout)
    if isinstance(d, dict) and "supermicro" in json.dumps(d).lower():
        return DeviceInfo("Supermicro IPMI", None,
                          details={"kind": "bmc", "note": "Firmware benötigt Zugangsdaten"})
    for base in (f"https://{host}", f"http://{host}"):
        r = _http_get(f"{base}/", timeout)
        if r is not None and ("supermicro" in r.text[:6000].lower()
                              or "/cgi/url_redirect.cgi" in r.text[:6000].lower()):
            return DeviceInfo("Supermicro IPMI", None, details={"kind": "bmc"})
    return None


def _mod_tplink(host: str, timeout: float, creds: dict | None = None) -> DeviceInfo | None:
    """TP-Link router/switch/AP: best-effort identity via its web UI."""
    for base in (f"http://{host}", f"https://{host}"):
        r = _http_get(f"{base}/", timeout)
        if r is None:
            continue
        text = r.text[:8000].lower()
        if "tp-link" in text or "tplink" in text or "tplinkwifi" in text:
            m = re.search(r"(Archer[\w-]+|EAP[\w-]+|TL-[\w-]+|Deco[\w-]+)", r.text[:8000])
            return DeviceInfo(f"TP-Link {m.group(1)}" if m else "TP-Link",
                              None, details={"note": "Modell/Firmware ggf. hinter Login"})
    return None


# Each module: probe function + metadata (typical ports, whether richer details
# need credentials). The server activates a subset per agent via config["modules"].
@dataclass
class Module:
    label: str
    probe: object  # Callable[[str, float], DeviceInfo | None]
    ports: tuple = ()
    needs_auth: bool = False


DEVICE_MODULES: dict[str, Module] = {
    "shelly": Module("Shelly (Gen1/Gen2)", _mod_shelly, (80,)),
    "tasmota": Module("Tasmota", _mod_tasmota, (80,)),
    "toshiba": Module("Toshiba Drucker", _mod_toshiba, (80, 443)),
    "homeassistant": Module("Home Assistant", _mod_homeassistant, (8123,), needs_auth=True),
    "octoprint": Module("OctoPrint", _mod_octoprint, (80, 5000), needs_auth=True),
    "smartwb": Module("SmartWB Wallbox", _mod_smartwb, (80,)),
    "warp": Module("WARP Wallbox", _mod_warp, (80,)),
    "dahua": Module("Dahua Kamera/NVR", _mod_dahua, (80, 443), needs_auth=True),
    "supermicro": Module("Supermicro IPMI", _mod_supermicro, (80, 443), needs_auth=True),
    "tplink": Module("TP-Link", _mod_tplink, (80, 443), needs_auth=True),
}


def _run_modules(
    host: str, timeout: float, enabled: list[str], open_ports: set[int],
    credentials: dict | None = None,
) -> DeviceInfo | None:
    """Run enabled modules against a host; first match wins.

    To avoid needless requests, a module is skipped when the host's open ports
    are known and none of the module's typical ports are open. Hosts seen only
    via ARP (no known open ports) are probed by all enabled modules, since their
    device-specific port may simply not be in the scanned set. `credentials`
    (per module) let credentialed modules read versions behind a login.
    """
    credentials = credentials or {}
    for name in enabled:
        mod = DEVICE_MODULES.get(name)
        if mod is None:
            continue
        if open_ports and mod.ports and not any(p in open_ports for p in mod.ports):
            continue
        try:
            res = mod.probe(host, timeout, credentials.get(name))
        except Exception:
            res = None
        if res and res.product:
            return res
    return None


class NetworkDiscoveryCollector:
    name = "network_discovery"

    def collect(self, config: dict) -> CollectResult:
        ports = _resolve_ports(config.get("ports"))
        timeout = float(config.get("timeout", 0.5))
        concurrency = int(config.get("concurrency", 200))
        grab = bool(config.get("grab_banner", False))
        max_hosts = int(config.get("max_hosts", 1024))

        hosts = _expand_targets(config.get("targets"), max_hosts)
        result = CollectResult()
        # host -> list of (port, version, banner)
        open_by_host: dict[str, list[tuple[int, str | None, str | None]]] = {}

        with ThreadPoolExecutor(max_workers=concurrency) as pool:
            futures = [
                pool.submit(_probe, h, p, timeout, grab) for h in hosts for p in ports
            ]
            for fut in as_completed(futures):
                found = fut.result()
                if not found:
                    continue
                host, port, version, banner = found
                open_by_host.setdefault(host, []).append((port, version, banner))

        # ARP neighbours: find devices that are up even with no scanned port open
        # (IoT/ESP32 etc.). Only hosts within the scanned set are reported.
        arp = _arp_neighbors() if config.get("arp", True) else {}
        scanned = set(hosts)
        arp_only = sorted(ip for ip in arp if ip in scanned and ip not in open_by_host)

        # One reverse-DNS lookup per alive host (short-circuit, never fatal).
        all_hosts = list(open_by_host) + arp_only
        hostnames = {h: _reverse_dns(h) for h in all_hosts}

        # Emit one package per open port, enriched with hostname/mac/banner/version.
        for host, entries in sorted(open_by_host.items()):
            hostname = hostnames[host]
            mac = arp.get(host)
            for port, version, banner in sorted(entries):
                service = COMMON_PORTS.get(port, "unknown")
                extra: dict = {"port": port}
                if hostname:
                    extra["hostname"] = hostname
                if mac:
                    extra["mac"] = mac
                if banner:
                    extra["banner"] = banner
                if version:
                    extra["product"] = version
                result.packages.append(
                    PackageResult(
                        name=service,
                        version=version or str(port),
                        type="open-port",
                        source=host,
                        extra=extra,
                    )
                )

        # One device row per ARP-only host (reachable, no scanned port open).
        for host in arp_only:
            extra = {"mac": arp.get(host), "via": "arp"}
            if hostnames.get(host):
                extra["hostname"] = hostnames[host]
            result.packages.append(
                PackageResult(
                    name="(nur ARP sichtbar – kein gescannter Port offen)",
                    version=None,
                    type="open-port",
                    source=host,
                    extra=extra,
                )
            )

        # Device-identification modules (Shelly/Tasmota/Toshiba/HA/OctoPrint/…).
        # Enabled per agent by the server via config["modules"] (default: all).
        # Each module targets its own port(s), so we run them on every alive host.
        iot_by_host: dict[str, DeviceInfo] = {}
        enabled_modules = config.get("modules")
        if enabled_modules is None:
            enabled_modules = list(DEVICE_MODULES)
        if enabled_modules:
            alive = sorted(set(open_by_host) | set(arp_only))
            open_ports_by_host = {
                h: {e[0] for e in entries} for h, entries in open_by_host.items()
            }
            mod_creds = config.get("module_credentials") or {}
            with ThreadPoolExecutor(max_workers=min(concurrency, 32)) as pool:
                futs = {
                    pool.submit(
                        _run_modules, h, max(timeout, 1.0), enabled_modules,
                        open_ports_by_host.get(h, set()), mod_creds,
                    ): h
                    for h in alive
                }
                for fut in as_completed(futs):
                    res = fut.result()
                    if res:
                        host = futs[fut]
                        iot_by_host[host] = res
                        extra = {
                            "hostname": hostnames.get(host),
                            "mac": arp.get(host),
                            **res.details,
                        }
                        if res.name:
                            extra["device_name"] = res.name
                        if res.latest:
                            extra["latest"] = res.latest  # device-reported (cached)
                        result.packages.append(
                            PackageResult(
                                name=res.product, version=res.version, type="iot-device",
                                source=host, extra=extra,
                            )
                        )

        # Derive a suggested deeper collector per live host for convenience.
        suggestions: dict[str, str] = {}
        hosts_detail: dict[str, dict] = {}
        for host, entries in sorted(open_by_host.items()):
            oports = sorted(e[0] for e in entries)
            if 22 in oports:
                suggestions[host] = "ssh_linux"
            elif 2375 in oports or 2376 in oports:
                suggestions[host] = "docker"
            elif 5001 in oports:
                suggestions[host] = "synology(manual)"
            # Rich per-host view: hostname + each open port's service/version.
            ports_detail = []
            for port, version, _banner in sorted(entries):
                entry = {"port": port, "service": COMMON_PORTS.get(port, "unknown")}
                if version:
                    entry["version"] = version
                ports_detail.append(entry)
            detail = {"hostname": hostnames[host], "mac": arp.get(host), "ports": ports_detail}
            if host in iot_by_host:
                info = iot_by_host[host]
                detail["device"] = info.product
                detail["firmware"] = info.version
                if info.details:
                    detail["device_details"] = info.details
            hosts_detail[host] = detail
        for host in arp_only:
            hosts_detail[host] = {
                "hostname": hostnames.get(host), "mac": arp.get(host), "ports": [],
            }

        live_hosts = {
            h: sorted(e[0] for e in entries) for h, entries in sorted(open_by_host.items())
        }
        for host in arp_only:
            live_hosts[host] = []

        result.summary = {
            "hosts_scanned": len(hosts),
            "hosts_alive": len(open_by_host) + len(arp_only),
            "hosts_with_open_ports": len(open_by_host),
            "hosts_arp_only": len(arp_only),
            "open_ports": sum(len(v) for v in open_by_host.values()),
            "ports_probed": len(ports),
            # Backwards-compatible compact map: host -> sorted open ports.
            "live_hosts": live_hosts,
            # Detailed map: host -> {hostname, mac, ports:[{port, service, version?}]}.
            "hosts": hosts_detail,
            "deeper_scan_suggestions": suggestions,
        }
        return result


register(NetworkDiscoveryCollector())
