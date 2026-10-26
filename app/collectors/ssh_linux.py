"""SSH collector for Linux / Synology / router style hosts (read-only).

Runs a small set of **inventory** commands over SSH and parses installed
packages, pending updates and OS release. It executes only read commands
(dpkg-query, rpm, apk, uname, cat /etc/os-release, apt-get -s). It never
installs, upgrades or changes anything on the target.

collector_config keys:
    host, port (22), username, password | key_filename
    host_key_policy  "reject" (default, verify host key) | "auto" (trust on first
                     use via AutoAddPolicy — opt-in, weaker)
    known_hosts      optional path to a known_hosts file to verify the host key
    sudo       (bool) prefix update-check with sudo -n (non-interactive)
    via        optional jump host to tunnel through (same keys), e.g. a VPN
               edge node that can reach an otherwise isolated device:
               {"host": "edge", "username": "...", "key_filename": "..."}
               `via` may itself contain a `via` for multi-hop chains.
"""
from __future__ import annotations

import logging

from app.collectors.base import CollectResult, PackageResult, VulnResult, register
from app.models import Severity
from app.services import eol

log = logging.getLogger(__name__)

# Each command: (shell, parser). First that yields output wins for packages.
_OS_RELEASE = "cat /etc/os-release 2>/dev/null; uname -a 2>/dev/null"

_PKG_COMMANDS = [
    ("dpkg-query -W -f='${Package}\\t${Version}\\n'", "deb"),
    ("rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n'", "rpm"),
    ("apk info -vv 2>/dev/null", "apk"),
]


def _run(client, command: str) -> str:
    stdin, stdout, stderr = client.exec_command(command, timeout=60)
    return stdout.read().decode("utf-8", "replace")


def _parse_packages(output: str, ptype: str) -> list[PackageResult]:
    pkgs: list[PackageResult] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if ptype == "apk":
            # format: name-1.2.3-r0 description  -> split on first space
            token = line.split(" ", 1)[0]
            name, _, ver = token.rpartition("-")
            name, _, rel = name.rpartition("-")
            pkgs.append(PackageResult(name=name, version=f"{rel}-{ver}" if rel else ver, type=ptype))
        else:
            name, _, ver = line.partition("\t")
            if name:
                pkgs.append(PackageResult(name=name.strip(), version=ver.strip() or None, type=ptype))
    return pkgs


def _connect(config: dict, sock=None):
    """Open an SSH client to ``config['host']``, optionally through a jump host.

    Returns (client, jump_client) where jump_client (if any) must be closed
    after the main client.
    """
    import paramiko

    jump_client = None
    via = config.get("via")
    if via:
        jump_client, _ = _connect(via)  # recurse for multi-hop
        transport = jump_client.get_transport()
        sock = transport.open_channel(
            "direct-tcpip",
            (config["host"], int(config.get("port", 22))),
            ("127.0.0.1", 0),
        )

    client = paramiko.SSHClient()
    # Host-key verification (MITM protection). Default is to REJECT unknown
    # hosts; AutoAdd (trust-on-first-use) must be explicitly opted into with
    # "host_key_policy": "auto". A "known_hosts" path can pin expected keys.
    client.load_system_host_keys()
    known_hosts = config.get("known_hosts")
    if known_hosts:
        try:
            client.load_host_keys(known_hosts)
        except OSError as exc:
            log.warning("ssh_linux: cannot load known_hosts %s: %s", known_hosts, exc)
    policy = str(config.get("host_key_policy", "reject")).lower()
    if policy == "auto":
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    else:
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
    connect_kwargs = {
        "hostname": config["host"],
        "port": int(config.get("port", 22)),
        "username": config.get("username"),
        "timeout": 20,
        "sock": sock,
    }
    if config.get("password"):
        connect_kwargs["password"] = config["password"]
    if config.get("key_filename"):
        connect_kwargs["key_filename"] = config["key_filename"]
    try:
        client.connect(**connect_kwargs)
    except Exception:
        if jump_client is not None:
            jump_client.close()
        raise
    return client, jump_client


class SSHLinuxCollector:
    name = "ssh_linux"

    def collect(self, config: dict) -> CollectResult:
        result = CollectResult()
        client, jump_client = _connect(config)
        try:
            os_info = _run(client, _OS_RELEASE)
            pkgs: list[PackageResult] = []
            for cmd, ptype in _PKG_COMMANDS:
                out = _run(client, cmd)
                parsed = _parse_packages(out, ptype)
                if parsed:
                    pkgs = parsed
                    break
            result.packages = pkgs
            result.summary = {
                "packages": len(pkgs),
                "os_release": _extract_os(os_info),
                "host": config["host"],
                "via": (config.get("via") or {}).get("host"),
            }
            # OS itself: end-of-life / newer-release check via endoflife.date.
            if config.get("check_os_eol", True):
                self._add_os_component(result, os_info, config)
        finally:
            client.close()
            if jump_client is not None:
                jump_client.close()
        return result

    @staticmethod
    def _add_os_component(result: CollectResult, os_info: str, config: dict) -> None:
        fields = _parse_os_release(os_info)
        distro_id = fields.get("ID")
        version_id = fields.get("VERSION_ID")
        pretty = fields.get("PRETTY_NAME") or _extract_os(os_info) or "Linux"
        status = eol.distro_status(distro_id, version_id, int(config.get("eol_timeout", 15)))

        extra = {"id": distro_id, "version_id": version_id}
        latest = pretty
        if status:
            extra["eol"] = status.get("eol")
            extra["latest"] = status.get("latest_label")
            result.summary["os_support"] = (
                "END-OF-LIFE" if status.get("is_eol")
                else "unterstützt" if status.get("is_eol") is False else "?"
            )
            result.summary["os_latest"] = status.get("latest_label")
            if status.get("outdated") and status.get("latest_label"):
                latest = status.get("latest_label")
                extra["update_type"] = "major"
            if status.get("is_eol"):
                result.vulnerabilities.append(
                    VulnResult(
                        cve_id="OS-EOL",
                        severity=Severity.critical,
                        package_name=pretty,
                        installed_version=version_id,
                        fixed_version=(
                            f"Upgrade auf {status.get('latest_label')}"
                            if status.get("latest_label") else None
                        ),
                        title=f"{pretty} ist End-of-Life (seit {status.get('eol')}) – "
                              "erhält keine Sicherheitsupdates mehr.",
                        source="OS-Version",
                    )
                )
        result.packages.insert(
            0,
            PackageResult(
                name=pretty, version=version_id or None, type="os",
                source="Betriebssystem", latest_version=latest, extra=extra,
            ),
        )


def _parse_os_release(os_info: str) -> dict:
    out: dict = {}
    for line in os_info.splitlines():
        if "=" in line and not line.startswith(" "):
            key, _, val = line.partition("=")
            out[key.strip()] = val.strip().strip('"')
    return out


def _extract_os(os_info: str) -> str | None:
    for line in os_info.splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return os_info.splitlines()[0] if os_info.strip() else None


register(SSHLinuxCollector())
