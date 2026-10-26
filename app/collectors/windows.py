"""Windows collector — installed software and update status (read-only).

Runs **locally on the Windows machine** where the agent is installed (reach it
from the dashboard via the `relay` collector). It:

* lists installed programs with their versions from the registry Uninstall
  keys (HKLM 64/32-bit + HKCU) — no admin rights needed, nothing is changed;
* asks `winget upgrade` which of them have a newer version available and
  records that as each package's `latest_version` (best-effort; needs winget,
  present on current Windows 10/11);
* reports the OS build and the latest installed hotfix in the summary.

It performs no installs or upgrades — it only reports what it sees.

collector_config keys:
    check_updates   query winget for available upgrades (default true)
    include_store   include Microsoft Store (MSIX) apps via winget (default true)
"""
from __future__ import annotations

import logging
import platform
import re
import subprocess

from app.collectors.base import CollectResult, PackageResult, VulnResult, register
from app.models import Severity
from app.services import eol

log = logging.getLogger(__name__)


def _read_installed() -> list[PackageResult]:
    import winreg

    paths = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
         winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0),
    ]
    seen: set[tuple[str, str]] = set()
    pkgs: list[PackageResult] = []
    for hive, subpath, flag in paths:
        try:
            root = winreg.OpenKey(hive, subpath, 0, winreg.KEY_READ | flag)
        except OSError:
            continue
        try:
            count = winreg.QueryInfoKey(root)[0]
            for i in range(count):
                try:
                    sub = winreg.EnumKey(root, i)
                    with winreg.OpenKey(root, sub) as k:
                        vals = _read_values(winreg, k)
                except OSError:
                    continue
                name = vals.get("DisplayName")
                if not name or vals.get("SystemComponent") == 1:
                    continue
                version = vals.get("DisplayVersion")
                key = (name, str(version))
                if key in seen:
                    continue
                seen.add(key)
                pkgs.append(
                    PackageResult(
                        name=name,
                        version=str(version) if version is not None else None,
                        type="windows-app",
                        source="registry",
                        extra={"publisher": vals.get("Publisher")} if vals.get("Publisher") else {},
                    )
                )
        finally:
            winreg.CloseKey(root)
    return pkgs


def _read_values(winreg, key) -> dict:
    out: dict = {}
    for name in ("DisplayName", "DisplayVersion", "Publisher", "SystemComponent"):
        try:
            out[name] = winreg.QueryValueEx(key, name)[0]
        except OSError:
            pass
    return out


def _winget_list() -> dict[str, dict] | None:
    """Return all programs winget knows via `winget list`.

    `winget list` enumerates every installed program (it also reads the same
    Add/Remove-Programs data as the registry) and, crucially, shows the
    "Available" and "Source" columns. That lets us tell three cases apart:
    recognized+up-to-date, update-available, and not-known-to-winget — unlike
    `winget upgrade`, which only lists outdated items.

    Returns ``None`` if winget could not be run at all.
    Each value: {"id", "version", "available"|None, "source"|None}.
    """
    cmd = ["winget", "list", "--disable-interactivity"]
    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=300)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        log.info("winget not available: %s", exc)
        return None
    raw = proc.stdout or b""
    for enc in ("utf-8", "utf-16", "cp1252", "latin-1"):
        try:
            text = raw.decode(enc)
            if "\x00" not in text:
                break
        except UnicodeDecodeError:
            continue
    else:
        text = raw.decode("utf-8", "replace")
    return _parse_winget_list(text)


def _col(header: str, *labels: str) -> int:
    """Start index of a column by any of its (localized) header labels/prefixes."""
    for label in labels:
        i = header.find(label)
        if i != -1:
            return i
    return -1


def _parse_winget_list(output: str) -> dict[str, dict]:
    """Parse `winget list` by fixed column positions (encoding/locale tolerant).

    Columns: Name, Id, Version, Available, Source. We anchor on the ASCII
    labels Name/Id/Version and prefix-match the localized Available/Source
    headers (English "Available"/"Source", German "Verfügbar"/"Quelle"), then
    slice each row by column start so an empty Available column stays empty.
    """
    lines = output.splitlines()
    header_idx = None
    for i in range(1, len(lines)):
        stripped = lines[i].strip()
        if stripped and set(stripped) <= {"-"} and lines[i - 1].strip():
            header_idx = i - 1
            break
    if header_idx is None:
        return {}
    header = lines[header_idx]

    cols = [
        ("name", _col(header, "Name")),
        ("id", _col(header, "Id", "ID")),
        ("version", _col(header, "Version")),
        ("available", _col(header, "Available", "Verf")),
        ("source", _col(header, "Source", "Quelle", "Que")),
    ]
    cols = sorted(((k, s) for k, s in cols if s != -1), key=lambda x: x[1])
    starts = [s for _, s in cols]
    keys = [k for k, _ in cols]

    result: dict[str, dict] = {}
    for ln in lines[header_idx + 2:]:
        if not ln.strip():
            continue
        row: dict[str, str] = {}
        for idx, key in enumerate(keys):
            start = starts[idx]
            end = starts[idx + 1] if idx + 1 < len(starts) else len(ln)
            row[key] = ln[start:end].strip()
        name = row.get("name", "")
        if not name or not row.get("id"):
            continue
        avail = row.get("available") or None
        if avail and not any(c.isdigit() for c in avail):
            avail = None  # e.g. stray non-version text
        result[name.lower()] = {
            "id": row.get("id"),
            "version": row.get("version") or None,
            "available": avail,
            "source": row.get("source") or None,
        }
    return result


def _choco_outdated() -> dict[str, dict] | None:
    """Return {name_lower: {available, id}} from `choco outdated` (if installed).

    Chocolatey covers many programs winget does not. Machine-readable output
    (`-r`) is: id|current|available|pinned, one per line. Returns None if choco
    is not installed.
    """
    try:
        proc = subprocess.run(
            ["choco", "outdated", "-r", "--ignore-pinned"],
            capture_output=True, text=True, timeout=300, encoding="utf-8", errors="replace",
        )
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        log.info("choco not available: %s", exc)
        return None
    result: dict[str, dict] = {}
    for line in proc.stdout.splitlines():
        parts = line.split("|")
        if len(parts) < 3:
            continue
        cid, _current, available = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if cid and available and any(c.isdigit() for c in available):
            result[cid.lower()] = {"available": available, "id": cid}
    return result


def _first_int(version: str | None) -> int | None:
    """Leading integer of a version string ("4.27" -> 4), or None."""
    if not version:
        return None
    m = re.match(r"\D*(\d+)", version)
    return int(m.group(1)) if m else None


def _classify_update(installed: str | None, available: str) -> str:
    """'major' if the first version component increases, else 'minor'."""
    im, am = _first_int(installed), _first_int(available)
    if im is not None and am is not None and am > im:
        return "major"
    return "minor"


def _os_release() -> dict:
    """True OS version from the registry (authoritative, unlike platform.*)."""
    import winreg

    vals: dict = {}
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as k:
            for name in ("ProductName", "DisplayVersion", "ReleaseId", "CurrentBuild",
                         "UBR", "EditionID"):
                try:
                    vals[name] = winreg.QueryValueEx(k, name)[0]
                except OSError:
                    pass
    except OSError:
        pass
    return vals


def _latest_hotfix() -> str | None:
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "(Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1)."
             "HotFixID"],
            capture_output=True, text=True, timeout=60,
        )
        if proc.returncode == 0 and proc.stdout.strip():
            return proc.stdout.strip()
    except subprocess.SubprocessError:
        pass
    return None


def _os_component(config: dict) -> tuple[PackageResult, VulnResult | None, dict]:
    """Build the OS inventory row + an EOL vulnerability if unsupported."""
    rel = _os_release()
    build = int(rel.get("CurrentBuild", 0) or 0)
    ubr = rel.get("UBR")
    feature = rel.get("DisplayVersion") or rel.get("ReleaseId") or "?"
    # ProductName misreports Windows 11 as "Windows 10"; the build is authoritative.
    product = "Windows 11" if build >= 22000 else "Windows 10"
    edition = rel.get("EditionID", "")
    name = f"{product} {edition}".strip()
    version = f"{feature} (Build {build}.{ubr})" if ubr else f"{feature} (Build {build})"

    extra = {"feature": feature, "build": f"{build}.{ubr}" if ubr else str(build)}
    vuln = None
    summary = {"os": name, "os_version": version}

    status = None
    if config.get("check_os_eol", True) and build:
        status = eol.windows_status(build, edition, int(config.get("eol_timeout", 15)))
    if status:
        extra["eol"] = status.get("eol")
        extra["latest"] = status.get("latest_label")
        summary["os_support"] = (
            "END-OF-LIFE" if status.get("is_eol") else "unterstützt" if status.get("is_eol") is False else "?"
        )
        summary["os_latest"] = status.get("latest_label")
        if status.get("outdated") and status.get("latest_label"):
            # Show the newer feature version as the "latest" so the OS row flags it.
            # Store without a build suffix so the update badge reads cleanly.
            extra["update_type"] = "major"
        if status.get("is_eol"):
            vuln = VulnResult(
                cve_id="OS-EOL",
                severity=Severity.critical,
                package_name=name,
                installed_version=version,
                fixed_version=f"Upgrade auf {status.get('latest_label')}" if status.get("latest_label") else None,
                title=f"Betriebssystem {feature} ist End-of-Life (seit {status.get('eol')}) – "
                      "erhält keine Sicherheitsupdates mehr.",
                source="OS-Version",
            )

    pkg = PackageResult(
        name=name,
        version=version,
        type="os",
        source="Betriebssystem",
        latest_version=(status.get("latest_label") if status and status.get("outdated") else version),
        extra=extra,
    )
    hotfix = _latest_hotfix()
    if hotfix:
        extra["latest_hotfix"] = hotfix
        summary["latest_hotfix"] = hotfix
    return pkg, vuln, summary


# Make PowerShell emit UTF-8 so umlauts in names decode correctly in Python.
_PS_UTF8 = "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"

# PowerShell to search (read-only, no install) for pending Windows OS updates.
_WU_SCRIPT = (
    _PS_UTF8
    + "$ErrorActionPreference='Stop';"
    "try{"
    "$s=New-Object -ComObject Microsoft.Update.Session;"
    "$r=$s.CreateUpdateSearcher().Search('IsInstalled=0 and IsHidden=0');"
    "foreach($u in $r.Updates){"
    "$kb=($u.KBArticleIDs -join ',');"
    "$sev=if($u.MsrcSeverity){$u.MsrcSeverity}else{''};"
    "$typ=if($u.Type -eq 2){'Treiber'}else{'Software'};"
    "Write-Output (\"{0}`t{1}`t{2}`t{3}\" -f $u.Title,$kb,$sev,$typ)"
    "}}catch{Write-Output ('WUERR`t'+$_.Exception.Message)}"
)


def _windows_updates(timeout: int) -> tuple[list[PackageResult], str]:
    """Search for pending OS updates via the Windows Update API (no install)."""
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", _WU_SCRIPT],
            capture_output=True, text=True, timeout=timeout, encoding="utf-8", errors="replace",
        )
    except subprocess.SubprocessError as exc:
        return [], f"error: {exc}"
    if proc.returncode != 0 and not proc.stdout.strip():
        return [], "error: windows update search failed"

    pkgs: list[PackageResult] = []
    status = "ok"
    for line in proc.stdout.splitlines():
        if not line.strip():
            continue
        parts = line.split("\t")
        if parts[0] == "WUERR":
            return [], f"error: {parts[1] if len(parts) > 1 else 'unknown'}"
        title = parts[0].strip()
        kb = parts[1].strip() if len(parts) > 1 else ""
        sev = parts[2].strip() if len(parts) > 2 else ""
        category = parts[3].strip() if len(parts) > 3 else "Software"
        kb_label = f"KB{kb}" if kb else None
        pkgs.append(
            PackageResult(
                name=title[:120],
                version="ausstehend",
                latest_version="ausstehend",  # drives the "update" badge
                type="windows-update",
                source=f"Windows Update ({category})",
                extra={
                    "kb": kb_label,
                    "severity": sev,
                    "category": category,
                    "update_cmd": (
                        f"Install-WindowsUpdate -KBArticleID {kb_label} -AcceptAll"
                        if kb_label else "Start-Process ms-settings:windowsupdate"
                    ),
                },
            )
        )
    return pkgs, status


def _services() -> list[PackageResult]:
    """Enumerate Windows services (read-only), incl. python/custom daemons.

    Captures each service's state, start mode, binary path and run-as account
    via WMI, so services not visible in Add/Remove Programs (e.g. a Python
    service, a bespoke agent) still show up in the inventory.
    """
    script = (
        _PS_UTF8
        + "Get-CimInstance Win32_Service | ForEach-Object {"
        "Write-Output (\"{0}`t{1}`t{2}`t{3}`t{4}`t{5}\" -f "
        "$_.Name,$_.DisplayName,$_.State,$_.StartMode,$_.StartName,$_.PathName) }"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=120, encoding="utf-8", errors="replace",
        )
    except subprocess.SubprocessError as exc:
        log.info("service enumeration failed: %s", exc)
        return []
    out: list[PackageResult] = []
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) < 6 or not parts[0].strip():
            continue
        name, display, state, start_mode, account, path = (p.strip() for p in parts[:6])
        out.append(
            PackageResult(
                name=display or name,
                version=state,  # Running / Stopped
                type="service",
                source="Windows-Dienst",
                extra={
                    "service": name,
                    "start_mode": start_mode,
                    "account": account,
                    "path": path,
                },
            )
        )
    return out


class WindowsCollector:
    name = "windows"

    @staticmethod
    def _mark_update(p: PackageResult, src: str, pkg_id: str, avail: str) -> None:
        cmd = (
            f"winget upgrade --id {pkg_id} -e" if src == "winget"
            else f"choco upgrade {pkg_id} -y"
        )
        p.latest_version = avail
        p.extra = {
            **(p.extra or {}),
            "update_source": src,
            f"{src}_id": pkg_id,
            "update_type": _classify_update(p.version, avail),
            "update_cmd": cmd,
        }

    def collect(self, config: dict) -> CollectResult:
        if platform.system() != "Windows":
            raise RuntimeError(
                "windows collector must run on a Windows host (deploy the agent there "
                "and reach it via the relay collector)."
            )

        pkgs = _read_installed()
        updates_available = 0
        not_checked = 0
        if not config.get("check_updates", True):
            update_check = "skipped"
        else:
            winget = _winget_list()
            choco = _choco_outdated() if config.get("check_choco", True) else None
            sources = [s for s, v in (("winget", winget), ("choco", choco)) if v is not None]

            if not sources:
                update_check = "no package manager (winget/choco) available"
            else:
                update_check = "+".join(sources)
                for p in pkgs:
                    key = (p.name or "").lower()
                    rec = winget.get(key) if winget else None
                    # winget recognizes the program (has a source) -> trust it.
                    if rec and rec.get("source"):
                        avail = rec.get("available")
                        if avail and avail != p.version:
                            self._mark_update(p, "winget", rec["id"], avail)
                            updates_available += 1
                        else:
                            p.latest_version = p.version  # checked, up to date
                        continue
                    # Fallback to chocolatey for programs winget does not know.
                    crec = choco.get(key) if choco else None
                    if crec:
                        avail = crec.get("available")
                        if avail and avail != p.version:
                            self._mark_update(p, "choco", crec["id"], avail)
                            updates_available += 1
                        else:
                            p.latest_version = p.version
                        continue
                    not_checked += 1  # neither winget nor choco knows this program

        installed_count = len(pkgs)

        # The OS itself: real version + end-of-life / newer-feature-version check.
        os_pkg, os_vuln, os_summary = _os_component(config)
        pkgs.insert(0, os_pkg)
        vulns: list[VulnResult] = [os_vuln] if os_vuln else []

        # Windows services (incl. python/custom daemons).
        services: list[PackageResult] = []
        if config.get("check_services", True):
            services = _services()
            pkgs.extend(services)

        # Windows itself: pending OS updates (read-only search).
        win_updates: list[PackageResult] = []
        wu_status = "skipped"
        if config.get("check_windows_update", True):
            win_updates, wu_status = _windows_updates(int(config.get("wu_timeout", 180)))
            pkgs.extend(win_updates)

        wu_software = sum(1 for p in win_updates if p.extra.get("category") == "Software")
        wu_driver = len(win_updates) - wu_software
        running = sum(1 for s in services if s.version == "Running")
        result = CollectResult(packages=pkgs, vulnerabilities=vulns)
        result.summary = {
            **os_summary,
            "installed_programs": installed_count,
            "app_updates_available": updates_available,
            "apps_not_checked": not_checked,
            "services": len(services),
            "services_running": running,
            "windows_updates_pending": len(win_updates),
            "windows_updates_software": wu_software,
            "windows_updates_driver": wu_driver,
            "update_check": update_check,
            "windows_update_check": wu_status,
        }
        return result


register(WindowsCollector())
