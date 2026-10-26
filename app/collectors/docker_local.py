"""Docker collector — decomposes containers/images into their components.

Connects to a Docker daemon read-only (local socket or remote via DOCKER_HOST)
and reports, per image/container:

* image metadata: tags, digest, size, created date, layer count, config
  (entrypoint, exposed ports, env keys, labels) and the detected base OS;
* a software bill of materials (SBOM): OS packages and application
  dependencies;
* known vulnerabilities for those components.

SBOM/CVE depth depends on what is installed on the host running this tool:

* `trivy` present  -> full SBOM **and** CVEs (preferred);
* `syft`  present  -> full SBOM (no CVEs);
* neither          -> metadata-level components only (images, layers, config).

The collector only *reads*: it never starts, stops or changes containers.

collector_config keys:
    base_url   DOCKER_HOST style URL (default: local socket)
    targets    "running" (default) | "all" | list[str] of image/container refs
"""
from __future__ import annotations

import json
import logging
import shutil
import subprocess

from app.collectors.base import CollectResult, PackageResult, VulnResult, register
from app.config import settings
from app.models import Severity

log = logging.getLogger(__name__)

_SEVERITY_MAP = {
    "UNKNOWN": Severity.unknown,
    "LOW": Severity.low,
    "MEDIUM": Severity.medium,
    "HIGH": Severity.high,
    "CRITICAL": Severity.critical,
    "NEGLIGIBLE": Severity.low,
}


def _docker_client(base_url: str | None):
    import docker
    from docker.errors import DockerException

    try:
        client = docker.DockerClient(base_url=base_url) if base_url else docker.from_env()
        client.ping()  # fail fast with a clear message if no daemon is reachable
        return client
    except DockerException as exc:
        where = base_url or "local daemon (socket/named pipe)"
        raise RuntimeError(
            f"Kein Docker-Daemon erreichbar über {where}. "
            "Läuft Docker (Desktop/Engine)? Für ein entferntes Host nutze "
            "base_url 'ssh://user@host' bzw. 'tcp://host:2375', oder scanne den "
            "Docker-Host über einen Edge-Agenten (relay)."
        ) from exc


def _resolve_targets(client, targets) -> list[str]:
    """Turn the config `targets` into a list of image references to scan."""
    if isinstance(targets, list):
        return [t for t in targets if t]
    refs: list[str] = []
    running_only = targets != "all"
    for container in client.containers.list(all=not running_only):
        tags = getattr(container.image, "tags", None) or []
        refs.append(tags[0] if tags else container.image.id)
    # de-duplicate, keep order
    seen: set[str] = set()
    out: list[str] = []
    for r in refs:
        if r not in seen:
            seen.add(r)
            out.append(r)
    return out


def _metadata_packages(client, ref: str) -> list[PackageResult]:
    """Fallback SBOM: coarse components derived from image metadata only."""
    results: list[PackageResult] = []
    try:
        image = client.images.get(ref)
    except Exception as exc:  # image not pulled locally
        log.warning("Cannot inspect image %s: %s", ref, exc)
        return results

    attrs = image.attrs
    cfg = attrs.get("Config", {}) or {}
    os_name = attrs.get("Os")
    layers = (attrs.get("RootFS", {}) or {}).get("Layers", []) or []
    results.append(
        PackageResult(
            name=ref,
            version=(image.tags[0].split(":")[-1] if image.tags else None),
            type="docker-image",
            source=ref,
            extra={
                "digest": (attrs.get("RepoDigests") or [None])[0],
                "size_bytes": attrs.get("Size"),
                "created": attrs.get("Created"),
                "os": os_name,
                "architecture": attrs.get("Architecture"),
                "layers": len(layers),
                "entrypoint": cfg.get("Entrypoint"),
                "cmd": cfg.get("Cmd"),
                "exposed_ports": sorted((cfg.get("ExposedPorts") or {}).keys()),
                "env_keys": [e.split("=", 1)[0] for e in (cfg.get("Env") or [])],
                "labels": cfg.get("Labels") or {},
            },
        )
    )
    return results


def _run_json(cmd: list[str]) -> dict | None:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    except Exception as exc:
        log.warning("Command failed (%s): %s", " ".join(cmd[:2]), exc)
        return None
    if proc.returncode != 0:
        log.warning("Command %s exited %s: %s", cmd[:2], proc.returncode, proc.stderr[:300])
        return None
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError:
        return None


def _trivy_scan(ref: str) -> tuple[list[PackageResult], list[VulnResult]]:
    data = _run_json([settings.trivy_bin, "image", "--quiet", "--format", "json", ref])
    pkgs: list[PackageResult] = []
    vulns: list[VulnResult] = []
    if not data:
        return pkgs, vulns
    for res in data.get("Results", []) or []:
        target = res.get("Target", ref)
        ptype = res.get("Type")
        for p in res.get("Packages", []) or []:
            pkgs.append(
                PackageResult(
                    name=p.get("Name"),
                    version=p.get("Version"),
                    type=ptype,
                    source=f"{ref} ({target})",
                    purl=(p.get("Identifier") or {}).get("PURL"),
                )
            )
        for v in res.get("Vulnerabilities", []) or []:
            vulns.append(
                VulnResult(
                    cve_id=v.get("VulnerabilityID", "?"),
                    severity=_SEVERITY_MAP.get((v.get("Severity") or "").upper(), Severity.unknown),
                    package_name=v.get("PkgName"),
                    installed_version=v.get("InstalledVersion"),
                    fixed_version=v.get("FixedVersion"),
                    title=v.get("Title") or v.get("Description", "")[:200] or None,
                    source=f"{ref} ({target})",
                )
            )
    return pkgs, vulns


def _syft_scan(ref: str) -> list[PackageResult]:
    data = _run_json([settings.syft_bin, "-q", "-o", "syft-json", ref])
    pkgs: list[PackageResult] = []
    if not data:
        return pkgs
    for a in data.get("artifacts", []) or []:
        pkgs.append(
            PackageResult(
                name=a.get("name"),
                version=a.get("version"),
                type=a.get("type"),
                source=ref,
                purl=a.get("purl"),
            )
        )
    return pkgs


class DockerCollector:
    name = "docker"

    def collect(self, config: dict) -> CollectResult:
        base_url = config.get("base_url") or None
        targets = config.get("targets", "running")

        client = _docker_client(base_url)
        refs = _resolve_targets(client, targets)

        have_trivy = bool(shutil.which(settings.trivy_bin))
        have_syft = bool(shutil.which(settings.syft_bin))
        mode = "trivy" if have_trivy else "syft" if have_syft else "metadata"

        result = CollectResult()
        for ref in refs:
            # Always include image-level metadata so layers/config are visible.
            result.packages.extend(_metadata_packages(client, ref))
            if mode == "trivy":
                pkgs, vulns = _trivy_scan(ref)
                result.packages.extend(pkgs)
                result.vulnerabilities.extend(vulns)
            elif mode == "syft":
                result.packages.extend(_syft_scan(ref))

        result.summary = {
            "images_scanned": len(refs),
            "mode": mode,
            "packages": len(result.packages),
            "vulnerabilities": len(result.vulnerabilities),
            "base_url": base_url or "local",
        }
        try:
            client.close()
        except Exception:
            pass
        return result


register(DockerCollector())
