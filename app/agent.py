"""Argus agent: enroll once with a join token, then push on a schedule.

    python -m app.agent join argus-join-eyJ...      # one-time enrollment
    python -m app.agent run                          # push loop (reads config)

`join` exchanges the one-time token for a durable per-client secret and stores
it in the agent config file. `run` then authenticates per client and never
needs the token again. The server's identity (fingerprint, when provided in the
token) is pinned so the agent only talks to the trusted server.

This is the secure, frictionless path: all traffic is client-initiated and each
agent has its own revocable credential (see app/services/enrollment.py).
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import logging
import os
import platform
import socket
import ssl
import sys
import time
from pathlib import Path
from urllib.parse import urlparse

import httpx

import secrets

from app import __version__
from app.collectors.base import load_builtin_collectors, run_collector
from app.services import crypto
from app.services.enrollment import decode_join_token

log = logging.getLogger("argus.agent")

CONFIG_PATH = Path(os.environ.get("ARGUS_AGENT_CONFIG", str(Path.home() / ".argus" / "agent.json")))


def _default_collector() -> str:
    return "windows" if platform.system() == "Windows" else "manual"


def _primary_ip() -> str | None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("203.0.113.1", 9))
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def _fetch_leaf_cert_der(host: str, port: int, timeout: float = 20.0) -> bytes:
    """Fetch the server's leaf certificate (DER) without trusting any CA."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)
    if not der:
        raise RuntimeError("no server certificate presented")
    return der


def _normalise_fingerprint(fp: str) -> str:
    return fp.split("sha256:", 1)[-1].replace(":", "").strip().lower()


def _verify_pinned_fingerprint(server: str, fingerprint: str) -> None:
    """Pin the server's TLS leaf cert to the SHA-256 carried in the join token.

    Raises RuntimeError on mismatch (or on a non-HTTPS server, which cannot be
    pinned). This runs before every request so a swapped server certificate is
    caught on join AND on every push.
    """
    u = urlparse(server)
    if u.scheme != "https":
        raise RuntimeError(f"fingerprint pinning requires https, got {server!r}")
    host = u.hostname
    port = u.port or 443
    der = _fetch_leaf_cert_der(host, port)
    got = hashlib.sha256(der).hexdigest()
    want = _normalise_fingerprint(fingerprint)
    if not want or not hmac.compare_digest(got, want):
        raise RuntimeError(
            f"server TLS fingerprint mismatch for {host}:{port}: "
            f"got sha256:{got}, expected sha256:{want}"
        )


def _make_client(server: str, fingerprint: str | None, insecure: bool, timeout: float) -> httpx.Client:
    """Build an httpx client with the right TLS posture.

    * fingerprint present → pin it first (preflight), then the request itself
      skips CA verification (the cert is typically self-signed; the pin is the
      trust anchor);
    * no fingerprint → normal CA verification, unless --insecure was passed.
    """
    if fingerprint:
        _verify_pinned_fingerprint(server, fingerprint)
        return httpx.Client(timeout=timeout, verify=False)
    return httpx.Client(timeout=timeout, verify=not insecure)


def _load_config() -> dict:
    return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))


def _save_config(cfg: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    try:  # best-effort tighten permissions (POSIX)
        os.chmod(CONFIG_PATH, 0o600)
    except OSError:
        pass


def cmd_join(args) -> int:
    info = decode_join_token(args.token)
    server = (args.server or info["server"] or "").rstrip("/")
    if not server or not info.get("code"):
        log.error("Join-Token unvollständig (server/code fehlen)")
        return 2
    name = args.name or socket.gethostname()
    fingerprint = info.get("fingerprint")

    # Zero-knowledge key setup: generate our keypair, protect the private key
    # with a random passphrase the SERVER will hold, keep only the ciphertext.
    priv_b64, pub_b64 = crypto.generate_keypair()
    passphrase = secrets.token_urlsafe(24)
    enc_privkey = crypto.encrypt_privkey(priv_b64, passphrase)

    try:
        client_ctx = _make_client(server, fingerprint, args.insecure, timeout=30)
    except RuntimeError as exc:
        log.error("TLS-Pinning fehlgeschlagen: %s", exc)
        return 1
    with client_ctx as c:
        resp = c.post(f"{server}/enroll", json={
            "name": name, "hostname": socket.gethostname(), "code": info["code"],
            "pubkey": pub_b64, "key_passphrase": passphrase,
        })
    if resp.status_code != 200:
        log.error("Enrollment fehlgeschlagen (%s): %s", resp.status_code, resp.text[:200])
        return 1

    creds = resp.json()
    cfg = {
        "server": server,
        "fingerprint": info.get("fingerprint"),
        "client_id": creds["client_id"],
        "client_secret": creds["client_secret"],
        "name": name,
        "collector": args.collector or _default_collector(),
        "config": json.loads(args.config or "{}"),
        "kind": args.kind or platform.system().lower(),
        "interval": args.interval,
        # Only the ENCRYPTED private key + public key live here. The passphrase
        # is held by the server and delivered at runtime (split knowledge).
        "pubkey": pub_b64,
        "enc_privkey": enc_privkey,
    }
    _save_config(cfg)
    log.info("Angelernt als %s (Status: %s). Konfig: %s", creds["client_id"],
             creds.get("status"), CONFIG_PATH)
    log.info("Starten mit:  python -m app.agent run")
    return 0


def cmd_set_cred(args) -> int:
    """Seal a module secret to this agent's own key and upload the blob."""
    try:
        cfg = _load_config()
    except FileNotFoundError:
        log.error("Keine Agent-Konfig — zuerst 'join' ausführen."); return 2
    if not cfg.get("pubkey"):
        log.error("Agent hat keinen Public Key (neu 'join' ausführen)."); return 2
    sealed = crypto.seal(cfg["pubkey"], args.secret)  # only this agent can open it
    headers = {"X-Client-Id": cfg["client_id"], "X-Client-Token": cfg["client_secret"]}
    body = {"module": args.module, "sealed": sealed,
            "username": args.username, "label": args.label, "match": args.target}
    with _make_client(cfg["server"], cfg.get("fingerprint"), cfg.get("insecure", False),
                      timeout=30) as c:
        r = c.post(f"{cfg['server']}/credentials/upload", json=body, headers=headers)
    if r.status_code == 200:
        log.info("Zugangsdaten für '%s' verschlüsselt hinterlegt (Server kann sie nicht lesen).",
                 args.module)
        return 0
    log.error("Upload fehlgeschlagen (%s): %s", r.status_code, r.text[:200])
    return 1


def _open_credentials(cfg: dict, data: dict) -> dict:
    """Decrypt sealed credentials from the server response, in RAM only.

    Unlocks our private key with the passphrase the server just delivered, then
    opens each sealed blob. Returns {module: {username, secret}}.
    """
    passphrase = data.get("key_passphrase")
    sealed = data.get("sealed_credentials") or []
    if not passphrase or not sealed or not cfg.get("enc_privkey"):
        return {}
    priv = crypto.decrypt_privkey(cfg["enc_privkey"], passphrase)
    if priv is None:
        log.warning("Privater Key konnte nicht entsperrt werden (falsche Passphrase?)")
        return {}
    out: dict = {}
    for c in sealed:
        secret = crypto.unseal(priv, c.get("sealed", ""))
        if secret is not None:
            out[c["module"]] = {"username": c.get("username"), "secret": secret,
                                "match": c.get("match")}
    return out


def _push_once(cfg: dict, ram_creds: dict | None = None) -> dict:
    # Inject server-delivered credentials (RAM only) into the collector config.
    scan_config = dict(cfg.get("config") or {})
    if ram_creds:
        scan_config["module_credentials"] = ram_creds
    result = run_collector(cfg["collector"], scan_config)
    payload = {
        "system": cfg["name"],
        "collector": cfg["collector"],
        "kind": cfg.get("kind"),
        "hostname": socket.gethostname(),
        "ip_address": _primary_ip(),
        "result": result.to_dict(),
    }
    headers = {"X-Client-Id": cfg["client_id"], "X-Client-Token": cfg["client_secret"]}
    # Pin the server TLS fingerprint (if the join token carried one) on EVERY
    # push, not just at join, so a swapped server certificate is always caught.
    with _make_client(cfg["server"], cfg.get("fingerprint"), cfg.get("insecure", False),
                      timeout=120) as c:
        resp = c.post(f"{cfg['server']}/ingest", json=payload, headers=headers)
    resp.raise_for_status()
    return resp.json()


def _apply_commands(commands: list[dict], cfg: dict) -> bool:
    rescan = False
    for cmd in commands:
        ctype, payload = cmd.get("type"), (cmd.get("payload") or {})
        if ctype == "rescan":
            rescan = True
        elif ctype == "set_interval":
            # Clamp to a sane minimum; never 0 — a 0 interval would exit the
            # loop-mode agent and leave it dead until the next reboot.
            cfg["interval"] = max(1, int(payload.get("minutes", cfg.get("interval", 60)) or 60))
        elif ctype == "set_config":
            if "collector" in payload:
                cfg["collector"] = payload["collector"]
            if "config" in payload:
                merged = dict(cfg.get("config") or {})
                merged.update(payload["config"] or {})
                cfg["config"] = merged
        _save_config(cfg)
    return rescan


def _push_due(cfg: dict) -> bool:
    """Is a push due according to the agent's own interval?

    In --once mode the OS scheduler is just a heartbeat that fires often; the
    agent itself decides whether its configured interval has elapsed since the
    last successful push. This keeps the cadence in the (centrally settable)
    agent config instead of the task definition, and tolerates a heartbeat that
    fires slightly early.
    """
    interval = int(cfg.get("interval") or 0)
    if interval <= 0:
        return True  # no interval configured -> always push on invocation
    last = float(cfg.get("last_push_ts") or 0)
    return (time.time() - last) >= (interval * 60 - 30)  # 30s slack


def cmd_run(args) -> int:
    load_builtin_collectors()
    try:
        cfg = _load_config()
    except FileNotFoundError:
        log.error("Keine Agent-Konfig unter %s — zuerst 'join' ausführen.", CONFIG_PATH)
        return 2

    once = bool(getattr(args, "once", False))
    if once and not _push_due(cfg):
        age = int(time.time() - float(cfg.get("last_push_ts") or 0))
        log.info("noch nicht fällig (Intervall %s min, letzter Push vor %ss) — nichts zu tun",
                 cfg.get("interval"), age)
        return 0

    ram_creds: dict = {}  # server-delivered credentials, kept in memory only
    rc = 0
    while True:
        rescan = False
        try:
            data = _push_once(cfg, ram_creds)
            cmds = data.get("commands", []) or []
            log.info("gepusht; %d Befehl(e)", len(cmds))
            # Open sealed credentials in RAM; never written to agent.json.
            ram_creds = _open_credentials(cfg, data)
            if data.get("server_version") and data["server_version"] != __version__:
                log.warning("Agent-Update verfügbar: %s -> %s", __version__, data["server_version"])
            rescan = _apply_commands(cmds, cfg)
            # Remember when we last pushed so --once can gate on the interval.
            cfg["last_push_ts"] = time.time()
            _save_config(cfg)
        except Exception:
            log.exception("Push fehlgeschlagen")
            rc = 1
        # A pending rescan is honoured immediately, even in --once mode.
        if rescan:
            continue
        # --once: one due push per invocation; the OS scheduler drives cadence
        # and restarts us (robust against crash/sleep/reboot).
        if once:
            return rc
        if not cfg.get("interval"):
            break
        time.sleep(int(cfg["interval"]) * 60)
    return rc


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Argus agent")
    sub = ap.add_subparsers(dest="cmd", required=True)

    j = sub.add_parser("join", help="einmalig mit Join-Token anlernen")
    j.add_argument("token")
    j.add_argument("--server", default=None, help="überschreibt die Server-URL aus dem Token")
    j.add_argument("--name", default=None)
    j.add_argument("--kind", default=None)
    j.add_argument("--collector", default=None)
    j.add_argument("--config", default="{}")
    j.add_argument("--interval", type=int, default=60)
    j.add_argument("--insecure", action="store_true")
    j.set_defaults(func=cmd_join)

    r = sub.add_parser("run", help="Push-Schleife starten")
    r.add_argument("--once", action="store_true",
                   help="einmal pushen und beenden (OS-Scheduler treibt den Takt)")
    r.set_defaults(func=cmd_run)

    s = sub.add_parser("set-cred", help="Modul-Zugangsdaten vor Ort verschlüsselt hinterlegen")
    s.add_argument("--module", required=True)
    s.add_argument("--secret", required=True)
    s.add_argument("--username", default=None)
    s.add_argument("--target", default=None, help="MAC/IP, optional")
    s.add_argument("--label", default=None)
    s.set_defaults(func=cmd_set_cred)

    args = ap.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
