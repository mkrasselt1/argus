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
import json
import logging
import os
import platform
import socket
import sys
import time
from pathlib import Path

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
    verify = info.get("fingerprint") or not args.insecure

    # Zero-knowledge key setup: generate our keypair, protect the private key
    # with a random passphrase the SERVER will hold, keep only the ciphertext.
    priv_b64, pub_b64 = crypto.generate_keypair()
    passphrase = secrets.token_urlsafe(24)
    enc_privkey = crypto.encrypt_privkey(priv_b64, passphrase)

    with httpx.Client(timeout=30, verify=(verify if isinstance(verify, bool) else True)) as c:
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
    with httpx.Client(timeout=30) as c:
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
    with httpx.Client(timeout=120) as c:
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
            cfg["interval"] = max(0, int(payload.get("minutes", cfg.get("interval", 0))))
        elif ctype == "set_config":
            if "collector" in payload:
                cfg["collector"] = payload["collector"]
            if "config" in payload:
                merged = dict(cfg.get("config") or {})
                merged.update(payload["config"] or {})
                cfg["config"] = merged
        _save_config(cfg)
    return rescan


def cmd_run(args) -> int:
    load_builtin_collectors()
    try:
        cfg = _load_config()
    except FileNotFoundError:
        log.error("Keine Agent-Konfig unter %s — zuerst 'join' ausführen.", CONFIG_PATH)
        return 2

    ram_creds: dict = {}  # server-delivered credentials, kept in memory only
    while True:
        try:
            data = _push_once(cfg, ram_creds)
            cmds = data.get("commands", []) or []
            log.info("gepusht; %d Befehl(e)", len(cmds))
            # Open sealed credentials in RAM; never written to agent.json.
            ram_creds = _open_credentials(cfg, data)
            if data.get("server_version") and data["server_version"] != __version__:
                log.warning("Agent-Update verfügbar: %s -> %s", __version__, data["server_version"])
            if _apply_commands(cmds, cfg):
                continue
        except Exception:
            log.exception("Push fehlgeschlagen")
        if not cfg.get("interval"):
            break
        time.sleep(int(cfg["interval"]) * 60)
    return 0


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
