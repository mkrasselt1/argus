"""Push client — run a collector locally and POST the result to Argus.

This is the secure data path: the client initiates an **outbound** HTTPS POST
to the Argus server and the server never needs a route back to the client.
The server may return control commands in the POST response; the client acts
on them (rescan now, change interval) and reports back on its next push.

Usage (on the monitored machine):

    python -m app.push \
        --server https://argus.example.com \
        --token  <SECSCAN_INGEST_TOKEN> \
        --system "Dieser PC" --kind windows \
        --collector windows \
        --interval 60            # minutes; omit or 0 for a single push

The collector config can be given as JSON via --config '{"...": ...}'.
"""
from __future__ import annotations

import argparse
import json
import logging
import socket
import time

import httpx

from app import __version__
from app.collectors.base import load_builtin_collectors, run_collector

log = logging.getLogger("argus.push")


def _primary_ip() -> str | None:
    """Best-effort primary outbound IPv4 of this host (no traffic is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("203.0.113.1", 9))  # TEST-NET-3; just picks the routing iface
        return s.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        s.close()


def push_once(server: str, token: str, system: str, collector: str, config: dict,
              kind: str | None, verify) -> list[dict]:
    """Run the collector and POST its result. Returns server commands, if any."""
    result = run_collector(collector, config)
    payload = {
        "system": system,
        "collector": collector,
        "kind": kind,
        "hostname": socket.gethostname(),
        "ip_address": _primary_ip(),
        "result": result.to_dict(),
    }
    with httpx.Client(timeout=120, verify=verify) as client:
        resp = client.post(
            f"{server.rstrip('/')}/ingest",
            json=payload,
            headers={"X-Ingest-Token": token},
        )
    resp.raise_for_status()
    data = resp.json()
    return data


def _apply_commands(commands: list[dict], state: dict) -> bool:
    """Handle server commands. Returns True if an immediate rescan is requested."""
    rescan = False
    for cmd in commands:
        ctype = cmd.get("type")
        payload = cmd.get("payload") or {}
        if ctype == "rescan":
            rescan = True
        elif ctype == "set_interval":
            minutes = int(payload.get("minutes", state["interval"]))
            state["interval"] = max(0, minutes)
            log.info("server set interval to %s min", state["interval"])
        elif ctype == "set_config":
            if "collector" in payload:
                state["collector"] = payload["collector"]
            if "config" in payload:
                # Merge so the server can send partial updates (e.g. just ports).
                merged = dict(state.get("config") or {})
                merged.update(payload["config"] or {})
                state["config"] = merged
            log.info("server updated collector/config: %s", state["config"])
        else:
            log.warning("ignoring unknown command type: %s", ctype)
    return rescan


def _version_tuple(v: str) -> tuple:
    out = []
    for part in str(v).split("."):
        num = "".join(ch for ch in part if ch.isdigit())
        out.append(int(num) if num else 0)
    return tuple(out)


def _check_self_update(server_version: str | None, mode: str, update_cmd: str | None) -> None:
    """Compare the agent's version with the server's and act per mode.

    mode = manual (default): only report that an update exists, change nothing.
    mode = auto:  run --update-cmd (if given) to update the agent, then let a
                  supervisor restart it. Without --update-cmd, auto behaves like
                  manual (we never run an unspecified command).
    """
    if not server_version:
        return
    if _version_tuple(server_version) <= _version_tuple(__version__):
        return
    log.warning("Agent-Update verfügbar: %s -> %s (Modus: %s)", __version__, server_version, mode)
    if mode == "auto" and update_cmd:
        import subprocess
        log.info("running update command: %s", update_cmd)
        try:
            subprocess.run(update_cmd, shell=True, check=True)
            log.info("update command finished; restart the agent to apply")
        except subprocess.SubprocessError as exc:
            log.error("update command failed: %s", exc)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    ap = argparse.ArgumentParser(description="Argus push client")
    ap.add_argument("--server", required=True)
    ap.add_argument("--token", required=True)
    ap.add_argument("--system", required=True)
    ap.add_argument("--collector", required=True)
    ap.add_argument("--kind", default=None)
    ap.add_argument("--config", default="{}", help="collector config as JSON")
    ap.add_argument("--interval", type=int, default=0, help="minutes between pushes (0 = once)")
    ap.add_argument("--insecure", action="store_true", help="skip TLS verification")
    ap.add_argument("--update-mode", choices=["manual", "auto"], default="manual",
                    help="agent self-update: manual = only report (default), auto = run --update-cmd")
    ap.add_argument("--update-cmd", default=None, help="command to update the agent when mode=auto")
    args = ap.parse_args()

    load_builtin_collectors()
    state = {
        "collector": args.collector,
        "config": json.loads(args.config or "{}"),
        "interval": args.interval,
    }
    verify = not args.insecure

    while True:
        try:
            data = push_once(
                args.server, args.token, args.system,
                state["collector"], state["config"], args.kind, verify,
            )
            commands = data.get("commands", []) or []
            log.info("pushed; %d command(s) from server", len(commands))
            _check_self_update(data.get("server_version"), args.update_mode, args.update_cmd)
            rescan = _apply_commands(commands, state)
            if rescan:
                log.info("server requested immediate rescan")
                continue
        except Exception:
            log.exception("push failed")

        if not state["interval"]:
            break
        time.sleep(state["interval"] * 60)


if __name__ == "__main__":
    main()
