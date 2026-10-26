"""Relay collector — collect *through* a remote argus agent.

Scenario: the dashboard cannot reach a customer's internal devices directly,
but it can reach one edge node (e.g. a production server over VPN) that runs
argus in agent mode. The relay collector asks that agent to run a real
collector locally and forwards the result back.

Because the inner collector can itself be ``relay``, gateways chain naturally:

    dashboard --relay--> edge node --relay--> jump host --ssh_linux--> device

collector_config keys:
    agent_url        base URL of the remote agent, e.g. https://edge:8080
    token            shared agent token (matches the agent's SECSCAN_AGENT_TOKEN)
    collector        name of the collector the agent should run
    config           config dict passed to that inner collector
    verify           TLS verification: true (default), false, or CA bundle path
"""
from __future__ import annotations

import logging

import httpx

from app.collectors.base import CollectResult, register
from app.config import settings

log = logging.getLogger(__name__)


class RelayCollector:
    name = "relay"

    def collect(self, config: dict) -> CollectResult:
        agent_url = str(config["agent_url"]).rstrip("/")
        inner = config.get("collector")
        if not inner:
            raise ValueError("relay: 'collector' (inner collector name) is required")
        if inner == "relay":
            # Allowed, but guard against an obvious self-loop.
            if config.get("config", {}).get("agent_url", "").rstrip("/") == agent_url:
                raise ValueError("relay: refusing to relay to the same agent (loop)")

        payload = {"collector": inner, "config": config.get("config", {}) or {}}
        verify = config.get("verify", True)

        with httpx.Client(timeout=settings.relay_timeout, verify=verify) as client:
            resp = client.post(
                f"{agent_url}/agent/collect",
                json=payload,
                headers={"X-Agent-Token": config.get("token", "")},
            )
        if resp.status_code == 401:
            raise ValueError("relay: agent rejected token (401)")
        resp.raise_for_status()
        result = CollectResult.from_dict(resp.json())

        # Annotate every finding so it is clear the data came via this gateway.
        gateway = config.get("label") or agent_url
        for p in result.packages:
            p.source = f"via {gateway}: {p.source}" if p.source else f"via {gateway}"
        for v in result.vulnerabilities:
            v.source = f"via {gateway}: {v.source}" if v.source else f"via {gateway}"
        result.summary = {"relay_via": gateway, "inner_collector": inner, **result.summary}
        return result


register(RelayCollector())
