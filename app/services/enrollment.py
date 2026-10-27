"""Agent enrollment: codes, join tokens, per-client credentials, approval.

Flow (frictionless): the server mints a short-lived enrollment code, embedded in
a one-line install/join command. The agent runs it once, calls /enroll with the
code, and receives a durable per-client secret. From then on it authenticates
per client (X-Client-Id + X-Client-Token) and the admin can approve/revoke/rotate
each agent individually. Codes and secrets are stored only as hashes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import timedelta

from sqlmodel import Session, select

from app.db import engine
from app.models import Client, ClientStatus, Credential, EnrollmentCode, utcnow


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def encode_join_token(server_url: str, code: str, fingerprint: str | None = None) -> str:
    """Pack server URL + code (+ optional server cert fingerprint) into one token."""
    raw = json.dumps({"s": server_url, "c": code, "f": fingerprint}, separators=(",", ":"))
    return "argus-join-" + base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_join_token(token: str) -> dict:
    body = token.removeprefix("argus-join-")
    body += "=" * (-len(body) % 4)
    data = json.loads(base64.urlsafe_b64decode(body).decode())
    return {"server": data.get("s"), "code": data.get("c"), "fingerprint": data.get("f")}


def create_code(
    label: str | None = None,
    auto_approve: bool = True,
    max_uses: int = 1,
    ttl_minutes: int = 60,
    group: str | None = None,
    tags: list | None = None,
) -> tuple[str, EnrollmentCode]:
    """Create an enrollment code; returns the clear-text code (shown once)."""
    code = secrets.token_urlsafe(9)
    row = EnrollmentCode(
        code_hash=_hash(code),
        label=label,
        auto_approve=auto_approve,
        max_uses=max_uses,
        expires_at=utcnow() + timedelta(minutes=ttl_minutes) if ttl_minutes else None,
        group=group,
        tags=tags or [],
    )
    with Session(engine) as session:
        session.add(row)
        session.commit()
        session.refresh(row)
    return code, row


def enroll(code: str, name: str, hostname: str | None = None,
           pubkey: str | None = None, key_passphrase: str | None = None) -> dict:
    """Validate the code and issue a per-client credential.

    Also records the agent's public key (secrets are sealed to it) and the
    passphrase that unlocks the agent's own private key (delivered at runtime).
    Returns {client_id, client_secret, status}. Raises ValueError on a bad,
    expired or exhausted code.
    """
    with Session(engine) as session:
        row = session.exec(
            select(EnrollmentCode).where(EnrollmentCode.code_hash == _hash(code))
        ).first()
        if row is None:
            raise ValueError("Ungültiger Enrollment-Code")
        if row.expires_at and row.expires_at < utcnow():
            raise ValueError("Enrollment-Code abgelaufen")
        if row.uses >= row.max_uses:
            raise ValueError("Enrollment-Code bereits aufgebraucht")

        client_id = "agt_" + secrets.token_hex(8)
        client_secret = secrets.token_urlsafe(24)
        status = ClientStatus.approved if row.auto_approve else ClientStatus.pending
        client = Client(
            client_id=client_id,
            secret_hash=_hash(client_secret),
            name=name,
            status=status,
            pubkey=pubkey,
            key_passphrase=key_passphrase,
        )
        row.uses += 1
        session.add(client)
        session.add(row)
        session.commit()
        return {"client_id": client_id, "client_secret": client_secret, "status": status.value}


def authenticate(client_id: str, secret: str, ip: str | None = None) -> Client | None:
    """Return the Client if credentials are valid AND approved, else None.

    Raises PermissionError if the client exists but is not approved/revoked, so
    callers can distinguish "unknown" from "not yet approved".
    """
    with Session(engine) as session:
        client = session.exec(select(Client).where(Client.client_id == client_id)).first()
        if client is None or not secrets.compare_digest(client.secret_hash, _hash(secret)):
            return None
        if client.status != ClientStatus.approved:
            raise PermissionError(client.status.value)
        client.last_seen = utcnow()
        if ip:
            client.last_ip = ip
        session.add(client)
        session.commit()
        session.refresh(client)
        return client


def set_status(client_id: int, status: ClientStatus) -> None:
    with Session(engine) as session:
        client = session.get(Client, client_id)
        if client:
            client.status = status
            session.add(client)
            session.commit()


def delete_client(client_id: int) -> bool:
    """Remove an agent for good. Credentials sealed to its key are useless
    without it, so they go too; the system and its scans stay."""
    with Session(engine) as session:
        client = session.get(Client, client_id)
        if client is None:
            return False
        for cred in session.exec(select(Credential).where(Credential.client_id == client_id)).all():
            session.delete(cred)
        session.delete(client)
        session.commit()
        return True


def rotate_secret(client_id: int) -> str | None:
    with Session(engine) as session:
        client = session.get(Client, client_id)
        if client is None:
            return None
        new_secret = secrets.token_urlsafe(24)
        client.secret_hash = _hash(new_secret)
        session.add(client)
        session.commit()
        return new_secret


def list_clients() -> list[Client]:
    with Session(engine) as session:
        return session.exec(select(Client).order_by(Client.enrolled_at.desc())).all()
