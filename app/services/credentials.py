"""Module credentials — v2, zero-knowledge.

Secrets are SEALED to a specific agent's X25519 public key (see crypto.seal),
so the server stores only a blob it cannot read. At runtime the sealed blobs are
handed to that authenticated agent, which opens them with its own private key
(unlocked by the passphrase the server delivers). The server never sees plaintext.

Two entry paths produce the sealed blob:
* on-site CLI on the agent (`argus-agent set-cred`) — seals locally, uploads blob;
* central browser (WebCrypto) — seals to the agent's pubkey, uploads blob.
Both post the already-sealed blob here; this module never handles plaintext.
"""
from __future__ import annotations

from sqlmodel import Session, select

from app.db import engine
from app.models import Client, Credential


def add_sealed(client_id: int, module: str, sealed: str,
               username: str | None = None, label: str | None = None,
               match: str | None = None) -> int:
    with Session(engine) as session:
        row = Credential(client_id=client_id, module=module, sealed=sealed,
                         username=username or None, label=label or None,
                         match=match or None, secret_enc="")  # legacy col: NOT NULL in old DBs
        session.add(row)
        session.commit()
        session.refresh(row)
        return row.id  # type: ignore[return-value]


def delete_credential(cred_id: int) -> None:
    with Session(engine) as session:
        row = session.get(Credential, cred_id)
        if row:
            session.delete(row)
            session.commit()


def list_credentials() -> list[Credential]:
    with Session(engine) as session:
        return session.exec(select(Credential).order_by(Credential.module)).all()


def delivery_for_client(client_db_id: int) -> list[dict]:
    """Sealed credentials for one agent — opaque blobs the server cannot read."""
    with Session(engine) as session:
        rows = session.exec(
            select(Credential).where(Credential.client_id == client_db_id,
                                     Credential.sealed.is_not(None))
        ).all()
        return [{"module": c.module, "sealed": c.sealed, "username": c.username,
                 "match": c.match} for c in rows]


def client_by_id(client_id_str: str) -> Client | None:
    with Session(engine) as session:
        return session.exec(select(Client).where(Client.client_id == client_id_str)).first()
