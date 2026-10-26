"""Symmetric encryption for stored module credentials (envelope at rest).

Secrets (API tokens, logins) for device modules are stored **encrypted at rest**
on the server and only decrypted in memory when delivered to an authenticated
agent over its push response. The agent keeps them in RAM for one scan and never
persists plaintext — so a stolen client disk yields nothing usable.

The key comes from SECSCAN_CRYPTO_KEY (a Fernet key) if set, otherwise it is
derived from the admin password / secret so it works out of the box; set an
explicit key in production so secrets survive a password change.
"""
from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken

from app.config import settings


def _key() -> bytes:
    raw = getattr(settings, "crypto_key", "") or ""
    if raw:
        try:  # accept a ready-made Fernet key as-is
            Fernet(raw.encode())
            return raw.encode()
        except Exception:
            pass
    # Otherwise derive a stable key from the configured secret.
    material = (raw or settings.session_secret()).encode()
    return base64.urlsafe_b64encode(hashlib.sha256(material).digest())


def encrypt(plaintext: str) -> str:
    return Fernet(_key()).encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str | None:
    try:
        return Fernet(_key()).decrypt(token.encode()).decode()
    except (InvalidToken, ValueError):
        return None


# ---- collector_config secrets at rest ------------------------------------
# A system's collector_config may hold secrets (SSH password, API tokens). We
# encrypt those values at rest with the Fernet key above and decrypt them only
# in memory, right before a collector runs. Encrypted values carry a sentinel
# prefix so a config can be re-saved repeatedly without double-encrypting.

ENC_PREFIX = "enc:v1:"
# Keys whose values are treated as secrets and encrypted at rest.
SECRET_CONFIG_KEYS = {"password", "token", "secret", "api_key", "apikey"}


def _walk_config(value, key_is_secret: bool, transform):
    if isinstance(value, dict):
        return {k: _walk_config(v, k.lower() in SECRET_CONFIG_KEYS, transform)
                for k, v in value.items()}
    if isinstance(value, list):
        return [_walk_config(v, key_is_secret, transform) for v in value]
    if key_is_secret and isinstance(value, str) and value:
        return transform(value)
    return value


def encrypt_config(config: dict | None) -> dict:
    """Return a copy of the collector config with secret fields encrypted."""
    if not config:
        return config or {}

    def enc(v: str) -> str:
        if v.startswith(ENC_PREFIX):
            return v  # already encrypted — don't wrap twice
        return ENC_PREFIX + encrypt(v)

    return _walk_config(config, False, enc)


def decrypt_config(config: dict | None) -> dict:
    """Return a copy of the collector config with secret fields decrypted."""
    if not config:
        return config or {}

    def dec(v: str) -> str:
        if not v.startswith(ENC_PREFIX):
            return v
        plain = decrypt(v[len(ENC_PREFIX):])
        return plain if plain is not None else v

    # Decrypt any ENC_PREFIX string regardless of key name (keys are stable, but
    # be forgiving if a secret was stored under an unexpected key).
    def walk(value):
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        if isinstance(value, str) and value.startswith(ENC_PREFIX):
            return dec(value)
        return value

    return walk(config)


# ---- asymmetric (zero-knowledge) credential crypto -----------------------
# Each agent owns an X25519 keypair. Secrets are sealed to its public key so
# only that agent can open them (ECIES: ephemeral X25519 + HKDF + AES-GCM). The
# agent's private key is itself stored encrypted with a passphrase the SERVER
# holds and delivers at runtime (split knowledge). See ARCHITECTURE.md.

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.x25519 import (  # noqa: E402
    X25519PrivateKey, X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM  # noqa: E402
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # noqa: E402
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt  # noqa: E402

import os  # noqa: E402


def generate_keypair() -> tuple[str, str]:
    """Return (private_key_b64, public_key_b64) raw X25519 keys."""
    priv = X25519PrivateKey.generate()
    priv_raw = priv.private_bytes(serialization.Encoding.Raw,
                                  serialization.PrivateFormat.Raw,
                                  serialization.NoEncryption())
    pub_raw = priv.public_key().public_bytes(serialization.Encoding.Raw,
                                              serialization.PublicFormat.Raw)
    return base64.b64encode(priv_raw).decode(), base64.b64encode(pub_raw).decode()


def _derive(shared: bytes, salt: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=salt,
                info=b"argus-cred").derive(shared)


def seal(public_key_b64: str, plaintext: str) -> str:
    """Encrypt to an agent's public key (only its private key can open it)."""
    recipient = X25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64))
    eph = X25519PrivateKey.generate()
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw,
                                            serialization.PublicFormat.Raw)
    shared = eph.exchange(recipient)
    key = _derive(shared, eph_pub)
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(eph_pub + nonce + ct).decode()


def unseal(private_key_b64: str, blob_b64: str) -> str | None:
    try:
        blob = base64.b64decode(blob_b64)
        eph_pub, nonce, ct = blob[:32], blob[32:44], blob[44:]
        priv = X25519PrivateKey.from_private_bytes(base64.b64decode(private_key_b64))
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
        key = _derive(shared, eph_pub)
        return AESGCM(key).decrypt(nonce, ct, None).decode()
    except Exception:
        return None


def encrypt_privkey(private_key_b64: str, passphrase: str) -> str:
    """Encrypt the agent's private key at rest with a passphrase (scrypt+AES-GCM)."""
    salt = os.urandom(16)
    key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode())
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, base64.b64decode(private_key_b64), None)
    return base64.b64encode(salt + nonce + ct).decode()


def decrypt_privkey(enc_b64: str, passphrase: str) -> str | None:
    try:
        blob = base64.b64decode(enc_b64)
        salt, nonce, ct = blob[:16], blob[16:28], blob[28:]
        key = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(passphrase.encode())
        return base64.b64encode(AESGCM(key).decrypt(nonce, ct, None)).decode()
    except Exception:
        return None
