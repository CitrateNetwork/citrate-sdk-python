"""PKCE (RFC 7636) for the Citrate OIDC flow (DEVX-S1). Stdlib only."""
from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def generate_verifier() -> str:
    """A 43-char base64url verifier (256 bits of entropy)."""
    return _b64url(secrets.token_bytes(32))


def challenge_from_verifier(verifier: str) -> str:
    return _b64url(hashlib.sha256(verifier.encode("ascii")).digest())


@dataclass(frozen=True)
class Pkce:
    verifier: str
    challenge: str
    method: str = "S256"


def create_pkce() -> Pkce:
    v = generate_verifier()
    return Pkce(verifier=v, challenge=challenge_from_verifier(v))
