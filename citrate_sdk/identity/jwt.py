"""ID-token verification (DEVX-S1) — Python parity, using ``cryptography`` (already a dep).

Hardened against the OIDC attack classes: alg:none, alg-confusion (HS*), wrong aud/iss,
expired/not-before, tampered signature, kid mismatch. RS256 only.
"""
from __future__ import annotations

import base64
import json
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers


class IdTokenError(Exception):
    pass


def _b64url_bytes(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _b64url_int(s: str) -> int:
    return int.from_bytes(_b64url_bytes(s), "big")


def _decode(seg: str) -> dict[str, Any]:
    try:
        return json.loads(_b64url_bytes(seg).decode("utf-8"))
    except Exception:
        raise IdTokenError("malformed token segment")


def verify_id_token(
    token: str,
    issuer: str,
    audience: str,
    jwks: list[dict[str, Any]],
    now_ms: int | None = None,
    clock_tolerance_sec: int = 60,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Verify an OIDC ID token and return its (now-trusted) claims. Raises IdTokenError."""
    parts = token.split(".")
    if len(parts) != 3:
        raise IdTokenError("token must have three segments")
    header = _decode(parts[0])
    if header.get("alg") != "RS256":  # rejects alg:none and alg-confusion
        raise IdTokenError("unsupported or unsafe alg: {!r} (only RS256 accepted)".format(header.get("alg")))
    if not parts[2]:
        raise IdTokenError("empty signature")

    kid = header.get("kid")
    rsa_keys = [k for k in jwks if k.get("kty") == "RSA" and k.get("n") and k.get("e")]
    if kid:
        jwk = next((k for k in rsa_keys if k.get("kid") == kid), None)
    else:
        jwk = rsa_keys[0] if len(rsa_keys) == 1 else None
    if jwk is None:
        raise IdTokenError(("no RSA JWK for kid " + str(kid)) if kid else "ambiguous or missing RSA JWK")

    pub = RSAPublicNumbers(e=_b64url_int(jwk["e"]), n=_b64url_int(jwk["n"])).public_key()
    signing_input = (parts[0] + "." + parts[1]).encode("ascii")
    try:
        pub.verify(_b64url_bytes(parts[2]), signing_input, padding.PKCS1v15(), hashes.SHA256())
    except InvalidSignature:
        raise IdTokenError("signature verification failed")

    payload = _decode(parts[1])
    if payload.get("iss") != issuer:
        raise IdTokenError("iss mismatch: {}".format(payload.get("iss")))
    aud = payload.get("aud")
    aud_ok = (audience in aud) if isinstance(aud, list) else (aud == audience)
    if not aud_ok:
        raise IdTokenError("aud mismatch")

    now = (now_ms if now_ms is not None else int(time.time() * 1000)) // 1000
    tol = clock_tolerance_sec
    exp = payload.get("exp")
    if isinstance(exp, (int, float)) and now > exp + tol:
        raise IdTokenError("token expired")
    nbf = payload.get("nbf")
    if isinstance(nbf, (int, float)) and now + tol < nbf:
        raise IdTokenError("token not yet valid")
    if nonce is not None and payload.get("nonce") != nonce:
        raise IdTokenError("nonce mismatch")
    return payload
