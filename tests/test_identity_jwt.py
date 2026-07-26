"""DEVX-S1 / F2 — PKCE + hardened ID-token verification (Python parity).
Real RSA crypto via ``cryptography`` (no mocks)."""
from __future__ import annotations

import base64
import json

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from citrate_sdk.identity.jwt import IdTokenError, verify_id_token
from citrate_sdk.identity.pkce import challenge_from_verifier, create_pkce, generate_verifier

ISSUER = "https://auth.citrate.ai"
AUD = "citrate-core"
KID = "kid-1"

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_pub = _key.public_key().public_numbers()


def _int_b64url(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


JWKS = [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
         "n": _int_b64url(_pub.n), "e": _int_b64url(_pub.e)}]


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode("ascii")


def _make_token(payload, header=None):
    header = header or {"alg": "RS256", "kid": KID, "typ": "JWT"}
    signing_input = _b64url(header) + "." + _b64url(payload)
    sig = _key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + base64.urlsafe_b64encode(sig).rstrip(b"=").decode("ascii")


def _valid():
    import time
    return {"iss": ISSUER, "sub": "user-1", "aud": AUD, "exp": int(time.time()) + 3600}


def _raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


def test_pkce_shape():
    p = create_pkce()
    assert p.method == "S256"
    assert len(p.verifier) == 43
    assert p.challenge == challenge_from_verifier(p.verifier)
    assert generate_verifier() != generate_verifier()


def test_verify_happy_path():
    claims = verify_id_token(_make_token(_valid()), issuer=ISSUER, audience=AUD, jwks=JWKS)
    assert claims["sub"] == "user-1"


def test_reject_alg_none():
    header = {"alg": "none", "typ": "JWT"}
    token = _b64url(header) + "." + _b64url(_valid()) + "."
    assert _raises(IdTokenError, lambda: verify_id_token(token, issuer=ISSUER, audience=AUD, jwks=JWKS))


def test_reject_alg_confusion_hs256():
    token = _make_token(_valid(), header={"alg": "HS256", "kid": KID, "typ": "JWT"})
    # signed RS256 but header claims HS256 -> alg allowlist rejects before any verify
    assert _raises(IdTokenError, lambda: verify_id_token(token, issuer=ISSUER, audience=AUD, jwks=JWKS))


def test_reject_wrong_aud_and_iss():
    assert _raises(IdTokenError, lambda: verify_id_token(_make_token(_valid()), issuer=ISSUER, audience="other", jwks=JWKS))
    bad = _valid(); bad["iss"] = "https://evil.example"
    assert _raises(IdTokenError, lambda: verify_id_token(_make_token(bad), issuer=ISSUER, audience=AUD, jwks=JWKS))


def test_reject_expired():
    import time
    past = _valid(); past["exp"] = int(time.time()) - 3600
    assert _raises(IdTokenError, lambda: verify_id_token(_make_token(past), issuer=ISSUER, audience=AUD, jwks=JWKS))


def test_reject_tampered():
    token = _make_token(_valid())
    h, _p, s = token.split(".")
    tampered = h + "." + _b64url({**_valid(), "sub": "attacker"}) + "." + s
    assert _raises(IdTokenError, lambda: verify_id_token(tampered, issuer=ISSUER, audience=AUD, jwks=JWKS))


def test_reject_unknown_kid():
    other = [{**JWKS[0], "kid": "different"}]
    assert _raises(IdTokenError, lambda: verify_id_token(_make_token(_valid()), issuer=ISSUER, audience=AUD, jwks=other))
