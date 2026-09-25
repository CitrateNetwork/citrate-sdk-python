"""Hardening round 3 (Python).

1. Transport gate: the urllib3/urllib.parse host-agreement check has its own
   regression tests (IPv6 zone-id forms), so dropping it cannot go unnoticed.
2. ID tokens: an ``iat`` beyond the clock tolerance in the future is refused
   (parity with the JS SDK).
3. Share guard: the structural match needs an x in 1..255 and a share-length
   y (>= 16 bytes), so ordinary coordinate-like metadata is not refused.
"""
from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from citrate_sdk._url_security import InsecureTransportError, enforce_transport_security
from citrate_sdk.crypto import assert_no_key_share_material
from citrate_sdk.errors import CitrateError
from citrate_sdk.identity.jwt import IdTokenError, verify_id_token


@pytest.mark.parametrize("url", [
    "http://[::1%25eth0]:8545",
    "http://[::1%25evil.com]:8545",
    "http://[::1%2540evil.com]:8545",
    "http://[fe80::1%25en0]:8545",
])
def test_ipv6_zone_id_forms_are_refused_by_host_agreement(url: str) -> None:
    with pytest.raises(InsecureTransportError, match="urllib.parse sees host|unparseable|not allowed"):
        enforce_transport_security(url)


def test_plain_ipv6_loopback_still_passes() -> None:
    assert enforce_transport_security("http://[::1]:8545") == "http://[::1]:8545"


_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_n = _key.public_key().public_numbers()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


JWKS = [{"kty": "RSA", "kid": "k", "n": _b64(_n.n.to_bytes(256, "big")), "e": _b64(_n.e.to_bytes(3, "big"))}]
NOW = 1_900_000_000


def _tok(iat: int) -> str:
    h = _b64(json.dumps({"alg": "RS256", "kid": "k"}).encode())
    p = _b64(json.dumps({"iss": "https://i", "aud": "a", "sub": "u", "iat": iat, "exp": NOW + 3600}).encode())
    return f"{h}.{p}.{_b64(_key.sign(f'{h}.{p}'.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


def _verify(tok: str) -> dict[str, Any]:
    return verify_id_token(tok, "https://i", "a", JWKS, now_ms=NOW * 1000)


def test_iat_within_tolerance_is_accepted() -> None:
    assert _verify(_tok(NOW + 60))["sub"] == "u"


@pytest.mark.parametrize("iat", [NOW + 61, NOW + 10**6])
def test_future_iat_is_refused(iat: int) -> None:
    with pytest.raises(IdTokenError, match="issued in the future"):
        _verify(_tok(iat))


Y32 = "ab" * 32


@pytest.mark.parametrize("meta", [
    {"x": 1, "y": "10"},
    {"point": {"x": 1, "y": "ff"}},
    {"theme": {"x": 0, "y": "abcdef"}},
    {"x": 0, "y": Y32},
    {"x": 256, "y": Y32},
    {"x": "one", "y": Y32},
    {"x": 1, "y": "ab" * 15},
    {"x": 1, "y": "abc" * 11},
    {"x": 1, "y": b"\x01\x02"},
    {"grid": json.dumps({"x": 3, "y": "1234"})},
    {"x": "0", "y": Y32},
    {"x": "256", "y": Y32},
    {"x": "1a", "y": Y32},
    {"x": " 12", "y": Y32},
    {"x": "", "y": Y32},
    {"x": True, "y": Y32},
    {"x": [5], "y": Y32},
    {"x": 1, "y": bytes(15)},
    {"x": 1, "y": [Y32]},
])
def test_coordinate_like_metadata_is_not_refused(meta: dict[str, Any]) -> None:
    assert_no_key_share_material(meta)


@pytest.mark.parametrize("meta", [
    {"a": {"x": 1, "y": Y32}},
    {"a": {"x": "255", "y": "0x" + Y32}},
    {"a": {"x": 7, "y": "ab" * 16}},
    {"a": {"x": 2, "y": bytes(32)}},
    {"a": {"x": 2, "y": "1" * 64}},
    {"blob": json.dumps([{"x": 2, "y": Y32}])},
    {"a": {"x": 255, "y": Y32}},
    {"a": {"x": "1", "y": Y32}},
    {"a": {"x": 1, "y": bytes(16)}},
])
def test_share_shaped_values_are_still_refused(meta: dict[str, Any]) -> None:
    with pytest.raises(CitrateError, match="shaped like a key share"):
        assert_no_key_share_material(meta)
