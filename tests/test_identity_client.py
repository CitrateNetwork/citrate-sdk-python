"""DEVX-S1 / F2 — IdentityClient end-to-end over an injected transport (Python parity)."""
from __future__ import annotations

import base64
import json
import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from citrate_sdk._generated import contract
from citrate_sdk.identity.client import IdentityClient

ID = contract.identity()
CLIENT_ID = "citrate-core"
KID = "kid-1"

_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_pub = _key.public_key().public_numbers()


def _int_b64url(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


JWKS = [{"kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256", "n": _int_b64url(_pub.n), "e": _int_b64url(_pub.e)}]


def _b64url(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode("ascii")


NONCE = "nonce-abc123"


def _id_token(nonce=NONCE):
    header = {"alg": "RS256", "kid": KID, "typ": "JWT"}
    payload = {"iss": ID["issuer"], "sub": "user-1", "aud": CLIENT_ID, "iat": int(time.time()), "exp": int(time.time()) + 3600}
    if nonce is not None:
        payload["nonce"] = nonce
    si = _b64url(header) + "." + _b64url(payload)
    return si + "." + base64.urlsafe_b64encode(_key.sign(si.encode(), padding.PKCS1v15(), hashes.SHA256())).rstrip(b"=").decode("ascii")


DISCOVERY = {
    "issuer": ID["issuer"],
    "authorization_endpoint": ID["issuer"] + "/auth",
    "token_endpoint": ID["issuer"] + "/token",
    "userinfo_endpoint": ID["issuer"] + "/me",
    "jwks_uri": ID["issuer"] + "/jwks",
    "end_session_endpoint": ID["issuer"] + "/session/end",
}


def _make_transport(userinfo_body):
    def transport(method, url, headers, body):
        if url == ID["discovery"]:
            return 200, DISCOVERY
        if url == DISCOVERY["jwks_uri"]:
            return 200, {"keys": JWKS}
        if url == DISCOVERY["token_endpoint"]:
            return 200, {"id_token": _id_token(), "access_token": "at-1", "refresh_token": "rt-1"}
        if url == DISCOVERY["userinfo_endpoint"]:
            return 200, userinfo_body
        if url == ID["issuer"] + "/aa/enroll-validator":
            return 200, {"digest": "0xd1", "signature": "0x51", "factory": "f"}
        return 404, {}
    return transport


def test_authorize_url():
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="http://127.0.0.1:8899/auth/callback", transport=_make_transport({}))
    url, pk = c.authorize_url(state="st", nonce="no")
    assert (ID["issuer"] + "/auth?") in url
    assert "code_challenge_method=S256" in url
    assert ("code_challenge=" + pk.challenge) in url
    assert ("client_id=" + CLIENT_ID) in url


def test_exchange_code_verifies_token():
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport({}))
    # SPY-B-010: nonce is now required and is checked against the ID token's
    # `nonce` claim (the token minted by the fixture carries NONCE).
    tokens = c.exchange_code(code="abc", code_verifier="v" * 43, nonce=NONCE)
    assert tokens.claims["sub"] == "user-1"
    assert tokens.access_token == "at-1"
    assert tokens.refresh_token == "rt-1"


def test_exchange_code_requires_nonce():
    """SPY-B-010 tripwire: without a nonce the ID token is never bound to the
    authorization request, so exchange_code must refuse rather than silently
    skip the nonce check."""
    import pytest
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport({}))
    with pytest.raises(Exception) as ei:
        c.exchange_code(code="abc", code_verifier="v" * 43, nonce="")
    assert "nonce" in str(ei.value).lower()


def test_exchange_code_rejects_nonce_mismatch():
    """A token whose nonce does not match the one from authorize_url is rejected."""
    import pytest
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport({}))
    with pytest.raises(Exception):
        c.exchange_code(code="abc", code_verifier="v" * 43, nonce="a-different-nonce")


def test_userinfo_commercial_kyc_caps():
    body = {"sub": "user-1", "wallet_address": "0xfb43484CDbA25C6457C2775C1d6dfeD71cE4e720",
            ID["entitlementClaim"]: {"tier": "commercial.kyc"}}
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport(body))
    info = c.user_info("at-1")
    assert info.tier == "commercial.kyc"
    assert info.capabilities.ecosystem_tx is True
    assert info.capabilities.confidential_docs is False
    assert info.wallet_address == "0xfb43484CDbA25C6457C2775C1d6dfeD71cE4e720"


def test_userinfo_role_does_not_grant_all_caps():
    # RC-8 (SPY-B-002): the old fixture asserted a `citrateRole` at tier `public`
    # yielded confidential_docs=True through the identity spine — it encoded the
    # over-broad grant. A role must NOT escalate; capabilities derive from the tier.
    body = {"sub": "a", ID["entitlementClaim"]: {"tier": "public", "citrateRole": "auditor"}}
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport(body))
    info = c.user_info("at-1")
    assert info.tier == "public"
    assert info.capabilities.confidential_docs is False
    assert info.capabilities.ecosystem_tx is False


def test_userinfo_confidential_tier_grants_confidential_docs():
    # Legitimate access is preserved: a real confidential-tier principal still passes.
    body = {"sub": "a", ID["entitlementClaim"]: {"tier": "confidential"}}
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport(body))
    info = c.user_info("at-1")
    assert info.tier == "confidential"
    assert info.capabilities.confidential_docs is True


def test_request_deploy_permit():
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_make_transport({}))
    permit = c.request_deploy_permit("0x" + "42" * 32, "0xabcd", 1780000000, "at-1")
    assert permit["digest"] == "0xd1"
    assert permit["signature"] == "0x51"
