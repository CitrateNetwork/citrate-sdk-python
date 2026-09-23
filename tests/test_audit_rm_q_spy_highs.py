"""RM-Q (2026-09-06) — regression tripwires for the three open HIGH findings in
the graded federation audit against citrate-sdk-python:

  * SPY-B-003 — IdentityClient.user_info() ignored entitlement `expiresAt`, so an
    expired claim still yielded full capabilities through the identity spine while
    `can()` correctly collapsed it to `public`. Two implementations of one policy.
  * SPY-B-004 — the transport-security gate was wired into only 2 of the 5
    URL-taking clients; the 3 it missed (gateway, memory, identity) are exactly the
    ones that carry bearer credentials, so a remote `http://` endpoint shipped API
    keys / id_tokens / refresh tokens in cleartext with no warning at all.
  * SPY-B-005 — the EIP-155 chain-id that domain-separates every signature was
    taken from the RPC (`eth_chainId`) and never compared against the vendored
    `chain.chainId` (40204), so a hostile RPC could make the SDK sign a tx valid on
    any chain it names (e.g. Ethereum mainnet) — defeating replay protection.

Each test is RED on pre-fix code and GREEN after. Signing-path tests are CI-gated
(eth_account/cryptography), so they only exercise `_eip155_chain_id`, not a real sign.
"""
from __future__ import annotations

import inspect
from unittest.mock import patch

import pytest

from citrate_sdk._generated import contract
from citrate_sdk.entitlements import can

ID = contract.identity()


# ── SPY-B-003 · user_info() must honour entitlement expiry ────────────────────

def _identity_transport(userinfo_body):
    """Minimal offline transport that serves discovery/jwks and one userinfo body."""
    discovery = {
        "issuer": ID["issuer"],
        "userinfo_endpoint": ID["issuer"] + "/me",
        "jwks_uri": ID["issuer"] + "/jwks",
    }

    def transport(method, url, headers, body):
        if url == ID["discovery"]:
            return 200, discovery
        if url == discovery["userinfo_endpoint"]:
            return 200, userinfo_body
        return 404, {}

    return transport


def _user_info(entitlement):
    from citrate_sdk.identity.client import IdentityClient

    body = {"sub": "u", ID["entitlementClaim"]: entitlement}
    c = IdentityClient(client_id="citrate-core", redirect_uri="x",
                       transport=_identity_transport(body))
    return c.user_info("at")


def test_userinfo_expired_claim_yields_public_capabilities():
    """RED: user_info() ignored `expiresAt` and returned confidential_docs=True for
    a long-expired confidential claim. GREEN: it collapses to public, like can()."""
    expired = {"tier": "confidential", "expiresAt": 1}  # epoch-ms, long past
    # can() has always enforced this:
    assert can(expired, "confidential_docs") is False
    # the identity spine must now agree:
    info = _user_info(expired)
    assert info.capabilities.confidential_docs is False
    assert info.capabilities.ecosystem_tx is False


def test_userinfo_unexpired_claim_still_grants():
    """Legitimate access preserved: a far-future expiry keeps confidential access."""
    live = {"tier": "confidential", "expiresAt": 10_000_000_000_000}
    info = _user_info(live)
    assert info.capabilities.confidential_docs is True


def test_userinfo_equals_can_across_claim_matrix():
    """Structural tripwire: user_info()'s capability set equals the can()-derived
    set for every claim, so the two paths cannot diverge on expiry again."""
    caps_attrs = ("ecosystem_tx", "gateway_keys", "academic_data", "confidential_docs")
    claims = [
        {"tier": "confidential", "expiresAt": 1},
        {"tier": "confidential", "expiresAt": 10_000_000_000_000},
        {"tier": "academic"},
        {"tier": "commercial.kyc", "expiresAt": 5},
        {"tier": "public"},
    ]
    for claim in claims:
        info = _user_info(claim)
        for cap in caps_attrs:
            assert getattr(info.capabilities, cap) == can(claim, cap), (claim, cap)


# ── SPY-B-004 · every URL-taking client routes through the transport gate ─────

def test_transport_gate_applied_to_every_credential_client():
    """RED: gateway/memory/identity never invoked enforce_transport_security. This
    is the finding's own repro, inverted to require full coverage."""
    from citrate_sdk import client as cc
    from citrate_sdk import gateway as g
    from citrate_sdk import ipfs as ip
    from citrate_sdk import memory as m
    from citrate_sdk.identity import client as ic

    uncovered = []
    for name, mod in [("client", cc), ("ipfs", ip), ("gateway", g),
                      ("memory", m), ("identity.client", ic)]:
        if "enforce_transport_security" not in inspect.getsource(mod):
            uncovered.append(name)
    assert uncovered == [], f"clients not routed through the gate: {uncovered}"
    # all three previously-missed clients carry a bearer credential:
    for mod in (g, m, ic):
        assert "Bearer " in inspect.getsource(mod)


def _remote_http_raises(construct):
    # SPY-B-009: the gate now FAILS CLOSED on remote plaintext instead of warning.
    from citrate_sdk._url_security import InsecureTransportError
    with pytest.raises(InsecureTransportError):
        construct()


def test_gateway_remote_http_raises():
    from citrate_sdk.gateway import GatewayClient
    _remote_http_raises(
        lambda: GatewayClient(api_key="cgk_x", base_url="http://gw.example.com"))


def test_memory_remote_http_raises():
    from citrate_sdk.memory import ByomMemoryClient, MemoryClient
    _remote_http_raises(
        lambda: MemoryClient(origin="http://mem.example.com", id_token="t"))
    _remote_http_raises(
        lambda: ByomMemoryClient(origin="http://mem.example.com", sub="s",
                                 connect_token="t"))


def test_identity_remote_http_raises():
    """A hostile discovery document returning http endpoints must be flagged —
    now by raising rather than warning (SPY-B-009)."""
    from citrate_sdk.identity.client import IdentityClient

    def hostile_transport(method, url, headers, body):
        # discovery served over http to a remote host
        if url == ID["discovery"]:
            return 200, {"issuer": ID["issuer"],
                         "userinfo_endpoint": "http://evil.example.com/me",
                         "jwks_uri": ID["issuer"] + "/jwks"}
        return 200, {"sub": "u"}

    c = IdentityClient(client_id="citrate-core", redirect_uri="x",
                       transport=hostile_transport)
    _remote_http_raises(lambda: c.user_info("at"))


# ── SPY-B-005 · chain-id must be pinned to the vendored value ─────────────────

def _client(**kw):
    from citrate_sdk.client import CitrateClient
    return CitrateClient(rpc_url="http://localhost:8545", **kw)


def test_chain_id_mismatch_refuses_to_sign():
    """RED: `_eip155_chain_id` adopted whatever the RPC reported. GREEN: it raises
    on any value other than the configured/vendored chain-id (40204)."""
    from citrate_sdk.errors import CitrateError

    c = _client()
    with patch.object(c, "get_chain_id", return_value="0x1"):  # Ethereum mainnet
        with pytest.raises(CitrateError):
            c._eip155_chain_id()


def test_chain_id_match_is_accepted():
    """The honest RPC (40204 == vendored) still works and caches."""
    c = _client()
    with patch.object(c, "get_chain_id", return_value="0x9d0c") as mock:  # 40204
        assert c._eip155_chain_id() == 40204
        assert c._eip155_chain_id() == 40204  # cached
        assert mock.call_count == 1


def test_chain_id_default_is_vendored_40204():
    """The pin defaults to the value the package vendors, not the RPC's answer."""
    assert contract.chain_id() == 40204
    c = _client()
    with patch.object(c, "get_chain_id", return_value=40204):
        assert c._eip155_chain_id() == 40204


def test_chain_id_explicit_override_is_enforced():
    """A caller may pin a different chain-id; the RPC must still match it."""
    from citrate_sdk.errors import CitrateError

    c = _client(chain_id=1)
    with patch.object(c, "get_chain_id", return_value="0x9d0c"):  # 40204 != 1
        with pytest.raises(CitrateError):
            c._eip155_chain_id()
    c2 = _client(chain_id=1)
    with patch.object(c2, "get_chain_id", return_value="0x1"):
        assert c2._eip155_chain_id() == 1
