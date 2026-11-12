"""Call-site pins for two fail-closed guards.

Each test drives the public entry point (not the helper) and asserts the
observable outcome: the call refuses, and nothing goes over the wire. Both
guards were previously reachable only through a masking check elsewhere, so
removing them left the rest of the suite green.

All transports are in-process fakes; no test opens a socket.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

import citrate_sdk.client as client_mod
from citrate_sdk import CitrateClient
from citrate_sdk.errors import CitrateError
from citrate_sdk.identity.client import IdentityClient, IdentityError
from citrate_sdk.models import ModelConfig
from tests.test_identity_client import (
    CLIENT_ID,
    DISCOVERY,
    ID,
    JWKS,
    _id_token,
)

OWNER = "0x" + "11" * 32


# ── exchange_code: a missing nonce is refused before any token request ────────

def _recording_transport(calls: list[tuple[str, str]]) -> Any:
    def transport(method: str, url: str, headers: Any, body: Any) -> Any:
        calls.append((method, url))
        if url == ID["discovery"]:
            return 200, DISCOVERY
        if url == DISCOVERY["jwks_uri"]:
            return 200, {"keys": JWKS}
        if url == DISCOVERY["token_endpoint"]:
            # The token the authority returns carries a nonce claim; whether it
            # is checked depends entirely on the caller-supplied nonce.
            return 200, {"id_token": _id_token(), "access_token": "at-1", "refresh_token": "rt-1"}
        return 404, {}

    return transport


@pytest.mark.parametrize("missing", [None, ""])
def test_exchange_code_without_a_nonce_is_refused_before_the_token_request(missing: Any) -> None:
    calls: list[tuple[str, str]] = []
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_recording_transport(calls))

    with pytest.raises(IdentityError) as ei:
        c.exchange_code(code="abc", code_verifier="v" * 43, nonce=missing)

    assert "requires the nonce" in str(ei.value)
    # Refused up front: the authorization code is never redeemed.
    assert DISCOVERY["token_endpoint"] not in [u for _, u in calls]


def test_exchange_code_with_the_matching_nonce_still_succeeds() -> None:
    from tests.test_identity_client import NONCE

    calls: list[tuple[str, str]] = []
    c = IdentityClient(client_id=CLIENT_ID, redirect_uri="x", transport=_recording_transport(calls))
    tokens = c.exchange_code(code="abc", code_verifier="v" * 43, nonce=NONCE)
    assert tokens.claims["nonce"] == NONCE
    assert DISCOVERY["token_endpoint"] in [u for _, u in calls]


# ── deploy_model: an IPFS upload failure aborts the deploy, no tx is sent ─────

def _deploy_client(sent: list[str]) -> CitrateClient:
    client = CitrateClient("http://localhost:8545", private_key=OWNER)

    def rpc(method: str, params: Any = None) -> Any:
        if method == "eth_sendRawTransaction":
            sent.append(params[0])
            return "0x" + "ab" * 32
        return {"eth_getTransactionCount": "0x0", "eth_chainId": hex(40204), "eth_gasPrice": "0x1"}[method]

    stubs: dict[str, Any] = {
        "_rpc_call": rpc,
        "_wait_for_receipt": lambda h: {"logs": []},
        "_extract_model_id_from_receipt": lambda r: "0x01",
    }
    for name, fn in stubs.items():
        setattr(client, name, fn)
    return client


def test_deploy_model_aborts_when_the_ipfs_upload_fails(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    mp = tmp_path / "m.onnx"
    mp.write_bytes(b"weights")

    def failing_upload(data: bytes) -> str:
        raise ConnectionError("ipfs node unreachable")

    monkeypatch.setattr(client_mod, "upload_to_ipfs", failing_upload)
    sent: list[str] = []
    client = _deploy_client(sent)

    with pytest.raises(CitrateError) as ei:
        client.deploy_model(mp, ModelConfig(name="m"))

    assert "IPFS upload failed" in str(ei.value)
    assert sent == [], "no deployment transaction may be broadcast without a real CID"


def test_deploy_model_carries_the_cid_the_upload_returned(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import rlp  # type: ignore[import-untyped]

    mp = tmp_path / "m.onnx"
    mp.write_bytes(b"weights")
    monkeypatch.setattr(client_mod, "upload_to_ipfs", lambda data: "bafyrealcid")
    sent: list[str] = []
    client = _deploy_client(sent)

    client.deploy_model(mp, ModelConfig(name="m"))

    assert len(sent) == 1
    payload = json.loads(bytes(rlp.decode(bytes.fromhex(sent[0][2:]))[5]))
    assert payload["ipfs_hash"] == "bafyrealcid"
