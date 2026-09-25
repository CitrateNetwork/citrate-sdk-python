"""PBA-L6b-027: verify_wallet_address_on_chain was ungated and chain-blind.

It posted to any rpc_url, including remote plaintext http://, with no
eth_chainId assertion and no check that the factory has code there. A MITM or
hostile RPC could echo the (publicly computable) predicted address and the
"do not fund on mismatch" check passed. It now goes through the transport gate,
asserts eth_chainId against the pinned chain, and requires factory code.
"""
from __future__ import annotations

import json
from typing import Any
from unittest import mock

import pytest
import requests

from citrate_sdk._generated import contract as _contract
from citrate_sdk._url_security import InsecureTransportError
from citrate_sdk.identity import wallet

UID = "0x" + "42" * 32


def _rpc(chain_id: int = 40204, code: str = "0x6080", echo: bool = True) -> tuple[Any, list[str]]:
    methods: list[str] = []
    local = wallet.predict_wallet_address(UID)

    def fake_post(url: str, data: str | None = None, headers: Any = None, timeout: Any = None) -> requests.Response:
        body = json.loads(data or "{}")
        methods.append(body["method"])
        if body["method"] == "eth_chainId":
            result: Any = hex(chain_id)
        elif body["method"] == "eth_getCode":
            result = code
        elif body["method"] == "eth_call":
            result = "0x" + "00" * 12 + (local[2:].lower() if echo else "11" * 20)
        else:
            raise AssertionError(body["method"])
        r = requests.Response()
        r.status_code = 200
        r._content = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        return r

    return fake_post, methods


def test_remote_plaintext_rpc_is_refused_before_any_request() -> None:
    post, methods = _rpc()
    with mock.patch.object(wallet.requests, "post", post):
        with pytest.raises(InsecureTransportError):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="http://rpc.attacker.example:8545")
    assert methods == []


def test_wrong_chain_is_refused_even_when_the_rpc_echoes_the_address() -> None:
    post, methods = _rpc(chain_id=1)
    with mock.patch.object(wallet.requests, "post", post):
        with pytest.raises(wallet.WalletPredictionError, match="chain"):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")
    assert "eth_call" not in methods


@pytest.mark.parametrize("code", ["0x", "0x0", "", None])
def test_codeless_factory_is_refused(code: Any) -> None:
    post, _ = _rpc(code=code)
    with mock.patch.object(wallet.requests, "post", post):
        with pytest.raises(wallet.WalletPredictionError, match="no code"):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")


def test_mismatch_still_refused() -> None:
    post, _ = _rpc(echo=False)
    with mock.patch.object(wallet.requests, "post", post):
        with pytest.raises(wallet.WalletPredictionError, match="do not fund"):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")


def test_happy_path_checks_chain_then_code_then_prediction() -> None:
    post, methods = _rpc()
    with mock.patch.object(wallet.requests, "post", post):
        assert wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example") == \
            wallet.predict_wallet_address(UID)
    assert methods == ["eth_chainId", "eth_getCode", "eth_call"]


def test_expected_chain_defaults_to_the_artifact_and_is_overridable() -> None:
    post, _ = _rpc(chain_id=31337)
    with mock.patch.object(wallet.requests, "post", post):
        with pytest.raises(wallet.WalletPredictionError, match=str(_contract.chain_id())):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="http://127.0.0.1:8545")
        assert wallet.verify_wallet_address_on_chain(UID, rpc_url="http://127.0.0.1:8545", chain_id=31337)
