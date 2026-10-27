"""r1006 address book + genesis guard.

r1005 and r1006 share chain id 40204, so the SPY-B-005 / PBA-L6b-042 chain-id pins cannot
tell them apart. The vendored artifact is the r1006 book (citrate-chain
``contracts/addresses/r1006/40204.json`` via citrate-federation gen-contract) and carries the
r1006 block-0 hash (``R1006_GENESIS`` in citrate-chain core/consensus/src/hardening.rs). Every
write path and the on-chain wallet verification read block 0 first and refuse another network.
"""
from __future__ import annotations

import json
from typing import Any
from unittest import mock

import pytest
import requests

from citrate_sdk import CitrateClient
from citrate_sdk._generated import contract
from citrate_sdk.compute import ComputeManager
from citrate_sdk.errors import CitrateError, ConfigurationError, WrongNetworkError
from citrate_sdk.identity import wallet
from citrate_sdk.learning import StakingManager

R1006 = "0xa3651a272fe411948cbb4cf7cca4cee44be4248d32ab4376cea7636821c6cdd4"
R1005 = "0x1dcfc4909dd9fdcb0f03c823d627e4b2032cc86bef5fc4561030d6c64b9775f1"
KEY = "0x" + "11" * 32
ACCT = "0x" + "01" * 20
ADDRS = dict.fromkeys(("computePool", "disputeResolution"), "0x" + "02" * 20)


# ── the vendored book ────────────────────────────────────────────────────────

def test_artifact_carries_the_r1006_genesis() -> None:
    assert contract.genesis_hash() == R1006


def test_book_points_at_r1006_contracts() -> None:
    aa = contract.aa_stack()
    assert aa["CitrateWalletFactory"].lower() == "0x6ee3b59099c9c812cdf1c9e7e6ff166b2558434c"
    assert aa["CitratePaymaster"].lower() == "0x5a1e2d73f8154a01a78b56e551c977cb8327ff56"
    assert contract.contracts()["ComputeMarketplace"].lower() == "0x2fec2ac1dde3a1a749c84d487738904cd2ed50c2"


def test_book_drops_contracts_not_in_r1006_block_0() -> None:
    names = contract.contracts()
    for gone in ("LiquidStakingPool", "CitAgentTimelock", "DefensePrimeComplianceRegistry", "TenantHierarchy"):
        assert gone not in names


def test_staking_manager_says_liquid_staking_is_not_in_r1006() -> None:
    with pytest.raises(ConfigurationError, match="not in the r1006 address book"):
        StakingManager(_manager_rpc(R1006)[0], default_account=ACCT).deposit("1")


def test_no_r1005_address_leaks() -> None:
    blob = json.dumps(contract.federation_contract()).lower()
    for dead in ("0x9ac05ad6", "0x804a8021", "0xf8ad11f6", "0xa93f7f68", "0x73270e98", "0xa96a891b"):
        assert dead not in blob, dead


# ── CitrateClient ────────────────────────────────────────────────────────────

def _client(genesis: Any, **kw: Any) -> tuple[CitrateClient, list[str]]:
    c = CitrateClient("http://127.0.0.1:8545", private_key=KEY, **kw)
    methods: list[str] = []

    def rpc(method: str, params: Any = None) -> Any:
        methods.append(method)
        if method == "eth_getBlockByNumber":
            if isinstance(genesis, Exception):
                raise genesis
            return None if genesis is None else {"number": "0x0", "hash": genesis}
        if method == "eth_chainId":
            return hex(40204)
        if method == "eth_getTransactionCount":
            return "0x0"
        return "0x" + "ab" * 32

    c._rpc_call = rpc  # type: ignore[method-assign]
    return c, methods


def test_client_refuses_an_r1005_node_naming_both_hashes() -> None:
    c, _ = _client(R1005)
    with pytest.raises(WrongNetworkError) as e:
        c.verify_network()
    assert R1005 in str(e.value) and R1006 in str(e.value)
    assert e.value.error_code == "WRONG_NETWORK"
    assert isinstance(e.value, CitrateError)


def test_client_accepts_r1006_in_any_case_and_checks_once() -> None:
    c, methods = _client(R1006.upper().replace("0X", "0x"))
    c.verify_network()
    c.verify_network()
    assert methods.count("eth_getBlockByNumber") == 1


@pytest.mark.parametrize("genesis", [None, "", CitrateError("Network error: down")])
def test_client_fails_closed_without_block_0(genesis: Any) -> None:
    c, _ = _client(genesis)
    with pytest.raises(WrongNetworkError):
        c.verify_network()


def test_client_failure_is_not_cached() -> None:
    c, methods = _client(R1005)
    for _ in range(2):
        with pytest.raises(WrongNetworkError):
            c.verify_network()
    assert methods.count("eth_getBlockByNumber") == 2


def test_client_send_refuses_before_signing_on_another_network() -> None:
    c, methods = _client(R1005)
    with pytest.raises(WrongNetworkError):
        c._send_transaction("0x" + "00" * 19 + "01", {"x": 1})
    assert "eth_sendRawTransaction" not in methods


def test_client_send_goes_through_on_r1006() -> None:
    c, methods = _client(R1006)
    c._send_transaction("0x" + "00" * 19 + "01", {"x": 1})
    assert "eth_sendRawTransaction" in methods


def test_client_override_and_opt_out() -> None:
    off, methods = _client(R1005, expected_genesis_hash=None)
    off.verify_network()
    assert "eth_getBlockByNumber" not in methods
    pinned, _ = _client(R1005, expected_genesis_hash=R1005)
    pinned.verify_network()
    dev, dev_methods = _client(R1005, chain_id=31337)
    dev.verify_network()
    assert "eth_getBlockByNumber" not in dev_methods
    with pytest.raises(CitrateError, match="expected_genesis_hash"):
        CitrateClient("http://127.0.0.1:8545", expected_genesis_hash="0x12")


# ── node-signed manager writes (pinned_send) ─────────────────────────────────

def _manager_rpc(genesis: str) -> tuple[Any, list[str]]:
    methods: list[str] = []

    def rpc(method: str, params: Any) -> Any:
        methods.append(method)
        if method == "eth_chainId":
            return hex(40204)
        if method == "eth_getBlockByNumber":
            return {"hash": genesis}
        return "0xhash"

    return rpc, methods


def test_manager_write_refuses_an_r1005_node_before_sending() -> None:
    rpc, methods = _manager_rpc(R1005)
    with pytest.raises(WrongNetworkError):
        ComputeManager(rpc, default_account=ACCT, contract_addresses=ADDRS).heartbeat()
    assert "eth_sendTransaction" not in methods


def test_manager_write_sends_on_r1006_and_checks_once() -> None:
    rpc, methods = _manager_rpc(R1006)
    mgr = ComputeManager(rpc, default_account=ACCT, contract_addresses=ADDRS)
    mgr.heartbeat()
    mgr.heartbeat()
    assert methods.count("eth_getBlockByNumber") == 1 and methods.count("eth_sendTransaction") == 2


def test_manager_override_and_opt_out() -> None:
    rpc, methods = _manager_rpc(R1005)
    ComputeManager(rpc, default_account=ACCT, contract_addresses=ADDRS, expected_genesis_hash=None).heartbeat()
    assert "eth_getBlockByNumber" not in methods
    rpc2, _ = _manager_rpc(R1005)
    ComputeManager(rpc2, default_account=ACCT, contract_addresses=ADDRS, expected_genesis_hash=R1005).heartbeat()


# ── verify_wallet_address_on_chain ───────────────────────────────────────────

UID = "0x" + "42" * 32


def _wallet_post(genesis: str) -> Any:
    local = wallet.predict_wallet_address(UID)

    def fake_post(url: str, data: str | None = None, headers: Any = None, timeout: Any = None) -> requests.Response:
        body = json.loads(data or "{}")
        m = body["method"]
        result: Any = {
            "eth_chainId": hex(40204),
            "eth_getBlockByNumber": {"hash": genesis},
            "eth_getCode": "0x6080",
            "eth_call": "0x" + "00" * 12 + local[2:].lower(),
        }[m]
        r = requests.Response()
        r.status_code = 200
        r._content = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
        return r

    return fake_post


def test_wallet_verify_refuses_an_r1005_node() -> None:
    with mock.patch.object(wallet.requests, "post", _wallet_post(R1005)):
        with pytest.raises(WrongNetworkError):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")


def test_wallet_verify_passes_on_r1006() -> None:
    with mock.patch.object(wallet.requests, "post", _wallet_post(R1006)):
        assert wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example") == \
            wallet.predict_wallet_address(UID)
