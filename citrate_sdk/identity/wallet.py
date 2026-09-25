"""Embedded smart-account wallet (DEVX-S1) — Python parity of the JS module.

Prediction mirrors Solady ``LibClone::predictDeterministicAddressERC1967`` — the exact scheme
``CitrateWalletFactory.predictAddress`` uses on-chain and the Rust ``wallet-aa`` crate replicates.
Inputs come from the federation contract artifact (DEVX-S0).

SECURITY (handoffs/IDENTITY_AA_ADDRESS_DRIFT_2026-07-25.md): do NOT trust the authority's
``/aa/address`` — compute locally and verify against the on-chain factory. The factory is the
only ground truth.
"""
from __future__ import annotations

import json
from typing import Any

import requests
from eth_utils import keccak, to_checksum_address

from .._generated import contract as _contract
from .._url_security import enforce_transport_security

_PREFIX = bytes.fromhex("603d3d8160223d3973")
_SEP = bytes.fromhex("6009")
_BODY = bytes.fromhex("5155f3363d3d373d3d363d7f360894a13ba1a3210667c828492db98dca3e2076")
_TAIL = bytes.fromhex("cc3735a920a3ca505d382bbc545af43d6000803e6038573d6000fd5b3d6000f3")
_ZERO = "0x" + "00" * 20


class WalletPredictionError(Exception):
    pass


def _addr_bytes(a: str) -> bytes:
    return bytes.fromhex(to_checksum_address(a)[2:])


def uuid_to_user_id(uuid: str) -> str:
    """keccak256(utf8(lowercase(uuid))) — matches the authority's wallet-claims.ts."""
    return "0x" + keccak(uuid.lower().encode("utf-8")).hex()


def address_to_user_id(address: str) -> str:
    """Left-pad a 20-byte EOA to a 32-byte AA userId (SIWE-keyed principals)."""
    return "0x" + "00" * 12 + to_checksum_address(address)[2:].lower()


def _erc1967_init_code_hash(implementation: str) -> bytes:
    if to_checksum_address(implementation) == to_checksum_address(_ZERO):
        raise WalletPredictionError("implementation cannot be the zero address")
    return keccak(_PREFIX + _addr_bytes(implementation) + _SEP + _BODY + _TAIL)


def predict_wallet_address(
    user_id: str, factory: str | None = None, implementation: str | None = None
) -> str:
    """Predict the counterfactual smart-wallet address for a userId. Pure + offline."""
    if not (isinstance(user_id, str) and user_id.startswith("0x") and len(user_id) == 66):
        raise WalletPredictionError("userId must be a 0x-prefixed 32-byte hex string")
    aa = _contract.aa_stack()
    f = factory or aa["CitrateWalletFactory"]
    impl = implementation or aa["CitrateWallet"]
    if to_checksum_address(f) == to_checksum_address(_ZERO):
        raise WalletPredictionError("factory cannot be the zero address")
    salt = keccak(bytes.fromhex(user_id[2:]))
    init_hash = _erc1967_init_code_hash(impl)
    packed = b"\xff" + _addr_bytes(f) + salt + init_hash
    return to_checksum_address(keccak(packed)[-20:])


def _rpc(url: str, method: str, params: list[Any], timeout: float) -> Any:
    payload = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    resp = requests.post(url, data=json.dumps(payload),
                         headers={"content-type": "application/json"}, timeout=timeout)
    resp.raise_for_status()
    body = resp.json()
    if not isinstance(body, dict) or "error" in body:
        raise WalletPredictionError(f"{method} failed: {body.get('error') if isinstance(body, dict) else body!r}")
    return body.get("result")


def verify_wallet_address_on_chain(
    user_id: str,
    rpc_url: str | None = None,
    factory: str | None = None,
    implementation: str | None = None,
    timeout: float = 10.0,
    *,
    chain_id: int | None = None,
    allow_insecure_http: bool = False,
) -> str:
    """Verify the local prediction against the on-chain factory (ground truth).

    The factory is the deployer, so its own ``predictAddress`` view is authoritative — this is
    the check that would have caught the 2026-07-25 stale-authority bug. Raises on mismatch.

    PBA-L6b-027: the RPC is only as trustworthy as the path to it. The URL goes
    through the transport gate (remote plaintext refused unless
    ``allow_insecure_http``), ``eth_chainId`` must equal ``chain_id`` (default:
    the pinned federation chain), and the factory must have code there — so a
    MITM or a wrong-chain RPC cannot make "verified" pass by echoing the
    publicly computable prediction.
    """
    local = predict_wallet_address(user_id, factory=factory, implementation=implementation)
    aa = _contract.aa_stack()
    f = factory or aa["CitrateWalletFactory"]
    url = enforce_transport_security(rpc_url or _contract.rpc_url(), allow_insecure_http=allow_insecure_http)
    expected_chain = int(chain_id) if chain_id is not None else _contract.chain_id()

    reported = _rpc(url, "eth_chainId", [], timeout)
    try:
        reported_chain = int(str(reported), 16)
    except ValueError:
        raise WalletPredictionError(f"eth_chainId returned {reported!r}")
    if reported_chain != expected_chain:
        raise WalletPredictionError(
            f"RPC is on chain {reported_chain}, expected chain {expected_chain} — refusing to verify"
        )

    code = _rpc(url, "eth_getCode", [f, "latest"], timeout)
    if not isinstance(code, str) or code.lower() in ("", "0x", "0x0"):
        raise WalletPredictionError(f"factory {f} has no code on chain {expected_chain} — refusing to verify")

    selector = keccak(b"predictAddress(bytes32)")[:4].hex()
    data = "0x" + selector + user_id[2:]
    result = _rpc(url, "eth_call", [{"to": f, "data": data}, "latest"], timeout)
    if not isinstance(result, str) or len(result) < 66:
        raise WalletPredictionError("factory predictAddress returned no address")
    onchain = to_checksum_address("0x" + result[-40:])
    if onchain != local:
        raise WalletPredictionError(
            f"wallet address mismatch: local {local} != on-chain factory {onchain} — do not fund this address"
        )
    return local
