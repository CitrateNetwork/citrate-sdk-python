"""Typed accessor over the vendored federation contract artifact (DEVX-S0, ADR-0001).

The single source of truth for chain addresses, chainId, endpoints, and the
entitlement tier vocabulary. Do NOT hand-edit ``federation_contract.json`` — it is
synced from ``citrate-federation/contract/federation-contract.json`` via
``python scripts/sync_contract.py``, which is generated from
``citrate-chain/contracts/addresses/40204.json`` + ``citrate-identity``.
"""
from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
from typing import Any

_ARTIFACT = Path(__file__).with_name("federation_contract.json")


@lru_cache(maxsize=1)
def federation_contract() -> dict[str, Any]:
    """Return the full contract artifact as a dict."""
    return json.loads(_ARTIFACT.read_text(encoding="utf-8"))


def chain_id() -> int:
    return int(federation_contract()["chain"]["chainId"])


def rpc_url() -> str:
    return str(federation_contract()["chain"]["rpcUrl"])


def ws_url() -> str:
    return str(federation_contract()["chain"]["wsUrl"])


def aa_stack() -> dict[str, str]:
    """ERC-4337 account-abstraction stack addresses (EntryPoint, factory, paymaster, …)."""
    return dict(federation_contract()["aaStack"])


def contracts() -> dict[str, str]:
    return dict(federation_contract()["contracts"])


def membership() -> dict[str, Any]:
    return dict(federation_contract()["membership"])


def precompiles() -> dict[str, str]:
    return dict(federation_contract()["precompiles"])


def identity() -> dict[str, Any]:
    """OIDC issuer/discovery/jwks/scopes + the entitlement claim URI."""
    return dict(federation_contract()["identity"])


def gateway() -> dict[str, str]:
    return dict(federation_contract()["gateway"])


def entitlement_tiers() -> list[str]:
    return list(federation_contract()["entitlements"]["tiers"])


def kyc_baseline_tier() -> str:
    return str(federation_contract()["entitlements"]["kycBaselineTier"])
