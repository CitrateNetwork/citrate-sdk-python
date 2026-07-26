"""DEVX-S0 / F1 — the vendored federation contract pins the on-chain-verified truth."""
from __future__ import annotations

from citrate_sdk._generated import contract


def test_chain_id_is_40204():
    assert contract.chain_id() == 40204
    assert contract.rpc_url() == "https://rpc.citrate.ai"
    assert contract.ws_url() == "wss://rpc.citrate.ai/ws"


def test_aa_stack_pins_the_live_07_23_addresses():
    aa = contract.aa_stack()
    assert aa["EntryPoint"].lower() == "0xc698feaf0ff7fdb0d60e2f620c97cb729a694975"
    assert aa["CitrateWalletFactory"].lower() == "0xc9c7b3d3fe28012ab5f2583a4f58531e9f26d3f5"
    assert aa["CitratePaymaster"].lower() == "0x0cd122ace90084afb26d5101074af15aaccc1c0e"


def test_membership_addresses_present():
    m = contract.membership()
    assert m["CitrateMemberSBT"] == "0x4CE39F891c0A519Fa0E0De97A1DD3e3f856e0cF1"
    assert m["MembershipStakeVault"] == "0x61E324cFd6B7Cb106AC0AD1dF163bdFef2b74268"


def test_entitlement_vocabulary():
    assert contract.entitlement_tiers() == [
        "public", "commercial", "commercial.kyc", "academic", "confidential",
    ]
    assert contract.kyc_baseline_tier() == "commercial.kyc"


def test_identity_and_gateway_endpoints():
    idn = contract.identity()
    assert idn["issuer"] == "https://auth.citrate.ai"
    assert idn["entitlementClaim"] == "https://citrate.ai/entitlement"
    assert "wallet" in idn["scopes"] and "kyc" in idn["scopes"]
    assert contract.gateway()["baseUrl"] == "https://infer.citrate.ai"


def test_no_dead_dcp1_addresses_leak():
    import json
    blob = json.dumps(contract.federation_contract()).lower()
    for dead in ("0x5a45b6f8", "0xf14f56e8", "0x149e85a3", "0x0aceb7b4"):
        assert dead not in blob, f"stale D-CP-1 address {dead} leaked into the artifact"
