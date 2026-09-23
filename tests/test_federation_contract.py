"""DEVX-S0 / F1 — the vendored federation contract pins the on-chain-verified truth."""
from __future__ import annotations

from citrate_sdk._generated import contract


def test_chain_id_is_40204():
    assert contract.chain_id() == 40204
    assert contract.rpc_url() == "https://rpc.citrate.ai"
    assert contract.ws_url() == "wss://rpc.citrate.ai/ws"


def test_aa_stack_pins_the_live_addresses():
    aa = contract.aa_stack()
    assert aa["EntryPoint"].lower() == "0x97d5391a647429233e202f99231743c53a648f3c"
    assert aa["CitrateWalletFactory"].lower() == "0x86486d1de9f256e2cba327c46ac11120df0aa51a"
    assert aa["CitratePaymaster"].lower() == "0xfdc9f7a72163b5d45becdb8a9d8d44b970f77318"


def test_membership_addresses_present():
    m = contract.membership()
    assert m["CitrateMemberSBT"].lower() == "0xf0badd9eed5a81871a2f0d309b1f0a225646448a"
    assert m["MembershipStakeVault"].lower() == "0x53fb4badffaceedd575d47d0e74bb721504f786e"


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
