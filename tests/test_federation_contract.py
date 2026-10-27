"""DEVX-S0 / F1 — the vendored federation contract pins the r1006 book (genesis 0xa3651a27…).

citrate-chain contracts/addresses/r1006/40204.json (final since a857443e; every contract is in
block 0), via citrate-federation gen-contract.
"""
from __future__ import annotations

from citrate_sdk._generated import contract


def test_chain_id_is_40204():
    assert contract.chain_id() == 40204
    assert contract.rpc_url() == "https://rpc.citrate.ai"
    assert contract.ws_url() == "wss://rpc.citrate.ai/ws"


def test_aa_stack_pins_the_r1006_addresses():
    aa = contract.aa_stack()
    assert aa["EntryPoint"].lower() == "0x97d5391a647429233e202f99231743c53a648f3c"
    assert aa["CitrateWalletFactory"].lower() == "0x6ee3b59099c9c812cdf1c9e7e6ff166b2558434c"
    assert aa["CitratePaymaster"].lower() == "0x5a1e2d73f8154a01a78b56e551c977cb8327ff56"


def test_membership_addresses_present():
    m = contract.membership()
    assert m["CitrateMemberSBT"].lower() == "0x883165132776171fbcfde2d3c789ef5bdb0d060d"
    assert m["MembershipStakeVault"].lower() == "0xd6632ea2179d047d2460f1de90abcc519839555e"


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


def test_no_pre_reroll_addresses_leak():
    """Fresh-keys reroll 2026-09-29 (citrate-chain 0aab474b) retired these."""
    import json
    blob = json.dumps(contract.federation_contract()).lower()
    for dead in ("0xf0badd9e", "0x53fb4bad", "0x2655d9fb", "0xf42a1919"):
        assert dead not in blob, f"pre-reroll address {dead} leaked into the artifact"


def test_no_r0929_addresses_leak():
    """r1005 reroll 2026-10-06 (genesis 0x1dcfc490…, citrate-chain bf551422) retired the 09-29 book."""
    import json
    blob = json.dumps(contract.federation_contract()).lower()
    for dead in ("0xa24aa35f", "0x4c0f8b27", "0xba4abd4f", "0x915fada6", "0xa3512be8", "0x24e2a41e", "0x8e65bff9"):
        assert dead not in blob, f"09-29 address {dead} leaked into the artifact"
