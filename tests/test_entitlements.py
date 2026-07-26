"""DEVX-S2 / F3 — entitlement capabilities (Python parity with JS; same answers)."""
from __future__ import annotations

from citrate_sdk.entitlements import (
    DEFAULT_CAPABILITIES,
    TIERS,
    can,
    capabilities,
    normalize_tier,
)


def test_normalize_tier_passthrough_and_failsafe():
    for t in TIERS:
        assert normalize_tier(t) == t
    assert normalize_tier("totally-made-up") == "public"
    assert normalize_tier(None) == "public"
    assert normalize_tier(42) == "public"
    assert normalize_tier({"tier": "confidential"}) == "public"


def test_commercial_kyc_opens_tx_not_content():
    caps = capabilities("commercial.kyc")
    assert caps.ecosystem_tx is True
    assert caps.gateway_keys is True
    assert caps.confidential_docs is False
    assert caps.academic_data is False


def test_commercial_kyc_equals_commercial_no_ordinal():
    assert capabilities("commercial.kyc") == capabilities("commercial")


def test_only_confidential_unlocks_confidential_docs():
    assert DEFAULT_CAPABILITIES["confidential"].confidential_docs is True
    assert DEFAULT_CAPABILITIES["academic"].confidential_docs is False
    assert DEFAULT_CAPABILITIES["public"].confidential_docs is False


def test_can_role_bypass_and_expiry():
    assert can({"tier": "public"}, "confidential_docs") is False
    assert can({"tier": "public", "citrateRole": "auditor"}, "confidential_docs") is True
    assert can({"tier": "confidential", "expiresAt": 1000}, "confidential_docs", now_ms=2000) is False
    assert can(None, "ecosystem_tx") is False
