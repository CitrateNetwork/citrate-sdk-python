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


def test_can_role_does_not_escalate_and_expiry():
    # RC-8 (SPY-B-002): the old fixture asserted `citrateRole` alone granted
    # confidential_docs (`... is True`) — it encoded the over-broad grant as the
    # expected behaviour. A truthy-but-unauthorized role must NOT escalate;
    # capabilities fall back to the tier, the same fail-safe `normalize_tier`
    # applies to unknown tiers. `citrateRole` at the authority only exempts a
    # principal from the consumer-KYC downgrade (citrate-identity
    # resolveEntitlementClaim); it never itself confers confidential access.
    assert can({"tier": "public"}, "confidential_docs") is False
    assert can({"tier": "public", "citrateRole": "auditor"}, "confidential_docs") is False
    assert can({"tier": "confidential", "expiresAt": 1000}, "confidential_docs", now_ms=2000) is False
    assert can(None, "ecosystem_tx") is False


def test_unknown_role_does_not_escalate():
    """Mirror of the unknown-tier fail-safe: a truthy but non-allowlisted
    `citrateRole` grants nothing beyond the tier (SPY-B-002 tripwire)."""
    assert can({"tier": "public", "citrateRole": "viewer"}, "confidential_docs") is False
    assert can({"tier": "public", "citrateRole": "intern"}, "confidential_docs") is False
    assert can({"tier": "nonsense", "citrateRole": "x"}, "confidential_docs") is False
    # Legitimate tier-based access is preserved end-to-end:
    assert can({"tier": "confidential"}, "confidential_docs") is True
    assert can({"tier": "confidential", "citrateRole": "auditor"}, "confidential_docs") is True


def test_capability_matrix_role_never_adds_a_capability():
    """Structural tripwire over the whole (tier x role x capability) matrix:
    a `citrateRole` never adds a capability the principal's tier lacks, and no
    sub-confidential tier ever yields confidential_docs — with or without a role.
    This is the single assertion that would have caught SPY-B-002."""
    caps_attrs = ("ecosystem_tx", "gateway_keys", "academic_data", "confidential_docs")
    roles = ("viewer", "intern", "auditor", "admin", "exec", "x", "")
    for tier in TIERS:
        base = capabilities(tier)
        for role in roles:
            claim = {"tier": tier, "citrateRole": role} if role else {"tier": tier}
            for cap in caps_attrs:
                assert can(claim, cap) == getattr(base, cap), (tier, role, cap)
    for tier in ("public", "commercial", "commercial.kyc", "academic"):
        assert can({"tier": tier}, "confidential_docs") is False
        assert can({"tier": tier, "citrateRole": "auditor"}, "confidential_docs") is False
