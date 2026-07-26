"""Entitlement capabilities (DEVX-S2, ADR-0002) — Python parity of the JS module.

Capabilities, NOT a global rank. `normalize_tier` collapses any unknown value to ``public``
and never escalates; `capabilities` returns an explicit set. There is no tier ordering.
`commercial.kyc` opens ecosystem transactions but NOT confidential content (owner's call).
"""
from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Dict, Mapping, Optional

#: The five tiers the authority mints (mirrors citrate-identity TIERS).
TIERS = ("public", "commercial", "commercial.kyc", "academic", "confidential")

# Attribute names are snake_case (Pythonic) but map 1:1 to the JS CapabilitySet:
#   ecosystem_tx<->ecosystemTx, gateway_keys<->gatewayKeys,
#   academic_data<->academicData, confidential_docs<->confidentialDocs


@dataclass(frozen=True)
class CapabilitySet:
    ecosystem_tx: bool = False
    gateway_keys: bool = False
    academic_data: bool = False
    confidential_docs: bool = False


DEFAULT_CAPABILITIES: Dict[str, CapabilitySet] = {
    "public": CapabilitySet(),
    "commercial": CapabilitySet(ecosystem_tx=True, gateway_keys=True),
    # NOT "above" commercial — same content capabilities; the distinction is KYC-verified baseline.
    "commercial.kyc": CapabilitySet(ecosystem_tx=True, gateway_keys=True),
    "academic": CapabilitySet(ecosystem_tx=True, gateway_keys=True, academic_data=True),
    "confidential": CapabilitySet(True, True, True, True),
}

_TIER_SET = set(TIERS)


def normalize_tier(value: object) -> str:
    """Fail-safe: unknown/garbage/non-str collapses to ``public``. Never escalates."""
    return value if isinstance(value, str) and value in _TIER_SET else "public"


def capabilities(tier: object, overrides: Optional[Mapping[str, CapabilitySet]] = None) -> CapabilitySet:
    t = normalize_tier(tier)
    if overrides and t in overrides:
        return overrides[t]
    return DEFAULT_CAPABILITIES[t]


def can(
    claim: Optional[dict],
    capability: str,
    now_ms: Optional[int] = None,
    overrides: Optional[Mapping[str, CapabilitySet]] = None,
) -> bool:
    """Whether a claim grants a capability, with expiry + role-bypass (matches resolveEntitlementClaim)."""
    if not claim:
        return getattr(DEFAULT_CAPABILITIES["public"], capability)
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    exp = claim.get("expiresAt")
    if isinstance(exp, (int, float)) and exp <= now:
        return getattr(DEFAULT_CAPABILITIES["public"], capability)
    if claim.get("citrateRole"):
        return True
    return getattr(capabilities(claim.get("tier"), overrides), capability)
