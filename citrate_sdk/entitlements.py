"""Entitlement capabilities (DEVX-S2, ADR-0002) — Python parity of the JS module.

Capabilities, NOT a global rank. `normalize_tier` collapses any unknown value to ``public``
and never escalates; `capabilities` returns an explicit set. There is no tier ordering.
`commercial.kyc` opens ecosystem transactions but NOT confidential content (owner's call).
"""
from __future__ import annotations

import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import cast

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


DEFAULT_CAPABILITIES: dict[str, CapabilitySet] = {
    "public": CapabilitySet(),
    "commercial": CapabilitySet(ecosystem_tx=True, gateway_keys=True),
    # NOT "above" commercial — same content capabilities; the distinction is KYC-verified baseline.
    "commercial.kyc": CapabilitySet(ecosystem_tx=True, gateway_keys=True),
    "academic": CapabilitySet(ecosystem_tx=True, gateway_keys=True, academic_data=True),
    "confidential": CapabilitySet(True, True, True, True),
}

_TIER_SET = set(TIERS)

#: EXPLICIT allowlist of `citrateRole` values that carry capabilities beyond the
#: principal's tier, replacing the blanket ``if claim.get("citrateRole"): return True``
#: bypass that granted EVERY capability — including ``confidential_docs`` — to ANY truthy
#: role (SPY-B-002 / SJS-B-001). A role absent from this map does NOT escalate:
#: capabilities fall back to the tier, the same fail-safe ``normalize_tier`` applies to
#: unknown tiers. The authority's ``resolveEntitlementClaim`` (citrate-identity
#: src/entitlements.ts) uses ``citrateRole`` only to exempt a principal from the
#: consumer-KYC *downgrade*; the tier it returns is what confers capabilities, so a role
#: never itself buys confidential access. The canonical default is therefore empty. A
#: relying party that genuinely elevates a specific role registers it here explicitly.
ROLE_CAPABILITIES: dict[str, CapabilitySet] = {}


def normalize_tier(value: object) -> str:
    """Fail-safe: unknown/garbage/non-str collapses to ``public``. Never escalates."""
    return value if isinstance(value, str) and value in _TIER_SET else "public"


def capabilities(tier: object, overrides: Mapping[str, CapabilitySet] | None = None) -> CapabilitySet:
    t = normalize_tier(tier)
    if overrides and t in overrides:
        return overrides[t]
    return DEFAULT_CAPABILITIES[t]


def capabilities_for_claim(
    claim: dict | None,
    overrides: Mapping[str, CapabilitySet] | None = None,
) -> CapabilitySet:
    """Resolve a claim's capability set WITHOUT the truthiness bypass.

    An allowlisted ``citrateRole`` grants its explicitly declared set; every other
    role (and no role) derives capabilities from the tier — fail-safe, never escalated.
    Expiry is NOT applied here; callers that must honour ``expiresAt`` (see ``can``)
    check it before calling. This is the single resolver both ``can`` and the identity
    spine use so the policy cannot diverge between them.
    """
    if not claim:
        return DEFAULT_CAPABILITIES["public"]
    role = claim.get("citrateRole")
    if isinstance(role, str) and role in ROLE_CAPABILITIES:
        return ROLE_CAPABILITIES[role]
    return capabilities(claim.get("tier"), overrides)


def resolve_capabilities(
    claim: dict | None,
    now_ms: int | None = None,
    overrides: Mapping[str, CapabilitySet] | None = None,
) -> CapabilitySet:
    """Resolve a claim's full capability set, honouring ``expiresAt``.

    This is THE single policy implementation. Both ``can`` and the identity spine
    (``IdentityClient.user_info``) route through it, so the expiry check cannot be
    present on one path and absent on the other (SPY-B-003 / SJS-B-002): an expired
    claim collapses to ``public`` here, once, for every caller. Role escalation is
    still gated by the ``ROLE_CAPABILITIES`` allowlist via ``capabilities_for_claim``.
    """
    if not claim:
        return DEFAULT_CAPABILITIES["public"]
    now = now_ms if now_ms is not None else int(time.time() * 1000)
    exp = claim.get("expiresAt")
    if isinstance(exp, (int, float)) and exp <= now:
        return DEFAULT_CAPABILITIES["public"]
    return capabilities_for_claim(claim, overrides)


def can(
    claim: dict | None,
    capability: str,
    now_ms: int | None = None,
    overrides: Mapping[str, CapabilitySet] | None = None,
) -> bool:
    """Whether a claim grants a capability. Expired claims collapse to ``public``; a
    ``citrateRole`` escalates only if it is in the ``ROLE_CAPABILITIES`` allowlist,
    otherwise capabilities derive from the tier (matches resolveEntitlementClaim, which
    uses the role only to skip the KYC downgrade, never to confer confidential access).

    A thin projection of ``resolve_capabilities`` onto one capability — the same
    resolver the identity spine uses, so the two cannot diverge on expiry."""
    return cast(bool, getattr(resolve_capabilities(claim, now_ms, overrides), capability))
