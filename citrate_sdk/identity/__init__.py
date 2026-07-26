"""citrate_sdk.identity (DEVX-S1) — the Citrate authorization spine + embedded wallet.

OIDC PKCE + SIWE, hardened ID-token verification, wallet address prediction (verified against
the on-chain factory, never the authority), userinfo → normalized entitlement capabilities.
"""
from ..entitlements import (
    DEFAULT_CAPABILITIES,
    TIERS,
    CapabilitySet,
    can,
    capabilities,
    normalize_tier,
)
from .client import IdentityClient, IdentityError, TokenSet, UserInfo
from .jwt import IdTokenError, verify_id_token
from .pkce import Pkce, challenge_from_verifier, create_pkce, generate_verifier
from .wallet import (
    WalletPredictionError,
    address_to_user_id,
    predict_wallet_address,
    uuid_to_user_id,
    verify_wallet_address_on_chain,
)

__all__ = [
    "predict_wallet_address", "verify_wallet_address_on_chain", "uuid_to_user_id",
    "address_to_user_id", "WalletPredictionError",
    "create_pkce", "generate_verifier", "challenge_from_verifier", "Pkce",
    "verify_id_token", "IdTokenError",
    "IdentityClient", "IdentityError", "TokenSet", "UserInfo",
    "normalize_tier", "capabilities", "can", "CapabilitySet", "DEFAULT_CAPABILITIES", "TIERS",
]
