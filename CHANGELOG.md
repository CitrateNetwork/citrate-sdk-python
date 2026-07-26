# Changelog

All notable changes to `citrate-ai-sdk` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased] — DevX Convergence (2026-07-25)

### Added
- **Federation contract artifact** (`citrate_sdk._generated.contract`): the single source of
  truth for chain addresses, chainId, endpoints, and the entitlement tier vocabulary, vendored
  from the generated `federation-contract.json` and drift-gated (`scripts/sync_contract.py`).
- **Identity spine + embedded wallet** (`citrate_sdk.identity`): OIDC PKCE + SIWE, hardened
  `verify_id_token` (RS256; rejects alg:none / alg-confusion / bad aud/iss / expired / tampered),
  `IdentityClient` (discover / authorize / exchange / refresh / userinfo → capabilities / deploy
  permit / guardians / logout), and smart-account address prediction
  (`predict_wallet_address` / `verify_wallet_address_on_chain`) verified byte-for-byte against
  the on-chain factory — never trusting the authority's `/aa/address`.
- **Entitlement capabilities** (`citrate_sdk.entitlements`): canonical `normalize_tier`
  (unknown → public, never escalates) + capability map (`commercial.kyc` opens transactions,
  not content; no global rank).
- **Inference gateway client** (`citrate_sdk.gateway`): OpenAI-compatible over
  `infer.citrate.ai`, `cgk_` bearer, typed 401/402/429/503, fail-closed without a key.
- **Command line** (`citrate`): `contract`, `wallet predict`, `entitlement`, `gateway` — fixes
  the previously-declared-but-missing `citrate_sdk.cli:main` entry point.
- **`py.typed`** marker so type checkers recognize the package's inline types.

### Notes
- All new crypto uses existing dependencies (`eth_utils`, `cryptography`, `requests`) — no new
  runtime dependencies.
- Cross-language parity: address prediction and capability answers match the JavaScript SDK
  (`@citratenetwork/sdk`) exactly.
