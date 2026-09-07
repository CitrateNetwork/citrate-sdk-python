# Changelog

All notable changes to `citrate-labs-sdk` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.6.1] - 2026-08-02 — SECREM-02 K3 envelope hardening

**0.6.0 is YANKED.** It shipped with seven SECREM-02 K3 security tripwires
failing. They were committed red-first (`ac3bfc1`, marked `wip`) and the
implementation never followed; the release went out 33 days later. Details and
proof-of-concept in
`citrate-security/audits/2026-08-02-sdk-python-k3-addendum/`.

### Security

- **`ECDH_SCHEME_V2`** replaces V1 for all new envelopes. V1 derived the
  key-encryption key from a **constant** HKDF salt over the sender's **static**
  identity key, so the KEK was identical for a given (sender, recipient) pair
  forever. V2 mixes a fresh 32-byte `kdf_salt` per envelope, so the KEK is no
  longer **reused or correlatable** across messages to the same recipient.
  **This is NOT forward secrecy (CIT-SDKPY-01).** The ECDH remains
  static-static (the sender's static identity key × the recipient's fixed key),
  and `kdf_salt` ships in the envelope in cleartext — so anyone who compromises
  either static private key re-derives every past and future KEK from the public
  salt and **still decrypts every envelope ever sent to that recipient.** The
  per-message salt prevents KEK reuse; it does not confine a key compromise to a
  single message. Forward secrecy would require an ephemeral per-message key
  (ECIES), which V2 does not use.
- **Both endpoint public keys are now bound into the HKDF `info`.** Previously
  `recipient_public_key` rode in the envelope unauthenticated — a PoC confirmed
  it could be overwritten with `00`×65 and decryption still succeeded with
  identical plaintext. It looked like a control and was not one. Tampering with
  either key field, or with the salt, now changes the derived KEK and the
  AES-GCM unwrap fails its tag check.
- **The legacy cleartext-key envelope is refused on read.** Producing it stopped
  in 2026-06; reading it did not, so the downgrade survived the fix meant to
  close it. An envelope carrying BOTH `wrapped_key` and a cleartext `key` is
  now rejected outright rather than silently preferring the safe field.
- **V1 envelopes are refused.** Fail closed and re-encrypt.
- `verify_model_integrity` uses `hmac.compare_digest` instead of `==`.
- KEKs are zeroized best-effort after use (see `_zeroize` for honest limits).

### Added

- **`decrypt_data(..., expected_sender_public_key=...)`** — pin the sender.
  Static-static ECDH already guarantees the envelope was produced by the holder
  of `sender_public_key`; relabelling someone else's envelope as a trusted
  sender's is refused. What it cannot tell you is whether that key is one you
  trust — anyone may send you a valid envelope under their own key. Pass this
  whenever origin matters.
- **`CitrateClient(timeout=...)`** — the JSON-RPC timeout was hardcoded to 30s
  with no way to change it.

### Fixed

- **`citrate_sdk.__version__` was stuck at `"0.5.0"`.** The published 0.6.0 wheel
  reports itself as 0.5.0 — the 0.5.0 to 0.6.0 bump edited `pyproject.toml` and
  nothing else, so every runtime version check against the published package got
  an answer a full release stale. `pip show` and `importlib.metadata` read
  pyproject while application code reads `__version__`, so the two only
  disagreed where nobody was looking. Now pinned together by a test.
- **`list_models()` returned the raw RPC dict** `{"models": [...]}` despite
  being annotated `-> List[Dict]`. `for m in client.list_models()` iterated
  **dict keys** and yielded the string `"models"` — no exception, silently
  wrong. It now unwraps.
- Nine long-broken tests repaired rather than left red: `test_get_public_key`
  asserted a pre-SEC1 32-byte key; three tests called `sign_message`, which does
  not exist; the timeout test set `session.timeout`, which `requests` ignores;
  four balance tests asserted Anvil devnet funding against chain 40204 and now
  skip unless the account is actually funded. A suite where nine failures are
  expected noise is a suite nobody reads, which is how seven real ones survived
  a release.

### BREAKING

- Envelopes produced before 0.6.1 (V1 or legacy) can no longer be decrypted.
  Nothing that was ever confidential is lost: legacy envelopes shipped their key
  in public calldata, and V1 envelopes remain readable by anyone who compromises
  the sender's static key. **Re-encrypt.**

## [0.6.0] - 2026-07-26 — DevX Convergence

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
