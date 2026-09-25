# Changelog

All notable changes to `citrate-labs-sdk` are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [0.6.3] - 2026-09-25 — Hardening

### Changed

- `deploy_model` serialises the transaction payload once, runs the key-share
  guard on the parsed form of those exact bytes, and sends the same bytes.
  `_send_transaction` accepts an already-serialised JSON payload.

### Tests

- A differential property test runs the share guard against the strict share
  parser and other known hex decoders over generated near-hex input.

## [0.6.2] - 2026-09-25 — Pre-bounty audit remediation (SECURITY)

> **Security advisory: upgrade from 0.6.0 (and any unreleased 0.6.1 build).**
> `CitrateClient.deploy_model` with `encrypted=True` and
> `EncryptionConfig(threshold_shares > 0)` wrote **every Shamir share of the
> model AES key** into the public deploy calldata (`encryption_metadata.key_shares`).
> Anyone reading the chain could rebuild the key and decrypt the uploaded model
> with no private key (PBA-L6b-003, CRITICAL; same design flaw as the JS SDK's
> PBA-L4-001). Models deployed that way should be treated as disclosed: rotate
> (re-encrypt under a new key) and redeploy. Deploys with `threshold_shares=0`
> (the default) were not affected. 0.6.0 is to be yanked on PyPI.

### Security

- **PBA-L6b-003 (CRITICAL):** key shares never enter metadata or calldata.
  `encrypt_model` refuses `threshold_shares > 0`; the new
  `KeyManager.encrypt_model_with_key_shares` requires
  `EncryptionConfig.share_holder_public_keys` (one distinct secp256k1 key per
  share), ECDH-wraps each share to its holder (V2 envelope) and returns the
  envelopes separately. `deploy_model` returns them on
  `ModelDeployment.key_share_envelopes` for **off-chain** delivery; holders open
  theirs with `KeyManager.unwrap_key_share(envelope, owner_public_key)`.
  `deploy_model` also refuses any payload that carries a key-share field.
  Tripwires: a calldata decoder asserts no subset of the deploy calldata
  rebuilds the key, in the test suite and against the built wheel in CI and in
  the publish workflow.
- Shamir hardening (variant of the JS PBA-L4-005): every share is validated
  (integer x in 1..255, distinct, equal non-empty y);
  `reconstruct_key_from_shares(shares, threshold)` takes the threshold from the
  caller; `verify_shares` now checks consistency.
- **PBA-L6b-026:** the transport gate refused plain remote `http://` but passed
  `"\u00a0http://..."` (empty parsed scheme). It now refuses whitespace and
  control characters anywhere, allows only https/http, and refuses an empty
  scheme or host.
- **PBA-L6b-027:** `verify_wallet_address_on_chain` goes through the transport
  gate, asserts `eth_chainId`, and requires factory code.
- **PBA-L6b-028:** the default classroom invite code is
  `secrets.token_urlsafe(16)` (was a millisecond timestamp); it is available as
  `ClassroomManager.last_invite_code`.
- **PBA-L6b-029:** `verify_id_token` requires numeric `exp` and `iat` and
  refuses a `typ` other than `JWT`.
- **PBA-L6b-030:** IPFS downloads stream under `max_bytes` (default 1 GiB) and
  verify `expected_sha256` and self-describing CIDs.
- **PBA-L6b-042:** manager writes assert `eth_chainId` against the pinned chain.

- **Verifier follow-ups (still 0.6.2, unreleased):**
  - Transport-gate hardening: characters outside RFC 3986 and userinfo are
    refused, and the gate checks the same host the HTTP stack connects to
    (PBA-L6b-026 / PBA-L6b-027).
  - IPFS downloads of CIDs that cannot verify their own content need
    `expected_sha256`, or an explicit `verify=False`, which logs a warning
    (PBA-L6b-030).
  - `threshold_shares=1` needs `allow_single_holder_recovery=True`.
  - The deploy guard also refuses values shaped like shares, not only the
    known field names.

- **Round 3 (still 0.6.2, unreleased):**
  - `ClassroomManager` now follows the invite-key flow of ClassroomRegistry
    (citrate-chain #222). `create()` and `rotate_invite_code()` return the
    invite secret in `last_invite_code`. `enroll_with_invite(secret)` signs
    the enrolment. `enroll()` is deprecated.
  - `verify_id_token` refuses an `iat` beyond the clock tolerance in the
    future (parity with the JS SDK).
  - The share guard matches only share-shaped values (x in 1..255 and a y of
    at least 16 bytes), so coordinate-like metadata is no longer refused.

### Changed (breaking)

- `IdentityClient.refresh(refresh_token, expected_sub)`: `expected_sub` is
  required; a refreshed token naming another `sub` is refused.
- `IdentityClient.siwe_challenge()` takes no argument and returns `{"nonce"}`
  (GET, as the authority serves it); build the message with
  `build_siwe_message(...)`. `siwe_verify` returns
  `{"kind": "redirect" | "token", ...}` (the authority never returned the
  access/refresh tokens the old client expected).
- `reconstruct_key_from_shares(shares, threshold)`: threshold is required.
- Endpoint URLs with credentials (`user:pass@host`) or non-RFC-3986
  characters are refused; pass credentials as headers.
- `download_bytes("Qm...")` without `expected_sha256` raises unless
  `verify=False`.
- Unknown `access` / `tier` / `mode` strings raise `ValueError` (PBA-L6b-031)
  instead of silently becoming option 0.

### Fixed

- **PBA-L6b-040:** `ClassroomManager.enroll` encodes `enrollWithCode(bytes)`
  (the contract hashes the raw code); `get_classroom` decodes the struct
  return. A parity test pins every ClassroomRegistry selector.
- **PBA-L6b-041:** `uv.lock` regenerated (cryptography 50.0.1) and checked in
  CI with `uv lock --check`.

## [0.6.1] - 2026-08-02 (never published) — SECREM-02 K3 envelope hardening

**Package metadata (2026-09-24):** Repository, Bug Tracker and Changelog now point at
`github.com/CitrateNetwork/citrate-sdk-python`. The published 0.6.0 pointed at a private
pre-split repo that 404s for the public.

**0.6.0 is YANKED.** It shipped with seven SECREM-02 K3 security tripwires
failing. They were committed red-first (`ac3bfc1`, marked `wip`) and the
implementation never followed; the release went out 33 days later. Details and
proof-of-concept are held in an internal security audit.

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
