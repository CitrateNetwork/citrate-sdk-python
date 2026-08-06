# Diagnosis: 17 failing tests in the published 0.6.0

**Date:** 2026-08-02 · **Scope:** `citrate-labs-sdk` 0.6.0, live on PyPI

## Is this actually the published package?

Yes, and it was checked rather than assumed. The 0.6.0 wheel was downloaded from
PyPI, extracted, and compared file-by-file against the working tree:

```
published .py files: 31   local .py files: 31
IDENTICAL: 31   DIFFERENT: 0   only-in-wheel: 0   only-in-local: 0
```

Every failure below is a failure that users of the published package have.

## Summary

`pytest tests/` on clean `main`: **17 failed, 309 passed**.

| Bucket | Count | Is it a product defect? |
|---|---|---|
| SECREM-02 K3 hardening never implemented | 7 | **Yes** |
| `list_models()` return shape contradicts its annotation | 1 | **Yes** |
| Stale tests (code is correct) | 5 | No |
| Local-devnet fixtures run against the real RPC | 4 | No |

**8 product defects, 9 test-suite problems.**

An earlier note in PR #12 said "13 real". That conflated *a failing test* with *a
broken product*. Five of those thirteen are tests that drifted away from correct
code, and calling them defects would misdirect the fix.

---

## 1. SECREM-02 K3: red-first tests, implementation never written (7 failures)

This is the finding that matters, and the git history states it outright:

```
ac3bfc1  2026-06-23  wip(SECREM-02 K3): SEC1 compressed pubkey + KEK zeroize
                     helper + red-first FUA-SDK-PY-01/02/03 tests
3c79821  2026-07-26  release: bump to 0.6.0
         2026-07-27  uploaded to PyPI
```

The tests were committed **red-first**, as the methodology prescribes. The
commit is marked `wip`. The implementation never followed, and **33 days later
the package was released over them.**

So this is neither a regression nor test drift. The tests are correct
specifications of behaviour that was never built, and the release process did not
consult them.

### What did land

`b65ac66` (2026-06-01) is real and works: the symmetric key is ECDH-wrapped to
the recipient and no longer shipped in calldata. That was the serious audit
finding (RM-E / SDK_PYTHON-001) and it is **fixed**.

### What K3 wanted and did not get

| Test | Shipped behaviour | Consequence |
|---|---|---|
| `test_envelope_carries_fresh_kdf_salt` | `ECDH_SCHEME_V1` only; no `ECDH_SCHEME_V2`, no `kdf_salt` | **No forward secrecy** — see below |
| `test_missing_kdf_salt_rejected` | `KeyError: 'kdf_salt'` — the field does not exist | as above |
| `test_kdf_salt_is_load_bearing` | `DID NOT RAISE` | as above |
| `test_legacy_cleartext_key_envelope_rejected` | `decrypt_data` still honours a legacy `"key"` envelope | **Downgrade path** |
| `test_cleartext_key_rejected_even_beside_wrapped_key` | mixed envelope silently prefers `wrapped_key` | no rejection on a malformed envelope |
| `test_envelope_binds_recipient_public_key` | `recipient_public_key` is in the envelope but not authenticated | the field is decorative and can lie |
| `test_verify_model_integrity_uses_constant_time_compare` | `return actual_hash == expected_hash` | **timing side channel** |

### The forward-secrecy point, stated precisely

```python
def derive_shared_key(self, peer_public_key: str) -> bytes:
    return self.ecdh_manager.derive_shared_secret(
        peer_key_bytes,
        salt=b"citrate-model-encryption",   # CONSTANT
        info=b"shared-key-derivation"
    )
```

A **constant** HKDF salt combined with the sender's **static** identity key means
the key-encryption key is identical for a given (sender, recipient) pair for
every envelope, forever.

This is not an immediate break — each envelope still gets a fresh random
`wrap_nonce`, so AES-GCM nonce reuse is avoided. The consequence is narrower and
worth stating exactly: **compromising the sender's static private key once
decrypts every envelope ever sent to that recipient, past and future.** A
per-envelope `kdf_salt` — precisely what the K3 tests demand — is what confines a
key compromise to a single message.

### The legacy-cleartext path

```python
elif "key" in package:
    # Legacy insecure envelope (CITRATE_SDK_PYTHON-001) ...
    key = bytes.fromhex(package["key"])
```

The comment says "read it for back-compat but never produce this form", and the
producing side is indeed clean. The reading side means an attacker who controls
an envelope can present one carrying a key of their choosing and have it
processed. This is an authenticity problem, not a leak of the sender's key.

## 2. `list_models()` contradicts its own type annotation (1 failure)

```python
def list_models(self, ...) -> List[Dict[str, Any]]:
    return self._rpc_call("citrate_listModels", params)   # returns {'models': [...]}
```

The node returns a dict; the annotation promises a list. A caller writing
`for m in client.list_models()` iterates **dict keys** and gets `'models'` — no
exception, just silently wrong. The test asserting a list agrees with the
annotation, so the implementation is the thing that is wrong; it should unwrap
`["models"]`.

## 3. Stale tests — code is correct (5 failures)

- **`test_get_public_key`** expects 64 hex chars; the code returns 66. That is a
  **SEC1 compressed** public key (`02…`), which the same `ac3bfc1` commit
  introduced deliberately. The code is right; the test was never updated.
- **`test_message_signing`**, **`test_different_messages_different_signatures`**,
  **`test_consistent_signing`** all call `KeyManager.sign_message`, which does not
  exist and appears never to have. The method is `sign_transaction`.
- **`test_timeout_error`** sets `slow_client.session.timeout = 0.001`.
  `requests.Session` has no honoured `timeout` attribute — it must be passed
  per-request, and `_rpc_call` already hardcodes `timeout=30`. The test is wrong
  about the library. (Worth noting separately: that 30s is not configurable.)

## 4. Local-devnet fixtures against the real RPC (4 failures)

`test_genesis_account_has_balance`, `test_lowercase_address`,
`test_checksum_address`, `test_can_get_sender_balance` — all `assert 0 > 0`.

They query `0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266` and
`0x70997970C51812dc3A010C7d01b50e0d17dc79C8`, the standard Anvil default
accounts. Confirmed via `cast balance` that both hold zero on chain 40204. These
pass against a local devnet and fail against the real RPC the suite defaults to.

---

## How this survived a release

`NON_CANONICAL.md` records that CI for this repo is `workflow_dispatch`-only,
opt-in. Nothing ran the suite on the way to PyPI. Combined with a work package
left in its red state, that is sufficient explanation: the tripwires fired into
an empty room.

## Recommended order

1. **Finish SECREM-02 K3 or withdraw 0.6.0.** Seven security tripwires red in a
   published package is the item that should not wait. The forward-secrecy gap
   and the timing compare are the concrete ones.
2. **Fix `list_models()`** — silent wrong-iteration is the kind of bug integrators
   report as "the SDK returns nothing".
3. **Repair or delete the five stale tests.** Dead tests that call nonexistent
   methods erode trust in the suite, which is how seven real ones got ignored.
4. **Point the devnet fixtures at a devnet**, or skip them when the RPC is not
   local.
5. **Make CI non-optional before the next publish.**
