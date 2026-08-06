"""SECREM-02 KEYSAFE WP K3 — FUA-SDK-PY-01/-02/-03 (+ prior -007/-008/-011).

Red-first against the pre-fix behavior:

- FUA-SDK-PY-01: ``get_public_key()`` emitted an AMBIGUOUS 32-byte x-only
  form; ``perform_ecdh`` guessed even-Y for it. Empirical correction recorded
  during this WP: because ECDH shared secrets are x-only and negation-
  invariant (x(a·(−B)) == x(a·B)), the parity guess does NOT break the wrap
  round-trip (0/200 pre-fix failures, 101 odd-Y recipients) — the audit's
  "~50% decrypt failure" mechanism does not reproduce. The encoding is still
  ambiguous (and parity-sensitive on any ECDSA/point-encoding consumer), so
  the canonical fix stands: the SDK's native format is 33-byte SEC1
  compressed (0x02/0x03 + X), and the guessing 32-byte branch is REMOVED
  (fail closed).
- FUA-SDK-PY-02: the legacy cleartext-``key`` envelope must be rejected on
  decrypt (downgrade / forged-key read).
- FUA-SDK-PY-03 (= prior -008): per-message random ``kdf_salt`` carried in
  the envelope and fed to HKDF; both endpoint public keys bound into HKDF
  ``info``; derived KEKs zeroized best-effort after use.
"""

import json
import secrets

import pytest

from citrate_sdk.crypto import KeyManager
from citrate_sdk.ecdh_real import ECDHManager
from citrate_sdk.errors import CitrateError

SENDER_PK = "0x" + "11" * 32


def _fresh_recipient() -> KeyManager:
    return KeyManager(secrets.token_bytes(32).hex())


def _odd_y_recipient() -> KeyManager:
    """Generate a recipient whose ECDH public point has an odd Y."""
    while True:
        km = _fresh_recipient()
        if km.ecdh_manager.public_key.public_numbers().y % 2 == 1:
            return km


# ── FUA-SDK-PY-01: canonical native key format ──────────────────────────


def test_get_public_key_is_canonical_sec1_compressed():
    """Native format = 33-byte SEC1 compressed: 0x02/0x03 prefix + X.

    RED pre-fix: get_public_key() returned a 32-byte prefix-less x-only
    string with no parity information (prior -007 root cause).
    """
    for _ in range(8):
        km = _fresh_recipient()
        pub = bytes.fromhex(km.get_public_key())
        assert len(pub) == 33, "native public key must be SEC1 compressed"
        assert pub[0] in (0x02, 0x03), "SEC1 parity prefix required"
        # Prefix must reflect the actual Y parity — no guessing convention.
        y = km.ecdh_manager.public_key.public_numbers().y
        assert pub[0] == (0x03 if y % 2 else 0x02)


def test_ambiguous_32_byte_pubkey_rejected():
    """The parity-guessing 32-byte branch is deleted; ambiguous input fails
    closed. RED pre-fix: perform_ecdh accepted 32 bytes and guessed even-Y."""
    a = ECDHManager()
    b = ECDHManager()
    x_only = b.public_key.public_numbers().x.to_bytes(32, "big")
    with pytest.raises(CitrateError):
        a.perform_ecdh(x_only)


def test_native_key_roundtrip_1000_of_1000():
    """Sprint red test: encrypt→decrypt with the SDK's NATIVE key format
    succeeds 1000/1000.

    Honest pre-fix status (recorded as a finding correction): this also
    passed pre-fix, because the even-Y guess only ever negates the peer
    point and ECDH output is negation-invariant. Post-fix it passes by
    construction (deterministic SEC1 decode, no guessing) rather than by
    algebraic accident.
    """
    sender = KeyManager(SENDER_PK)
    failures = 0
    for i in range(1000):
        recipient = _fresh_recipient()
        plaintext = f"msg-{i}"
        try:
            envelope = sender.encrypt_data(plaintext, recipient.get_public_key())
            if recipient.decrypt_data(envelope) != plaintext:
                failures += 1
        except CitrateError:
            failures += 1
    assert failures == 0, f"{failures}/1000 native-key round-trips failed"


def test_odd_y_recipient_roundtrip_native_format():
    """Determinism witness for the historically 'guessed' half of the
    keyspace: an odd-Y recipient round-trips on the native format."""
    sender = KeyManager(SENDER_PK)
    recipient = _odd_y_recipient()
    envelope = sender.encrypt_data("odd-y", recipient.get_public_key())
    assert recipient.decrypt_data(envelope) == "odd-y"


def test_uncompressed_65_byte_recipient_still_supported():
    """65-byte SEC1 uncompressed remains a valid recipient encoding
    (cross-SDK contract: sdk-js getPublicKey() emits uncompressed)."""
    sender = KeyManager(SENDER_PK)
    recipient = _fresh_recipient()
    pub65 = recipient.ecdh_manager.get_public_key_uncompressed().hex()
    envelope = sender.encrypt_data("sec1-uncompressed", pub65)
    assert recipient.decrypt_data(envelope) == "sec1-uncompressed"


# ── FUA-SDK-PY-02: legacy cleartext-key envelope rejected ───────────────


def test_legacy_cleartext_key_envelope_rejected():
    """RED pre-fix: decrypt_data honored a hostile envelope carrying the
    raw AES key — a silent downgrade with no binding to any keypair."""
    recipient = _fresh_recipient()
    key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    forged = json.dumps(
        {
            "ciphertext": AESGCM(key).encrypt(nonce, b"attacker says hi", None).hex(),
            "nonce": nonce.hex(),
            "key": key.hex(),
        }
    )
    with pytest.raises(CitrateError):
        recipient.decrypt_data(forged)


def test_cleartext_key_rejected_even_beside_wrapped_key():
    """An envelope carrying BOTH wrapped_key and a cleartext key is hostile
    by construction — reject outright, never silently prefer either."""
    sender = KeyManager(SENDER_PK)
    recipient = _fresh_recipient()
    pkg = json.loads(sender.encrypt_data("x", recipient.get_public_key()))
    pkg["key"] = secrets.token_bytes(32).hex()
    with pytest.raises(CitrateError):
        recipient.decrypt_data(json.dumps(pkg))


def test_v1_constant_salt_envelope_rejected():
    """Pre-K3 'ecdh-secp256k1-aesgcm-v1' envelopes (constant HKDF salt, no
    kdf_salt field) are no longer decryptable — fail closed, re-encrypt."""
    recipient = _fresh_recipient()
    v1_shaped = json.dumps(
        {
            "scheme": "ecdh-secp256k1-aesgcm-v1",
            "ciphertext": "00" * 16,
            "nonce": "00" * 12,
            "wrapped_key": "00" * 48,
            "wrap_nonce": "00" * 12,
            "sender_public_key": KeyManager(SENDER_PK)
            .ecdh_manager.get_public_key_uncompressed()
            .hex(),
            "recipient_public_key": recipient.get_public_key(),
        }
    )
    with pytest.raises(CitrateError):
        recipient.decrypt_data(v1_shaped)


# ── FUA-SDK-PY-03: per-message KDF freshness + key binding ──────────────


def test_envelope_carries_fresh_kdf_salt():
    """RED pre-fix: no per-message salt existed; HKDF salt was the constant
    b"citrate-model-encryption" (prior -008)."""
    sender = KeyManager(SENDER_PK)
    recipient = _fresh_recipient()
    pub = recipient.get_public_key()
    pkg1 = json.loads(sender.encrypt_data("same plaintext", pub))
    pkg2 = json.loads(sender.encrypt_data("same plaintext", pub))

    assert pkg1["scheme"] == KeyManager.ECDH_SCHEME_V2
    for pkg in (pkg1, pkg2):
        assert "kdf_salt" in pkg, "per-message KDF salt must ride in the envelope"
        assert len(bytes.fromhex(pkg["kdf_salt"])) == 32
    assert pkg1["kdf_salt"] != pkg2["kdf_salt"], "salt must be fresh per message"
    assert pkg1["wrapped_key"] != pkg2["wrapped_key"]


def test_kdf_salt_is_load_bearing():
    """Tampering with the envelope salt must break decryption — proves the
    salt actually feeds the KDF instead of being decorative."""
    sender = KeyManager(SENDER_PK)
    recipient = _fresh_recipient()
    pkg = json.loads(sender.encrypt_data("bound", recipient.get_public_key()))
    pkg["kdf_salt"] = secrets.token_bytes(32).hex()
    with pytest.raises(CitrateError):
        recipient.decrypt_data(json.dumps(pkg))


def test_envelope_binds_recipient_public_key():
    """Both endpoint keys are bound into HKDF info: swapping the recipient
    field for another key must break decryption. RED pre-fix: the field was
    decorative (decrypt never read it)."""
    sender = KeyManager(SENDER_PK)
    recipient = _fresh_recipient()
    other = _fresh_recipient()
    pkg = json.loads(sender.encrypt_data("bound", recipient.get_public_key()))
    pkg["recipient_public_key"] = other.get_public_key()
    with pytest.raises(CitrateError):
        recipient.decrypt_data(json.dumps(pkg))


def test_missing_kdf_salt_rejected():
    sender = KeyManager(SENDER_PK)
    recipient = _fresh_recipient()
    pkg = json.loads(sender.encrypt_data("x", recipient.get_public_key()))
    del pkg["kdf_salt"]
    with pytest.raises(CitrateError):
        recipient.decrypt_data(json.dumps(pkg))


# ── prior -011 (closed opportunistically): constant-time digest compare ──


def test_verify_model_integrity_uses_constant_time_compare():
    """Tripwire: hash comparison must route through hmac.compare_digest,
    not `==` (prior -011, INFO)."""
    import inspect

    from citrate_sdk import crypto as crypto_mod

    src = inspect.getsource(crypto_mod.verify_model_integrity)
    assert "compare_digest" in src, "verify_model_integrity must use hmac.compare_digest"


def test_verify_model_integrity_behavior():
    from citrate_sdk.crypto import hash_model_data, verify_model_integrity

    data = b"model-bytes"
    assert verify_model_integrity(data, hash_model_data(data)) is True
    assert verify_model_integrity(data, hash_model_data(b"other")) is False


# ── SEC-2026-08-02-031: sender identity — what ECDH gives, and what it does not ──


def test_relabelling_an_envelope_with_a_trusted_sender_key_is_refused():
    """Static-static ECDH authenticates the sender IMPLICITLY.

    The KEK is ECDH(sender_priv, recipient_pub) == ECDH(recipient_priv,
    sender_pub), so only the holder of the private key matching
    `sender_public_key` can produce an envelope that unwraps. Mallory cannot
    take her own valid envelope and relabel it as Alice's.

    This test exists because the 2026-08-02 audit initially claimed the envelope
    had NO sender authentication. That was overstated — the PoC only showed
    Mallory speaking AS HERSELF. This pins the property that was actually there
    all along, so nobody "fixes" it twice or weakens it by accident.
    """
    victim = _fresh_recipient()
    alice = _fresh_recipient()
    mallory = _fresh_recipient()

    victim_pub = victim.ecdh_manager.get_public_key_uncompressed().hex()
    alice_pub = alice.ecdh_manager.get_public_key_uncompressed().hex()

    pkg = json.loads(mallory.encrypt_data("payload", victim_pub))
    pkg["sender_public_key"] = alice_pub  # claim to be Alice

    with pytest.raises(CitrateError):
        victim.decrypt_data(json.dumps(pkg))


def test_an_unknown_sender_can_still_send_a_valid_envelope():
    """The residual issue, pinned as behaviour rather than left implicit.

    Anyone holding the recipient's PUBLIC key can mint a valid envelope under
    their own keypair. Decryption succeeds. That is not a flaw in the crypto —
    it is what encryption to a public key means — but a caller who reads
    success as "this came from someone I trust" is wrong, which is why
    `expected_sender_public_key` exists.
    """
    victim = _fresh_recipient()
    stranger = _fresh_recipient()
    victim_pub = victim.ecdh_manager.get_public_key_uncompressed().hex()

    envelope = stranger.encrypt_data("unsolicited", victim_pub)
    assert victim.decrypt_data(envelope) == "unsolicited"


def test_expected_sender_pinning_refuses_a_stranger():
    victim = _fresh_recipient()
    alice = _fresh_recipient()
    stranger = _fresh_recipient()
    victim_pub = victim.ecdh_manager.get_public_key_uncompressed().hex()
    alice_pub = alice.ecdh_manager.get_public_key_uncompressed().hex()

    envelope = stranger.encrypt_data("unsolicited", victim_pub)
    with pytest.raises(CitrateError):
        victim.decrypt_data(envelope, expected_sender_public_key=alice_pub)


def test_expected_sender_pinning_accepts_the_real_sender():
    victim = _fresh_recipient()
    alice = _fresh_recipient()
    victim_pub = victim.ecdh_manager.get_public_key_uncompressed().hex()
    alice_pub = alice.ecdh_manager.get_public_key_uncompressed().hex()

    envelope = alice.encrypt_data("hello", victim_pub)
    assert victim.decrypt_data(envelope, expected_sender_public_key=alice_pub) == "hello"
