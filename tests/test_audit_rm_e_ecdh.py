"""RM-E / CITRATE_SDK_PYTHON-2026-05-31-001 — encrypt_data must ECDH-wrap the
symmetric key to a recipient and never ship it in cleartext.

CI-gated: requires the `cryptography` + `eth_account` deps (not installable in
the read-only audit env). Authored red-first against the pre-fix behavior,
which put the raw key in the envelope.
"""

import json

import pytest

from citrate_sdk.crypto import KeyManager
from citrate_sdk.errors import CitrateError

# Two fixed test identities.
SENDER_PK = "0x" + "11" * 32
RECIPIENT_PK = "0x" + "22" * 32


def _recipient_pub(km: KeyManager) -> str:
    return km.ecdh_manager.get_public_key_uncompressed().hex()


def test_encrypt_data_never_ships_cleartext_key():
    sender = KeyManager(SENDER_PK)
    recipient = KeyManager(RECIPIENT_PK)
    envelope = sender.encrypt_data(
        json.dumps({"secret": "hello"}), _recipient_pub(recipient)
    )
    pkg = json.loads(envelope)
    # The pre-fix envelope contained a raw "key"; the fix must not.
    assert "key" not in pkg, "symmetric key must never be in the envelope"
    assert "wrapped_key" in pkg and "sender_public_key" in pkg
    # Pins the CURRENT scheme, not a frozen string. This asserted
    # ECDH_SCHEME_V1 literally, which was a proxy for "the wrapped form" — so
    # when K3 landed V2 (fresh per-envelope kdf_salt + endpoint-key binding)
    # this failed despite the invariant it exists to protect being strictly
    # better satisfied. The invariant is "no cleartext key, and the envelope
    # names the scheme this SDK produces"; the version number is not the point.
    assert pkg["scheme"] == KeyManager.ECDH_SCHEME_V2
    assert pkg["scheme"] != KeyManager.ECDH_SCHEME_V1, (
        "V1 derived its KEK from a constant salt with no endpoint binding and "
        "must never be produced again"
    )


def test_encrypt_data_fails_closed_without_recipient():
    sender = KeyManager(SENDER_PK)
    with pytest.raises(CitrateError):
        sender.encrypt_data(json.dumps({"secret": "hello"}))


def test_ecdh_roundtrip_recipient_can_decrypt():
    sender = KeyManager(SENDER_PK)
    recipient = KeyManager(RECIPIENT_PK)
    plaintext = json.dumps({"secret": "hello", "n": 42})
    envelope = sender.encrypt_data(plaintext, _recipient_pub(recipient))
    # Only the intended recipient (holding RECIPIENT_PK) can unwrap.
    assert recipient.decrypt_data(envelope) == plaintext


def test_non_recipient_cannot_decrypt():
    sender = KeyManager(SENDER_PK)
    recipient = KeyManager(RECIPIENT_PK)
    attacker = KeyManager("0x" + "33" * 32)
    envelope = sender.encrypt_data(json.dumps({"x": 1}), _recipient_pub(recipient))
    with pytest.raises(CitrateError):
        attacker.decrypt_data(envelope)
