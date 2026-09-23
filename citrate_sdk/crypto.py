"""
Cryptographic utilities for Citrate SDK
"""

import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_account.signers.local import LocalAccount

from .ecdh_real import ECDHManager
from .errors import CitrateError
from .finite_field import reconstruct_secret_bytes, split_secret_bytes


def _zeroize(buf: bytearray | None) -> None:
    """Best-effort in-place wipe of key material (SECREM-02 K3 /
    FUA-SDK-PY-03).

    HONEST LIMITS (CPython): this only clears the bytearray we hold.
    Immutable ``bytes`` snapshots handed to AESGCM/HKDF, interned copies,
    and interpreter-internal buffers cannot be wiped from Python, and the
    GC may have already duplicated pages. This narrows the exposure
    window; it is NOT a guarantee the KEK is gone from process memory.
    """
    if buf is None:
        return
    for i in range(len(buf)):
        buf[i] = 0


class KeyManager:
    """
    Manages cryptographic keys for Citrate operations.

    Handles:
    - Ethereum account management
    - Model encryption/decryption
    - Key derivation and sharing
    - Transaction signing
    """

    def __init__(self, private_key: str = None):
        """
        Initialize key manager.

        Args:
            private_key: Hex-encoded private key, or None to generate new key
        """
        if private_key:
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            self.account: LocalAccount = Account.from_key(private_key)
        else:
            self.account: LocalAccount = Account.create()

        # Generate ECDH key pair for model encryption
        private_key_bytes = None
        if private_key:
            # Use Ethereum private key for ECDH as well
            if private_key.startswith('0x'):
                private_key = private_key[2:]
            private_key_bytes = bytes.fromhex(private_key)

        self.ecdh_manager = ECDHManager(private_key_bytes)

    def get_address(self) -> str:
        """Get Ethereum address"""
        return self.account.address

    def get_private_key(self) -> str:
        """Get private key as hex string"""
        return self.account.key.hex()

    def get_public_key(self) -> str:
        """Get ECDH public key for sharing"""
        public_bytes = self.ecdh_manager.get_public_key_compressed()
        return public_bytes.hex()

    def sign_transaction(self, transaction: dict[str, Any]) -> str:
        """
        Sign Ethereum transaction.

        Args:
            transaction: Transaction dict with standard fields

        Returns:
            Signed transaction as hex string
        """
        try:
            signed_txn = self.account.sign_transaction(transaction)
            return "0x" + signed_txn.raw_transaction.hex()
        except Exception as e:
            raise CitrateError(f"Transaction signing failed: {str(e)}")

    def encrypt_model(
        self,
        model_data: bytes,
        config: 'EncryptionConfig'
    ) -> tuple[bytes, dict[str, Any]]:
        """
        Encrypt model data with AES-256-GCM.

        Args:
            model_data: Raw model file bytes
            config: Encryption configuration

        Returns:
            Tuple of (encrypted_data, encryption_metadata)
        """
        # Generate random key and nonce
        key = secrets.token_bytes(32)  # 256-bit key
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM

        # Encrypt data
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, model_data, None)

        # Create encryption metadata
        metadata = {
            "algorithm": config.algorithm,
            "nonce": nonce.hex(),
            "key_derivation": config.key_derivation,
            "encrypted_key": self._encrypt_key_for_owner(key),
            "access_control": config.access_control
        }

        # Add threshold sharing if enabled
        if config.threshold_shares > 0:
            key_shares = self._create_key_shares(key, config.threshold_shares, config.total_shares)
            metadata["key_shares"] = key_shares

        return ciphertext, metadata

    def decrypt_model(
        self,
        encrypted_data: bytes,
        metadata: dict[str, Any]
    ) -> bytes:
        """
        Decrypt model data.

        Args:
            encrypted_data: Encrypted model bytes
            metadata: Encryption metadata from deployment

        Returns:
            Decrypted model data
        """
        try:
            # Extract encryption parameters
            nonce = bytes.fromhex(metadata["nonce"])
            encrypted_key = metadata["encrypted_key"]

            # Decrypt the encryption key
            key = self._decrypt_key_from_owner(encrypted_key)

            # Decrypt model data
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, encrypted_data, None)

            return plaintext

        except Exception as e:
            raise CitrateError(f"Model decryption failed: {str(e)}")

    # CITRATE_SDK_PYTHON-2026-05-31-001: envelope scheme tag for the
    # ECDH-wrapped format. The pre-fix envelope shipped the AES key in
    # cleartext ("key") next to the ciphertext — on public, permanent EVM
    # calldata that is zero confidentiality. The symmetric key is now
    # ECDH-wrapped to the recipient's public key and never appears raw.
    ECDH_SCHEME_V1 = "ecdh-secp256k1-aesgcm-v1"

    # SECREM-02 K3 / SEC-2026-08-02-031,033,034. V1 wrapped the symmetric key to
    # the recipient — which fixed the original finding (the key was in public
    # calldata) — but derived the KEK from a CONSTANT HKDF salt over the sender's
    # STATIC identity key. The KEK was therefore identical for a given
    # (sender, recipient) pair forever.
    #
    # V1 also carried `recipient_public_key` without binding it. An audit PoC
    # confirmed the field could be overwritten with 0x00*65 and decryption still
    # succeeded, returning identical plaintext — it looked like a control and was
    # not one.
    #
    # V2 fixes TWO of V1's problems: a fresh 32-byte `kdf_salt` per envelope
    # (so the KEK is no longer identical/correlatable across messages to the same
    # recipient), and BOTH endpoint public keys bound into the HKDF `info`.
    # Tampering with either the salt or a key field changes the derived KEK, so
    # the AES-GCM unwrap fails its tag check instead of being silently ignored.
    #
    # WHAT V2 DOES NOT GIVE YOU: FORWARD SECRECY (CIT-SDKPY-01).
    #
    # The ECDH is static-static — `sender_priv` is the long-lived Ethereum
    # identity key (reused verbatim as the ECDH key, see __init__) and
    # `recipient_pub` is fixed — so ECDH(sender_priv, recipient_pub) is the SAME
    # secret for every message. `kdf_salt` is carried in the envelope IN
    # CLEARTEXT. So an attacker who ever compromises the sender's (or recipient's)
    # static private key recomputes the one static ECDH secret, reads each
    # envelope's own public `kdf_salt`, and re-derives EVERY past and future KEK —
    # decrypting all envelopes to that recipient. The per-message salt prevents
    # KEK REUSE/correlation; it does NOT confine a key compromise to a single
    # message. Real forward secrecy requires an EPHEMERAL per-message key
    # (ECIES / ephemeral-static ECDH), which V2 does not use. Because the ECDH
    # key IS the signing/wallet key, that single key — if lost — retroactively
    # discloses every encrypted payload. Do not represent V2 as forward-secret.
    #
    # SENDER AUTHENTICATION — what this scheme does and does not give you.
    #
    # Static-static ECDH authenticates the sender IMPLICITLY: the KEK is
    # ECDH(sender_priv, recipient_pub) == ECDH(recipient_priv, sender_pub), so
    # only a party holding the private key matching `sender_public_key` can
    # produce an envelope that unwraps. Relabelling someone else's envelope with
    # a trusted sender's public key is therefore REFUSED — the KEK no longer
    # matches and the AEAD tag fails. (Verified: see the audit PoC.)
    #
    # What it does NOT give you is a REASON TO TRUST that key. Anyone can mint a
    # valid envelope under their OWN keypair, and `decrypt_data` will happily
    # return the plaintext. A caller that reads a successful decrypt as "this
    # came from someone I trust" is wrong.
    #
    # So pass `expected_sender_public_key` to `decrypt_data` whenever origin
    # matters. Without it the call still succeeds — the API cannot know whether
    # the caller has an out-of-band expectation — but the sender is then
    # unverified by construction.
    ECDH_SCHEME_V2 = "ecdh-secp256k1-aesgcm-v2"

    @staticmethod
    def _kek_info(sender_public_key: str, recipient_public_key: str) -> bytes:
        """HKDF `info` binding both endpoint keys into the derived KEK.

        The EXACT envelope strings are used, not re-encoded points: the two
        sides must agree byte-for-byte, and a public key has several valid
        encodings (compressed/uncompressed) that would otherwise derive
        different KEKs for the same key pair.
        """
        return (
            b"citrate-ecdh-v2|"
            + sender_public_key.encode("utf-8")
            + b"|"
            + recipient_public_key.encode("utf-8")
        )

    def encrypt_data(self, data: str, recipient_public_key: str = None) -> str:
        """Encrypt arbitrary string data, ECDH-wrapping the symmetric key to
        ``recipient_public_key`` (hex). The raw key is NEVER included in the
        returned envelope.

        CITRATE_SDK_PYTHON-001: a recipient public key is REQUIRED. Shipping
        the symmetric key alongside the ciphertext provided no confidentiality
        on public calldata; rather than fabricate confidentiality we fail
        closed when no recipient is supplied.
        """
        if not recipient_public_key:
            raise CitrateError(
                "encrypt_data requires recipient_public_key: the symmetric key "
                "is ECDH-wrapped to the recipient and never shipped in cleartext "
                "(CITRATE_SDK_PYTHON-001). Resolve the model/recipient public key "
                "before requesting encrypted inference."
            )

        data_bytes = data.encode('utf-8')
        key = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)

        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, data_bytes, None)

        # ECDH-wrap the symmetric key to the recipient (V2). The KEK is
        # HKDF(ECDH(sender_priv, recipient_pub), salt=kdf_salt, info=both keys);
        # the recipient re-derives it from ECDH(recipient_priv, sender_pub) plus
        # the salt and key fields carried in the envelope.
        kdf_salt = secrets.token_bytes(32)
        sender_public_key = self.ecdh_manager.get_public_key_uncompressed().hex()
        shared = self.derive_shared_key(
            recipient_public_key,
            salt=kdf_salt,
            info=self._kek_info(sender_public_key, recipient_public_key),
        )
        wrap_nonce = secrets.token_bytes(12)
        try:
            wrapped_key = AESGCM(shared).encrypt(wrap_nonce, key, None)
        finally:
            # Best-effort wipe of the KEK. See _zeroize for the honest limits —
            # this narrows the window, it does not guarantee erasure.
            _zeroize(bytearray(shared))

        package = {
            "scheme": self.ECDH_SCHEME_V2,
            "ciphertext": ciphertext.hex(),
            "nonce": nonce.hex(),
            "wrapped_key": wrapped_key.hex(),
            "wrap_nonce": wrap_nonce.hex(),
            "kdf_salt": kdf_salt.hex(),
            "sender_public_key": sender_public_key,
            "recipient_public_key": recipient_public_key,
        }

        return json.dumps(package)

    def decrypt_data(
        self,
        encrypted_package: str,
        expected_sender_public_key: str | None = None,
    ) -> str:
        """Decrypt a V2 ECDH-wrapped envelope. FAILS CLOSED on anything else.

        Args:
            encrypted_package: the JSON envelope from ``encrypt_data``.
            expected_sender_public_key: hex public key the envelope MUST claim.
                Pass this whenever origin matters. Static-static ECDH already
                guarantees the envelope was produced by the holder of
                `sender_public_key` — an attacker cannot relabel their envelope
                as coming from someone else — but it cannot tell you whether
                that key is one you trust. Anybody may send you a perfectly
                valid envelope under their own key.

                Omitting this is allowed, because the SDK cannot know whether
                the caller has an out-of-band expectation. But a decrypt without
                it authenticates nothing about WHO, and callers routinely read
                success as trust. If you have an expected sender, say so.

        SECREM-02 K3 / SEC-2026-08-02-032. This used to accept the legacy
        cleartext-key envelope "for backward-compatible READS only". An audit
        PoC confirmed the consequence: an attacker-supplied envelope carrying a
        raw key of their choosing decrypted successfully. Producing the legacy
        form had been stopped in 2026-06; reading it had not, so the downgrade
        survived the fix that was supposed to close it.

        It also accepted V1, whose KEK derives from a constant salt with no
        binding of the endpoint keys. Both are now refused.

        MIGRATION: pre-V2 envelopes are no longer decryptable. Nothing is lost
        that was ever confidential — legacy-form envelopes shipped their key in
        public calldata, and V1 envelopes remain readable by anyone who ever
        compromises the sender's static key. Re-encrypt rather than reaching for
        a compatibility flag.
        """
        try:
            package = json.loads(encrypted_package)

            # A cleartext `key` is hostile by construction — checked FIRST, and
            # before the scheme, so an envelope carrying BOTH a wrapped_key and
            # a cleartext key is rejected outright rather than silently
            # preferring one. Preferring the safe field would still be
            # processing an envelope that has been tampered with.
            if "key" in package:
                raise CitrateError(
                    "Data decryption failed: refusing a cleartext-key envelope. The "
                    "symmetric key must "
                    "be ECDH-wrapped to the recipient. An envelope carrying a "
                    "raw key is either pre-2026-06 (never confidential — "
                    "re-encrypt it) or forged."
                )

            scheme = package.get("scheme")
            if scheme != self.ECDH_SCHEME_V2:
                raise CitrateError(
                    f"Data decryption failed: unsupported envelope scheme {scheme!r}. "
                    f"This SDK reads "
                    f"only {self.ECDH_SCHEME_V2}. V1 envelopes derived their key "
                    f"from a constant salt with no binding of the endpoint keys "
                    f"and are refused; re-encrypt with a current SDK."
                )

            if "kdf_salt" not in package:
                raise CitrateError(
                    "Data decryption failed: envelope is missing kdf_salt. A V2 "
                    "envelope without a "
                    "per-message salt is malformed or stripped"
                )

            for field in ("ciphertext", "nonce", "wrapped_key", "wrap_nonce",
                          "sender_public_key", "recipient_public_key"):
                if field not in package:
                    raise CitrateError(f"Data decryption failed: envelope is missing required field {field!r}")

            # Sender pinning, when the caller has an expectation. Compared
            # BEFORE any key derivation so a mismatch costs nothing and cannot
            # be distinguished by timing from a malformed envelope. The
            # comparison is constant-time out of habit rather than necessity —
            # both values are public keys.
            if expected_sender_public_key is not None:
                if not hmac.compare_digest(
                    package["sender_public_key"].lower(),
                    expected_sender_public_key.lower(),
                ):
                    raise CitrateError(
                        "Data decryption failed: envelope sender does not match the "
                        "expected sender. "
                        "refusing to decrypt. The envelope is cryptographically "
                        "valid but was produced by a different keypair."
                    )

            ciphertext = bytes.fromhex(package["ciphertext"])
            nonce = bytes.fromhex(package["nonce"])

            # Re-derive the KEK. Both endpoint keys and the salt come from the
            # envelope and all three feed the derivation, so tampering with any
            # of them yields a different KEK and the unwrap below fails its tag
            # check. That is the binding: it is enforced by the AEAD, not by a
            # comparison we could forget to make.
            shared = self.derive_shared_key(
                package["sender_public_key"],
                salt=bytes.fromhex(package["kdf_salt"]),
                info=self._kek_info(
                    package["sender_public_key"], package["recipient_public_key"]
                ),
            )
            wrap_nonce = bytes.fromhex(package["wrap_nonce"])
            wrapped_key = bytes.fromhex(package["wrapped_key"])
            try:
                key = AESGCM(shared).decrypt(wrap_nonce, wrapped_key, None)
            finally:
                _zeroize(bytearray(shared))

            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)

            return plaintext.decode('utf-8')

        except CitrateError:
            raise
        except Exception as e:
            raise CitrateError(f"Data decryption failed: {str(e)}")

    def derive_shared_key(
        self,
        peer_public_key: str,
        *,
        salt: bytes | None = None,
        info: bytes | None = None,
    ) -> bytes:
        """
        Derive shared key using ECDH.

        Args:
            peer_public_key: Hex-encoded peer public key
            salt: HKDF salt. Envelope callers pass a FRESH per-message salt
                (SEC-034). The legacy constant is retained only as the default
                for direct callers doing plain key agreement, where both sides
                must reach the same value with nothing to carry between them.
            info: HKDF info. Envelope callers bind both endpoint public keys
                here so a swapped key field changes the derived KEK.

        Returns:
            32-byte shared key
        """
        try:
            peer_key_bytes = bytes.fromhex(peer_public_key)
            return self.ecdh_manager.derive_shared_secret(
                peer_key_bytes,
                salt=b"citrate-model-encryption" if salt is None else salt,
                info=b"shared-key-derivation" if info is None else info,
            )

        except Exception as e:
            raise CitrateError(f"Key derivation failed: {str(e)}")

    def _encrypt_key_for_owner(self, key: bytes) -> str:
        """Encrypt key for model owner using proper key wrapping"""
        # Use HKDF for proper key derivation from account key
        salt = secrets.token_bytes(32)
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'citrate-key-wrapping',
            backend=default_backend()
        )
        owner_key = hkdf.derive(self.account.key)

        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(owner_key)
        encrypted_key = aesgcm.encrypt(nonce, key, None)

        return json.dumps({
            "encrypted_key": encrypted_key.hex(),
            "nonce": nonce.hex(),
            "salt": salt.hex()
        })

    def _decrypt_key_from_owner(self, encrypted_key_package: str) -> bytes:
        """Decrypt key for model owner using proper key derivation"""
        package = json.loads(encrypted_key_package)
        encrypted_key = bytes.fromhex(package["encrypted_key"])
        nonce = bytes.fromhex(package["nonce"])
        salt = bytes.fromhex(package["salt"])

        # Derive owner key using same HKDF parameters
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'citrate-key-wrapping',
            backend=default_backend()
        )
        owner_key = hkdf.derive(self.account.key)

        aesgcm = AESGCM(owner_key)
        return aesgcm.decrypt(nonce, encrypted_key, None)

    def _create_key_shares(self, key: bytes, threshold: int, total: int) -> list[dict[str, str]]:
        """Create Shamir's secret shares for key using proper finite field arithmetic"""
        shares_tuples = split_secret_bytes(key, threshold, total)

        shares = []
        for x, share_bytes in shares_tuples:
            shares.append({
                "x": str(x),
                "y": share_bytes.hex(),
                "threshold": str(threshold)
            })

        return shares

    def reconstruct_key_from_shares(self, shares: list[dict[str, str]]) -> bytes:
        """Reconstruct key from Shamir's shares using proper Lagrange interpolation"""
        if not shares:
            raise CitrateError("No shares provided")

        threshold = int(shares[0]["threshold"])
        if len(shares) < threshold:
            raise CitrateError("Insufficient shares for key reconstruction")

        # Convert shares back to tuples format
        shares_tuples = []
        for share in shares:
            x = int(share["x"])
            y = bytes.fromhex(share["y"])
            shares_tuples.append((x, y))

        return reconstruct_secret_bytes(shares_tuples, threshold)


class EncryptionConfig:
    """Configuration for model encryption"""

    def __init__(
        self,
        algorithm: str = "AES-256-GCM",
        key_derivation: str = "HKDF-SHA256",
        access_control: bool = True,
        threshold_shares: int = 0,
        total_shares: int = 0
    ):
        self.algorithm = algorithm
        self.key_derivation = key_derivation
        self.access_control = access_control
        self.threshold_shares = threshold_shares
        self.total_shares = total_shares


def generate_model_key() -> str:
    """Generate random 256-bit key for model encryption"""
    return secrets.token_bytes(32).hex()


def hash_model_data(data: bytes) -> str:
    """Generate SHA-256 hash of model data"""
    return hashlib.sha256(data).hexdigest()


def verify_model_integrity(data: bytes, expected_hash: str) -> bool:
    """Verify model data integrity against expected hash.

    SEC-036: uses ``hmac.compare_digest`` rather than ``==``. Python's string
    equality short-circuits on the first differing byte, so the comparison time
    leaks how much of the digest matched. The values here are hashes rather than
    secrets, which is why this was LOW — but the fix costs one call and removes
    the question.
    """
    actual_hash = hash_model_data(data)
    return hmac.compare_digest(actual_hash, expected_hash)
