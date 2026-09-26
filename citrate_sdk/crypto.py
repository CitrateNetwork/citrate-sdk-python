"""
Cryptographic utilities for Citrate SDK
"""

import hashlib
import hmac
import json
import re
import secrets
from typing import Any, cast

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from eth_account import Account
from eth_account.signers.local import LocalAccount

from .ecdh_real import ECDHManager
from .errors import CitrateError
from .finite_field import reconstruct_secret_bytes, split_secret_bytes

#: Field names that only ever hold Shamir share material (PBA-L6b-003). Deploy
#: calldata is public; ``CitrateClient.deploy_model`` refuses a payload that
#: carries any of them, at any depth.
SHARE_FIELD_DENYLIST = frozenset({"key_shares", "keyShares", "key_share_envelopes", "keyShareEnvelopes"})
_MAX_GUARD_DEPTH = 32


#: A share's y is at least 16 bytes (the SDK shares 32-byte keys), as
#: even-length hex, optionally 0x-prefixed.
_MIN_SHARE_BYTES = 16
_STRICT_HEX_RE = re.compile(r"(?:0[xX])?((?:[0-9a-fA-F]{2})+)")
_HEX_RUN_RE = re.compile(r"[0-9a-fA-F]{%d,}" % (2 * _MIN_SHARE_BYTES))
_WS_RE = re.compile(r"\s+")


def parse_share_y(y: str) -> bytes:
    """The SDK's one share-value parser: optional 0x/0X, then an even number of
    hex digits and nothing else (no whitespace, no trailing junk). Raises
    ValueError otherwise. ``reconstruct_key_from_shares`` uses it."""
    m = _STRICT_HEX_RE.fullmatch(y) if isinstance(y, str) else None
    if m is None:
        raise ValueError("share y must be an even-length hex string")
    return bytes.fromhex(m.group(1))


def _share_y_like(y: str) -> bool:
    """Deliberately LENIENT (a superset of ``parse_share_y`` and of the lenient
    parsers other consumers may use): after removing whitespace, any run of
    >= 16 bytes of hex digits counts (a 0x/0X prefix cannot join the run)."""
    return _HEX_RUN_RE.search(_WS_RE.sub("", y)) is not None


def _share_x(x: Any) -> bool:
    if isinstance(x, bool):
        return False
    if isinstance(x, int):
        return 1 <= x <= 255
    if isinstance(x, float):
        # JSON "1.0" is the Number 1 in JS: treat an integral float as an integer.
        return x.is_integer() and 1 <= x <= 255
    return isinstance(x, str) and x.isascii() and x.isdigit() and 1 <= int(x) <= 255


def _is_byte_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v <= 255


def _bytes_like_len(y: Any) -> int:
    """Length of ``y`` if it is bytes or a JSON rendering of bytes (an integer
    list, the ``{"type": "Buffer", "data": [...]}`` shape, or an object keyed
    "0".."n-1" with byte values); otherwise 0."""
    if isinstance(y, (bytes, bytearray)):
        return len(y)
    if isinstance(y, (list, tuple)):
        return len(y) if all(_is_byte_int(v) for v in y) else 0
    if isinstance(y, dict):
        if set(y) == {"type", "data"} and y.get("type") == "Buffer":
            return _bytes_like_len(list(y["data"])) if isinstance(y.get("data"), list) else 0
        n = len(y)
        if n and all(isinstance(k, str) for k in y) and set(y) == {str(i) for i in range(n)}:
            return n if all(_is_byte_int(y[str(i)]) for i in range(n)) else 0
    return 0


class _DuplicateKeyError(ValueError):
    pass


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateKeyError(k)
        out[k] = v
    return out


def _loads_strict(text: str) -> Any:
    """json.loads that rejects duplicate object keys (raises _DuplicateKeyError)."""
    return json.loads(text, object_pairs_hook=_no_duplicate_keys)


_DUP_MSG = (
    "deploy_model: refusing to publish JSON with duplicate object keys; decoders disagree on "
    "which value wins, so the content cannot be checked for key-share material (PBA-L6b-003)."
)


def assert_payload_has_no_key_share_material(payload: str) -> None:
    """Guard a serialised JSON payload exactly as it will be sent: parse it
    (refusing duplicate keys) and run :func:`assert_no_key_share_material`."""
    try:
        decoded = _loads_strict(payload)
    except _DuplicateKeyError:
        raise CitrateError(_DUP_MSG)
    except (ValueError, RecursionError):
        raise CitrateError("deploy_model: payload is not valid JSON; refusing to publish it.")
    assert_no_key_share_material(decoded)


def _looks_like_share(d: dict[Any, Any]) -> bool:
    """A raw Shamir share ({x in 1..255, y of share length as hex or bytes})
    or a holder-wrapped share record ({holder_public_key/holderPublicKey,
    envelope}). Short or coordinate-like values are not treated as shares."""
    y = d.get("y")
    if "x" in d and _share_x(d["x"]):
        if _bytes_like_len(y) >= _MIN_SHARE_BYTES:
            return True
        if isinstance(y, str) and _share_y_like(y):
            return True
    return "envelope" in d and ("holder_public_key" in d or "holderPublicKey" in d)


def assert_no_key_share_material(value: Any, _depth: int = 0) -> None:
    """Raise CitrateError if ``value`` carries key-share material (PBA-L6b-003).

    Refuses the known share field names AND, by structure, any object that
    looks like a share ({x, y-hex}) or a wrapped share record, at any depth,
    including inside JSON-encoded string values (a renamed field such as
    ``myShares`` is caught too).
    """
    if isinstance(value, str):
        # Any string that parses as JSON is checked too (no size cap: a padded
        # blob must not slip through).
        try:
            decoded = _loads_strict(value)
        except _DuplicateKeyError:
            raise CitrateError(_DUP_MSG)
        except (ValueError, RecursionError):
            return
        assert_no_key_share_material(decoded, _depth + 1)
        return
    if isinstance(value, dict):
        items = list(value.items())
    elif isinstance(value, (list, tuple)):
        items = [(None, v) for v in value]
    else:
        return
    if _depth > _MAX_GUARD_DEPTH:
        raise CitrateError(
            f"deploy_model: metadata is nested more than {_MAX_GUARD_DEPTH} levels deep; refusing to "
            "publish calldata that cannot be fully checked for key-share material (PBA-L6b-003)."
        )
    if isinstance(value, dict) and _looks_like_share(value):
        raise CitrateError(
            "deploy_model: refusing to publish a value shaped like a key share ({x, y} or a "
            "wrapped share record) in public deploy calldata. Deliver key shares to their "
            "holders off-chain (PBA-L6b-003)."
        )
    for k, v in items:
        if k in SHARE_FIELD_DENYLIST:
            raise CitrateError(
                f"deploy_model: refusing to publish key-share material ({k!r}) in public deploy "
                "calldata. Deliver key shares to their holders off-chain (PBA-L6b-003)."
            )
        assert_no_key_share_material(v, _depth + 1)


def canonical_public_key_hex(public_key: str) -> str:
    """Normalise a secp256k1 public key (hex, 0x optional, SEC1 compressed or
    uncompressed) to uncompressed lowercase hex. Raises CitrateError if it is
    not a valid curve point."""
    try:
        raw = bytes.fromhex(public_key[2:] if public_key.startswith("0x") else public_key)
        point = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256K1(), raw)
    except Exception:
        raise CitrateError("invalid secp256k1 public key")
    return point.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    ).hex()


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

    def __init__(self, private_key: str | None = None):
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
            self.account = Account.create()

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
        return cast(str, self.account.address)

    def get_private_key(self) -> str:
        """Get private key as hex string"""
        # Contract: 0x-prefixed, 66 chars. hexbytes >=1.0 dropped the prefix
        # from ``HexBytes.hex()`` (older releases emitted it), so normalise
        # rather than depend on the installed hexbytes version.
        key_hex = self.account.key.hex()
        return key_hex if key_hex.startswith("0x") else "0x" + key_hex

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
            # eth-account renamed this attribute from ``rawTransaction`` to
            # ``raw_transaction`` (0.13+); support both installed versions.
            # Recent hexbytes also makes ``.hex()`` 0x-prefixed, so normalise
            # before re-prefixing to avoid a ``0x0x...`` result.
            raw = getattr(signed_txn, "raw_transaction", None)
            if raw is None:
                raw = getattr(signed_txn, "rawTransaction", None)
            if raw is None:
                raise CitrateError("signed transaction exposes no raw bytes")
            raw_hex = cast(str, raw.hex())
            if raw_hex.startswith("0x"):
                raw_hex = raw_hex[2:]
            return "0x" + raw_hex
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
            Tuple of (encrypted_data, encryption_metadata). The metadata is
            PUBLIC (``deploy_model`` writes it to calldata) and never carries key
            material.

        Raises:
            CitrateError: if ``config.threshold_shares > 0``. Threshold sharing
                goes through :meth:`encrypt_model_with_key_shares`, which returns
                the holder-wrapped shares separately from the metadata
                (PBA-L6b-003).
        """
        if config.threshold_shares:
            raise CitrateError(
                "encrypt_model: threshold_shares > 0 needs encrypt_model_with_key_shares(), "
                "which wraps each share to a named holder and returns the shares apart "
                "from the public metadata. Shares are never placed in metadata (PBA-L6b-003)."
            )
        ciphertext, metadata, _ = self._encrypt_model(model_data, config, None)
        return ciphertext, metadata

    def encrypt_model_with_key_shares(
        self,
        model_data: bytes,
        config: 'EncryptionConfig'
    ) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
        """
        Encrypt a model and split its key for threshold recovery (PBA-L6b-003).

        Each Shamir share is ECDH-wrapped (V2 envelope) to one of
        ``config.share_holder_public_keys`` and returned as the third element.
        Deliver each envelope to its holder OFF-CHAIN. The returned metadata
        carries only the share parameters, never share values.

        Returns:
            (encrypted_data, public_metadata, key_share_envelopes)
        """
        plan = self._plan_key_sharing(config)
        if plan is None:
            raise CitrateError(
                "encrypt_model_with_key_shares: threshold_shares must be > 0; use encrypt_model()."
            )
        return self._encrypt_model(model_data, config, plan)

    def _encrypt_model(
        self,
        model_data: bytes,
        config: 'EncryptionConfig',
        plan: tuple[int, int, list[str]] | None,
    ) -> tuple[bytes, dict[str, Any], list[dict[str, Any]]]:
        key = bytearray(secrets.token_bytes(32))  # 256-bit key
        nonce = secrets.token_bytes(12)  # 96-bit nonce for GCM
        try:
            ciphertext = AESGCM(bytes(key)).encrypt(nonce, model_data, None)
            # Everything in here is PUBLIC: deploy_model writes it to calldata.
            metadata: dict[str, Any] = {
                "algorithm": config.algorithm,
                "nonce": nonce.hex(),
                "key_derivation": config.key_derivation,
                "encrypted_key": self._encrypt_key_for_owner(bytes(key)),
                "access_control": config.access_control
            }
            envelopes: list[dict[str, Any]] = []
            if plan is not None:
                threshold, total, holders = plan
                # PBA-L6b-003: the old code put every raw share into the metadata,
                # i.e. into public calldata. Shares are now wrapped to holders and
                # returned beside the metadata, never inside it.
                envelopes = self._create_key_shares(bytes(key), threshold, total, holders)
                metadata["key_sharing"] = {"threshold": threshold, "total_shares": total}
            return ciphertext, metadata, envelopes
        finally:
            _zeroize(key)

    @staticmethod
    def _plan_key_sharing(config: 'EncryptionConfig') -> tuple[int, int, list[str]] | None:
        """Validate a threshold-sharing request (PBA-L6b-003). None when off."""
        threshold = config.threshold_shares
        if not threshold:
            return None
        total = config.total_shares
        if (isinstance(threshold, bool) or isinstance(total, bool)
                or not isinstance(threshold, int) or not isinstance(total, int)
                or threshold < 1 or threshold > total or total > 255):
            raise CitrateError(
                f"encrypt_model: invalid share parameters (threshold_shares={threshold!r}, "
                f"total_shares={total!r}); need integers with 1 <= threshold_shares <= "
                "total_shares <= 255."
            )
        if threshold == 1 and not config.allow_single_holder_recovery:
            raise CitrateError(
                "encrypt_model: threshold_shares=1 lets ANY single holder recover the model key, "
                "which is not threshold sharing. Pass allow_single_holder_recovery=True if that "
                "is really intended (PBA-L6b-003 follow-up)."
            )
        holders = config.share_holder_public_keys
        if not holders:
            raise CitrateError(
                "encrypt_model: threshold_shares > 0 requires share_holder_public_keys. Key "
                "shares are never written to deploy metadata (it is public calldata); each "
                "share is wrapped to a named holder key and returned for off-chain delivery "
                "(PBA-L6b-003). Pass one holder public key per share, or set threshold_shares to 0."
            )
        if len(holders) != total:
            raise CitrateError(
                f"encrypt_model: need one holder public key per share (total_shares={total}, "
                f"share_holder_public_keys has {len(holders)}) (PBA-L6b-003)."
            )
        canonical = [canonical_public_key_hex(h) for h in holders]
        if len(set(canonical)) != len(canonical):
            raise CitrateError(
                "encrypt_model: share_holder_public_keys must be distinct; one holder with "
                "several shares defeats the threshold (PBA-L6b-003)."
            )
        return threshold, total, canonical

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

    def encrypt_data(self, data: str, recipient_public_key: str | None = None) -> str:
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

    def _create_key_shares(
        self, key: bytes, threshold: int, total: int, holder_public_keys: list[str]
    ) -> list[dict[str, Any]]:
        """Split ``key`` and ECDH-wrap share i to holder i (PBA-L6b-003).

        Returns one record per share: ``x`` and ``threshold`` (not secret), the
        holder's public key, and the V2 ``envelope`` holding the share value.
        Raw share values never leave this function.
        """
        if len(holder_public_keys) != total:
            raise CitrateError("_create_key_shares: need exactly one holder public key per share")
        records: list[dict[str, Any]] = []
        for (x, share_bytes), holder in zip(split_secret_bytes(key, threshold, total), holder_public_keys, strict=True):
            envelope = self.encrypt_data(share_bytes.hex(), holder)
            records.append({
                "x": x,
                "threshold": threshold,
                "holder_public_key": holder,
                "envelope": envelope,
            })
        return records

    def unwrap_key_share(self, share: dict[str, Any], owner_public_key: str) -> dict[str, str]:
        """Holder side of PBA-L6b-003: open a key-share envelope addressed to this key.

        ``owner_public_key`` pins the sender (the model owner); an envelope from
        anyone else is refused. Returns the share in the form
        :meth:`reconstruct_key_from_shares` takes.
        """
        mine = self.ecdh_manager.get_public_key_uncompressed().hex()
        if not hmac.compare_digest(canonical_public_key_hex(str(share["holder_public_key"])), mine):
            raise CitrateError("unwrap_key_share: this share is addressed to a different holder key.")
        y = self.decrypt_data(share["envelope"], canonical_public_key_hex(owner_public_key))
        return {"x": str(share["x"]), "y": y, "threshold": str(share["threshold"])}

    def reconstruct_key_from_shares(self, shares: list[dict[str, str]], threshold: int) -> bytes:
        """Reconstruct a key from Shamir shares (Lagrange interpolation).

        PBA-L4-005 / PBA-L6b-003: ``threshold`` comes from the CALLER, never
        from the shares (an attacker-supplied share could lower it), and share
        x values are validated before interpolation.
        """
        if isinstance(threshold, bool) or not isinstance(threshold, int) or not 1 <= threshold <= 255:
            raise CitrateError(f"reconstruct_key_from_shares: threshold must be an integer in 1..255, got {threshold!r}")
        if not shares:
            raise CitrateError("No shares provided")
        if len(shares) < threshold:
            raise CitrateError("Insufficient shares for key reconstruction")

        shares_tuples = []
        for share in shares:
            x_text = str(share["x"])
            if not (x_text.isascii() and x_text.isdigit() and 1 <= len(x_text) <= 3):
                raise CitrateError(f"Invalid share: x must be an integer in 1..255, got {x_text!r}")
            try:
                y = parse_share_y(share["y"])
            except ValueError:
                raise CitrateError("Invalid share: y is not hex (an even-length hex string is required)")
            shares_tuples.append((int(x_text), y))

        try:
            return reconstruct_secret_bytes(shares_tuples, threshold)
        except ValueError as e:
            raise CitrateError(str(e))


class EncryptionConfig:
    """Configuration for model encryption"""

    def __init__(
        self,
        algorithm: str = "AES-256-GCM",
        key_derivation: str = "HKDF-SHA256",
        access_control: bool = True,
        threshold_shares: int = 0,
        total_shares: int = 0,
        share_holder_public_keys: list[str] | None = None,
        allow_single_holder_recovery: bool = False,
    ):
        """
        Args:
            threshold_shares: Shamir threshold for splitting the model key; 0
                (default) disables key sharing.
            total_shares: number of shares.
            share_holder_public_keys: REQUIRED when ``threshold_shares > 0``
                (PBA-L6b-003): one distinct secp256k1 public key per share. Each
                share is ECDH-wrapped to its holder and returned for off-chain
                delivery; shares are never written to deploy calldata.
            allow_single_holder_recovery: threshold_shares=1 (any one holder
                alone recovers the key) is refused unless this is True.
        """
        self.algorithm = algorithm
        self.key_derivation = key_derivation
        self.access_control = access_control
        self.threshold_shares = threshold_shares
        self.total_shares = total_shares
        self.share_holder_public_keys = share_holder_public_keys
        self.allow_single_holder_recovery = allow_single_holder_recovery


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
