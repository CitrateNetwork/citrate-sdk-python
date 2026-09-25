"""PBA-L6b-003 (CRITICAL) and the Python variant of PBA-L4-005.

L6b-003: ``deploy_model`` with ``threshold_shares > 0`` put every Shamir share
of the model AES key into ``tx_data["encryption_metadata"]["key_shares"]``,
which ``_send_transaction`` hex-encodes into public calldata. Anyone reading the
chain rebuilt the key and decrypted the uploaded model.

Fix under test: shares never enter metadata or calldata. Each share is wrapped
to a named holder key (ECDH V2 envelope) and returned on the deployment result
for off-chain delivery; ``threshold_shares > 0`` without holder keys is refused.

These tests drive the real entry point (``CitrateClient.deploy_model``); only the
RPC and the IPFS upload are stubbed. The signed raw transaction is RLP-decoded
exactly as an observer would, and scripts/keyshare_leak_tripwire.py (own GF(2^8)
code) checks whether any subset of the calldata rebuilds the key.
"""
from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest
import rlp  # type: ignore[import-untyped]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from citrate_sdk import CitrateClient, KeyManager
from citrate_sdk.crypto import EncryptionConfig
from citrate_sdk.errors import CitrateError
from citrate_sdk.finite_field import (
    ShamirSecretSharing,
    reconstruct_secret_bytes,
    split_secret_bytes,
)
from citrate_sdk.models import ModelConfig

_spec = importlib.util.spec_from_file_location(
    "keyshare_leak_tripwire", Path(__file__).resolve().parents[1] / "scripts" / "keyshare_leak_tripwire.py"
)
assert _spec and _spec.loader
tripwire = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tripwire)

OWNER = "0x" + "11" * 32
HOLDER_KEYS = ["0x" + "22" * 32, "0x" + "33" * 32, "0x" + "44" * 32]
MODEL = b"SECRET-MODEL-WEIGHTS" * 100


def _client(tmp_path: Path) -> tuple[CitrateClient, dict[str, Any], Path]:
    mp = tmp_path / "m.onnx"
    mp.write_bytes(MODEL)
    client = CitrateClient("http://localhost:8545", private_key=OWNER)
    box: dict[str, Any] = {}

    def fake_rpc(method: str, params: Any = None) -> Any:
        if method == "eth_getTransactionCount":
            return "0x0"
        if method == "eth_chainId":
            return hex(40204)
        if method == "eth_gasPrice":
            return "0x1"
        if method == "eth_sendRawTransaction":
            box["raw"] = params[0]
            return "0x" + "ab" * 32
        raise AssertionError(method)

    def fake_upload(data: bytes) -> str:
        box["blob"] = data
        return "bafyFAKE"

    stubs: dict[str, Any] = {
        "_rpc_call": fake_rpc,
        "_upload_to_ipfs": fake_upload,
        "_wait_for_receipt": lambda h: {"logs": []},
        "_extract_model_id_from_receipt": lambda r: "0x01",
    }
    for name, fn in stubs.items():  # offline: RPC and IPFS are stubbed
        setattr(client, name, fn)
    return client, box, mp


def _calldata(raw_hex: str) -> bytes:
    fields = rlp.decode(bytes.fromhex(raw_hex[2:]))
    return bytes(fields[5])


def _owner_key(calldata: bytes) -> bytes:
    meta = json.loads(calldata.decode())["encryption_metadata"]
    return KeyManager(OWNER)._decrypt_key_from_owner(meta["encrypted_key"])


def _holder_pubs() -> list[str]:
    return [KeyManager(k).get_public_key() for k in HOLDER_KEYS]


def _cfg(**enc: Any) -> ModelConfig:
    base: dict[str, Any] = {"threshold_shares": 2, "total_shares": 3}
    base.update(enc)
    return ModelConfig(name="m", encrypted=True, encryption_config=EncryptionConfig(**base))


class TestDeployCalldataCarriesNoShares:
    def test_threshold_without_holders_is_refused_before_upload_or_send(self, tmp_path: Path) -> None:
        client, box, mp = _client(tmp_path)
        with pytest.raises(CitrateError, match="share_holder_public_keys"):
            client.deploy_model(mp, _cfg())
        assert "raw" not in box and "blob" not in box

    def test_encrypt_model_refuses_threshold_sharing(self) -> None:
        with pytest.raises(CitrateError, match="encrypt_model_with_key_shares"):
            KeyManager(OWNER).encrypt_model(MODEL, EncryptionConfig(threshold_shares=2, total_shares=3))

    def test_no_subset_of_calldata_reconstructs_the_key(self, tmp_path: Path) -> None:
        client, box, mp = _client(tmp_path)
        dep = client.deploy_model(mp, _cfg(share_holder_public_keys=_holder_pubs()))
        calldata = _calldata(box["raw"])
        key = _owner_key(calldata)
        # Sanity: that really is the model key.
        meta = json.loads(calldata.decode())["encryption_metadata"]
        assert AESGCM(key).decrypt(bytes.fromhex(meta["nonce"]), box["blob"], None) == MODEL
        assert tripwire.reveals_key(calldata, key) == (False, "")
        text = calldata.decode()
        assert "key_shares" not in text and "envelope" not in text and "wrapped_key" not in text
        assert meta["key_sharing"] == {"threshold": 2, "total_shares": 3}
        assert dep.key_share_envelopes is not None and len(dep.key_share_envelopes) == 3

    def test_holders_rebuild_the_key_offchain_and_outsiders_cannot(self, tmp_path: Path) -> None:
        client, box, mp = _client(tmp_path)
        dep = client.deploy_model(mp, _cfg(share_holder_public_keys=_holder_pubs()))
        key = _owner_key(_calldata(box["raw"]))
        owner_pub = KeyManager(OWNER).get_public_key()
        envs = dep.key_share_envelopes or []
        s0 = KeyManager(HOLDER_KEYS[0]).unwrap_key_share(envs[0], owner_pub)
        s2 = KeyManager(HOLDER_KEYS[2]).unwrap_key_share(envs[2], owner_pub)
        assert KeyManager(HOLDER_KEYS[0]).reconstruct_key_from_shares([s0, s2], threshold=2) == key
        with pytest.raises(CitrateError, match="different holder"):
            KeyManager(HOLDER_KEYS[1]).unwrap_key_share(envs[0], owner_pub)
        with pytest.raises(CitrateError):
            KeyManager("0x" + "55" * 32).unwrap_key_share(envs[0], owner_pub)
        # A forged envelope under another sender is refused by the owner pin.
        forged = dict(envs[0])
        forged["envelope"] = KeyManager("0x" + "66" * 32).encrypt_data("00" * 32, envs[0]["holder_public_key"])
        with pytest.raises(CitrateError):
            KeyManager(HOLDER_KEYS[0]).unwrap_key_share(forged, owner_pub)

    def test_holder_list_must_name_one_distinct_key_per_share(self) -> None:
        km = KeyManager(OWNER)
        pubs = _holder_pubs()
        with pytest.raises(CitrateError, match="one holder public key per share"):
            km.encrypt_model_with_key_shares(MODEL, EncryptionConfig(threshold_shares=2, total_shares=3,
                                                                     share_holder_public_keys=pubs[:2]))
        with pytest.raises(CitrateError, match="distinct"):
            km.encrypt_model_with_key_shares(MODEL, EncryptionConfig(threshold_shares=2, total_shares=3,
                                                                     share_holder_public_keys=[pubs[0], pubs[0], pubs[1]]))

    def test_caller_metadata_cannot_smuggle_share_fields(self, tmp_path: Path) -> None:
        client, box, mp = _client(tmp_path)
        cfg = ModelConfig(name="m", encrypted=False,
                          metadata={"nested": [{"key_shares": [{"x": "1", "y": "ab"}]}]})
        with pytest.raises(CitrateError, match="key-share material"):
            client.deploy_model(mp, cfg)
        assert "raw" not in box

    def test_threshold_zero_still_deploys_without_revealing_the_key(self, tmp_path: Path) -> None:
        client, box, mp = _client(tmp_path)
        client.deploy_model(mp, _cfg(threshold_shares=0, total_shares=0))
        calldata = _calldata(box["raw"])
        assert tripwire.reveals_key(calldata, _owner_key(calldata)) == (False, "")

    def test_tripwire_flags_the_pre_fix_shape(self) -> None:
        key = bytes(range(32))
        shares = [{"x": str(x), "y": y.hex(), "threshold": "2"} for x, y in split_secret_bytes(key, 2, 3)]
        leaked = json.dumps({"encryption_metadata": {"key_shares": shares}}).encode()
        assert tripwire.reveals_key(leaked, key)[0]
        bare = json.dumps({"a": shares[0]["y"], "b": shares[2]["y"]}).encode()
        assert tripwire.reveals_key(bare, key)[0]

    def test_example_uses_holder_keys(self) -> None:
        src = (Path(__file__).resolve().parents[1] / "examples" / "encrypted_inference.py").read_text()
        assert "share_holder_public_keys" in src and "unwrap_key_share" in src


class TestShamirValidation:
    """Python twin of PBA-L4-005 (found by the variant sweep)."""

    secret = b"ABC"

    def test_x_zero_share_is_rejected(self) -> None:
        forged = [(0, b"AB"), (1, b"\x99\x10"), (2, b"\x07\xee")]
        with pytest.raises(ValueError, match=r"x must be an integer in 1\.\.255"):
            reconstruct_secret_bytes(forged, 3)

    @pytest.mark.parametrize("bad", [256, -1, 1.5, True, "1", None])
    def test_bad_x_values(self, bad: Any) -> None:
        s = split_secret_bytes(self.secret, 2, 3)
        with pytest.raises(ValueError, match=r"x must be an integer in 1\.\.255"):
            reconstruct_secret_bytes([(bad, s[0][1]), s[1]], 2)

    def test_duplicate_x(self) -> None:
        s = split_secret_bytes(self.secret, 2, 3)
        with pytest.raises(ValueError, match="duplicate share x"):
            reconstruct_secret_bytes([s[0], (s[0][0], s[1][1])], 2)

    def test_length_mismatch_anywhere(self) -> None:
        s = split_secret_bytes(self.secret, 2, 3)
        with pytest.raises(ValueError, match="same length"):
            reconstruct_secret_bytes([s[0], s[1], (3, b"\x01")], 2)

    def test_empty_y(self) -> None:
        with pytest.raises(ValueError, match="empty"):
            reconstruct_secret_bytes([(1, b""), (2, b"")], 2)

    def test_threshold_comes_from_the_caller(self) -> None:
        km = KeyManager(OWNER)
        shares = [{"x": str(x), "y": y.hex(), "threshold": "1"} for x, y in split_secret_bytes(self.secret, 3, 5)]
        with pytest.raises(CitrateError, match="Insufficient shares"):
            km.reconstruct_key_from_shares(shares[:2], threshold=3)
        assert km.reconstruct_key_from_shares(shares[:3], threshold=3) == self.secret

    @pytest.mark.parametrize("x", [" 1", "1 ", "0x1", "1a", "1000", "٣"])
    def test_share_x_text_is_strict(self, x: str) -> None:
        with pytest.raises(CitrateError, match="x must be an integer"):
            KeyManager(OWNER).reconstruct_key_from_shares([{"x": x, "y": "aa"}], threshold=1)

    def test_verify_shares_detects_an_off_polynomial_share(self) -> None:
        sss = ShamirSecretSharing(2, 4)
        s = sss.split_secret(self.secret)
        assert sss.verify_shares(s)
        tampered = (4, bytes([s[3][1][0] ^ 1]) + s[3][1][1:])
        assert not sss.verify_shares([s[0], s[1], s[2], tampered])
        assert not sss.verify_shares([s[0], s[0], s[1]])
        assert not sss.verify_shares([(0, s[0][1]), s[1], s[2]])

    def test_valid_shares_round_trip(self) -> None:
        s = split_secret_bytes(self.secret, 3, 5)
        assert reconstruct_secret_bytes([s[4], s[1], s[2]], 3) == self.secret


def test_guard_rejects_each_denylisted_name() -> None:
    from citrate_sdk.crypto import assert_no_key_share_material

    for name in ("key_shares", "keyShares", "key_share_envelopes", "keyShareEnvelopes"):
        with pytest.raises(CitrateError, match=f"key-share material \\('{name}'\\)"):
            assert_no_key_share_material({"a": [{"b": {name: []}}]})
    assert_no_key_share_material({"a": None, "b": "key_shares", "c": [1, (2, {"d": 3})]})
