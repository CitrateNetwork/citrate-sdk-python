"""Key-sharing hardening (PBA-L6b-003 follow-up).

1. Holder de-duplication runs on canonical keys (same key in compressed,
   uncompressed and 0x-prefixed forms counts once).
2. threshold_shares=1 needs allow_single_holder_recovery=True.
3. The deploy guard recognises share-shaped values by structure as well as by
   field name.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from citrate_sdk import CitrateClient, KeyManager
from citrate_sdk.crypto import EncryptionConfig, assert_no_key_share_material
from citrate_sdk.errors import CitrateError
from citrate_sdk.finite_field import split_secret_bytes
from citrate_sdk.models import ModelConfig

OWNER = "0x" + "11" * 32
H = [KeyManager("0x" + b * 32) for b in ("22", "33", "44")]


def _cfg(pubs: list[str], t: int = 2, **kw: Any) -> EncryptionConfig:
    return EncryptionConfig(threshold_shares=t, total_shares=len(pubs), share_holder_public_keys=pubs, **kw)


class TestCanonicalDedupe:
    def test_same_holder_compressed_and_uncompressed_is_refused(self) -> None:
        comp = H[0].get_public_key()
        unc = H[0].ecdh_manager.get_public_key_uncompressed().hex()
        assert comp != unc
        with pytest.raises(CitrateError, match="distinct"):
            KeyManager(OWNER).encrypt_model_with_key_shares(b"m", _cfg([comp, unc, H[1].get_public_key()]))

    def test_same_holder_with_and_without_0x_is_refused(self) -> None:
        comp = H[0].get_public_key()
        with pytest.raises(CitrateError, match="distinct"):
            KeyManager(OWNER).encrypt_model_with_key_shares(b"m", _cfg([comp, "0x" + comp, H[1].get_public_key()]))

    def test_distinct_holders_in_mixed_encodings_are_accepted(self) -> None:
        pubs = [H[0].get_public_key(), H[1].ecdh_manager.get_public_key_uncompressed().hex(),
                "0x" + H[2].get_public_key()]
        _, _, envs = KeyManager(OWNER).encrypt_model_with_key_shares(b"m", _cfg(pubs))
        assert len({e["holder_public_key"] for e in envs}) == 3


class TestThresholdOne:
    def test_threshold_one_is_refused_by_default(self) -> None:
        with pytest.raises(CitrateError, match=r"threshold_shares=1 lets ANY single holder recover.*allow_single_holder_recovery=True"):
            KeyManager(OWNER).encrypt_model_with_key_shares(b"m", _cfg([h.get_public_key() for h in H], t=1))

    def test_threshold_one_with_explicit_opt_in(self) -> None:
        _, meta, envs = KeyManager(OWNER).encrypt_model_with_key_shares(
            b"m", _cfg([h.get_public_key() for h in H], t=1, allow_single_holder_recovery=True))
        assert meta["key_sharing"]["threshold"] == 1 and len(envs) == 3

    def test_threshold_two_needs_no_opt_in(self) -> None:
        KeyManager(OWNER).encrypt_model_with_key_shares(b"m", _cfg([h.get_public_key() for h in H], t=2))


class TestStructuralGuard:
    shares = [{"x": str(x), "y": y.hex()} for x, y in split_secret_bytes(b"k" * 32, 2, 3)]

    @pytest.mark.parametrize("meta", [
        {"myShares": shares},
        {"a": [{"x": 1, "y": "ab12" * 16}]},
        {"a": {"x": "1", "y": "0x" + "ab" * 32}},
        {"blob": json.dumps({"parts": shares})},
        {"blob": json.dumps([{"x": 2, "y": "cd" * 32}])},
        {"w": {"holder_public_key": "02" + "11" * 32, "envelope": "{}"}},
        {"w": [{"holderPublicKey": "02" + "11" * 32, "envelope": "{}"}]},
        {"y": {"x": 1, "y": b"\\x01" * 32}},
        {"padded": '  {"x": 1, "y": "abababababababababababababababababababababababababababababababab"}  '},
        {"big": json.dumps({"pad": "a" * 1_100_000, "s": {"x": 1, "y": "ab" * 32}})},
    ], ids=lambda m: str(list(m)[0]))
    def test_share_shaped_values_are_refused(self, meta: dict[str, Any]) -> None:
        with pytest.raises(CitrateError, match="key share|key-share"):
            assert_no_key_share_material(meta)

    @pytest.mark.parametrize("meta", [
        {"x": 1, "y": 2},
        {"x": 1, "y": "not hex"},
        {"point": {"x": 1}},
        {"blob": "{not json"},
        {"envelope": "e"},
        {"text": "[1, 2, 3]"},
        {"x": 1, "y": "zz12"},
        {"x": 1, "y": "12zz"},
        {"n": "123"},
    ])
    def test_ordinary_metadata_passes(self, meta: dict[str, Any]) -> None:
        assert_no_key_share_material(meta)

    def test_json_in_string_nesting_counts_toward_depth(self) -> None:
        v: Any = {"leaf": 1}
        for _ in range(20):
            v = json.dumps({"n": v})
        with pytest.raises(CitrateError, match="nested more than 32 levels"):
            assert_no_key_share_material({"v": v})

    def test_message(self) -> None:
        with pytest.raises(CitrateError, match=r"shaped like a key share \(\{x, y\} or a wrapped share record\) in public deploy calldata\. Deliver key shares"):
            assert_no_key_share_material({"a": {"x": 1, "y": "ab" * 32}})

    def test_deploy_refuses_renamed_share_field(self, tmp_path: Path) -> None:
        mp = tmp_path / "m.onnx"
        mp.write_bytes(b"w")
        client = CitrateClient("http://localhost:8545", private_key=OWNER)
        sent: list[Any] = []

        def rpc(method: str, params: Any = None) -> Any:
            sent.append(method)
            return "0x0"
        stubs: dict[str, Any] = {"_rpc_call": rpc, "_upload_to_ipfs": lambda d: "bafy"}
        for name, fn in stubs.items():
            setattr(client, name, fn)
        with pytest.raises(CitrateError, match="key share"):
            client.deploy_model(mp, ModelConfig(name="m", metadata={"myShares": self.shares}))
        assert "eth_sendRawTransaction" not in sent

    def test_real_encrypted_deploy_metadata_is_not_a_false_positive(self) -> None:
        pubs = [h.get_public_key() for h in H]
        _, meta, _ = KeyManager(OWNER).encrypt_model_with_key_shares(b"m", _cfg(pubs))
        assert_no_key_share_material({"encryption_metadata": meta})


@pytest.mark.parametrize(("t", "n"), [(True, 3), (2, True), (True, True)])
def test_bool_share_parameters_are_parameter_errors(t: Any, n: Any) -> None:
    pubs = [h.get_public_key() for h in H]
    cfg = EncryptionConfig(threshold_shares=t, total_shares=n, share_holder_public_keys=pubs)
    with pytest.raises(CitrateError, match="invalid share parameters"):
        KeyManager(OWNER).encrypt_model_with_key_shares(b"m", cfg)
