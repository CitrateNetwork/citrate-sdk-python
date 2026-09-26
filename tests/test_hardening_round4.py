"""Hardening round 4 (Python).

1. Invite secrets are validated as secp256k1 private keys independently of the
   installed eth-keys version: 1 <= secret < n, and any parse failure is a
   ValueError.
2. The share guard and the SDK's share parser cannot drift: the guard refuses
   every y the parser would accept, and the parser is strict (no whitespace,
   no junk, even length).
3. Both SDKs run the same test vectors (tests/fixtures/share_guard_vectors.json,
   byte-identical in citrate-sdk-js; the sha256 below pins it).
"""
from __future__ import annotations

import hashlib
import json
import secrets as pysecrets
from pathlib import Path
from typing import Any

import pytest

from citrate_sdk import KeyManager, crypto
from citrate_sdk.crypto import assert_no_key_share_material
from citrate_sdk.errors import CitrateError
from citrate_sdk.learning import ClassroomManager

SECP256K1_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
VECTORS = Path(__file__).parent / "fixtures" / "share_guard_vectors.json"
VECTORS_SHA256 = "674d35d72f4fca132e59e325efec3a61fcb4cbe7d6cfc5afd85d1821afcf884f"


def _mgr() -> tuple[ClassroomManager, list[Any]]:
    sent: list[Any] = []

    def rpc(method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return hex(40204)
        sent.append(params)
        return "0xhash"
    return ClassroomManager(rpc, default_account="0x" + "01" * 20, classroom_address="0x" + "02" * 20), sent


@pytest.mark.parametrize("secret", [
    "0x" + "00" * 32,
    hex(SECP256K1_N),
    "0x" + format(SECP256K1_N + 1, "064x"),
    "0x" + "ff" * 32,
])
def test_out_of_range_invite_secrets_are_value_errors(secret: str) -> None:
    mgr, sent = _mgr()
    with pytest.raises(ValueError, match="invite secret"):
        mgr.create("c", 3, invite_code=secret)
    assert sent == []


@pytest.mark.parametrize("secret", ["0x" + "00" * 31 + "01", "0x" + format(SECP256K1_N - 1, "064x")])
def test_range_edges_are_accepted(secret: str) -> None:
    mgr, sent = _mgr()
    mgr.create("c", 3, invite_code=secret)
    assert mgr.last_invite_code == secret and len(sent) == 1


def test_vector_file_is_the_shared_copy() -> None:
    assert hashlib.sha256(VECTORS.read_bytes()).hexdigest() == VECTORS_SHA256


_VECS = json.loads(VECTORS.read_text())["vectors"]


@pytest.mark.parametrize("vec", _VECS, ids=[v["name"] for v in _VECS])
def test_shared_vectors(vec: dict[str, Any]) -> None:
    if vec["refuse"]:
        with pytest.raises(CitrateError):
            assert_no_key_share_material(vec["meta"])
    else:
        assert_no_key_share_material(vec["meta"])


@pytest.mark.parametrize("y", ["ab cd" + "ab" * 30, "ab" * 32 + " ", " " + "ab" * 32, "ab" * 32 + "\n",
                               "ab" * 32 + "z", "ab" * 32 + "a", "0x", "", "xyz"])
def test_share_parser_is_strict(y: str) -> None:
    with pytest.raises(ValueError):
        crypto.parse_share_y(y)
    with pytest.raises(CitrateError):
        KeyManager("0x" + "11" * 32).reconstruct_key_from_shares([{"x": "1", "y": y}], threshold=1)


@pytest.mark.parametrize("y", ["ab" * 32, "AB" * 32, "0x" + "ab" * 32, "0X" + "cd" * 16])
def test_share_parser_accepts_canonical_hex(y: str) -> None:
    assert len(crypto.parse_share_y(y)) >= 16


def test_guard_refuses_everything_the_parser_accepts() -> None:
    """The invariant that keeps the guard and the parser from drifting: any y the
    SDK parser accepts (at share length) is refused by the guard."""
    for n in (16, 17, 32, 64):
        for _ in range(25):
            raw = pysecrets.token_bytes(n)
            for y in (raw.hex(), raw.hex().upper(), "0x" + raw.hex(), "0X" + raw.hex()):
                assert len(crypto.parse_share_y(y)) == n
                with pytest.raises(CitrateError):
                    assert_no_key_share_material({"x": 1 + n % 200, "y": y})


def test_range_check_holds_even_if_the_key_library_accepts(monkeypatch: pytest.MonkeyPatch) -> None:
    """The range check must not depend on eth-keys rejecting n."""
    from citrate_sdk import learning

    class _Acct:
        address = "0x" + "12" * 20

    monkeypatch.setattr(learning.Account, "from_key", staticmethod(lambda k: _Acct()))
    with pytest.raises(ValueError, match="out of range"):
        learning._invite_account(hex(SECP256K1_N))


def test_any_key_library_error_becomes_value_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from citrate_sdk import learning

    def boom(k: str) -> None:
        raise Exception("Invalid privkey")

    monkeypatch.setattr(learning.Account, "from_key", staticmethod(boom))
    with pytest.raises(ValueError, match="not a valid secp256k1 key"):
        learning._invite_account("0x" + "11" * 32)


_RAW = json.loads(VECTORS.read_text())["raw_payloads"]


@pytest.mark.parametrize("vec", _RAW, ids=[v["name"] for v in _RAW])
def test_shared_raw_payloads(vec: dict[str, Any]) -> None:
    if vec["refuse"]:
        with pytest.raises(CitrateError):
            crypto.assert_payload_has_no_key_share_material(vec["text"])
    else:
        crypto.assert_payload_has_no_key_share_material(vec["text"])


@pytest.mark.parametrize("y", [[171.0] * 32, [-85] * 32, {"type": "Buffer", "data": [171] * 32, "k": 1}])
def test_byte_forms_refused_in_json_strings_too(y: Any) -> None:
    with pytest.raises(CitrateError):
        assert_no_key_share_material({"blob": json.dumps({"x": 1, "y": y})})
    with pytest.raises(CitrateError):
        assert_no_key_share_material({"blob": json.dumps({"X": 1, "Y": y})})


@pytest.mark.parametrize("meta", [
    {"x": "junk", "X": 1, "y": "ab" * 32},
    {"x": 1, "y": "10", "Y": "ab" * 32},
    {"X": 2, "y": "10", "Y": [171] * 32},
])
def test_mixed_case_keys_are_all_checked(meta: dict[str, Any]) -> None:
    with pytest.raises(CitrateError):
        assert_no_key_share_material({"a": meta})
