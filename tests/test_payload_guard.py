"""Deploy payload is guarded as sent.

deploy_model serialises the payload once, guards the parsed payload, and sends
that exact payload.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
import rlp  # type: ignore[import-untyped]

from citrate_sdk import CitrateClient
from citrate_sdk.errors import CitrateError
from citrate_sdk.models import ModelConfig

OWNER = "0x" + "11" * 32
Y = "ab" * 32


class _Mapping(dict):
    def __getitem__(self, k: Any) -> Any:
        return {"x": 0, "y": "10"}.get(k, super().get(k))

    def get(self, k: Any, default: Any = None) -> Any:
        return {"x": 0, "y": "10"}.get(k, default)


class _Key(str):
    """A str subclass; two distinct instances with the same text."""

    def __hash__(self) -> int:
        return id(self)

    def __eq__(self, other: object) -> bool:
        return self is other


def _client(tmp_path: Path) -> tuple[CitrateClient, dict[str, Any], Path]:
    mp = tmp_path / "m.onnx"
    mp.write_bytes(b"w")
    client = CitrateClient("http://localhost:8545", private_key=OWNER)
    box: dict[str, Any] = {}

    def rpc(method: str, params: Any = None) -> Any:
        if method == "eth_sendRawTransaction":
            box["raw"] = params[0]
            return "0x" + "ab" * 32
        return {"eth_getTransactionCount": "0x0", "eth_chainId": hex(40204), "eth_gasPrice": "0x1"}[method]

    stubs: dict[str, Any] = {"_rpc_call": rpc, "_upload_to_ipfs": lambda d: "bafy",
                             "_wait_for_receipt": lambda h: {"logs": []},
                             "_extract_model_id_from_receipt": lambda r: "0x01"}
    for name, fn in stubs.items():
        setattr(client, name, fn)
    return client, box, mp


def _dup_y() -> dict[Any, Any]:
    d: dict[Any, Any] = {"x": 1}
    d[_Key("y")] = Y
    d[_Key("y")] = "10"
    return d


def _dup_x() -> dict[Any, Any]:
    d: dict[Any, Any] = {}
    d[_Key("x")] = 1
    d[_Key("x")] = "junk"
    d["y"] = Y
    return d


@pytest.mark.parametrize("meta", [
    {"m": _Mapping({"x": 1, "y": Y})},
    {"m": [_Mapping({"x": "7", "y": Y})]},
    {"m": _Mapping({"x": 1, "y": Y, "note": "n"})},
    {"m": _dup_y()},
    {"m": _dup_x()},
    {"blob": '{"x": 1, "y": "' + Y + '", "y": "10"}'},
], ids=["case-1", "case-2", "case-3", "case-4", "case-5", "case-6"])
def test_payload_guarded_as_sent(tmp_path: Path, meta: dict[str, Any]) -> None:
    client, box, mp = _client(tmp_path)
    with pytest.raises(CitrateError):
        client.deploy_model(mp, ModelConfig(name="m", metadata=meta))
    assert "raw" not in box


def test_the_guard_sees_exactly_the_bytes_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from citrate_sdk import client as client_mod

    seen: list[str] = []
    real = client_mod.assert_payload_has_no_key_share_material

    def spy(payload: str) -> None:
        seen.append(payload)
        real(payload)

    monkeypatch.setattr(client_mod, "assert_payload_has_no_key_share_material", spy)
    client, box, mp = _client(tmp_path)
    client.deploy_model(mp, ModelConfig(name="m", metadata={"note": "ok"}))
    sent = bytes(rlp.decode(bytes.fromhex(box["raw"][2:]))[5]).decode()
    assert seen == [sent]
    assert "model_hash" in json.loads(sent)


def test_benign_deploy_still_sends(tmp_path: Path) -> None:
    client, box, mp = _client(tmp_path)
    client.deploy_model(mp, ModelConfig(name="m", metadata={"x": 1, "y": "10"}))
    assert "raw" in box
