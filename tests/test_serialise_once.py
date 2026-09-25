"""Serialise once (deploy_model).

deploy_model serialises the transaction payload exactly once, runs the share
guard on the parsed result of those bytes, and sends those same bytes. The
guard therefore judges what is sent, whatever the live objects do when read
(dict subclasses overriding __getitem__ / get, and so on).
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


class ReadsBenign(dict):
    """Stores a share, but item access reports something harmless."""

    def __getitem__(self, k: Any) -> Any:
        return {"x": 0, "y": "10"}.get(k, super().get(k))

    def get(self, k: Any, default: Any = None) -> Any:
        return {"x": 0, "y": "10"}.get(k, default)


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


@pytest.mark.parametrize("meta", [
    {"m": ReadsBenign({"x": 1, "y": Y})},
    {"m": [ReadsBenign({"x": "7", "y": Y})]},
    {"m": ReadsBenign({"x": 1, "y": Y, "note": "n"})},
], ids=["dict-subclass", "in-list", "extra-field"])
def test_stateful_mapping_cannot_carry_a_share(tmp_path: Path, meta: dict[str, Any]) -> None:
    client, box, mp = _client(tmp_path)
    with pytest.raises(CitrateError, match="key share|key-share"):
        client.deploy_model(mp, ModelConfig(name="m", metadata=meta))
    assert "raw" not in box


def test_the_guard_sees_exactly_the_bytes_sent(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from citrate_sdk import client as client_mod

    seen: list[Any] = []
    real = client_mod.assert_no_key_share_material

    def spy(value: Any) -> None:
        seen.append(value)
        real(value)

    monkeypatch.setattr(client_mod, "assert_no_key_share_material", spy)
    client, box, mp = _client(tmp_path)
    client.deploy_model(mp, ModelConfig(name="m", metadata={"note": "ok"}))
    sent = bytes(rlp.decode(bytes.fromhex(box["raw"][2:]))[5])
    assert len(seen) == 1
    # The guard was handed the parsed form of the exact bytes that went out.
    assert seen[0] == json.loads(sent)
    assert type(seen[0]) is dict


def test_benign_deploy_still_sends(tmp_path: Path) -> None:
    client, box, mp = _client(tmp_path)
    client.deploy_model(mp, ModelConfig(name="m", metadata={"x": 1, "y": "10"}))
    assert "raw" in box
