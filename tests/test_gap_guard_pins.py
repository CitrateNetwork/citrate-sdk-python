"""Pins for guards whose removal the rest of the suite did not notice.

Each test drives the public entry point (``decrypt_data``, ``list_models``,
``verify_model_integrity``, ``ClassroomManager.create``, the client
constructors, ``IPFSClient``) and fails on an assertion if the guard it names
is removed. No network: RPC and HTTP are replaced in-process, and the keys
are fixed throwaway test scalars.
"""
from __future__ import annotations

import json
from typing import Any

import pytest

from citrate_sdk import crypto as crypto_mod
from citrate_sdk._url_security import InsecureTransportError
from citrate_sdk.client import CitrateClient
from citrate_sdk.crypto import KeyManager, verify_model_integrity
from citrate_sdk.errors import CitrateError
from citrate_sdk.ipfs import IPFSClient
from citrate_sdk.learning import ClassroomManager

SENDER_PK = "0x" + "11" * 32
RECIPIENT_PK = "0x" + "22" * 32


def _envelope() -> tuple[KeyManager, str]:
    sender = KeyManager(SENDER_PK)
    recipient = KeyManager(RECIPIENT_PK)
    env = sender.encrypt_data("payload", recipient.get_public_key())
    return recipient, env


# ── envelope scheme and salt checks in decrypt_data ─────────────────────────

def test_positive_control_v2_envelope_decrypts() -> None:
    recipient, env = _envelope()
    assert recipient.decrypt_data(env) == "payload"


@pytest.mark.parametrize("scheme", ["ecdh-secp256k1-aesgcm-v1", None, "", "ECDH-SECP256K1-AESGCM-V2 "])
def test_a_well_formed_envelope_under_another_scheme_label_is_refused(scheme: Any) -> None:
    """Every other field is a valid V2 envelope, so only the scheme check can
    stop this decrypting (an older-scheme or unlabelled envelope must not be read)."""
    recipient, env = _envelope()
    pkg = json.loads(env)
    if scheme is None:
        del pkg["scheme"]
    else:
        pkg["scheme"] = scheme
    with pytest.raises(CitrateError, match="unsupported envelope scheme"):
        recipient.decrypt_data(json.dumps(pkg))


def test_an_envelope_without_its_kdf_salt_is_refused_by_name() -> None:
    recipient, env = _envelope()
    pkg = json.loads(env)
    del pkg["kdf_salt"]
    with pytest.raises(CitrateError, match="missing kdf_salt"):
        recipient.decrypt_data(json.dumps(pkg))


# ── verify_model_integrity uses a constant-time compare ─────────────────────

def test_verify_model_integrity_compares_with_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    import hashlib
    import hmac

    seen: list[tuple[Any, Any]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(crypto_mod.hmac, "compare_digest", spy)
    data = b"model-bytes"
    good = hashlib.sha256(data).hexdigest()
    assert verify_model_integrity(data, good) is True
    assert verify_model_integrity(data, "0" * 64) is False
    assert [b for _, b in seen] == [good, "0" * 64]


# ── list_models unwraps the node's {"models": [...]} answer ─────────────────

def test_list_models_unwraps_the_node_shape(monkeypatch: pytest.MonkeyPatch) -> None:
    client = CitrateClient("http://localhost:8545")
    rows = [{"model_id": "m1"}, {"model_id": "m2"}]
    monkeypatch.setattr(client, "_rpc_call", lambda method, params=None: {"models": rows})
    got = client.list_models(limit=2)
    assert got == rows
    assert [m["model_id"] for m in got] == ["m1", "m2"]


def test_list_models_of_an_empty_node_answer_is_an_empty_list(monkeypatch: pytest.MonkeyPatch) -> None:
    client = CitrateClient("http://localhost:8545")
    monkeypatch.setattr(client, "_rpc_call", lambda method, params=None: {})
    assert client.list_models() == []


# ── ClassroomManager.create default invite secret is random, not clock-derived ──

def _classroom() -> ClassroomManager:
    def rpc(method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return hex(40204)
        if method == "eth_sendTransaction":
            return "0xhash"
        raise AssertionError(method)

    return ClassroomManager(rpc, default_account="0x" + "01" * 20, classroom_address="0x" + "02" * 20)


def test_default_invite_secret_does_not_depend_on_the_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    import time as time_mod

    monkeypatch.setattr(time_mod, "time", lambda: 1_700_000_000.123)
    mgr = _classroom()
    mgr.create("A", 10)
    first = mgr.last_invite_code
    mgr.create("B", 10)
    second = mgr.last_invite_code
    assert first and second and first != second


def test_default_invite_secret_comes_from_the_os_csprng(monkeypatch: pytest.MonkeyPatch) -> None:
    import citrate_sdk.learning as learning

    monkeypatch.setattr(learning.secrets, "token_bytes", lambda n: b"\x5a" * n)
    mgr = _classroom()
    mgr.create("A", 10)
    assert mgr.last_invite_code == "0x" + "5a" * 32


# ── transport gate: only https/http are accepted, wherever the URL enters ───

@pytest.mark.parametrize("url", [
    "ftp://localhost:8545",
    "ws://127.0.0.1:8545",
    "gopher://localhost:8545",
    "file://localhost/etc/passwd",
])
def test_client_refuses_a_non_http_scheme_even_on_loopback(url: str) -> None:
    with pytest.raises(InsecureTransportError, match="is not https or http"):
        CitrateClient(url)


@pytest.mark.parametrize("url", ["ftp://ipfs.example.com:5001", "wss://ipfs.example.com:5001"])
def test_insecure_opt_in_does_not_admit_other_schemes(url: str) -> None:
    with pytest.raises(InsecureTransportError, match="is not https or http"):
        IPFSClient(url, allow_insecure_http=True)


# ── every IPFS request carries the client's timeout ─────────────────────────

class _Resp:
    def __init__(self, body: dict[str, Any] | None = None, chunks: list[bytes] | None = None) -> None:
        self.status_code = 200
        self._body = body or {}
        self._chunks = chunks or []
        self.text = json.dumps(self._body)

    def json(self) -> dict[str, Any]:
        return self._body

    def iter_content(self, chunk_size: int = 0) -> Any:
        return iter(self._chunks)

    def close(self) -> None:
        pass


def _recording_client(calls: list[tuple[str, dict[str, Any]]], data: bytes = b"x") -> IPFSClient:
    c = IPFSClient("http://localhost:5001", timeout=7.5)

    def post(url: str, **kw: Any) -> _Resp:
        calls.append((url.rsplit("/api/v0/", 1)[-1], kw))
        if url.endswith("/add"):
            return _Resp({"Hash": "QmTest", "Size": "1"})
        if url.endswith("/files/stat") or url.endswith("/object/stat"):
            return _Resp({"Hash": "QmTest", "Size": 1, "CumulativeSize": 1, "Type": "file"})
        if url.endswith("/cat"):
            return _Resp(chunks=[data])
        return _Resp({})

    c.session.post = post  # type: ignore[method-assign]
    return c


def test_upload_and_its_verification_carry_the_timeout() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []
    c = _recording_client(calls)
    c.upload_bytes(b"model")
    assert calls, "upload made no request"
    assert calls[0][0] == "add"
    for endpoint, kw in calls:
        assert kw.get("timeout") == 7.5, f"{endpoint} request sent without the client timeout"


def test_download_and_pin_carry_the_timeout() -> None:
    import hashlib

    calls: list[tuple[str, dict[str, Any]]] = []
    c = _recording_client(calls, data=b"abc")
    c.download_bytes("QmTest", expected_sha256=hashlib.sha256(b"abc").hexdigest())
    c.pin_file("QmTest")
    seen = {e for e, _ in calls}
    assert {"cat", "pin/add"} <= seen, seen
    for endpoint, kw in calls:
        assert kw.get("timeout") == 7.5, f"{endpoint} request sent without the client timeout"
