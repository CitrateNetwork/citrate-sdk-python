"""PBA-L6b-030: IPFS download returned bytes with no content check and no size
bound (the whole body was buffered).

Now ``download_bytes`` streams with a ``max_bytes`` cap, verifies
``expected_sha256`` when given, and verifies self-describing CIDs it can check
locally (CIDv1 raw + sha2-256, and ``sha256:<hex>`` pointers the JS SDK emits).
A dag-pb CID (Qm..., bafybei...) cannot be recomputed from the bytes without
the chunking parameters, so for those the caller must pass ``expected_sha256``
(e.g. the on-chain model_hash) for end-to-end integrity; the docstring says so.
"""
from __future__ import annotations

import base64
import hashlib
from typing import Any
from unittest import mock

import pytest
import requests

from citrate_sdk.errors import IPFSError
from citrate_sdk.ipfs import IPFSClient, IPFSManager

DATA = b"model-bytes" * 100


def _raw_cid(data: bytes) -> str:
    mh = bytes([0x12, 0x20]) + hashlib.sha256(data).digest()
    cid = bytes([0x01, 0x55]) + mh
    return "b" + base64.b32encode(cid).decode().lower().rstrip("=")


def _serve(body: bytes, status: int = 200) -> Any:
    def post(url: str, params: Any = None, timeout: Any = None, stream: bool = False, **kw: Any) -> requests.Response:
        r = requests.Response()
        r.status_code = status
        r.raw = __import__("io").BytesIO(body)
        return r
    return post


def _client(body: bytes, status: int = 200) -> IPFSClient:
    c = IPFSClient("http://127.0.0.1:5001")
    c.session.post = _serve(body, status)  # type: ignore[method-assign]
    return c


def test_expected_sha256_mismatch_is_refused() -> None:
    with pytest.raises(IPFSError, match="sha256"):
        _client(b"tampered").download_bytes("QmWhatever", expected_sha256=hashlib.sha256(DATA).hexdigest())


def test_expected_sha256_match_returns_bytes() -> None:
    assert _client(DATA).download_bytes("QmWhatever", expected_sha256=hashlib.sha256(DATA).hexdigest()) == DATA


def test_raw_cid_is_verified_without_a_hint() -> None:
    cid = _raw_cid(DATA)
    assert _client(DATA).download_bytes(cid) == DATA
    with pytest.raises(IPFSError, match="does not match"):
        _client(b"tampered").download_bytes(cid)


def test_sha256_pointer_is_verified() -> None:
    ptr = "sha256:" + hashlib.sha256(DATA).hexdigest()
    assert _client(DATA).download_bytes(ptr) == DATA
    with pytest.raises(IPFSError, match="does not match"):
        _client(b"x").download_bytes(ptr)


def test_size_cap_stops_the_stream() -> None:
    with pytest.raises(IPFSError, match="exceeds max_bytes"):
        _client(b"a" * 1025).download_bytes("QmWhatever", max_bytes=1024, verify=False)
    assert _client(b"a" * 1024).download_bytes("QmWhatever", max_bytes=1024, verify=False) == b"a" * 1024


def test_default_cap_exists() -> None:
    c = _client(b"")
    with mock.patch("citrate_sdk.ipfs.DEFAULT_MAX_DOWNLOAD_BYTES", 10):
        with pytest.raises(IPFSError, match="exceeds max_bytes"):
            _client(b"a" * 11).download_bytes("QmWhatever", verify=False)
    assert c.download_bytes("QmWhatever", verify=False) == b""


def test_manager_threads_the_checks_through() -> None:
    m = IPFSManager("http://127.0.0.1:5001")
    m.primary.session.post = _serve(b"tampered")  # type: ignore[method-assign]
    m.primary.is_available = lambda: True  # type: ignore[method-assign]
    with pytest.raises(IPFSError):
        m.download("QmWhatever", expected_sha256=hashlib.sha256(DATA).hexdigest())
