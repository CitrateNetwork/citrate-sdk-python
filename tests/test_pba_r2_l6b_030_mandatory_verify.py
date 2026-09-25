"""IPFS hardening (PBA-L6b-030 follow-up): verification is mandatory.

A download whose address cannot verify its own content requires
``expected_sha256``, or an explicit ``verify=False`` opt-out that logs a
warning.
"""
from __future__ import annotations

import hashlib
import io
import logging
from typing import Any
from unittest import mock

import pytest
import requests

from citrate_sdk.errors import IPFSError
from citrate_sdk.ipfs import IPFSClient, IPFSManager, download_from_ipfs

EVIL = b"ATTACKER-BYTES"
DAG_PB = ["QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
          "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi"]


def _client(body: bytes = EVIL) -> IPFSClient:
    c = IPFSClient("http://127.0.0.1:5001")

    def post(url: str, params: Any = None, timeout: Any = None, stream: bool = False) -> requests.Response:
        r = requests.Response()
        r.status_code = 200
        r.raw = io.BytesIO(body)
        return r
    c.session.post = post  # type: ignore[method-assign,assignment]
    return c


@pytest.mark.parametrize("cid", DAG_PB)
def test_unverifiable_cid_without_hash_is_refused(cid: str) -> None:
    with pytest.raises(IPFSError, match="expected_sha256"):
        _client().download_bytes(cid)


@pytest.mark.parametrize("cid", DAG_PB)
def test_expected_sha256_still_works(cid: str) -> None:
    assert _client().download_bytes(cid, expected_sha256=hashlib.sha256(EVIL).hexdigest()) == EVIL
    with pytest.raises(IPFSError, match="does not match"):
        _client().download_bytes(cid, expected_sha256="00" * 32)


def test_explicit_opt_out_returns_bytes_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="citrate_sdk.ipfs"):
        assert _client().download_bytes(DAG_PB[0], verify=False) == EVIL
    assert any("UNVERIFIED" in r.getMessage() and DAG_PB[0] in r.getMessage() for r in caplog.records)


def test_opt_out_does_not_skip_a_supplied_hash_or_the_cap() -> None:
    with pytest.raises(IPFSError, match="does not match"):
        _client().download_bytes(DAG_PB[0], verify=False, expected_sha256="00" * 32)
    with pytest.raises(IPFSError, match="exceeds max_bytes"):
        _client().download_bytes(DAG_PB[0], verify=False, max_bytes=3)


def test_manager_and_helper_enforce_it_too() -> None:
    m = IPFSManager("http://127.0.0.1:5001")
    m.primary = _client()
    m.primary.is_available = lambda: True  # type: ignore[method-assign]
    with pytest.raises(IPFSError, match="expected_sha256"):
        m.download(DAG_PB[0])
    assert m.download(DAG_PB[0], verify=False) == EVIL
    with mock.patch("citrate_sdk.ipfs.get_ipfs_manager", return_value=m):
        with pytest.raises(IPFSError, match="expected_sha256"):
            download_from_ipfs(DAG_PB[1])
        assert download_from_ipfs(DAG_PB[1], verify=False) == EVIL


def test_refusal_happens_before_any_request() -> None:
    c = IPFSClient("http://127.0.0.1:5001")
    calls: list[Any] = []
    c.session.post = lambda *a, **k: calls.append(a)  # type: ignore[method-assign,assignment]
    with pytest.raises(IPFSError, match="expected_sha256"):
        c.download_bytes(DAG_PB[0])
    assert calls == []
