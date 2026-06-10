"""
SECREM-01 WEB-4 (pre-audit 2026-06-09): tests for the cleartext-transport
warning on remote http:// RPC/IPFS endpoints.
"""

import warnings

import pytest

from citrate_sdk._url_security import enforce_transport_security
from citrate_sdk import CitrateClient
from citrate_sdk.ipfs import IPFSClient


def _warns(url, **kwargs):
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        enforce_transport_security(url, **kwargs)
    return [w for w in caught if issubclass(w.category, UserWarning)]


# ── helper-level ─────────────────────────────────────────────────────────────

@pytest.mark.parametrize("url", [
    "http://localhost:8545",
    "http://127.0.0.1:5001",
    "http://[::1]:8545",
    "http://localhost",
])
def test_local_http_is_silent(url):
    assert _warns(url) == []


@pytest.mark.parametrize("url", [
    "https://rpc.citrate.ai",
    "https://gateway.example.com:5001",
])
def test_remote_https_is_silent(url):
    assert _warns(url) == []


@pytest.mark.parametrize("url", [
    "http://rpc.citrate.ai:8545",
    "http://203.0.113.5:8545",
    "http://node.example.com/rpc",
])
def test_remote_http_warns(url):
    caught = _warns(url)
    assert len(caught) == 1
    assert "cleartext" in str(caught[0].message).lower()


def test_remote_http_opt_out_is_silent():
    assert _warns("http://rpc.citrate.ai:8545", allow_insecure_http=True) == []


def test_url_returned_unchanged():
    # We never implicitly rewrite the scheme.
    url = "http://rpc.citrate.ai:8545"
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        assert enforce_transport_security(url) == url


# ── integration: constructors surface the warning ────────────────────────────

def test_client_remote_http_warns():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CitrateClient(rpc_url="http://rpc.citrate.ai:8545")
    assert any(issubclass(w.category, UserWarning) for w in caught)


def test_client_localhost_is_silent():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CitrateClient(rpc_url="http://localhost:8545")
    assert [w for w in caught if issubclass(w.category, UserWarning)] == []


def test_ipfs_remote_http_warns():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        IPFSClient(api_url="http://ipfs.example.com:5001")
    assert any(issubclass(w.category, UserWarning) for w in caught)
