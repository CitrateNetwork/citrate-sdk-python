"""
SECREM-01 WEB-4 (pre-audit 2026-06-09): tests for the cleartext-transport
warning on remote http:// RPC/IPFS endpoints.
"""

import warnings

import pytest

from citrate_sdk._url_security import enforce_transport_security, InsecureTransportError
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
def test_remote_http_raises(url):
    # SPY-B-009: remote plaintext now FAILS CLOSED instead of warning-and-proceeding.
    with pytest.raises(InsecureTransportError) as ei:
        enforce_transport_security(url)
    assert "cleartext" in str(ei.value).lower()


def test_remote_http_opt_out_is_silent():
    # Explicit opt-in returns the URL unchanged with no warning and no raise.
    assert _warns("http://rpc.citrate.ai:8545", allow_insecure_http=True) == []
    assert (enforce_transport_security("http://rpc.citrate.ai:8545",
                                       allow_insecure_http=True)
            == "http://rpc.citrate.ai:8545")


def test_url_returned_unchanged():
    # We never implicitly rewrite the scheme — with the opt-in, the URL is
    # returned verbatim.
    url = "http://rpc.citrate.ai:8545"
    assert enforce_transport_security(url, allow_insecure_http=True) == url


# ── integration: constructors surface the warning ────────────────────────────

def test_client_remote_http_raises():
    # SPY-B-009: a remote plaintext RPC endpoint fails closed at construction.
    with pytest.raises(InsecureTransportError):
        CitrateClient(rpc_url="http://rpc.citrate.ai:8545")


def test_client_remote_http_opt_in_ok():
    # The opt-in still lets a caller who genuinely needs plaintext proceed.
    c = CitrateClient(rpc_url="http://rpc.citrate.ai:8545", allow_insecure_http=True)
    assert c.rpc_url == "http://rpc.citrate.ai:8545"


def test_client_localhost_is_silent():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        CitrateClient(rpc_url="http://localhost:8545")
    assert [w for w in caught if issubclass(w.category, UserWarning)] == []


def test_ipfs_remote_http_raises():
    # SPY-B-009: a remote plaintext IPFS API endpoint fails closed.
    with pytest.raises(InsecureTransportError):
        IPFSClient(api_url="http://ipfs.example.com:5001")
