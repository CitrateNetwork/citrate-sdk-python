"""PBA-L6b-026: transport gate bypassed by leading Unicode whitespace.

``"\\u00a0http://remote"`` parsed with an EMPTY scheme, so the gate returned it
unchecked; ``requests`` then stripped the whitespace and sent plaintext http to
the remote host. The gate now rejects whitespace/control characters anywhere in
the URL, allowlists {https, http}, and rejects an empty scheme; every gated
client uses the URL the gate returns.
"""
from __future__ import annotations

from typing import Any
from unittest import mock

import pytest
import requests

from citrate_sdk import CitrateClient
from citrate_sdk._url_security import InsecureTransportError, enforce_transport_security
from citrate_sdk.gateway import GatewayClient
from citrate_sdk.identity.client import IdentityClient
from citrate_sdk.ipfs import IPFSClient
from citrate_sdk.memory import MemoryClient

REMOTE = "http://rpc.attacker.example:8545"
PREFIXES = [" ", "\u00a0", "\u3000", "\u2003", "\x85", "\t", "\n", "\u200b", "\ufeff"]


@pytest.mark.parametrize("prefix", PREFIXES)
def test_leading_whitespace_or_control_is_refused(prefix: str) -> None:
    with pytest.raises(InsecureTransportError):
        enforce_transport_security(prefix + REMOTE)


@pytest.mark.parametrize("suffix", [" ", "\u00a0", "\r\n"])
def test_trailing_whitespace_is_refused(suffix: str) -> None:
    with pytest.raises(InsecureTransportError):
        enforce_transport_security("https://rpc.citrate.ai" + suffix)


@pytest.mark.parametrize("url", ["rpc.attacker.example:8545", "//rpc.attacker.example", "", "ftp://x.example",
                                 "ws://rpc.attacker.example", "file:///etc/passwd", "HTTP//x"])
def test_scheme_allowlist(url: str) -> None:
    with pytest.raises(InsecureTransportError):
        enforce_transport_security(url)


@pytest.mark.parametrize("url", ["https://rpc.citrate.ai", "HTTPS://rpc.citrate.ai/x", "http://localhost:8545",
                                 "http://127.0.0.1:5001"])
def test_good_urls_pass_unchanged(url: str) -> None:
    assert enforce_transport_security(url) == url


def test_uppercase_http_scheme_to_remote_is_still_refused() -> None:
    with pytest.raises(InsecureTransportError):
        enforce_transport_security("HTTP://rpc.attacker.example:8545")


def test_non_string_is_refused() -> None:
    with pytest.raises(InsecureTransportError):
        enforce_transport_security(None)  # type: ignore[arg-type]


@pytest.mark.parametrize("prefix", ["\u00a0", "\u3000"])
def test_rpc_client_never_sends_plaintext_via_whitespace(prefix: str) -> None:
    sent: dict[str, Any] = {}

    def fake_send(self: Any, request: Any, **kw: Any) -> requests.Response:
        sent["url"] = request.url
        r = requests.Response()
        r.status_code = 200
        r._content = b'{"jsonrpc":"2.0","id":1,"result":"0x9d0c"}'
        return r

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", fake_send):
        with pytest.raises(InsecureTransportError):
            CitrateClient(prefix + REMOTE)
    assert "url" not in sent


def _no_network(method: str, url: str, headers: Any, body: Any) -> Any:
    raise AssertionError(f"transport reached for {url!r}")


@pytest.mark.parametrize("make", [
    lambda u: IPFSClient(u),
    lambda u: GatewayClient("cgk_test", base_url=u),
    lambda u: MemoryClient(u),
    lambda u: IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb",
                             transport=_no_network)._get_json(u),
])
def test_every_gated_client_refuses_the_bypass(make: Any) -> None:
    with pytest.raises(InsecureTransportError):
        make("\u00a0" + REMOTE)
