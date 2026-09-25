"""Transport-gate hardening (PBA-L6b-026 follow-up).

The gate must judge the same host the HTTP stack will connect to. It refuses
characters outside RFC 3986 and any userinfo, and requires urllib3 (what
requests uses) and urllib.parse to agree on the host. The live test runs a
real listener on this host's non-loopback address and checks that a refused
URL never reaches it.
"""
from __future__ import annotations

import http.server
import json
import socket
import threading
from typing import Any
from unittest import mock

import pytest
import requests

from citrate_sdk import CitrateClient
from citrate_sdk._url_security import InsecureTransportError, enforce_transport_security
from citrate_sdk.gateway import GatewayClient
from citrate_sdk.identity import wallet
from citrate_sdk.ipfs import IPFSClient
from citrate_sdk.memory import MemoryClient

BYPASSES = [
    "http://evil.com\\@localhost",
    "http://evil.com\\@127.0.0.1:8545",
    "http://evil.com:8545\\x@localhost",
    "http://evil.com\\@[::1]:8545",
    "https://evil.com\\@localhost",
    "http://localhost\\@evil.com",
    "http://u:p@localhost:8545",
    "http://evil.com@localhost",
    "http://localhost@evil.com",
    "http://[::1]@evil.com",
    "http://evil.com%5C@localhost",
    "http://evil.com^@localhost",
    "http://evil.com`@localhost",
    "http://ev{il}.com",
    "http://evil.com|x@localhost",
    'http://evil.com"@localhost',
    "http://evil.com<x>@localhost",
]


@pytest.mark.parametrize("url", BYPASSES)
def test_parser_differential_inputs_are_refused(url: str) -> None:
    with pytest.raises(InsecureTransportError):
        enforce_transport_security(url)
    with pytest.raises(InsecureTransportError):
        enforce_transport_security(url, allow_insecure_http=True)


@pytest.mark.parametrize("url", [
    "http://localhost:8545", "http://127.0.0.1:5001/api", "http://[::1]:8545", "https://rpc.citrate.ai",
    "https://rpc.citrate.ai/path?q=1&x=%20#frag", "HTTPS://RPC.CITRATE.AI", "https://rpc.citrate.ai:443/a-b_c.d~e",
])
def test_ordinary_urls_still_pass(url: str) -> None:
    assert enforce_transport_security(url) == url


def test_remote_http_opt_in_still_works() -> None:
    assert enforce_transport_security("http://10.0.0.5:8545", allow_insecure_http=True) == "http://10.0.0.5:8545"


def test_client_never_sends_to_the_urllib3_host() -> None:
    sent: list[str] = []

    def fake_send(self: Any, request: Any, **kw: Any) -> requests.Response:
        sent.append(request.url)
        r = requests.Response()
        r.status_code = 200
        r._content = b'{"jsonrpc":"2.0","id":1,"result":"0x9d0c"}'
        return r

    with mock.patch.object(requests.adapters.HTTPAdapter, "send", fake_send):
        with pytest.raises(InsecureTransportError):
            CitrateClient("http://evil.com\\@localhost").get_chain_id()
    assert sent == []


def _non_loopback_ipv4() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1; UDP connect sends nothing
        return str(s.getsockname()[0])
    finally:
        s.close()


def test_live_listener_on_a_non_loopback_address_receives_nothing() -> None:
    """Live check against a real listener on a non-loopback address: refused
    URLs never reach it; the explicit opt-in path does (so the listener works)."""
    ip = _non_loopback_ipv4()
    assert not ip.startswith("127."), ip
    hits: list[str] = []

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            hits.append(self.path)
            body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": "0x9d0c"}).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a: Any) -> None:
            pass

    srv = http.server.HTTPServer((ip, 0), H)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        # Sanity: the plain remote URL is refused by the gate.
        with pytest.raises(InsecureTransportError):
            CitrateClient(f"http://{ip}:{port}")
        # A mixed-parser URL must be refused, and nothing may reach the listener.
        with pytest.raises(InsecureTransportError):
            CitrateClient(f"http://{ip}:{port}\\@localhost").get_chain_id()
        # And the opt-in path really does reach it (the listener works).
        assert CitrateClient(f"http://{ip}:{port}", allow_insecure_http=True).get_chain_id() == 40204
        assert hits == ["/"]
    finally:
        srv.shutdown()
        srv.server_close()


@pytest.mark.parametrize("make", [
    lambda u: IPFSClient(u),
    lambda u: GatewayClient("cgk_test", base_url=u),
    lambda u: MemoryClient(u),
])
def test_every_gated_client_refuses_the_backslash_form(make: Any) -> None:
    with pytest.raises(InsecureTransportError):
        make("http://evil.com\\@localhost")


def test_wallet_verification_inherits_the_fix() -> None:
    """PBA-L6b-027 re-test: verify_wallet_address_on_chain uses the same gate."""
    calls: list[Any] = []
    with mock.patch.object(wallet.requests, "post", lambda *a, **k: calls.append(a)):
        with pytest.raises(InsecureTransportError):
            wallet.verify_wallet_address_on_chain("0x" + "42" * 32, rpc_url="http://evil.com\\@localhost:8545")
    assert calls == []
