"""deploy_and_verify through CitrateClient's real signer path on a local anvil.

Skipped unless ``CITRATE_VERIFY_ANVIL_RPC`` and ``CITRATE_VERIFY_ANVIL_KEY`` are set (start
``anvil --chain-id 40204`` and pass one of its funded dev keys; no key is stored here). The chain
is real; the explorer is a test-only recorder, since this checks what the SDK sends: the creation
transaction on chain must be exactly the build-info's creation code plus the encoded constructor
arguments, and the submission must name that transaction and those arguments.
"""
from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl

import pytest
import requests
from eth_abi import encode

from citrate_sdk import CitrateClient
from citrate_sdk.verify import deploy_and_verify

RPC = os.environ.get("CITRATE_VERIFY_ANVIL_RPC")
KEY = os.environ.get("CITRATE_VERIFY_ANVIL_KEY")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not (RPC and KEY), reason="CITRATE_VERIFY_ANVIL_RPC/KEY not set"),
]

FORGE_BI = Path(__file__).parent / "fixtures" / "verify" / "forge" / "build-info" / "970692f6b0ae96cc.json"


def _rpc(method: str, params: list[Any]) -> Any:
    r = requests.post(str(RPC), json={"jsonrpc": "2.0", "id": 1, "method": method, "params": params}, timeout=10)
    return r.json()["result"]


def test_deploy_from_forge_build_info_on_anvil() -> None:
    bodies: list[str] = []
    answers = [
        json.dumps({"status": "1", "message": "OK", "result": "guid-anvil"}),
        json.dumps({"status": "1", "message": "OK", "result": "Pass - Verified"}),
    ]

    class Handler(BaseHTTPRequestHandler):
        def _answer(self) -> None:
            n = int(self.headers.get("content-length") or 0)
            bodies.append(self.rfile.read(n).decode("utf-8"))
            data = (answers.pop(0) if len(answers) > 1 else answers[0]).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = _answer
        do_POST = _answer

        def log_message(self, *args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        bi = json.loads(FORGE_BI.read_text(encoding="utf-8"))
        client = CitrateClient(rpc_url=str(RPC), private_key=KEY, expected_genesis_hash=None)
        r = deploy_and_verify(
            client=client,
            chain_id=40204,
            build_info=bi,
            contract="src/Greeter.sol:Greeter",
            args=[7, "hello"],
            explorer_url=f"http://127.0.0.1:{server.server_address[1]}/api",
            poll_interval=0.01,
        )
        greeter = bi["output"]["contracts"]["src/Greeter.sol"]["Greeter"]
        encoded = encode(["uint256", "string"], [7, "hello"]).hex()
        tx = _rpc("eth_getTransactionByHash", [r.tx_hash])
        assert tx["input"] == "0x" + greeter["evm"]["bytecode"]["object"] + encoded
        assert len(_rpc("eth_getCode", [r.address, "latest"])) > 2
        submitted = dict(parse_qsl(bodies[0]))
        assert submitted["contractaddress"].lower() == r.address.lower()
        assert submitted["creationtxhash"] == r.tx_hash
        assert submitted["constructorArguements"] == encoded
        assert r.verification.status == "verified"
    finally:
        server.shutdown()
        server.server_close()
