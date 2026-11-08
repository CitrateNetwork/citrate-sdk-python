"""verify_contract / deploy_and_verify against the explorer's Etherscan-compatible API.

The HTTP server here is a test-only recorder (Rule 1 allows test fakes). The request shapes it
checks come from real tools: ``tests/fixtures/verify/*/...-requests.jsonl`` are the requests
forge 1.5.1 and hardhat-verify 2.1.3 sent to a recording server, and the build-info files were
written by those tools' compilers (see the README there).
"""
from __future__ import annotations

import json
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import pytest
from eth_abi import encode

import citrate_sdk
from citrate_sdk import CitrateClient
from citrate_sdk.errors import CitrateError
from citrate_sdk.verify import (
    DEFAULT_EXPLORER_URL,
    BuildInfoError,
    ExplorerResponseError,
    VerificationFailedError,
    VerificationRateLimitedError,
    VerificationRejectedError,
    VerificationTimeoutError,
    build_verify_source_code_form,
    check_verify_status,
    deploy_and_verify,
    load_build_info,
    parse_build_info,
    prepare_standard_json,
    verify_contract,
)

FX = Path(__file__).parent / "fixtures" / "verify"
FORGE_BI = FX / "forge" / "build-info" / "970692f6b0ae96cc.json"
HH_BI = FX / "hardhat" / "artifacts" / "build-info" / "dd99b6a8e0696988f72849c906423ccc.json"
HH_ARTIFACT = FX / "hardhat" / "artifacts" / "contracts" / "Greeter.sol" / "Greeter.json"
FORGE_ADDR = "0x5fbdb2315678afecb367f032d99f2f9fc9a2f74b"
HH_ADDR = "0xe7f1725E7734CE288F8367e1Bb143E90bb3F0512"
GUID = "5d1d6cbe-5f4d-4bd4-a1c9-2c1a1c5b1e01"

OK_GUID = json.dumps({"status": "1", "message": "OK", "result": GUID})
PENDING = json.dumps({"status": "0", "message": "NOTOK", "result": "Pending in queue"})
PASS = json.dumps({"status": "1", "message": "OK", "result": "Pass - Verified"})
FAIL = json.dumps({"status": "0", "message": "NOTOK", "result": "Fail - Unable to verify"})
LIMITED = json.dumps({"status": "0", "message": "NOTOK", "result": "Max rate limit reached"})
FAST: dict[str, Any] = {"poll_interval": 0.005, "timeout": 5.0, "rate_limit_backoff": 0.005, "rate_limit_retries": 2}


def _json(p: Path) -> Any:
    return json.loads(p.read_text(encoding="utf-8"))


def forge_bi() -> dict[str, Any]:
    return _json(FORGE_BI)


def recorded(name: str) -> list[tuple[str, str, list[tuple[str, str]]]]:
    out = []
    for line in (FX / name).read_text(encoding="utf-8").splitlines():
        v = json.loads(line)
        out.append((v["method"], v["path"], parse_qsl(v["body"], keep_blank_values=True)))
    return out


def normalized(fields: list[tuple[str, str]]) -> dict[str, Any]:
    return {k: (json.loads(v) if k == "sourceCode" else v) for k, v in fields}


def hardhat_post() -> list[tuple[str, str]]:
    return next(f for m, _, f in recorded("hardhat/hardhat-verify-2.1.3-requests.jsonl") if m == "POST")


# ---------------------------------------------------------------------------
# test-only HTTP recorder
# ---------------------------------------------------------------------------


@dataclass
class Seen:
    method: str
    path: str
    content_type: str | None
    body: str

    def query(self) -> dict[str, str]:
        return dict(parse_qsl(urlsplit(self.path).query, keep_blank_values=True))

    def form(self) -> dict[str, str]:
        return dict(parse_qsl(self.body, keep_blank_values=True))


class Recorder:
    def __init__(self, script: list[tuple[int, str]]):
        self.seen: list[Seen] = []
        self._script = list(script)
        rec = self

        class Handler(BaseHTTPRequestHandler):
            def _answer(self) -> None:
                n = int(self.headers.get("content-length") or 0)
                body = self.rfile.read(n).decode("utf-8")
                rec.seen.append(Seen(self.command, self.path, self.headers.get("content-type"), body))
                status, answer = rec._script.pop(0) if len(rec._script) > 1 else rec._script[0]
                data = answer.encode("utf-8")
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            do_GET = _answer
            do_POST = _answer

            def log_message(self, *args: Any) -> None:
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/api"
        self._thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def recorder() -> Iterator[Any]:
    made: list[Recorder] = []

    def make(script: list[tuple[int, str]]) -> Recorder:
        r = Recorder(script)
        made.append(r)
        return r

    yield make
    for r in made:
        r.close()


# ---------------------------------------------------------------------------
# build-info parsing
# ---------------------------------------------------------------------------


def test_forge_build_info_gives_forges_own_standard_json() -> None:
    s = prepare_standard_json(forge_bi(), "src/Greeter.sol:Greeter")
    assert s.contract_name == "src/Greeter.sol:Greeter"
    # forge writes solcLongVersion "0.8.26"; the commit comes from the contract metadata.
    assert s.compiler_version == "v0.8.26+commit.8a97fa7a"
    assert s.standard_json_input == _json(FX / "forge" / "standard-json-input.json")
    assert "src/Unrelated.sol" not in s.standard_json_input["sources"]
    for extra in ("version", "allowPaths", "basePath", "includePaths"):
        assert extra not in s.standard_json_input


def test_bare_name_resolves_and_unknown_is_refused() -> None:
    assert prepare_standard_json(forge_bi(), "Greeter").contract_name == "src/Greeter.sol:Greeter"
    with pytest.raises(BuildInfoError, match="not in this build-info"):
        prepare_standard_json(forge_bi(), "Nope")


def test_plain_forge_build_info_is_refused_with_the_fix() -> None:
    with pytest.raises(BuildInfoError, match="forge build --build-info"):
        parse_build_info(_json(FX / "forge" / "minimal-build-info.json"))


def test_hardhat_artifact_gives_what_hardhat_verify_submits() -> None:
    bi, contract = load_build_info(HH_ARTIFACT)
    assert contract == "contracts/Greeter.sol:Greeter"
    s = prepare_standard_json(bi, contract)
    assert s.compiler_version == "v0.8.26+commit.8a97fa7a"
    assert normalized(hardhat_post())["sourceCode"] == s.standard_json_input


def test_hardhat_build_info_with_bare_name() -> None:
    bi, contract = load_build_info(HH_BI)
    assert contract is None
    assert prepare_standard_json(bi, "Greeter").contract_name == "contracts/Greeter.sol:Greeter"


def test_hardhat_artifact_as_json_points_to_load_build_info() -> None:
    with pytest.raises(BuildInfoError, match="dbg.json"):
        parse_build_info(_json(HH_ARTIFACT))


def test_bare_standard_json_needs_qualified_name_and_long_version() -> None:
    std = _json(FX / "forge" / "standard-json-input.json")
    bi = parse_build_info(std)
    with pytest.raises(BuildInfoError, match="path:Name"):
        prepare_standard_json(bi, "Greeter", "v0.8.26+commit.8a97fa7a")
    with pytest.raises(BuildInfoError, match="compiler version"):
        prepare_standard_json(bi, "src/Greeter.sol:Greeter")
    with pytest.raises(BuildInfoError, match="commit"):
        prepare_standard_json(bi, "src/Greeter.sol:Greeter", "0.8.26")
    s = prepare_standard_json(bi, "src/Greeter.sol:Greeter", "0.8.26+commit.8a97fa7a")
    assert s.standard_json_input == std


def test_url_only_sources_are_refused() -> None:
    std = _json(FX / "forge" / "standard-json-input.json")
    std["sources"]["src/Counter.sol"] = {"urls": ["ipfs://x"]}
    with pytest.raises(BuildInfoError, match="inline content"):
        prepare_standard_json(parse_build_info(std), "src/Greeter.sol:Greeter", "v0.8.26+commit.8a97fa7a")


# ---------------------------------------------------------------------------
# request shape
# ---------------------------------------------------------------------------


def test_request_matches_what_forge_sends() -> None:
    sub = prepare_standard_json(forge_bi(), "src/Greeter.sol:Greeter")
    ours = build_verify_source_code_form(
        address=FORGE_ADDR,
        submission=sub,
        constructor_args="0x0000000000000000000000000000000000000000000000000000000000000007",
    )
    method, path, fields = recorded("forge/forge-1.5.1-custom-verifier-requests.jsonl")[0]
    assert (method, path) == ("POST", "/api")
    assert normalized(ours) == normalized(fields)


def test_constructor_arguements_spelling_without_0x() -> None:
    sub = prepare_standard_json(forge_bi(), "Greeter")
    f = dict(build_verify_source_code_form(address=FORGE_ADDR, submission=sub, constructor_args="0xABCD"))
    assert f["constructorArguements"] == "abcd"
    assert f["constructorArguments"] == "abcd"
    assert dict(build_verify_source_code_form(address=FORGE_ADDR, submission=sub, constructor_args=b"\x01"))[
        "constructorArguements"
    ] == "01"
    assert "constructorArguements" not in dict(build_verify_source_code_form(address=FORGE_ADDR, submission=sub))
    with pytest.raises(BuildInfoError):
        build_verify_source_code_form(address=FORGE_ADDR, submission=sub, constructor_args="0xabc")
    with pytest.raises(BuildInfoError):
        build_verify_source_code_form(address="0x1234", submission=sub)


# ---------------------------------------------------------------------------
# verify_contract against a recorder
# ---------------------------------------------------------------------------


def test_submit_poll_pending_to_pass(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID), (200, PENDING), (200, PENDING), (200, PASS)])
    r = verify_contract(
        chain_id=40204,
        address=FORGE_ADDR,
        build_info=forge_bi(),
        contract="src/Greeter.sol:Greeter",
        constructor_args="0x07",
        explorer_url=srv.url,
        api_key="citrate",
        **FAST,
    )
    assert (r.status, r.guid, r.message) == ("verified", GUID, "Pass - Verified")
    assert (r.contract_name, r.compiler_version) == ("src/Greeter.sol:Greeter", "v0.8.26+commit.8a97fa7a")
    assert len(srv.seen) == 4
    post = srv.seen[0]
    assert (post.method, post.path, post.content_type) == ("POST", "/api", "application/x-www-form-urlencoded")
    body = post.form()
    assert {k: body[k] for k in ("apikey", "chainid", "module", "action", "contractaddress", "codeformat",
                                 "contractname", "compilerversion", "constructorArguements")} == {
        "apikey": "citrate",
        "chainid": "40204",
        "module": "contract",
        "action": "verifysourcecode",
        "contractaddress": FORGE_ADDR,
        "codeformat": "solidity-standard-json-input",
        "contractname": "src/Greeter.sol:Greeter",
        "compilerversion": "v0.8.26+commit.8a97fa7a",
        "constructorArguements": "07",
    }
    for s in srv.seen[1:]:
        assert s.method == "GET"
        assert s.query() == {
            "apikey": "citrate",
            "chainid": "40204",
            "module": "contract",
            "action": "checkverifystatus",
            "guid": GUID,
        }


def test_sends_what_hardhat_verify_sends(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID)])
    bi, contract = load_build_info(HH_ARTIFACT)
    assert contract is not None
    hh = dict(hardhat_post())
    verify_contract(
        chain_id=40204,
        address=HH_ADDR,
        build_info=bi,
        contract=contract,
        constructor_args=hh["constructorArguements"],
        explorer_url=srv.url,
        api_key="citrate",
        wait=False,
    )
    ours = normalized(parse_qsl(srv.seen[0].body, keep_blank_values=True))
    assert ours.pop("chainid") == "40204"
    assert ours.pop("constructorArguments") == hh["constructorArguements"]
    assert ours == normalized(hardhat_post())


def test_wait_false_returns_guid_without_polling(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID)])
    r = verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=srv.url, wait=False)
    assert (r.status, r.guid) == ("pending", GUID)
    assert len(srv.seen) == 1
    assert "apikey" not in srv.seen[0].form()


def test_accepts_standard_json_input(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID), (200, PASS)])
    r = verify_contract(
        chain_id=40204,
        address=FORGE_ADDR,
        standard_json_input=_json(FX / "forge" / "standard-json-input.json"),
        contract="src/Greeter.sol:Greeter",
        compiler_version="v0.8.26+commit.8a97fa7a",
        explorer_url=srv.url,
        **FAST,
    )
    assert r.status == "verified"


def test_fail_verdict_raises_typed(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID), (200, PENDING), (200, FAIL)])
    with pytest.raises(VerificationFailedError) as e:
        verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=srv.url, **FAST)
    assert (e.value.guid, e.value.result, e.value.error_code) == (GUID, "Fail - Unable to verify", "VERIFY_FAILED")


def test_poll_times_out_with_last_status(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID), (200, PENDING)])
    with pytest.raises(VerificationTimeoutError) as e:
        verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=srv.url, poll_interval=0.005, timeout=0.06)
    assert (e.value.guid, e.value.last_status) == (GUID, "Pending in queue")


def test_already_verified_is_a_result(recorder: Any) -> None:
    srv = recorder([(200, json.dumps({"status": "0", "message": "NOTOK",
                                       "result": "Contract source code already verified"}))])
    r = verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=srv.url)
    assert r.status == "already_verified"


def test_other_refusals_raise_with_explorer_string(recorder: Any) -> None:
    msg = f"Unable to locate ContractCode at {FORGE_ADDR}"
    srv = recorder([(200, json.dumps({"status": "0", "message": "NOTOK", "result": msg}))])
    with pytest.raises(VerificationRejectedError) as e:
        verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=srv.url)
    assert e.value.result == msg


def test_rate_limit_is_retried_then_typed(recorder: Any) -> None:
    ok = recorder([(429, LIMITED), (200, OK_GUID)])
    r = verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=ok.url, wait=False, **FAST)
    assert r.status == "pending"
    assert len(ok.seen) == 2
    never = recorder([(429, LIMITED)])
    with pytest.raises(VerificationRateLimitedError):
        verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url=never.url, **FAST)
    assert len(never.seen) == 3


def test_non_envelope_answers_raise(recorder: Any) -> None:
    bad = recorder([(502, "bad gateway")])
    with pytest.raises(ExplorerResponseError) as e:
        check_verify_status("g", explorer_url=bad.url)
    assert e.value.http_status == 502
    odd = recorder([(200, '{"verified": true}')])
    with pytest.raises(ExplorerResponseError):
        check_verify_status("g", explorer_url=odd.url)


def test_refuses_plaintext_remote_and_bad_params_before_sending() -> None:
    with pytest.raises(ValueError, match="(?i)http"):
        verify_contract(chain_id=40204, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter",
                        explorer_url="http://explorer.example.com/api")
    with pytest.raises(BuildInfoError):
        verify_contract(chain_id=0, address=FORGE_ADDR, build_info=forge_bi(), contract="Greeter")
    with pytest.raises(BuildInfoError):
        verify_contract(chain_id=40204, address=FORGE_ADDR, contract="Greeter")


def test_default_url_and_package_exports() -> None:
    assert DEFAULT_EXPLORER_URL == "https://explorer.citrate.ai/api"
    assert citrate_sdk.verify_contract is verify_contract
    assert citrate_sdk.deploy_and_verify is deploy_and_verify
    for name in ("verify_contract", "deploy_and_verify", "VerificationError", "BuildInfoError"):
        assert name in citrate_sdk.__all__


# ---------------------------------------------------------------------------
# deploy_and_verify
# ---------------------------------------------------------------------------

DEPLOYED = "0x00000000000000000000000000000000000000d1"
TX = "0x" + "ab" * 32


class RecordingDeployer:
    """Test-only deployer that records what it was asked to send."""

    def __init__(self) -> None:
        self.sent: list[tuple[str, int, int | None]] = []

    def deploy_contract(self, data: str, value: int = 0, gas_limit: int | None = None) -> dict[str, Any]:
        self.sent.append((data, value, gas_limit))
        return {"address": DEPLOYED, "tx_hash": TX, "block_number": 1}


def test_deploy_then_verify_with_creation_tx(recorder: Any) -> None:
    srv = recorder([(200, OK_GUID), (200, PASS)])
    bi = forge_bi()
    d = RecordingDeployer()
    r = deploy_and_verify(client=d, chain_id=40204, build_info=bi, contract="Greeter", args=[7, "hello"],
                          explorer_url=srv.url, **FAST)
    greeter = bi["output"]["contracts"]["src/Greeter.sol"]["Greeter"]
    encoded = encode(["uint256", "string"], [7, "hello"]).hex()
    assert d.sent == [("0x" + greeter["evm"]["bytecode"]["object"] + encoded, 0, None)]
    assert (r.address, r.tx_hash, r.verification.status, r.verification.guid) == (DEPLOYED, TX, "verified", GUID)
    body = srv.seen[0].form()
    assert body["contractaddress"] == DEPLOYED
    assert body["creationtxhash"] == TX
    assert body["constructorArguements"] == encoded
    assert body["contractname"] == "src/Greeter.sol:Greeter"


def test_deploy_retries_until_indexed(recorder: Any) -> None:
    not_yet = json.dumps({"status": "0", "message": "NOTOK", "result": f"Unable to locate ContractCode at {DEPLOYED}"})
    srv = recorder([(200, not_yet), (200, not_yet), (200, OK_GUID), (200, PASS)])
    r = deploy_and_verify(client=RecordingDeployer(), chain_id=40204, build_info=forge_bi(), contract="Greeter",
                          args=[1, "x"], explorer_url=srv.url, **FAST)
    assert r.verification.status == "verified"
    assert len([s for s in srv.seen if s.method == "POST"]) == 3


def test_deploy_refuses_bad_inputs_before_sending() -> None:
    d = RecordingDeployer()
    with pytest.raises(BuildInfoError):
        deploy_and_verify(client=d, chain_id=40204, build_info=forge_bi(), contract="Greeter",
                          args=[1, "x"], constructor_args="0x00")
    with pytest.raises(BuildInfoError, match="argument"):
        deploy_and_verify(client=d, chain_id=40204, build_info=forge_bi(), contract="Greeter", args=[1])
    linked = forge_bi()
    linked["output"]["contracts"]["src/Greeter.sol"]["Greeter"]["evm"]["bytecode"]["object"] = (
        "6080__$0123456789abcdef0123456789abcdef01$__"
    )
    with pytest.raises(BuildInfoError, match="unlinked"):
        deploy_and_verify(client=d, chain_id=40204, build_info=linked, contract="Greeter")
    assert d.sent == []


def test_client_deploy_contract_needs_a_key_and_hex() -> None:
    c = CitrateClient(rpc_url="http://127.0.0.1:1", expected_genesis_hash=None)
    with pytest.raises(CitrateError, match="Private key"):
        c.deploy_contract("0x6080")
    with pytest.raises(CitrateError, match="hex"):
        c.deploy_contract("6080")
