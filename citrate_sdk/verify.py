"""
Contract source verification on CitrateScan (chain 40204).

Data source: the explorer's Etherscan-compatible API, ``GET|POST <explorer_url>`` (default
``https://explorer.citrate.ai/api``), ``module=contract`` with the actions ``verifysourcecode``
(form-encoded POST) and ``checkverifystatus`` (GET). Every answer is Etherscan's
``{"status": "1" | "0", "message": ..., "result": ...}`` envelope.

The request shape is the one forge 1.5.1 (``--verifier custom``) and hardhat-verify 2.1.3 send;
``tests/fixtures/verify/`` holds their recorded requests and the tests compare against them.

Input is a compiler build-info (forge ``out/build-info/<id>.json`` written with
``forge build --build-info``, or hardhat ``artifacts/build-info/<id>.json``), a hardhat contract
artifact (via :func:`load_build_info`) or a solc standard JSON input. As forge and hardhat-verify
do, only the sources listed in the contract's metadata are submitted.
"""

from __future__ import annotations

import json
import re
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, Protocol
from urllib.parse import urlencode

import requests

from ._url_security import enforce_transport_security
from .errors import CitrateError

DEFAULT_EXPLORER_URL = "https://explorer.citrate.ai/api"
#: Explorer limits (CitrateScan docs, "Limits").
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_SOURCE_FILES = 64

_HEX = re.compile(r"^[0-9a-fA-F]*$")
_ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class VerificationError(CitrateError):
    """Base class for verification errors."""


class BuildInfoError(VerificationError):
    """The build-info or parameters cannot produce a submission. Nothing was sent."""

    def __init__(self, message: str):
        super().__init__(message, "VERIFY_BAD_INPUT")


class VerificationRejectedError(VerificationError):
    """The explorer refused the submission; ``result`` is Etherscan's string."""

    def __init__(self, result: str):
        super().__init__(f"explorer refused the submission: {result}", "VERIFY_REJECTED", {"result": result})
        self.result = result


class VerificationRateLimitedError(VerificationError):
    """``Max rate limit reached``, after the configured retries."""

    def __init__(self, result: str):
        super().__init__(f"explorer rate limit: {result}", "VERIFY_RATE_LIMITED", {"result": result})
        self.result = result


class VerificationFailedError(VerificationError):
    """The explorer compiled the source and it does not match the code on chain."""

    def __init__(self, guid: str, result: str):
        super().__init__(
            f"verification failed: {result} (guid {guid})", "VERIFY_FAILED", {"guid": guid, "result": result}
        )
        self.guid = guid
        self.result = result


class VerificationTimeoutError(VerificationError):
    """No verdict before the deadline. The job may still finish; poll ``guid`` later."""

    def __init__(self, guid: str, last_status: str):
        super().__init__(
            f"no verdict for {guid} before the deadline (last: {last_status})",
            "VERIFY_TIMEOUT",
            {"guid": guid, "last_status": last_status},
        )
        self.guid = guid
        self.last_status = last_status


class ExplorerResponseError(VerificationError):
    """The explorer could not be reached, or answered outside the documented envelope."""

    def __init__(self, message: str, http_status: int | None = None):
        super().__init__(message, "VERIFY_EXPLORER_RESPONSE", {"http_status": http_status})
        self.http_status = http_status


# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PreparedSubmission:
    standard_json_input: dict[str, Any]
    #: Fully qualified, ``path/To.sol:Name``.
    contract_name: str
    #: ``v0.8.26+commit.8a97fa7a``.
    compiler_version: str


@dataclass(frozen=True)
class VerifyStatus:
    state: Literal["pending", "verified", "failed"]
    message: str


@dataclass(frozen=True)
class VerifyResult:
    #: ``verified`` after ``Pass - Verified``; ``already_verified`` when the explorer already has a
    #: record; ``pending`` when called with ``wait=False``.
    status: Literal["verified", "already_verified", "pending"]
    message: str
    contract_name: str
    compiler_version: str
    guid: str | None = None


@dataclass(frozen=True)
class DeployAndVerifyResult:
    address: str
    tx_hash: str
    verification: VerifyResult


class ContractDeployer(Protocol):
    """What :func:`deploy_and_verify` needs; :class:`citrate_sdk.CitrateClient` provides it."""

    def deploy_contract(
        self, data: str, value: int = 0, gas_limit: int | None = None
    ) -> dict[str, Any]: ...


# ---------------------------------------------------------------------------
# Build-info parsing
# ---------------------------------------------------------------------------


def parse_build_info(obj: Any) -> dict[str, Any]:
    """Accept a forge or hardhat build-info, or a bare standard JSON input, as a build-info dict.

    A bare input is returned as ``{"input": obj}`` (no ``output``).
    """
    if not isinstance(obj, dict):
        raise BuildInfoError("build-info is not a JSON object")
    if obj.get("_format") == "hh-sol-artifact-1":
        raise BuildInfoError(
            "this is a hardhat contract artifact; pass the build-info its .dbg.json names "
            "(or use load_build_info(path))"
        )
    if isinstance(obj.get("input"), dict):
        return obj
    if "source_id_to_path" in obj:
        raise BuildInfoError(
            "this forge build-info has no compiler input; rebuild with `forge build --build-info` "
            "(or build_info = true in foundry.toml)"
        )
    if isinstance(obj.get("sources"), dict) and isinstance(obj.get("language"), str):
        return {"input": obj}
    raise BuildInfoError("not a forge or hardhat build-info or a standard JSON input")


def _read_json(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise BuildInfoError(f"cannot read {path}: {e}") from e


def load_build_info(path: str | Path) -> tuple[dict[str, Any], str | None]:
    """Read a build-info from disk.

    Also accepts a hardhat contract artifact (``artifacts/<path>/<Name>.json``) and follows its
    ``.dbg.json`` to the build-info. Returns ``(build_info, contract)``; ``contract`` is the
    artifact's ``sourceName:contractName`` for an artifact, else ``None``.
    """
    p = Path(path)
    obj = _read_json(p)
    if isinstance(obj, dict) and obj.get("_format") == "hh-sol-artifact-1":
        source_name, contract_name = obj.get("sourceName"), obj.get("contractName")
        if not isinstance(source_name, str) or not isinstance(contract_name, str):
            raise BuildInfoError("hardhat artifact has no sourceName/contractName")
        dbg_path = p.with_name(p.stem + ".dbg.json")
        dbg = _read_json(dbg_path)
        rel = dbg.get("buildInfo") if isinstance(dbg, dict) else None
        if not isinstance(rel, str):
            raise BuildInfoError(f"{dbg_path} names no buildInfo")
        bi = parse_build_info(_read_json((dbg_path.parent / rel).resolve()))
        return bi, f"{source_name}:{contract_name}"
    return parse_build_info(obj), None


def normalize_compiler_version(version: str) -> str:
    """``0.8.26+commit.8a97fa7a`` or ``v0.8.26+commit.8a97fa7a`` → ``v0.8.26+commit.8a97fa7a``."""
    t = version.strip().removeprefix("v")
    if "+commit." not in t:
        raise BuildInfoError(
            f"compiler version {version!r} lacks the commit; use e.g. v0.8.26+commit.8a97fa7a"
        )
    return "v" + t


def normalize_constructor_args(args: str | bytes) -> str:
    """Validate ABI-encoded constructor arguments; return lowercase hex without ``0x``."""
    if isinstance(args, bytes):
        return args.hex()
    t = args.strip()
    if t[:2].lower() == "0x":
        t = t[2:]
    if len(t) % 2 or not _HEX.match(t):
        raise BuildInfoError("constructor_args must be ABI-encoded hex")
    return t.lower()


def _contracts(bi: dict[str, Any]) -> dict[str, Any] | None:
    out = bi.get("output")
    c = out.get("contracts") if isinstance(out, dict) else None
    return c if isinstance(c, dict) else None


def _resolve_contract(bi: dict[str, Any], wanted: str) -> tuple[str, str]:
    contracts = _contracts(bi)
    if ":" in wanted:
        path, name = wanted.rsplit(":", 1)
        if contracts is not None and name not in (contracts.get(path) or {}):
            raise BuildInfoError(f"contract {wanted} is not in this build-info")
        return path, name
    if contracts is None:
        raise BuildInfoError("a standard JSON input carries no contract list; pass contract as path:Name")
    hits = [(p, n) for p, f in contracts.items() if isinstance(f, dict) for n in f if n == wanted]
    if len(hits) == 1:
        return hits[0]
    if not hits:
        raise BuildInfoError(f"contract {wanted} is not in this build-info")
    raise BuildInfoError(f"several contracts are named {wanted}: " + ", ".join(f"{p}:{n}" for p, n in hits))


def _metadata(bi: dict[str, Any], path: str, name: str) -> dict[str, Any] | None:
    raw = ((_contracts(bi) or {}).get(path) or {}).get(name, {}).get("metadata")
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
        except ValueError as e:
            raise BuildInfoError(f"metadata of {path}:{name} is not JSON") from e
        return parsed if isinstance(parsed, dict) else None
    return raw if isinstance(raw, dict) else None


def prepare_standard_json(
    build_info: dict[str, Any], contract: str, compiler_version: str | None = None
) -> PreparedSubmission:
    """The standard JSON input, fully qualified name and compiler version for one contract.

    The compiler version comes from the contract metadata (forge writes ``solcLongVersion``
    without the commit) unless ``compiler_version`` is given.
    """
    bi = parse_build_info(build_info)
    path, name = _resolve_contract(bi, contract)
    meta = _metadata(bi, path, name)
    meta_compiler = (meta or {}).get("compiler")
    version = compiler_version or (
        meta_compiler.get("version") if isinstance(meta_compiler, dict) else None
    ) or bi.get("solcLongVersion")
    if not isinstance(version, str) or not version:
        raise BuildInfoError("no compiler version in the build-info; pass compiler_version")

    inp = bi["input"]
    all_sources = inp.get("sources")
    if not isinstance(all_sources, dict):
        raise BuildInfoError("standard JSON input has no sources")
    meta_sources = (meta or {}).get("sources")
    keep = list(meta_sources) if isinstance(meta_sources, dict) else list(all_sources)
    sources: dict[str, Any] = {}
    for key in keep:
        src = all_sources.get(key)
        if not isinstance(src, dict):
            raise BuildInfoError(f"source {key} is in the metadata but not in the input")
        if not isinstance(src.get("content"), str):
            raise BuildInfoError(f"source {key} has no inline content (the explorer does not fetch urls)")
        sources[key] = src
    if len(sources) > MAX_SOURCE_FILES:
        raise BuildInfoError(f"{len(sources)} source files; the explorer accepts at most {MAX_SOURCE_FILES}")

    settings = dict(inp.get("settings") or {})
    sel = settings.get("outputSelection")
    if isinstance(sel, dict) and "*" not in sel and sel:
        # forge keys outputSelection by file; the pruned input uses one "*" entry.
        settings["outputSelection"] = {"*": next(iter(sel.values()))}
    settings.setdefault("libraries", {})

    std = {
        "language": inp.get("language") if isinstance(inp.get("language"), str) else "Solidity",
        "sources": sources,
        "settings": settings,
    }
    size = len(json.dumps(std, separators=(",", ":")).encode("utf-8"))
    if size > MAX_SOURCE_BYTES:
        raise BuildInfoError(f"standard JSON input is {size} bytes; the explorer accepts at most {MAX_SOURCE_BYTES}")
    return PreparedSubmission(std, f"{path}:{name}", normalize_compiler_version(version))


# ---------------------------------------------------------------------------
# Request shape
# ---------------------------------------------------------------------------


def build_verify_source_code_form(
    *,
    address: str,
    submission: PreparedSubmission,
    constructor_args: str | bytes | None = None,
    creation_tx_hash: str | None = None,
    chain_id: int | None = None,
    api_key: str | None = None,
) -> list[tuple[str, str]]:
    """The ``verifysourcecode`` form fields, in the order forge sends them.

    Constructor arguments go out as both ``constructorArguements`` (Etherscan's spelling) and
    ``constructorArguments``.
    """
    if not _ADDRESS.match(address):
        raise BuildInfoError(f"address {address!r} is not 20 bytes of hex")
    f: list[tuple[str, str]] = []
    if api_key:
        f.append(("apikey", api_key))
    if chain_id is not None:
        f.append(("chainid", str(chain_id)))
    f += [
        ("module", "contract"),
        ("action", "verifysourcecode"),
        ("contractaddress", address),
        ("sourceCode", json.dumps(submission.standard_json_input, separators=(",", ":"))),
        ("codeformat", "solidity-standard-json-input"),
        ("contractname", submission.contract_name),
        ("compilerversion", normalize_compiler_version(submission.compiler_version)),
    ]
    if constructor_args:
        hx = normalize_constructor_args(constructor_args)
        f += [("constructorArguements", hx), ("constructorArguments", hx)]
    if creation_tx_hash:
        f.append(("creationtxhash", creation_tx_hash))
    return f


# ---------------------------------------------------------------------------
# Explorer calls
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Envelope:
    ok: bool
    message: str
    result: Any

    @property
    def text(self) -> str:
        return self.result if isinstance(self.result, str) else json.dumps(self.result)


def _is_rate_limit(text: str) -> bool:
    return "rate limit" in text.lower()


class _Explorer:
    def __init__(
        self,
        explorer_url: str,
        api_key: str | None,
        chain_id: int | None,
        allow_insecure_http: bool,
        session: requests.Session | None,
        request_timeout: float,
    ):
        self.url = enforce_transport_security(explorer_url, allow_insecure_http=allow_insecure_http)
        self.api_key = api_key or None
        self.chain_id = chain_id
        self.session = session or requests.Session()
        self.request_timeout = request_timeout

    def _parse(self, resp: requests.Response) -> _Envelope:
        try:
            body = resp.json()
        except ValueError:
            body = None
        if isinstance(body, dict) and isinstance(body.get("status"), (str, int)):
            return _Envelope(str(body["status"]) == "1", str(body.get("message") or ""), body.get("result"))
        if not resp.ok:
            raise ExplorerResponseError(f"explorer answered HTTP {resp.status_code}: {resp.text[:300]}", resp.status_code)
        raise ExplorerResponseError(f"unexpected explorer answer: {resp.text[:300]}", resp.status_code)

    def post_form(self, form: list[tuple[str, str]]) -> _Envelope:
        try:
            resp = self.session.post(
                self.url,
                data=urlencode(form),
                headers={"content-type": "application/x-www-form-urlencoded"},
                timeout=self.request_timeout,
            )
        except requests.RequestException as e:
            raise ExplorerResponseError(f"could not reach the explorer: {e}") from e
        return self._parse(resp)

    def get(self, pairs: list[tuple[str, str]]) -> _Envelope:
        q: list[tuple[str, str]] = []
        if self.api_key:
            q.append(("apikey", self.api_key))
        if self.chain_id is not None:
            q.append(("chainid", str(self.chain_id)))
        q += pairs
        try:
            resp = self.session.get(self.url + "?" + urlencode(q), timeout=self.request_timeout)
        except requests.RequestException as e:
            raise ExplorerResponseError(f"could not reach the explorer: {e}") from e
        return self._parse(resp)


def _explorer(
    explorer_url: str = DEFAULT_EXPLORER_URL,
    api_key: str | None = None,
    chain_id: int | None = None,
    allow_insecure_http: bool = False,
    session: requests.Session | None = None,
    request_timeout: float = 60.0,
) -> _Explorer:
    return _Explorer(explorer_url, api_key, chain_id, allow_insecure_http, session, request_timeout)


def submit_verification(
    form: list[tuple[str, str]],
    *,
    explorer_url: str = DEFAULT_EXPLORER_URL,
    rate_limit_retries: int = 3,
    rate_limit_backoff: float = 5.0,
    allow_insecure_http: bool = False,
    session: requests.Session | None = None,
) -> str:
    """POST ``verifysourcecode`` once (retrying after ``Max rate limit reached``); return the guid."""
    ex = _explorer(explorer_url, allow_insecure_http=allow_insecure_http, session=session)
    attempt = 0
    while True:
        env = ex.post_form(form)
        if env.ok:
            if not env.text:
                raise ExplorerResponseError("empty guid")
            return env.text
        if _is_rate_limit(env.text) and attempt < rate_limit_retries:
            attempt += 1
            time.sleep(rate_limit_backoff)
            continue
        if _is_rate_limit(env.text):
            raise VerificationRateLimitedError(env.text)
        raise VerificationRejectedError(env.text)


def check_verify_status(
    guid: str,
    *,
    explorer_url: str = DEFAULT_EXPLORER_URL,
    api_key: str | None = None,
    chain_id: int | None = None,
    allow_insecure_http: bool = False,
    session: requests.Session | None = None,
) -> VerifyStatus:
    """One ``checkverifystatus`` call."""
    ex = _explorer(explorer_url, api_key, chain_id, allow_insecure_http, session)
    env = ex.get([("module", "contract"), ("action", "checkverifystatus"), ("guid", guid)])
    text = env.text
    if env.ok or "already verified" in text.lower():
        return VerifyStatus("verified", text)
    if text.lower().startswith("pending") or _is_rate_limit(text):
        return VerifyStatus("pending", text)
    return VerifyStatus("failed", text)


def wait_for_verification(
    guid: str,
    *,
    poll_interval: float = 3.0,
    timeout: float = 300.0,
    explorer_url: str = DEFAULT_EXPLORER_URL,
    api_key: str | None = None,
    chain_id: int | None = None,
    allow_insecure_http: bool = False,
    session: requests.Session | None = None,
) -> VerifyStatus:
    """Poll until ``Pass - Verified`` (returns) or ``Fail - ...`` (raises :class:`VerificationFailedError`)."""
    deadline = time.monotonic() + timeout
    while True:
        s = check_verify_status(
            guid,
            explorer_url=explorer_url,
            api_key=api_key,
            chain_id=chain_id,
            allow_insecure_http=allow_insecure_http,
            session=session,
        )
        if s.state == "verified":
            return s
        if s.state == "failed":
            raise VerificationFailedError(guid, s.message)
        if time.monotonic() + poll_interval > deadline:
            raise VerificationTimeoutError(guid, s.message)
        time.sleep(poll_interval)


def verify_contract(
    *,
    address: str,
    contract: str,
    build_info: dict[str, Any] | None = None,
    standard_json_input: dict[str, Any] | None = None,
    constructor_args: str | bytes | None = None,
    explorer_url: str = DEFAULT_EXPLORER_URL,
    api_key: str | None = None,
    compiler_version: str | None = None,
    creation_tx_hash: str | None = None,
    wait: bool = True,
    poll_interval: float = 3.0,
    timeout: float = 300.0,
    rate_limit_retries: int = 3,
    rate_limit_backoff: float = 5.0,
    allow_insecure_http: bool = False,
    session: requests.Session | None = None,
    chain_id: int | None = None,
) -> VerifyResult:
    """Verify a deployed contract's source on CitrateScan.

    Submits ``verifysourcecode`` and, unless ``wait=False``, polls ``checkverifystatus`` until a
    verdict. Returns ``verified`` or ``already_verified``; raises
    :class:`VerificationFailedError` on ``Fail - Unable to verify`` and the other
    :class:`VerificationError` subclasses otherwise.

    ``contract`` is ``path/To.sol:Name`` or a bare ``Name`` when unique in the build-info.
    ``constructor_args`` (ABI-encoded) is optional: the explorer reads them from the creation
    transaction.

    ``chain_id``, when given, is sent as Etherscan v2 ``chainid`` on the submission and on every
    status call (CitrateScan accepts 40204). When omitted nothing is sent, so an explorer for a
    local devnet with another chain id works.
    """
    if chain_id is not None and (not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id <= 0):
        raise BuildInfoError("chain_id must be a positive integer")
    source = build_info if build_info is not None else (
        {"input": standard_json_input} if standard_json_input is not None else None
    )
    if source is None:
        raise BuildInfoError("pass build_info or standard_json_input")
    submission = prepare_standard_json(source, contract, compiler_version)
    form = build_verify_source_code_form(
        address=address,
        submission=submission,
        constructor_args=constructor_args,
        creation_tx_hash=creation_tx_hash,
        chain_id=chain_id,
        api_key=api_key,
    )
    base = {"contract_name": submission.contract_name, "compiler_version": submission.compiler_version}
    try:
        guid = submit_verification(
            form,
            explorer_url=explorer_url,
            rate_limit_retries=rate_limit_retries,
            rate_limit_backoff=rate_limit_backoff,
            allow_insecure_http=allow_insecure_http,
            session=session,
        )
    except VerificationRejectedError as e:
        if "already verified" in e.result.lower():
            return VerifyResult(status="already_verified", message=e.result, **base)
        raise
    if not wait:
        return VerifyResult(status="pending", message="submitted", guid=guid, **base)
    s = wait_for_verification(
        guid,
        poll_interval=poll_interval,
        timeout=timeout,
        explorer_url=explorer_url,
        api_key=api_key,
        chain_id=chain_id,
        allow_insecure_http=allow_insecure_http,
        session=session,
    )
    return VerifyResult(status="verified", message=s.message, guid=guid, **base)


# ---------------------------------------------------------------------------
# Deploy, then verify
# ---------------------------------------------------------------------------


def encode_constructor_args(abi: list[dict[str, Any]], args: Sequence[Any]) -> str:
    """ABI-encode constructor arguments with the contract ABI; hex without ``0x``."""
    from eth_abi import encode
    from eth_utils import collapse_if_tuple

    ctor = next((e for e in abi if e.get("type") == "constructor"), None)
    inputs = ctor.get("inputs", []) if ctor else []
    if len(inputs) != len(args):
        raise BuildInfoError(f"constructor takes {len(inputs)} argument(s), got {len(args)}")
    types = [collapse_if_tuple(i) for i in inputs]
    return bytes(encode(types, list(args))).hex()


def deploy_and_verify(
    *,
    client: ContractDeployer,
    build_info: dict[str, Any],
    contract: str,
    args: Sequence[Any] | None = None,
    constructor_args: str | bytes | None = None,
    value: int = 0,
    gas_limit: int | None = None,
    index_timeout: float = 120.0,
    explorer_url: str = DEFAULT_EXPLORER_URL,
    api_key: str | None = None,
    compiler_version: str | None = None,
    wait: bool = True,
    poll_interval: float = 3.0,
    timeout: float = 300.0,
    rate_limit_retries: int = 3,
    rate_limit_backoff: float = 5.0,
    allow_insecure_http: bool = False,
    session: requests.Session | None = None,
    chain_id: int | None = None,
) -> DeployAndVerifyResult:
    """Deploy a contract from a build-info through the client's signer, then verify it.

    The creation code is the build-info's ``evm.bytecode.object`` (unlinked libraries are
    refused) followed by the constructor arguments (``args`` encoded with the contract ABI, or
    already-encoded ``constructor_args``). The creation transaction hash is passed to the
    explorer. While the explorer answers ``Unable to locate ContractCode`` (not indexed yet), the
    submission is retried until ``index_timeout`` seconds.
    """
    bi = parse_build_info(build_info)
    path, name = _resolve_contract(bi, contract)
    compiled = ((_contracts(bi) or {}).get(path) or {}).get(name) or {}
    bytecode = ((compiled.get("evm") or {}).get("bytecode") or {}).get("object")
    if not isinstance(bytecode, str) or not bytecode:
        raise BuildInfoError(f"{path}:{name} has no evm.bytecode.object in the build-info")
    if "__$" in bytecode:
        raise BuildInfoError(f"{path}:{name} has unlinked library placeholders; link them first")
    if args is not None and constructor_args is not None:
        raise BuildInfoError("pass args or constructor_args, not both")
    encoded = normalize_constructor_args(constructor_args) if constructor_args is not None else ""
    if args is not None:
        abi = compiled.get("abi")
        if not isinstance(abi, list):
            raise BuildInfoError(f"{path}:{name} has no ABI to encode args with")
        encoded = encode_constructor_args(abi, args)

    data = "0x" + bytecode.removeprefix("0x") + encoded
    deployed = client.deploy_contract(data, value=value, gas_limit=gas_limit)
    address, tx_hash = str(deployed["address"]), str(deployed["tx_hash"])

    deadline = time.monotonic() + index_timeout
    while True:
        try:
            verification = verify_contract(
                chain_id=chain_id,
                address=address,
                contract=f"{path}:{name}",
                build_info=bi,
                constructor_args=encoded or None,
                explorer_url=explorer_url,
                api_key=api_key,
                compiler_version=compiler_version,
                creation_tx_hash=tx_hash,
                wait=wait,
                poll_interval=poll_interval,
                timeout=timeout,
                rate_limit_retries=rate_limit_retries,
                rate_limit_backoff=rate_limit_backoff,
                allow_insecure_http=allow_insecure_http,
                session=session,
            )
            return DeployAndVerifyResult(address, tx_hash, verification)
        except VerificationRejectedError as e:
            if "unable to locate contractcode" not in e.result.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(poll_interval)
