"""Mutation hardening for the R2 fixes (mutmut survivors in the changed functions).

Each test pins a boundary, a parameter hand-off or a branch that a surviving
mutant flipped without any test noticing. Grouped by module; the finding each
function belongs to is noted on the class.
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
import requests
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_abi import encode as abi_encode
from eth_utils import to_checksum_address

from citrate_sdk import CitrateClient, KeyManager
from citrate_sdk._chain_guard import pinned_send
from citrate_sdk._generated import contract
from citrate_sdk._url_security import InsecureTransportError, enforce_transport_security
from citrate_sdk.crypto import (
    EncryptionConfig,
    assert_no_key_share_material,
    canonical_public_key_hex,
)
from citrate_sdk.errors import CitrateError, IPFSError
from citrate_sdk.finite_field import ShamirSecretSharing, split_secret_bytes
from citrate_sdk.identity import client as idc
from citrate_sdk.identity import wallet
from citrate_sdk.identity.client import IdentityClient, IdentityError
from citrate_sdk.identity.jwt import IdTokenError, verify_id_token
from citrate_sdk.ipfs import IPFSClient, IPFSManager
from citrate_sdk.learning import ClassroomManager, LearningManager
from citrate_sdk.models import ModelConfig

OWNER = "0x" + "11" * 32
ACCT = "0x" + "01" * 20
ADDR = "0x" + "02" * 20


# ── PBA-L6b-026: transport gate ─────────────────────────────────────────────
class TestTransportGate:
    def test_non_string_truthy_input_is_refused(self) -> None:
        with pytest.raises(InsecureTransportError):
            enforce_transport_security(123)  # type: ignore[arg-type]

    @pytest.mark.parametrize("url", ["https://rpc​.citrate.ai", "https://rpc.citrate.ai/‎", "https://a\x7fb.example"])
    def test_format_or_control_char_inside_the_url_is_refused(self, url: str) -> None:
        with pytest.raises(InsecureTransportError, match="control"):
            enforce_transport_security(url)

    def test_https_without_host_is_refused(self) -> None:
        with pytest.raises(InsecureTransportError, match="no host"):
            enforce_transport_security("https:///path")


# ── PBA-L6b-003: deploy guard, share plan, holder API ───────────────────────
def _nest(n: int) -> dict[str, Any]:
    return {"leaf": 1} if n == 0 else {"n": _nest(n - 1)}


class TestShareGuardAndPlan:
    def test_guard_depth_boundary(self) -> None:
        assert_no_key_share_material(_nest(32))
        with pytest.raises(CitrateError, match="nested more than 32 levels"):
            assert_no_key_share_material(_nest(33))

    def test_canonical_key_accepts_0x_and_compressed(self) -> None:
        km = KeyManager("0x" + "22" * 32)
        comp = km.get_public_key()
        unc = km.ecdh_manager.get_public_key_uncompressed().hex()
        assert canonical_public_key_hex(comp) == unc
        assert canonical_public_key_hex("0x" + comp) == unc
        assert canonical_public_key_hex("0x" + unc) == unc
        with pytest.raises(CitrateError, match="invalid secp256k1"):
            canonical_public_key_hex("0x" + "00" * 33)

    def _pubs(self, n: int) -> list[str]:
        return [KeyManager("0x" + (i + 100).to_bytes(32, "big").hex()).get_public_key() for i in range(n)]

    @pytest.mark.parametrize(("t", "n"), [(True, 3), (2, True), ("2", 3), (2, "3"), (0, 3), (4, 3), (2, 256), (-1, 3)])
    def test_invalid_share_parameters(self, t: Any, n: Any) -> None:
        cfg = EncryptionConfig(threshold_shares=t, total_shares=n, share_holder_public_keys=self._pubs(3))
        with pytest.raises(CitrateError):
            KeyManager(OWNER).encrypt_model_with_key_shares(b"m", cfg)

    @pytest.mark.parametrize(("t", "n"), [(1, 1), (3, 3), (2, 255)])
    def test_boundary_share_parameters_accepted(self, t: int, n: int) -> None:
        # threshold 1 needs the explicit opt-in since the R2 follow-up.
        cfg = EncryptionConfig(threshold_shares=t, total_shares=n, share_holder_public_keys=self._pubs(n),
                               allow_single_holder_recovery=(t == 1))
        _, meta, envs = KeyManager(OWNER).encrypt_model_with_key_shares(b"m", cfg)
        assert meta["key_sharing"] == {"threshold": t, "total_shares": n}
        assert [e["x"] for e in envs] == list(range(1, n + 1))

    def test_nonce_is_96_bits_and_zero_threshold_is_refused_by_the_shared_api(self) -> None:
        _, meta = KeyManager(OWNER).encrypt_model(b"m", EncryptionConfig())
        assert len(bytes.fromhex(meta["nonce"])) == 12
        with pytest.raises(CitrateError, match="threshold_shares must be > 0"):
            KeyManager(OWNER).encrypt_model_with_key_shares(b"m", EncryptionConfig())

    def test_unwrap_returns_the_share_threshold(self) -> None:
        owner = KeyManager(OWNER)
        holder = KeyManager("0x" + "22" * 32)
        envs = owner._create_key_shares(b"k" * 32, 2, 2, [holder.get_public_key(), self._pubs(1)[0]])
        share = holder.unwrap_key_share(envs[0], owner.get_public_key())
        assert share["threshold"] == "2" and share["x"] == "1"

    def test_create_key_shares_needs_one_holder_per_share(self) -> None:
        with pytest.raises(CitrateError, match="exactly one holder"):
            KeyManager(OWNER)._create_key_shares(b"k" * 32, 2, 3, self._pubs(2))


class TestReconstructKey:
    @pytest.mark.parametrize("t", [True, 0, 256, "2"])
    def test_bad_threshold(self, t: Any) -> None:
        with pytest.raises(CitrateError, match="threshold must be an integer"):
            KeyManager(OWNER).reconstruct_key_from_shares([{"x": "1", "y": "aa"}], t)

    def test_255_of_255_and_three_digit_x(self) -> None:
        shares = [{"x": str(x), "y": y.hex()} for x, y in split_secret_bytes(b"s", 255, 255)]
        assert KeyManager(OWNER).reconstruct_key_from_shares(shares, 255) == b"s"
        assert shares[-1]["x"] == "255"

    def test_validation_detail_propagates(self) -> None:
        dup = [{"x": "1", "y": "aa"}, {"x": "1", "y": "bb"}]
        with pytest.raises(CitrateError, match="duplicate share x = 1"):
            KeyManager(OWNER).reconstruct_key_from_shares(dup, 2)

    def test_empty_and_non_hex(self) -> None:
        with pytest.raises(CitrateError, match="No shares provided"):
            KeyManager(OWNER).reconstruct_key_from_shares([], 1)
        with pytest.raises(CitrateError, match="y is not hex"):
            KeyManager(OWNER).reconstruct_key_from_shares([{"x": "1", "y": "zz"}], 1)


class TestShamirBoundaries:
    @pytest.mark.parametrize(("t", "n"), [(True, 3), (2, True), (0, 3), (2, 256), (1.0, 2)])
    def test_constructor_refuses(self, t: Any, n: Any) -> None:
        with pytest.raises(ValueError):
            ShamirSecretSharing(t, n)

    def test_constructor_accepts_edges(self) -> None:
        ShamirSecretSharing(1, 1)
        ShamirSecretSharing(255, 255)

    def test_list_shaped_share_and_x_255(self) -> None:
        with pytest.raises(ValueError, match="tuple"):
            ShamirSecretSharing.validate_shares([[1, b"a"]])  # type: ignore[list-item]
        ShamirSecretSharing.validate_shares([(255, b"a")])
        with pytest.raises(ValueError, match="y must be bytes"):
            ShamirSecretSharing.validate_shares([(1, "a")])  # type: ignore[list-item]

    def test_verify_shares_threshold_edges(self) -> None:
        sss = ShamirSecretSharing(2, 3)
        s = sss.split_secret(b"ab")
        assert sss.verify_shares(s[:2]) is True
        assert sss.verify_shares(s[:1]) is False


# ── deploy_model calldata shape ─────────────────────────────────────────────
def test_unencrypted_deploy_sends_an_empty_access_list(tmp_path: Path) -> None:
    import rlp  # type: ignore[import-untyped]

    mp = tmp_path / "m.onnx"
    mp.write_bytes(b"w")
    client = CitrateClient("http://localhost:8545", private_key=OWNER)
    box: dict[str, Any] = {}

    def rpc(method: str, params: Any = None) -> Any:
        if method == "eth_sendRawTransaction":
            box["raw"] = params[0]
            return "0x" + "ab" * 32
        return {"eth_getTransactionCount": "0x0", "eth_chainId": hex(40204), "eth_gasPrice": "0x1"}[method]

    stubs: dict[str, Any] = {"_rpc_call": rpc, "_upload_to_ipfs": lambda d: "bafy",
                             "_wait_for_receipt": lambda h: {"logs": []},
                             "_extract_model_id_from_receipt": lambda r: "0x01"}
    for name, fn in stubs.items():
        setattr(client, name, fn)
    client.deploy_model(mp, ModelConfig(name="m"))
    payload = json.loads(bytes(rlp.decode(bytes.fromhex(box["raw"][2:]))[5]))
    assert payload["access_list"] == [] and "encryption_metadata" not in payload


# ── PBA-L6b-042: pinned_send ────────────────────────────────────────────────
class TestPinnedSend:
    def test_integer_chain_id_answer_is_accepted(self) -> None:
        sent: list[Any] = []

        class M:
            _expected_chain_id = 40204
            _chain_verified = False

            def _rpc_call(self, method: str, params: Any) -> Any:
                if method == "eth_chainId":
                    return 40204
                sent.append(params[0])
                return "0xh"

        assert pinned_send(M(), {"to": ADDR}) == "0xh"
        assert sent == [{"to": ADDR, "chainId": hex(40204)}]


# ── PBA-L6b-028/040/031: learning managers ──────────────────────────────────
def _rpc_capture(result: str = "0xhash") -> tuple[Any, list[Any]]:
    sent: list[Any] = []

    def rpc(method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return hex(40204)
        if method == "eth_sendTransaction":
            sent.append(params[0])
            return "0xhash"
        return result
    return rpc, sent


class TestLearningManagers:
    def test_create_targets_the_registry_with_a_22_char_code(self) -> None:
        rpc, sent = _rpc_capture()
        mgr = ClassroomManager(rpc, default_account=ACCT, classroom_address=ADDR)
        mgr.create("c", 3)
        assert sent[-1]["to"] == ADDR and len(mgr.last_invite_code or "") == 22

    def test_create_pool_targets_the_pool(self) -> None:
        rpc, sent = _rpc_capture()
        LearningManager(rpc, default_account=ACCT, contract_addresses={"learningPool": ADDR}).create_pool("p", "d", "Open", "1")
        assert sent[-1]["to"] == ADDR

    def test_get_classroom_accepts_unprefixed_hex(self) -> None:
        ret = abi_encode(["(address,string,uint256,uint256,uint256,bool)"], [(ADDR, "n", 1, 0, 2, True)]).hex()
        rpc, _ = _rpc_capture(result=ret)
        info = ClassroomManager(rpc, default_account=ACCT, classroom_address=ADDR).get_classroom(ADDR)
        assert info.name == "n" and info.exists is True


# ── PBA-L6b-029 / L3a twins: identity ───────────────────────────────────────
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_pub = _key.public_key().public_numbers()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


JWKS = [{"kty": "RSA", "kid": "k", "n": _b64(_pub.n.to_bytes(256, "big")), "e": _b64(_pub.e.to_bytes(3, "big"))}]
ISS = contract.identity()["issuer"]


def _tok(payload: dict[str, Any], kid: str | None = "k") -> str:
    header: dict[str, Any] = {"alg": "RS256"}
    if kid:
        header["kid"] = kid
    h, p = _b64(json.dumps(header).encode()), _b64(json.dumps(payload).encode())
    return f"{h}.{p}.{_b64(_key.sign(f'{h}.{p}'.encode(), padding.PKCS1v15(), hashes.SHA256()))}"


class TestVerifyIdTokenEdges:
    now = 1_900_000_000

    def _p(self, **kw: Any) -> dict[str, Any]:
        base: dict[str, Any] = {"iss": ISS, "aud": "c", "sub": "u", "iat": self.now, "exp": self.now + 600}
        base.update(kw)
        return base

    def _v(self, tok: str, **kw: Any) -> dict[str, Any]:
        return verify_id_token(tok, ISS, "c", JWKS, now_ms=kw.pop("now_ms", self.now * 1000), **kw)

    def test_exp_boundary_with_default_tolerance(self) -> None:
        exp = self.now - 60
        assert self._v(_tok(self._p(exp=exp)))["sub"] == "u"
        with pytest.raises(IdTokenError, match="expired"):
            self._v(_tok(self._p(exp=exp - 1)))

    def test_nbf_boundary(self) -> None:
        assert self._v(_tok(self._p(nbf=self.now + 60)))["sub"] == "u"
        with pytest.raises(IdTokenError, match="not yet valid"):
            self._v(_tok(self._p(nbf=self.now + 61)))

    def test_audience_list(self) -> None:
        assert self._v(_tok(self._p(aud=["x", "c"])))["sub"] == "u"
        with pytest.raises(IdTokenError, match="aud"):
            self._v(_tok(self._p(aud=["x", "y"])))

    def test_jwks_filter_and_kid_selection(self) -> None:
        jwks = [{"kty": "EC", "kid": "k", "n": "x", "e": "y"}, *JWKS]
        assert verify_id_token(_tok(self._p()), ISS, "c", jwks, now_ms=self.now * 1000)["sub"] == "u"
        with pytest.raises(IdTokenError, match="no RSA JWK for kid zz"):
            verify_id_token(_tok(self._p(), kid="zz"), ISS, "c", JWKS, now_ms=self.now * 1000)
        two = [*JWKS, dict(JWKS[0], kid="other")]
        with pytest.raises(IdTokenError, match="ambiguous or missing RSA JWK"):
            verify_id_token(_tok(self._p(), kid=None), ISS, "c", two, now_ms=self.now * 1000)

    def test_iss_mismatch_names_the_issuer(self) -> None:
        with pytest.raises(IdTokenError, match="iss mismatch: https://evil"):
            self._v(_tok(self._p(iss="https://evil")))


class TestSiweHelpers:
    def test_iso_ms_truncates_microseconds(self) -> None:
        t = datetime(2026, 9, 25, 0, 0, 0, 999_999, tzinfo=timezone.utc)
        assert idc._iso_ms(t) == "2026-09-25T00:00:00.999Z"

    @pytest.mark.parametrize("ttl", [1, 86400])
    def test_ttl_edges_accepted(self, ttl: int) -> None:
        addr = to_checksum_address("0x" + "ab" * 20)
        assert "Expiration Time" in idc.build_siwe_message(addr, "abcdefgh", ttl_seconds=ttl)

    def test_bool_ttl_refused(self) -> None:
        with pytest.raises(IdentityError, match="ttl_seconds"):
            idc.build_siwe_message(to_checksum_address("0x" + "ab" * 20), "abcdefgh", ttl_seconds=True)

    @pytest.mark.parametrize(("body", "ok"), [({"nonce": "abcdefgh"}, True), ({"nonce": "abcdefg"}, False),
                                              ({"nonce": 12345678}, False), ({}, False), ([], False)])
    def test_challenge_nonce_rules(self, body: Any, ok: bool) -> None:
        c = IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb", transport=lambda m, u, h, b: (200, body))
        if ok:
            assert c.siwe_challenge() == {"nonce": "abcdefgh"}
        else:
            with pytest.raises(IdentityError, match="no nonce"):
                c.siwe_challenge()

    @pytest.mark.parametrize(("status", "body", "msg"), [
        (300, {"redirectTo": "https://x"}, r"failed: 300$"),
        (401, {"reason": 5, "error": "invalid_grant"}, r"failed: 401 \(invalid_grant\)$"),
        (401, {"reason": "unknown_nonce"}, r"failed: 401 \(unknown_nonce\)$"),
        (500, [], r"failed: 500$"),
        (200, ["redirectTo"], "neither redirectTo nor id_token"),
    ])
    def test_verify_errors(self, status: int, body: Any, msg: str) -> None:
        c = IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb", transport=lambda m, u, h, b: (status, body))
        with pytest.raises(IdentityError, match=msg):
            c.siwe_verify("m", "s")

    def test_verify_redirect_with_bad_types(self) -> None:
        c = IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb",
                           transport=lambda m, u, h, b: (299, {"address": 1, "method": 2, "redirectTo": "https://x"}))
        assert c.siwe_verify("m", "s") == {"kind": "redirect", "address": "", "method": "", "redirect_to": "https://x"}


# ── PBA-L6b-027: wallet verification plumbing ───────────────────────────────
UID = "0x" + "42" * 32


def _wallet_post(chain: int = 40204, code: str = "0x60", result: Any = "echo", error: bool = False,
                 factory: str | None = None) -> tuple[Any, list[Any]]:
    calls: list[Any] = []

    def post(url: str, data: str | None = None, headers: Any = None, timeout: Any = None) -> requests.Response:
        body = json.loads(data or "{}")
        calls.append((url, body, headers, timeout))
        r = requests.Response()
        r.status_code = 200
        if error:
            r._content = json.dumps({"jsonrpc": "2.0", "id": 1, "error": {"code": -1}}).encode()
            return r
        m = body["method"]
        if m == "eth_chainId":
            res: Any = hex(chain)
        elif m == "eth_getCode":
            res = code
        else:
            local = wallet.predict_wallet_address(UID, factory=factory)
            res = ("0x" + "00" * 12 + local[2:].lower()) if result == "echo" else result
        r._content = json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}).encode()
        return r
    return post, calls


class TestWalletPlumbing:
    def test_request_shape(self) -> None:
        post, calls = _wallet_post()
        with mock.patch.object(wallet.requests, "post", post):
            wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")
        factory = contract.aa_stack()["CitrateWalletFactory"]
        url, body, headers, timeout = calls[-1]
        assert url == "https://rpc.example" and headers == {"content-type": "application/json"} and timeout == 10.0
        from eth_utils import keccak
        assert body["params"] == [{"to": factory, "data": "0x" + keccak(b"predictAddress(bytes32)")[:4].hex() + "42" * 32}, "latest"]
        assert calls[1][1]["params"] == [factory, "latest"]

    def test_rpc_error_object_is_refused(self) -> None:
        post, _ = _wallet_post(error=True)
        with mock.patch.object(wallet.requests, "post", post):
            with pytest.raises(wallet.WalletPredictionError, match="eth_chainId failed"):
                wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")

    @pytest.mark.parametrize("result", [None, "0x1234"])
    def test_missing_prediction_is_refused(self, result: Any) -> None:
        post, _ = _wallet_post(result=result)
        with mock.patch.object(wallet.requests, "post", post):
            with pytest.raises(wallet.WalletPredictionError, match="returned no address"):
                wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")

    def test_custom_factory_and_insecure_opt_in(self) -> None:
        f = to_checksum_address("0x" + "fe" * 20)
        post, calls = _wallet_post(factory=f)
        with mock.patch.object(wallet.requests, "post", post):
            out = wallet.verify_wallet_address_on_chain(UID, rpc_url="http://rpc.remote.example", factory=f,
                                                        allow_insecure_http=True)
        assert out == wallet.predict_wallet_address(UID, factory=f)
        assert calls[-1][1]["params"][0]["to"] == f

    def test_garbage_chain_id(self) -> None:
        post, _ = _wallet_post()

        def bad(url: str, data: str | None = None, headers: Any = None, timeout: Any = None) -> requests.Response:
            r: requests.Response = post(url, data, headers, timeout)
            if json.loads(data or "{}")["method"] == "eth_chainId":
                r._content = b'{"jsonrpc":"2.0","id":1,"result":"0xzz"}'
            return r
        with mock.patch.object(wallet.requests, "post", bad):
            with pytest.raises(wallet.WalletPredictionError, match="eth_chainId returned"):
                wallet.verify_wallet_address_on_chain(UID, rpc_url="https://rpc.example")


# ── PBA-L6b-030: IPFS plumbing ──────────────────────────────────────────────
DATA = b"bytes" * 10


def _session(body: bytes, calls: list[Any], status: int = 200) -> Any:
    def post(url: str, params: Any = None, timeout: Any = None, stream: bool = False) -> requests.Response:
        calls.append((url, params, timeout, stream))
        r = requests.Response()
        r.status_code = status
        r.raw = io.BytesIO(body)
        return r
    return post


class TestIpfsPlumbing:
    def test_request_shape(self) -> None:
        calls: list[Any] = []
        c = IPFSClient("http://127.0.0.1:5001", timeout=7.0)
        c.session.post = _session(DATA, calls)  # type: ignore[method-assign]
        assert c.download_bytes("QmX", verify=False) == DATA
        assert calls == [("http://127.0.0.1:5001/api/v0/cat", {"arg": "QmX"}, 7.0, True)]

    def test_0x_prefixed_expected_hash(self) -> None:
        c = IPFSClient("http://127.0.0.1:5001")
        c.session.post = _session(DATA, [])  # type: ignore[method-assign]
        assert c.download_bytes("QmX", expected_sha256="0x" + hashlib.sha256(DATA).hexdigest()) == DATA

    def test_http_error_and_connection_error(self) -> None:
        c = IPFSClient("http://127.0.0.1:5001")
        c.session.post = _session(b"", [], status=500)  # type: ignore[method-assign]
        with pytest.raises(IPFSError, match="HTTP 500"):
            c.download_bytes("QmX", verify=False)

        def boom(*a: Any, **k: Any) -> Any:
            raise requests.exceptions.ConnectionError("refused")
        c.session.post = boom  # type: ignore[method-assign]
        with pytest.raises(IPFSError, match="connection error"):
            c.download_bytes("QmX", verify=False)

    def test_non_raw_cidv1_is_not_misverified(self) -> None:
        mh = bytes([0x12, 0x20]) + hashlib.sha256(b"other").digest()
        cid = "b" + base64.b32encode(bytes([0x01, 0x70]) + mh).decode().lower().rstrip("=")
        c = IPFSClient("http://127.0.0.1:5001")
        c.session.post = _session(DATA, [])  # type: ignore[method-assign]
        assert c.download_bytes(cid, verify=False) == DATA

    def test_manager_falls_back_and_threads_parameters(self) -> None:
        m = IPFSManager("http://127.0.0.1:5001", fallback_urls=["http://127.0.0.1:5002"])
        good = hashlib.sha256(DATA).hexdigest()
        m.primary.session.post = _session(b"tampered", [])  # type: ignore[method-assign]
        m.fallbacks[0].session.post = _session(DATA, [])  # type: ignore[method-assign]
        for cl in (m.primary, m.fallbacks[0]):
            cl.is_available = lambda: True  # type: ignore[method-assign]
        assert m.download("QmX", expected_sha256=good) == DATA

    def test_manager_active_client_gets_the_parameters(self) -> None:
        m = _single(DATA)
        m.active_client = m.primary
        with pytest.raises(IPFSError, match="exceeds max_bytes"):
            m.download("QmX", max_bytes=3, verify=False)
        with pytest.raises(IPFSError, match="expected_sha256"):
            m.download("QmX", expected_sha256="00" * 32)

    def test_download_from_ipfs_threads_parameters(self) -> None:
        m = _single(DATA)
        with mock.patch("citrate_sdk.ipfs.get_ipfs_manager", return_value=m):
            from citrate_sdk.ipfs import download_from_ipfs
            assert download_from_ipfs("QmX", expected_sha256=hashlib.sha256(DATA).hexdigest()) == DATA
            with pytest.raises(IPFSError, match="expected_sha256"):
                download_from_ipfs("QmX", expected_sha256="00" * 32)
            with pytest.raises(IPFSError, match="exceeds max_bytes"):
                download_from_ipfs("QmX", max_bytes=3, verify=False)


def _single(body: bytes) -> IPFSManager:
    m = IPFSManager("http://127.0.0.1:5001")
    m.primary.session.post = _session(body, [])  # type: ignore[method-assign]
    m.primary.is_available = lambda: True  # type: ignore[method-assign]
    return m


def test_time_is_not_frozen() -> None:
    # Guard for the boundary tests above, which pass now_ms explicitly.
    assert time.time() > 1_700_000_000


# ── second round: survivors from the targeted mutmut rerun ──────────────────
class TestSecondRound:
    def test_malformed_sha256_pointer_is_refused(self) -> None:
        c = IPFSClient("http://127.0.0.1:5001")
        c.session.post = _session(DATA, [])  # type: ignore[method-assign]
        for ptr in ("sha256:" + "ab" * 16, "sha256:zz"):
            with pytest.raises(IPFSError, match="malformed sha256"):
                c.download_bytes(ptr)

    def test_active_client_receives_the_hash(self) -> None:
        calls: list[Any] = []
        m = IPFSManager("http://127.0.0.1:5001")
        m.primary.session.post = _session(DATA, calls)  # type: ignore[method-assign]
        m.active_client = m.primary
        assert m.download("QmY", verify=False) == DATA
        assert calls[0][1] == {"arg": "QmY"}

    def test_download_from_ipfs_passes_the_urls(self) -> None:
        with mock.patch("citrate_sdk.ipfs.get_ipfs_manager", return_value=_single(DATA)) as g:
            from citrate_sdk.ipfs import download_from_ipfs
            download_from_ipfs("QmX", ["http://127.0.0.1:5009"], verify=False)
        g.assert_called_once_with(["http://127.0.0.1:5009"])

    def test_pinned_send_verifies_when_the_flag_is_absent(self) -> None:
        seen: list[Any] = []

        class Bare:
            _expected_chain_id = 40204

            def _rpc_call(self, method: str, params: Any) -> Any:
                seen.append((method, params))
                return hex(1) if method == "eth_chainId" else "0xh"

        with pytest.raises(CitrateError, match="chain-id mismatch"):
            pinned_send(Bare(), {"to": ADDR})
        assert seen == [("eth_chainId", [])]

    def test_learning_tx_shape(self) -> None:
        rpc, sent = _rpc_capture()
        ClassroomManager(rpc, default_account=ACCT, classroom_address=ADDR, gas_limit=123).unenroll()
        tx = sent[-1]
        assert set(tx) == {"from", "to", "data", "value", "gas", "gasPrice", "chainId"}
        assert (tx["from"], tx["value"], tx["gas"], tx["gasPrice"]) == (ACCT, "0x0", hex(123), "0x3b9aca00")

    def test_get_classroom_calls_the_registry(self) -> None:
        ret = abi_encode(["(address,string,uint256,uint256,uint256,bool)"], [(ADDR, "n", 1, 0, 2, True)]).hex()
        calls: list[Any] = []

        def rpc(method: str, params: Any) -> Any:
            calls.append((method, params))
            return ret
        ClassroomManager(rpc, default_account=ACCT, classroom_address=ADDR).get_classroom(ACCT)
        method, params = calls[-1]
        assert method == "eth_call" and params[0]["to"] == ADDR and params[0]["data"].startswith("0x")
        assert params[0]["data"][10:].endswith(ACCT[2:].lower())

    def test_iso_ms_millisecond_rounding(self) -> None:
        assert idc._iso_ms(datetime(2026, 1, 1, 0, 0, 0, 1000, tzinfo=timezone.utc)).endswith(".001Z")

    def test_siwe_uppercase_nonce_and_chain_override(self) -> None:
        addr = to_checksum_address("0x" + "ab" * 20)
        msg = idc.build_siwe_message(addr, "ABCDEFGH", chain_id=31337)
        assert "\nNonce: ABCDEFGH\n" in msg and "\nChain ID: 31337\n" in msg

    def test_refresh_request_shape(self) -> None:
        now = int(time.time())
        tok = _tok({"iss": ISS, "aud": "c", "sub": "u", "iat": now, "exp": now + 600})
        seen: list[Any] = []

        def transport(method: str, url: str, headers: dict[str, str], body: str | None) -> Any:
            seen.append((method, url, headers, body))
            if url.endswith("/.well-known/openid-configuration") or url == contract.identity()["discovery"]:
                return 200, {"issuer": ISS, "token_endpoint": ISS + "/token", "jwks_uri": ISS + "/jwks"}
            if url.endswith("/jwks"):
                return 200, {"keys": JWKS}
            return 200, {"id_token": tok, "access_token": "a"}
        IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb", transport=transport).refresh("rt", expected_sub="u")
        method, url, headers, body = [s for s in seen if s[1].endswith("/token")][0]
        assert method == "POST" and headers == {"content-type": "application/x-www-form-urlencoded"}
        assert body == "grant_type=refresh_token&refresh_token=rt&client_id=c"

    def test_siwe_verify_request_and_token_shape(self) -> None:
        now = int(time.time())
        tok = _tok({"iss": ISS, "aud": "c", "sub": "u", "iat": now, "exp": now + 600})
        seen: list[Any] = []

        def transport(method: str, url: str, headers: dict[str, str], body: str | None) -> Any:
            seen.append((method, url, headers, body))
            if url.endswith("/siwe/verify"):
                return 200, {"address": "0xa", "method": "eoa", "id_token": tok}
            if url == contract.identity()["discovery"]:
                return 200, {"issuer": ISS, "jwks_uri": ISS + "/jwks"}
            return 200, {"keys": JWKS}
        r = IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb", transport=transport).siwe_verify("m", "s")
        assert set(r) == {"kind", "address", "method", "id_token", "claims"} and r["method"] == "eoa" and r["id_token"] == tok
        assert seen[0][2] == {"content-type": "application/json"}
        c = IdentityClient(client_id="c", redirect_uri="http://127.0.0.1/cb", transport=lambda *a: (401, {"reason": "x"}))
        with pytest.raises(IdentityError) as ei:
            c.siwe_verify("m", "s")
        assert ei.value.status == 401


class TestIdTokenMore:
    now = 1_900_000_000

    def test_single_key_without_kid(self) -> None:
        p = {"iss": ISS, "aud": "c", "sub": "u", "iat": self.now, "exp": self.now + 600}
        assert verify_id_token(_tok(p, kid=None), ISS, "c", JWKS, now_ms=self.now * 1000)["sub"] == "u"

    def test_string_aud_is_compared_exactly(self) -> None:
        p = {"iss": ISS, "aud": "xcx", "sub": "u", "iat": self.now, "exp": self.now + 600}
        with pytest.raises(IdTokenError, match="aud"):
            verify_id_token(_tok(p), ISS, "c", JWKS, now_ms=self.now * 1000)

    def test_now_is_whole_seconds(self) -> None:
        p = {"iss": ISS, "aud": "c", "sub": "u", "iat": self.now, "exp": self.now - 60}
        assert verify_id_token(_tok(p), ISS, "c", JWKS, now_ms=self.now * 1000 + 999)["sub"] == "u"

    def test_alg_message_names_the_alg(self) -> None:
        h = _b64(json.dumps({"alg": "HS256"}).encode())
        with pytest.raises(IdTokenError, match="'HS256'"):
            verify_id_token(f"{h}.e30.sig", ISS, "c", JWKS)


class TestWalletMore:
    def test_rpc_call_shapes_and_custom_implementation(self) -> None:
        impl = to_checksum_address("0x" + "ee" * 20)
        f = contract.aa_stack()["CitrateWalletFactory"]
        calls: list[Any] = []
        local = wallet.predict_wallet_address(UID, implementation=impl)

        def post(url: str, data: str | None = None, headers: Any = None, timeout: Any = None) -> requests.Response:
            body = json.loads(data or "{}")
            calls.append((url, body, timeout))
            res = {"eth_chainId": hex(40204), "eth_getCode": "0x60"}.get(body["method"], "0x" + "00" * 12 + local[2:].lower())
            r = requests.Response()
            r.status_code = 200
            r._content = json.dumps({"jsonrpc": "2.0", "id": 1, "result": res}).encode()
            return r
        with mock.patch.object(wallet.requests, "post", post):
            assert wallet.verify_wallet_address_on_chain(UID, rpc_url="https://r.example", implementation=impl, timeout=3.0) == local
        assert [(c[0], c[1]["method"], c[1]["params"], c[2]) for c in calls[:2]] == [
            ("https://r.example", "eth_chainId", [], 3.0), ("https://r.example", "eth_getCode", [f, "latest"], 3.0)]
        assert all(c[1]["jsonrpc"] == "2.0" for c in calls)


class TestDeployMore:
    def test_deploy_shape_and_plumbing(self, tmp_path: Path) -> None:
        import rlp

        mp = tmp_path / "m.onnx"
        mp.write_bytes(b"weights")
        client = CitrateClient("http://localhost:8545", private_key=OWNER)
        box: dict[str, Any] = {}

        def rpc(method: str, params: Any = None) -> Any:
            if method == "eth_sendRawTransaction":
                box["raw"] = params[0]
                return "0x" + "cd" * 32
            return {"eth_getTransactionCount": "0x0", "eth_chainId": hex(40204), "eth_gasPrice": "0x1"}[method]

        def wait(h: str) -> Any:
            assert h == "0x" + "cd" * 32
            return {"logs": ["L"]}

        def extract(r: Any) -> str:
            assert r == {"logs": ["L"]}
            return "0x77"
        stubs: dict[str, Any] = {"_rpc_call": rpc, "_upload_to_ipfs": lambda d: "bafy",
                                 "_wait_for_receipt": wait, "_extract_model_id_from_receipt": extract}
        for name, fn in stubs.items():
            setattr(client, name, fn)
        cfg = ModelConfig(name="m", encrypted=True, access_price=5)
        dep = client.deploy_model(mp, cfg)
        fields = rlp.decode(bytes.fromhex(box["raw"][2:]))
        payload = json.loads(bytes(fields[5]))
        assert set(payload) == {"model_hash", "ipfs_hash", "encrypted", "access_price", "access_list", "metadata",
                                "encryption_metadata"}
        assert payload["model_hash"] == hashlib.sha256(b"weights").hexdigest() and payload["ipfs_hash"] == "bafy"
        assert payload["encrypted"] is True and payload["access_price"] == 5 and payload["metadata"] == {}
        assert set(payload["encryption_metadata"]) == {"algorithm", "nonce", "key_derivation", "encrypted_key", "access_control"}
        assert "0x" + bytes(fields[3]).hex() == client._precompile("ModelDeploy").lower()
        assert (dep.model_id, dep.tx_hash, dep.encrypted, dep.access_price) == ("0x77", "0x" + "cd" * 32, True, 5)
        assert isinstance(dep.deployment_time, int) and dep.deployment_time > 1_700_000_000

    def test_total_256_is_a_parameter_error(self) -> None:
        pubs = [KeyManager("0x" + (i + 1).to_bytes(32, "big").hex()).get_public_key() for i in range(3)]
        with pytest.raises(CitrateError, match="invalid share parameters"):
            KeyManager(OWNER).encrypt_model_with_key_shares(
                b"m", EncryptionConfig(threshold_shares=2, total_shares=256, share_holder_public_keys=pubs))
