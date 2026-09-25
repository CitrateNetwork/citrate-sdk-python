"""PBA-L6b-029 plus the Python twins of PBA-L3a-011 and PBA-L3a-012.

L6b-029: ``verify_id_token`` accepted a token with no ``exp`` (or a string or
list one), so it never expired, and it did not check ``typ``, so other RS256
JWTs from the authority with the same key and audience (e.g. an ``at+jwt``
access token) passed as ID tokens. ``exp`` and ``iat`` must now be numeric and
``typ``, when present, must be ``JWT``.

L3a-011 twin: ``refresh()`` adopted whatever ``sub`` the refreshed ID token
named. ``refresh(refresh_token, expected_sub)`` now refuses a different sub.

L3a-012 twin: ``siwe_challenge`` POSTed ``{address}`` to a GET-only route and
``siwe_verify`` expected ``access_token``, which ``/siwe/verify`` never returns.
The fake authority below transcribes citrate-identity src/siwe-routes.ts @
08959bf (same contract the JS SDK tests use).
"""
from __future__ import annotations

import base64
import json
import time
from datetime import datetime, timezone
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from eth_utils import to_checksum_address

from citrate_sdk._generated import contract
from citrate_sdk.identity import client as idc
from citrate_sdk.identity.client import IdentityClient, IdentityError
from citrate_sdk.identity.jwt import IdTokenError, verify_id_token

ID = contract.identity()
CLIENT_ID = "citrate-core"
KID = "kid-r2"
ADDRESS = to_checksum_address("0x" + "ab" * 20)
_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
_pub = _key.public_key().public_numbers()


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


JWKS = [{"kty": "RSA", "kid": KID, "n": _b64(_pub.n.to_bytes(256, "big")), "e": _b64(_pub.e.to_bytes(3, "big"))}]


def _token(payload: dict[str, Any] | str, header: dict[str, Any] | None = None) -> str:
    h = _b64(json.dumps(header or {"alg": "RS256", "kid": KID, "typ": "JWT"}).encode())
    p = _b64((payload if isinstance(payload, str) else json.dumps(payload)).encode())
    sig = _key.sign(f"{h}.{p}".encode(), padding.PKCS1v15(), hashes.SHA256())
    return f"{h}.{p}.{_b64(sig)}"


def _claims(**extra: Any) -> dict[str, Any]:
    now = int(time.time())
    c: dict[str, Any] = {"iss": ID["issuer"], "sub": "user-1", "aud": CLIENT_ID, "iat": now, "exp": now + 3600}
    c.update(extra)
    return {k: v for k, v in c.items() if v is not _DROP}


_DROP = object()


def _verify(tok: str, **kw: Any) -> dict[str, Any]:
    return verify_id_token(tok, ID["issuer"], CLIENT_ID, JWKS, **kw)


class TestVerifyIdToken:
    def test_missing_exp(self) -> None:
        with pytest.raises(IdTokenError, match="exp"):
            _verify(_token(_claims(exp=_DROP)))

    @pytest.mark.parametrize("exp", ["9999999999", [1], None, True, {"a": 1}])
    def test_non_numeric_exp(self, exp: Any) -> None:
        with pytest.raises(IdTokenError, match="exp"):
            _verify(_token(_claims(exp=exp)))

    def test_infinite_exp(self) -> None:
        raw = json.dumps(_claims(exp=0)).replace('"exp": 0', '"exp": 1e400')
        with pytest.raises(IdTokenError, match="exp"):
            _verify(_token(raw))

    def test_missing_or_bad_iat(self) -> None:
        with pytest.raises(IdTokenError, match="iat"):
            _verify(_token(_claims(iat=_DROP)))
        with pytest.raises(IdTokenError, match="iat"):
            _verify(_token(_claims(iat="1")))

    @pytest.mark.parametrize("typ", ["at+jwt", "logout+jwt", "JWS", ""])
    def test_wrong_typ(self, typ: str) -> None:
        with pytest.raises(IdTokenError, match="typ"):
            _verify(_token(_claims(), {"alg": "RS256", "kid": KID, "typ": typ}))

    @pytest.mark.parametrize("header", [{"alg": "RS256", "kid": KID}, {"alg": "RS256", "kid": KID, "typ": "jwt"}])
    def test_absent_or_lowercase_jwt_typ_is_fine(self, header: dict[str, Any]) -> None:
        assert _verify(_token(_claims(), header))["sub"] == "user-1"

    def test_still_expires(self) -> None:
        with pytest.raises(IdTokenError, match="expired"):
            _verify(_token(_claims(exp=int(time.time()) - 3600)))


def _server(refreshed_sub: str = "user-1", direct: bool = False, interaction: bool = False) -> tuple[Any, list[Any]]:
    calls: list[Any] = []
    issued: set[str] = set()
    disc = {"issuer": ID["issuer"], "token_endpoint": ID["issuer"] + "/token", "jwks_uri": ID["issuer"] + "/jwks",
            "authorization_endpoint": ID["issuer"] + "/auth", "userinfo_endpoint": ID["issuer"] + "/me"}

    def transport(method: str, url: str, headers: dict[str, str], body: str | None) -> tuple[int, Any]:
        calls.append((method, url, headers, body))
        if url == ID["discovery"]:
            return 200, disc
        if url == disc["jwks_uri"]:
            return 200, {"keys": JWKS}
        if url == disc["token_endpoint"] and method == "POST":
            return 200, {"id_token": _token(_claims(sub=refreshed_sub)), "access_token": "at-2", "refresh_token": "rt-2"}
        if url == ID["issuer"] + "/siwe/challenge":
            if method != "GET":
                return 404, {"error": "invalid_request"}
            nonce = f"n{len(issued) + 1}abcdefgh"
            issued.add(nonce)
            return 200, {"nonce": nonce}
        if url == ID["issuer"] + "/siwe/verify" and method == "POST":
            b = json.loads(body or "{}")
            m = b.get("message")
            if not isinstance(m, str) or not isinstance(b.get("signature"), str):
                return 400, {"error": "invalid_request", "reason": "message and signature are required strings"}
            nonce = m.split("\nNonce: ")[1].split("\n")[0]
            if nonce not in issued:
                return 401, {"error": "invalid_grant", "reason": "unknown_nonce"}
            issued.discard(nonce)
            if "\nChain ID: 40204\n" not in m or "\nExpiration Time: " not in m:
                return 401, {"error": "invalid_grant", "reason": "wrong_chain_or_expiry"}
            if interaction:
                return 200, {"address": ADDRESS, "method": "eoa", "redirectTo": ID["issuer"] + "/auth/xyz"}
            if not direct:
                return 400, {"error": "invalid_request", "reason": "no active OIDC interaction; the direct token grant is disabled"}
            return 200, {"address": ADDRESS, "method": "eoa", "token_type": "Bearer",
                         "id_token": _token(_claims(sub=ADDRESS.lower())), "wallet_address": ADDRESS}
        return 404, {}

    return transport, calls


def _client(transport: Any) -> IdentityClient:
    return IdentityClient(client_id=CLIENT_ID, redirect_uri="http://127.0.0.1:8899/cb", transport=transport)


class TestRefreshPinsSub:
    def test_same_sub(self) -> None:
        t, _ = _server()
        assert _client(t).refresh("rt-1", expected_sub="user-1").claims["sub"] == "user-1"

    def test_changed_sub(self) -> None:
        t, _ = _server(refreshed_sub="user-2")
        with pytest.raises(IdentityError, match=r"sub changed \(user-2 != user-1\)"):
            _client(t).refresh("rt-1", expected_sub="user-1")

    def test_expected_sub_required(self) -> None:
        t, _ = _server()
        with pytest.raises(TypeError):
            _client(t).refresh("rt-1")  # type: ignore[call-arg]
        with pytest.raises(IdentityError, match="expected_sub"):
            _client(t).refresh("rt-1", expected_sub="")


class TestSiweContract:
    def test_challenge_is_get(self) -> None:
        t, calls = _server()
        assert _client(t).siwe_challenge() == {"nonce": "n1abcdefgh"}
        method, url, _, body = [c for c in calls if c[1].endswith("/siwe/challenge")][0]
        assert method == "GET" and body is None

    def test_message_matches_eip4361_exactly(self) -> None:
        issued = datetime(2026, 9, 25, tzinfo=timezone.utc)
        domain = ID["issuer"].split("://", 1)[1].split("/")[0]
        assert idc.build_siwe_message(ADDRESS.lower(), "abcdefgh", issued_at=issued) == (
            f"{domain} wants you to sign in with your Ethereum account:\n{ADDRESS}\n\n\n"
            f"URI: {ID['issuer']}\nVersion: 1\nChain ID: 40204\nNonce: abcdefgh\n"
            "Issued At: 2026-09-25T00:00:00.000Z\nExpiration Time: 2026-09-25T00:10:00.000Z"
        )
        assert "\n\nHi\n\nURI: " in idc.build_siwe_message(ADDRESS, "abcdefgh", statement="Hi", issued_at=issued)

    @pytest.mark.parametrize("kw", [{"uri": "https://evil.example/x"}, {"nonce": "short"}, {"nonce": "-abcdefgh"},
                                    {"ttl_seconds": 0}, {"ttl_seconds": 86401}, {"address": "0x1234"}])
    def test_message_inputs_are_checked(self, kw: dict[str, Any]) -> None:
        args: dict[str, Any] = {"address": ADDRESS, "nonce": "abcdefgh"}
        args.update(kw)
        with pytest.raises(IdentityError):
            idc.build_siwe_message(**args)

    def test_direct_token_path(self) -> None:
        t, _ = _server(direct=True)
        c = _client(t)
        nonce = c.siwe_challenge()["nonce"]
        r = c.siwe_verify(idc.build_siwe_message(ADDRESS, nonce), "0x" + "11" * 65)
        assert r["kind"] == "token" and r["address"] == ADDRESS and r["claims"]["sub"] == ADDRESS.lower()

    def test_interaction_path(self) -> None:
        t, _ = _server(interaction=True)
        c = _client(t)
        nonce = c.siwe_challenge()["nonce"]
        r = c.siwe_verify(idc.build_siwe_message(ADDRESS, nonce), "0x" + "11" * 65)
        assert r == {"kind": "redirect", "address": ADDRESS, "method": "eoa", "redirect_to": ID["issuer"] + "/auth/xyz"}

    def test_rejection_reason_surfaces(self) -> None:
        t, _ = _server()
        c = _client(t)
        nonce = c.siwe_challenge()["nonce"]
        with pytest.raises(IdentityError, match="direct token grant is disabled"):
            c.siwe_verify(idc.build_siwe_message(ADDRESS, nonce), "0x" + "11" * 65)

    def test_forged_id_token_rejected(self) -> None:
        t, _ = _server(direct=True)

        def forging(method: str, url: str, headers: dict[str, str], body: str | None) -> tuple[int, Any]:
            status, parsed = t(method, url, headers, body)
            if url.endswith("/siwe/verify") and status == 200:
                h, p, _s = parsed["id_token"].split(".")
                parsed = dict(parsed, id_token=f"{h}.{p}.AAAA")
            return status, parsed

        c = _client(forging)
        nonce = c.siwe_challenge()["nonce"]
        with pytest.raises(IdTokenError, match="signature"):
            c.siwe_verify(idc.build_siwe_message(ADDRESS, nonce), "0x" + "11" * 65)
