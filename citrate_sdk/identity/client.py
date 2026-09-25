"""IdentityClient (DEVX-S1) — Python parity of the JS authorization spine.

Wraps auth.citrate.ai: OIDC PKCE + SIWE, hardened ID-token verification, userinfo (with
normalized entitlement capabilities), logout. Endpoints/scopes/entitlement-claim come from the
federation contract artifact (DEVX-S0). Stateless + fail-closed; holds no keys.

The HTTP boundary is an injectable ``transport`` callable so the client is offline-testable:
    transport(method, url, headers, body) -> (status_code: int, parsed_json: Any)
The default transport uses ``requests``.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, cast
from urllib.parse import urlencode, urlparse

import requests
from eth_utils import to_checksum_address

from .._generated import contract as _contract
from .._url_security import enforce_transport_security
from ..entitlements import CapabilitySet, normalize_tier, resolve_capabilities
from .jwt import verify_id_token
from .pkce import Pkce, create_pkce

Transport = Callable[[str, str, dict[str, str], str | None], tuple[int, Any]]


class IdentityError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _default_transport(method: str, url: str, headers: dict[str, str], body: str | None) -> tuple[int, Any]:
    resp = requests.request(method, url, headers=headers, data=body, timeout=30)
    parsed: Any = {}
    if resp.status_code != 204 and resp.text:
        try:
            parsed = resp.json()
        except ValueError:
            parsed = {}
    return resp.status_code, parsed


#: citrate-identity rejects an Expiration Time more than 24 h out.
_SIWE_MAX_TTL_SECONDS = 24 * 60 * 60


def _iso_ms(t: datetime) -> str:
    t = t.astimezone(timezone.utc)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + "%03dZ" % (t.microsecond // 1000)


def build_siwe_message(
    address: str,
    nonce: str,
    *,
    statement: str | None = None,
    uri: str | None = None,
    chain_id: int | None = None,
    ttl_seconds: int = 600,
    issued_at: datetime | None = None,
) -> str:
    """Build the EIP-4361 message citrate-identity verifies (PBA-L3a-012 twin).

    Enforces what the authority enforces: chain 40204 (the artifact chain), a
    mandatory Expiration Time no more than 24 h out, a URI whose host is the
    authority's, and an EIP-55 checksummed address. Same output as the JS SDK's
    ``buildSiweMessage``.
    """
    issuer = _contract.identity()["issuer"]
    authority = urlparse(issuer)
    domain = authority.netloc
    the_uri = uri or f"{authority.scheme}://{authority.netloc}"
    if urlparse(the_uri).netloc != domain:
        raise IdentityError("build_siwe_message: uri host must be the authority domain " + domain)
    try:
        checksummed = to_checksum_address(address)
    except (ValueError, TypeError):
        raise IdentityError("build_siwe_message: address must be a valid 20-byte hex address")
    if not re.fullmatch(r"[A-Za-z0-9]{8,}", nonce or ""):
        raise IdentityError("build_siwe_message: nonce must be the alphanumeric value from siwe_challenge")
    if isinstance(ttl_seconds, bool) or not isinstance(ttl_seconds, int) or not 0 < ttl_seconds <= _SIWE_MAX_TTL_SECONDS:
        raise IdentityError("build_siwe_message: ttl_seconds must be an integer in 1..86400 (the authority caps expiry at 24 h)")
    start = issued_at or datetime.now(timezone.utc)
    lines = [
        f"{domain} wants you to sign in with your Ethereum account:",
        checksummed,
        "",
        # EIP-4361 ABNF: address LF LF [statement LF] LF "URI: ..."
        *([statement] if statement else []),
        "",
        "URI: " + the_uri,
        "Version: 1",
        f"Chain ID: {chain_id if chain_id is not None else _contract.chain_id()}",
        "Nonce: " + nonce,
        "Issued At: " + _iso_ms(start),
        "Expiration Time: " + _iso_ms(start + timedelta(seconds=ttl_seconds)),
    ]
    return "\n".join(lines)


@dataclass
class TokenSet:
    id_token: str
    access_token: str
    refresh_token: str | None
    claims: dict[str, Any]


@dataclass
class UserInfo:
    sub: str
    tier: str
    capabilities: CapabilitySet
    wallet_address: str | None
    wallets: list[str] | None
    kyc_status: str | None
    raw: dict[str, Any]


@dataclass
class IdentityClient:
    client_id: str
    redirect_uri: str
    scopes: list[str] | None = None
    transport: Transport = _default_transport
    # SPY-B-004: this client posts to token/userinfo/session endpoints taken from
    # the discovery document and carries access_token / refresh_token / id_token as
    # Bearer credentials. Route every URL through enforce_transport_security so a
    # plaintext http:// endpoint (including a hostile discovery doc) is flagged.
    # Localhost http:// stays silent; set True to silence the warning for a remote
    # http endpoint you genuinely intend to use.
    allow_insecure_http: bool = False
    _discovery: dict[str, Any] | None = field(default=None, init=False, repr=False)
    _jwks: list[dict[str, Any]] | None = field(default=None, init=False, repr=False)

    @property
    def _id(self) -> dict[str, Any]:
        return _contract.identity()

    def _get_json(self, url: str, bearer: str | None = None) -> Any:
        url = enforce_transport_security(url, allow_insecure_http=self.allow_insecure_http)
        headers = {"authorization": "Bearer " + bearer} if bearer else {}
        status, body = self.transport("GET", url, headers, None)
        if not (200 <= status < 300):
            raise IdentityError("GET %s failed: %d" % (url, status), status)
        return body

    def _post(self, url: str, headers: dict[str, str], body: str) -> Any:
        url = enforce_transport_security(url, allow_insecure_http=self.allow_insecure_http)
        status, parsed = self.transport("POST", url, headers, body)
        if not (200 <= status < 300):
            raise IdentityError("POST %s failed: %d" % (url, status), status)
        return parsed

    def discover(self) -> dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        doc = self._get_json(self._id["discovery"])
        if doc.get("issuer") != self._id["issuer"]:
            raise IdentityError("issuer mismatch: {}".format(doc.get("issuer")))
        self._discovery = doc
        return cast("dict[str, Any]", doc)

    def _get_jwks(self) -> list[dict[str, Any]]:
        if self._jwks is not None:
            return self._jwks
        try:
            uri = self.discover().get("jwks_uri") or self._id["jwks"]
        except IdentityError:
            uri = self._id["jwks"]
        body = self._get_json(uri)
        keys = body.get("keys") if isinstance(body, dict) else None
        if not keys:
            raise IdentityError("JWKS has no keys")
        self._jwks = keys
        return cast("list[dict[str, Any]]", keys)

    def authorize_url(self, state: str, nonce: str, pkce: Pkce | None = None,
                      scopes: list[str] | None = None) -> tuple[str, Pkce]:
        pk = pkce or create_pkce()
        params = {
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "response_type": "code",
            "scope": " ".join(scopes or self.scopes or self._id["scopes"]),
            "state": state,
            "nonce": nonce,
            "code_challenge": pk.challenge,
            "code_challenge_method": "S256",
        }
        base = (self._discovery or {}).get("authorization_endpoint") or (self._id["issuer"] + "/auth")
        return base + "?" + urlencode(params), pk

    def _finish_tokens(self, tok: dict[str, Any], nonce: str | None = None) -> TokenSet:
        claims = verify_id_token(
            tok["id_token"], issuer=self._id["issuer"], audience=self.client_id,
            jwks=self._get_jwks(), nonce=nonce,
        )
        return TokenSet(tok["id_token"], tok["access_token"], tok.get("refresh_token"), claims)

    def exchange_code(self, code: str, code_verifier: str, nonce: str) -> TokenSet:
        """Exchange an authorization code for tokens and verify the ID token.

        SPY-B-010: ``nonce`` is REQUIRED. ``authorize_url`` already requires a
        nonce, and ``verify_id_token`` only checks the nonce claim when a value
        is supplied — so an optional nonce here meant the obvious flow (generate
        a nonce, put it in the URL, exchange the code) produced a token that
        LOOKED nonce-protected but never bound the ID token to the authorization
        request. Threading the same nonce through closes the ID-token replay/
        injection gap that PKCE does not cover.
        """
        if not nonce:
            raise IdentityError(
                "exchange_code requires the nonce generated for authorize_url; "
                "without it the ID token is not bound to the authorization "
                "request and replay/injection is not detected (SPY-B-010)."
            )
        disc = self.discover()
        body = urlencode({
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": self.redirect_uri, "client_id": self.client_id,
            "code_verifier": code_verifier,
        })
        tok = self._post(disc["token_endpoint"], {"content-type": "application/x-www-form-urlencoded"}, body)
        return self._finish_tokens(tok, nonce)

    def refresh(self, refresh_token: str, expected_sub: str) -> TokenSet:
        """Refresh with a rotating refresh token.

        PBA-L3a-011 (Python twin): ``expected_sub`` is REQUIRED — the ``sub`` of
        the session being refreshed. OIDC Core 12.2 requires the refreshed ID
        token to carry the same ``sub``; the old code adopted a different one.
        """
        if not expected_sub:
            raise IdentityError("refresh requires expected_sub: the sub of the session being refreshed (PBA-L3a-011).")
        disc = self.discover()
        body = urlencode({"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": self.client_id})
        tok = self._post(disc["token_endpoint"], {"content-type": "application/x-www-form-urlencoded"}, body)
        tokens = self._finish_tokens(tok)
        if tokens.claims.get("sub") != expected_sub:
            raise IdentityError(
                "refresh: ID token sub changed ({} != {}); refusing the refreshed session "
                "(PBA-L3a-011).".format(tokens.claims.get("sub"), expected_sub)
            )
        return tokens

    def siwe_challenge(self) -> dict[str, str]:
        """GET /siwe/challenge -> ``{"nonce": ...}`` (PBA-L3a-012 twin).

        The authority serves this on GET only and returns just the nonce; build
        the message with :func:`build_siwe_message` and have the wallet sign it.
        """
        body = self._get_json(self._id["issuer"] + "/siwe/challenge")
        nonce = body.get("nonce") if isinstance(body, dict) else None
        if not isinstance(nonce, str) or len(nonce) < 8:
            raise IdentityError("siwe_challenge: authority returned no nonce")
        return {"nonce": nonce}

    def siwe_verify(self, message: str, signature: str) -> dict[str, Any]:
        """POST /siwe/verify ``{message, signature}`` (PBA-L3a-012 twin).

        Returns ``{"kind": "redirect", "address", "method", "redirect_to"}`` when
        an OIDC interaction was in flight (follow ``redirect_to`` to finish the
        code flow), or ``{"kind": "token", "address", "method", "id_token",
        "claims"}`` for the headless direct grant (only an ID token; it is
        verified against the JWKS first). Raises IdentityError with the
        authority's reason otherwise.
        """
        url = enforce_transport_security(self._id["issuer"] + "/siwe/verify",
                                         allow_insecure_http=self.allow_insecure_http)
        status, parsed = self.transport("POST", url, {"content-type": "application/json"},
                                        json.dumps({"message": message, "signature": signature}))
        body = parsed if isinstance(parsed, dict) else {}
        if not (200 <= status < 300):
            reason = body.get("reason") if isinstance(body.get("reason"), str) else str(body.get("error") or "")
            raise IdentityError("POST %s failed: %d%s" % (url, status, " (%s)" % reason if reason else ""), status)
        address = body.get("address") if isinstance(body.get("address"), str) else ""
        method = body.get("method") if isinstance(body.get("method"), str) else ""
        if isinstance(body.get("redirectTo"), str):
            return {"kind": "redirect", "address": address, "method": method, "redirect_to": body["redirectTo"]}
        if isinstance(body.get("id_token"), str):
            claims = verify_id_token(body["id_token"], issuer=self._id["issuer"], audience=self.client_id,
                                     jwks=self._get_jwks())
            return {"kind": "token", "address": address, "method": method, "id_token": body["id_token"],
                    "claims": claims}
        raise IdentityError("siwe_verify: authority response has neither redirectTo nor id_token")

    def user_info(self, access_token: str) -> UserInfo:
        disc = self.discover()
        raw = self._get_json(disc["userinfo_endpoint"], bearer=access_token)
        ent = raw.get(self._id["entitlementClaim"]) or {}
        tier = normalize_tier(ent.get("tier"))
        # SPY-B-002: was `CapabilitySet(True, True, True, True) if ent.get("citrateRole")`,
        # granting EVERY capability to any truthy role regardless of tier.
        # SPY-B-003: `capabilities_for_claim` does NOT apply `expiresAt`, so an expired
        # entitlement still yielded full capabilities here while `can()` collapsed it to
        # public — one policy, two answers. Route through the single canonical resolver
        # (`resolve_capabilities`, the same one `can` uses) so a role escalates only via
        # the ROLE_CAPABILITIES allowlist AND an expired claim collapses to public — no
        # inline duplicate, and the two paths cannot diverge on expiry.
        caps = resolve_capabilities(ent)
        wallets = raw.get("wallets") if isinstance(raw.get("wallets"), list) else None
        return UserInfo(
            sub=str(raw.get("sub", "")), tier=tier, capabilities=caps,
            wallet_address=raw.get("wallet_address") if isinstance(raw.get("wallet_address"), str) else None,
            wallets=wallets, kyc_status=raw.get("kyc_status") if isinstance(raw.get("kyc_status"), str) else None,
            raw=raw,
        )

    def request_deploy_permit(self, user_id: str, init_data: str, expires_at: int, access_token: str) -> dict[str, Any]:
        """Request a factory deploy permit for the embedded wallet (authenticated).

        POST /aa/enroll-validator — the authority signs with its identity-signer; the SDK never
        signs. The returned permit is included in the CitrateWalletFactory.deployFor call.
        """
        return cast("dict[str, Any]", self._post(
            self._id["issuer"] + "/aa/enroll-validator",
            {"authorization": "Bearer " + access_token, "content-type": "application/json"},
            json.dumps({"userId": user_id, "initData": init_data, "expiresAt": expires_at}),
        ))

    def list_validators(self, user_id: str) -> Any:
        """GET /aa/validators — validators installed on the wallet (chain read, no auth)."""
        from urllib.parse import quote
        return self._get_json(self._id["issuer"] + "/aa/validators?userId=" + quote(user_id))

    def guardian_config(self, access_token: str) -> Any:
        """GET /aa/guardians — stored guardian nomination + Kernel initConfig (Bearer)."""
        return self._get_json(self._id["issuer"] + "/aa/guardians", bearer=access_token)

    def logout(self, access_token: str) -> None:
        try:
            url = self.discover().get("end_session_endpoint") or (self._id["issuer"] + "/logout")
        except IdentityError:
            url = self._id["issuer"] + "/logout"
        self._post(url, {"authorization": "Bearer " + access_token,
                         "content-type": "application/x-www-form-urlencoded"}, "")
