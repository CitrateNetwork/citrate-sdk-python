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
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import urlencode

import requests

from .._generated import contract as _contract
from .._url_security import enforce_transport_security
from ..entitlements import CapabilitySet, normalize_tier, resolve_capabilities
from .jwt import verify_id_token
from .pkce import Pkce, create_pkce

Transport = Callable[[str, str, Dict[str, str], Optional[str]], Tuple[int, Any]]


class IdentityError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def _default_transport(method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, Any]:
    resp = requests.request(method, url, headers=headers, data=body, timeout=30)
    parsed: Any = {}
    if resp.status_code != 204 and resp.text:
        try:
            parsed = resp.json()
        except ValueError:
            parsed = {}
    return resp.status_code, parsed


@dataclass
class TokenSet:
    id_token: str
    access_token: str
    refresh_token: Optional[str]
    claims: Dict[str, Any]


@dataclass
class UserInfo:
    sub: str
    tier: str
    capabilities: CapabilitySet
    wallet_address: Optional[str]
    wallets: Optional[List[str]]
    kyc_status: Optional[str]
    raw: Dict[str, Any]


@dataclass
class IdentityClient:
    client_id: str
    redirect_uri: str
    scopes: Optional[List[str]] = None
    transport: Transport = _default_transport
    # SPY-B-004: this client posts to token/userinfo/session endpoints taken from
    # the discovery document and carries access_token / refresh_token / id_token as
    # Bearer credentials. Route every URL through enforce_transport_security so a
    # plaintext http:// endpoint (including a hostile discovery doc) is flagged.
    # Localhost http:// stays silent; set True to silence the warning for a remote
    # http endpoint you genuinely intend to use.
    allow_insecure_http: bool = False
    _discovery: Optional[Dict[str, Any]] = field(default=None, init=False, repr=False)
    _jwks: Optional[List[Dict[str, Any]]] = field(default=None, init=False, repr=False)

    @property
    def _id(self) -> Dict[str, Any]:
        return _contract.identity()

    def _get_json(self, url: str, bearer: Optional[str] = None) -> Any:
        enforce_transport_security(url, allow_insecure_http=self.allow_insecure_http)
        headers = {"authorization": "Bearer " + bearer} if bearer else {}
        status, body = self.transport("GET", url, headers, None)
        if not (200 <= status < 300):
            raise IdentityError("GET %s failed: %d" % (url, status), status)
        return body

    def _post(self, url: str, headers: Dict[str, str], body: str) -> Any:
        enforce_transport_security(url, allow_insecure_http=self.allow_insecure_http)
        status, parsed = self.transport("POST", url, headers, body)
        if not (200 <= status < 300):
            raise IdentityError("POST %s failed: %d" % (url, status), status)
        return parsed

    def discover(self) -> Dict[str, Any]:
        if self._discovery is not None:
            return self._discovery
        doc = self._get_json(self._id["discovery"])
        if doc.get("issuer") != self._id["issuer"]:
            raise IdentityError("issuer mismatch: %s" % doc.get("issuer"))
        self._discovery = doc
        return doc

    def _get_jwks(self) -> List[Dict[str, Any]]:
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
        return keys

    def authorize_url(self, state: str, nonce: str, pkce: Optional[Pkce] = None,
                      scopes: Optional[List[str]] = None) -> Tuple[str, Pkce]:
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

    def _finish_tokens(self, tok: Dict[str, Any], nonce: Optional[str] = None) -> TokenSet:
        claims = verify_id_token(
            tok["id_token"], issuer=self._id["issuer"], audience=self.client_id,
            jwks=self._get_jwks(), nonce=nonce,
        )
        return TokenSet(tok["id_token"], tok["access_token"], tok.get("refresh_token"), claims)

    def exchange_code(self, code: str, code_verifier: str, nonce: Optional[str] = None) -> TokenSet:
        disc = self.discover()
        body = urlencode({
            "grant_type": "authorization_code", "code": code,
            "redirect_uri": self.redirect_uri, "client_id": self.client_id,
            "code_verifier": code_verifier,
        })
        tok = self._post(disc["token_endpoint"], {"content-type": "application/x-www-form-urlencoded"}, body)
        return self._finish_tokens(tok, nonce)

    def refresh(self, refresh_token: str) -> TokenSet:
        disc = self.discover()
        body = urlencode({"grant_type": "refresh_token", "refresh_token": refresh_token, "client_id": self.client_id})
        tok = self._post(disc["token_endpoint"], {"content-type": "application/x-www-form-urlencoded"}, body)
        return self._finish_tokens(tok)

    def siwe_challenge(self, address: str) -> Dict[str, Any]:
        return self._post(self._id["issuer"] + "/siwe/challenge",
                          {"content-type": "application/json"}, json.dumps({"address": address}))

    def siwe_verify(self, message: str, signature: str) -> TokenSet:
        tok = self._post(self._id["issuer"] + "/siwe/verify",
                         {"content-type": "application/json"},
                         json.dumps({"message": message, "signature": signature}))
        return self._finish_tokens(tok)

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

    def request_deploy_permit(self, user_id: str, init_data: str, expires_at: int, access_token: str) -> Dict[str, Any]:
        """Request a factory deploy permit for the embedded wallet (authenticated).

        POST /aa/enroll-validator — the authority signs with its identity-signer; the SDK never
        signs. The returned permit is included in the CitrateWalletFactory.deployFor call.
        """
        return self._post(
            self._id["issuer"] + "/aa/enroll-validator",
            {"authorization": "Bearer " + access_token, "content-type": "application/json"},
            json.dumps({"userId": user_id, "initData": init_data, "expiresAt": expires_at}),
        )

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
