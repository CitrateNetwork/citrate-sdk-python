"""Inference gateway client (DEVX-S2) — OpenAI-compatible over infer.citrate.ai (Python parity).

A thin, typed client: a ``cgk_`` bearer key + the base URL from the federation artifact. Carries
the key; does not mint keys (server-side, E-2) or do x402 (server-side). Fail-closed: no key -> a
typed error, never a silent open call or a fabricated response.

The HTTP boundary is an injectable ``transport`` callable for offline testing:
    transport(method, url, headers, body) -> (status_code: int, parsed_json: Any)
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Optional, Tuple

import requests

from ._generated import contract as _contract
from ._url_security import enforce_transport_security

Transport = Callable[[str, str, Dict[str, str], Optional[str]], Tuple[int, Any]]


class GatewayError(Exception):
    def __init__(self, message: str, status: Optional[int] = None):
        super().__init__(message)
        self.status = status


def _default_transport(method: str, url: str, headers: Dict[str, str], body: Optional[str]) -> Tuple[int, Any]:
    resp = requests.request(method, url, headers=headers, data=body, timeout=300)
    parsed: Any = {}
    if resp.text:
        try:
            parsed = resp.json()
        except ValueError:
            parsed = {}
    return resp.status_code, parsed


class GatewayClient:
    def __init__(self, api_key: str, base_url: Optional[str] = None, transport: Optional[Transport] = None,
                 allow_insecure_http: bool = False):
        gw = _contract.gateway()
        if not api_key:
            raise GatewayError("gateway API key not configured (need a %s key)" % gw["keyPrefix"])
        self._api_key = api_key
        base = (base_url or gw["baseUrl"]).rstrip("/")
        # SPY-B-004: this client sends `Authorization: Bearer <cgk_ key>` on every
        # call. A remote http:// base_url would ship the key in cleartext — flag it
        # (localhost http:// stays silent; allow_insecure_http silences remote http).
        enforce_transport_security(base, allow_insecure_http=allow_insecure_http)
        self._base = base
        self._transport = transport or _default_transport

    def _call(self, method: str, path: str, body: Optional[str] = None) -> Any:
        headers = {"authorization": "Bearer " + self._api_key}
        if body is not None:
            headers["content-type"] = "application/json"
        status, parsed = self._transport(method, self._base + path, headers, body)
        if not (200 <= status < 300):
            raise self._error(status)
        return parsed

    def chat_completions(self, model: str, messages: List[Dict[str, str]], **kwargs: Any) -> Any:
        """POST /v1/chat/completions — OpenAI-shaped request and response."""
        payload = {"model": model, "messages": messages}
        payload.update(kwargs)
        return self._call("POST", "/v1/chat/completions", json.dumps(payload))

    def list_models(self) -> Any:
        return self._call("GET", "/v1/models")

    def get_usage(self) -> Any:
        return self._call("GET", "/v1/usage")

    def health(self) -> Any:
        status, parsed = self._transport("GET", self._base + "/health", {}, None)
        if not (200 <= status < 300):
            raise self._error(status)
        return parsed

    @staticmethod
    def _error(status: int) -> "GatewayError":
        msg = {
            401: "unauthorized: unknown or revoked gateway key",
            402: "insufficient balance: top up the gateway key",
            429: "rate limited: retry after backoff",
            503: "gateway upstream unavailable",
        }.get(status, "gateway request failed: %d" % status)
        return GatewayError(msg, status)
