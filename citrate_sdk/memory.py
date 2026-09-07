"""Memory client — typed access to a citrate-memories gateway ("git for agents"), Python parity.

Two auth surfaces, mirroring the gateway and the TS SDK's ``memory`` module:
  1. ``MemoryClient`` — OIDC ``id_token`` bearer over the per-org REST routes
     (``/api/orgs/:org/{layout,recall,search,neighbors,verify,review,assert}``).
  2. ``ByomMemoryClient`` — a connect-token + ``sub`` bearer over the BYOM
     MCP-over-HTTP endpoint (``POST /mcp/u/:sub``), speaking JSON-RPC to the same
     11 ``memory.*`` tools the stdio/daemon transports serve.

Thin and typed: carries a token, shapes requests/responses. Mints no tokens, holds
no keys. Fail-closed — a missing origin, token, or transport raises ``MemoryError``.

The gateway origin is per-deployment (e.g. ``MEM_GATEWAY_ORIGIN``), so it is a
required argument; no hostname is baked in.

The HTTP boundary is an injectable ``transport`` callable for offline testing:
    transport(method, url, headers, body) -> (status_code: int, parsed_json: Any)
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any, cast
from urllib.parse import quote, urlencode

import requests

from ._url_security import enforce_transport_security

Transport = Callable[[str, str, dict[str, str], str | None], tuple[int, Any]]


class MemoryError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


def _default_transport(
    method: str, url: str, headers: dict[str, str], body: str | None
) -> tuple[int, Any]:
    resp = requests.request(method, url, headers=headers, data=body, timeout=300)
    parsed: Any = {}
    if resp.text:
        try:
            parsed = resp.json()
        except ValueError:
            parsed = {}
    return resp.status_code, parsed


def _status_error(status: int, context: str) -> MemoryError:
    msg = {
        401: "unauthorized: missing, expired, or invalid id_token",
        403: "forbidden: no membership or capability for this org/resource",
        404: "not found: unknown org, route, or node id prefix",
        429: "rate limited: retry after backoff",
    }.get(status)
    if msg is None:
        msg = (
            f"gateway upstream error ({status})"
            if status >= 500
            else f"request failed ({status})"
        )
    return MemoryError(f"{context}: {msg}", status)


# The 11 canonical memory tool names served over MCP.
MEMORY_TOOLS = (
    "memory.recall",
    "memory.search",
    "memory.neighbors",
    "memory.as_of",
    "memory.verify",
    "memory.critique",
    "memory.analogy",
    "memory.assert",
    "memory.merge_diff",
    "memory.propose_edge",
    "memory.confirm_edge",
)


class OrgMemory:
    """Per-org, per-repo read/write surface. Obtain via ``MemoryClient.org(id)``."""

    def __init__(
        self, origin: str, org: str, transport: Transport, token: Callable[[], str]
    ):
        self._origin = origin
        self._org = org
        self._transport = transport
        self._token = token

    def layout(self) -> dict[str, Any]:
        """GET /api/orgs/:org/layout — the PCA-2D constellation scene."""
        return self._get("layout", {})

    def recall(
        self, repo: str, budget: int | None = None, include_in_flight: bool = False
    ) -> dict[str, Any]:
        """GET /api/orgs/:org/recall — the storyline of a repo (budgeted)."""
        self._need_repo(repo)
        params = {"repo": repo}
        params.update(self._budget(budget))
        params.update(self._in_flight(include_in_flight))
        return self._get("recall", params)

    def search(
        self,
        repo: str,
        q: str,
        budget: int | None = None,
        include_in_flight: bool = False,
    ) -> dict[str, Any]:
        """GET /api/orgs/:org/search — semantic search within a repo."""
        self._need_repo(repo)
        if not q:
            raise MemoryError("search: q required")
        params = {"repo": repo, "q": q}
        params.update(self._budget(budget))
        params.update(self._in_flight(include_in_flight))
        return self._get("search", params)

    def neighbors(
        self, repo: str, node_id: str, budget: int | None = None
    ) -> dict[str, Any]:
        """GET /api/orgs/:org/neighbors — graph neighbors of a node (id prefix ok)."""
        self._need_repo(repo)
        if not node_id:
            raise MemoryError("neighbors: node_id required")
        params = {"repo": repo, "id": node_id}
        params.update(self._budget(budget))
        return self._get("neighbors", params)

    def verify(self, repo: str, node_id: str) -> dict[str, Any]:
        """GET /api/orgs/:org/verify — is a node current, superseded, or contradicted?"""
        self._need_repo(repo)
        if not node_id:
            raise MemoryError("verify: node_id required")
        return self._get("verify", {"repo": repo, "id": node_id})

    def review(self, repo: str, budget: int | None = None) -> dict[str, Any]:
        """GET /api/orgs/:org/review — items a human should review."""
        self._need_repo(repo)
        params = {"repo": repo}
        params.update(self._budget(budget))
        return self._get("review", params)

    def assert_(
        self,
        repo: str,
        content: str,
        kind: str | None = None,
        valid_from: int | None = None,
    ) -> dict[str, Any]:
        """POST /api/orgs/:org/assert — write a signed, append-only assertion.

        Named ``assert_`` because ``assert`` is a Python keyword.
        """
        self._need_repo(repo)
        if not content:
            raise MemoryError("assert: content required")
        body: dict[str, Any] = {"repo": repo, "content": content}
        if kind is not None:
            body["kind"] = kind
        if valid_from is not None:
            body["valid_from"] = valid_from
        headers = {
            "authorization": "Bearer " + self._token(),
            "content-type": "application/json",
        }
        status, parsed = self._transport(
            "POST", self._base() + "/assert", headers, json.dumps(body)
        )
        if not (200 <= status < 300):
            raise _status_error(status, "assert")
        return cast("dict[str, Any]", parsed)

    def _base(self) -> str:
        return "{}/api/orgs/{}".format(self._origin, quote(self._org, safe=""))

    def _get(self, path: str, params: dict[str, str]) -> dict[str, Any]:
        qs = ("?" + urlencode(params)) if params else ""
        headers = {"authorization": "Bearer " + self._token()}
        status, parsed = self._transport(
            "GET", f"{self._base()}/{path}{qs}", headers, None
        )
        if not (200 <= status < 300):
            raise _status_error(status, path)
        return cast("dict[str, Any]", parsed)

    @staticmethod
    def _need_repo(repo: str) -> None:
        if not repo:
            raise MemoryError("repo required")

    @staticmethod
    def _budget(n: int | None) -> dict[str, str]:
        return {"budget": str(n)} if n is not None else {}

    @staticmethod
    def _in_flight(b: bool) -> dict[str, str]:
        return {"include_in_flight": "true"} if b else {}


class MemoryClient:
    """REST client over one citrate-memories gateway.

    ``.org(id)`` gives the per-org read/write surface; ``.health()`` needs no token.
    """

    def __init__(
        self,
        origin: str,
        id_token: str | None = None,
        transport: Transport | None = None,
        allow_insecure_http: bool = False,
    ):
        if not origin:
            raise MemoryError("memory gateway origin not configured")
        origin = origin.rstrip("/")
        # SPY-B-004: org routes send `Authorization: Bearer <id_token>` — an OIDC
        # identity assertion. A remote http:// origin would ship it in cleartext.
        enforce_transport_security(origin, allow_insecure_http=allow_insecure_http)
        self._origin = origin
        self._id_token = id_token
        self._transport = transport or _default_transport

    def health(self) -> dict[str, Any]:
        """GET /api/health — open readiness probe (no auth)."""
        status, parsed = self._transport("GET", self._origin + "/api/health", {}, None)
        if not (200 <= status < 300):
            raise _status_error(status, "health")
        return cast("dict[str, Any]", parsed)

    def org(self, org: str) -> OrgMemory:
        if not org:
            raise MemoryError("org id required")
        return OrgMemory(self._origin, org, self._transport, self._require_token)

    def _require_token(self) -> str:
        if not self._id_token:
            raise MemoryError("id_token required for org routes; set id_token", 401)
        return self._id_token


class ByomMemoryClient:
    """BYOM client: JSON-RPC to ``POST /mcp/u/:sub``.

    The gateway mints the capability grant server-side from the connect token, so
    the caller supplies no grant — just the tool name and arguments. Agent adapters
    wrap ``call_tool`` for recall/assert hooks.
    """

    def __init__(
        self,
        origin: str,
        sub: str,
        connect_token: str,
        transport: Transport | None = None,
        allow_insecure_http: bool = False,
    ):
        if not origin:
            raise MemoryError("memory gateway origin not configured")
        if not sub:
            raise MemoryError("BYOM sub required")
        if not connect_token:
            raise MemoryError("BYOM connect token required")
        origin = origin.rstrip("/")
        # SPY-B-004: the BYOM endpoint carries `Authorization: Bearer <connect_token>`.
        # A remote http:// origin would ship it in cleartext.
        enforce_transport_security(origin, allow_insecure_http=allow_insecure_http)
        self._url = "{}/mcp/u/{}".format(origin, quote(sub, safe=""))
        self._connect_token = connect_token
        self._transport = transport or _default_transport
        self._id = 0

    def rpc(self, method: str, params: Any = None) -> Any:
        """Send one JSON-RPC request and return its ``result`` (raises on error)."""
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params}
        )
        headers = {
            "authorization": "Bearer " + self._connect_token,
            "content-type": "application/json",
        }
        status, parsed = self._transport("POST", self._url, headers, payload)
        if not (200 <= status < 300):
            raise _status_error(status, method)
        if not isinstance(parsed, dict):
            raise MemoryError(f"{method}: malformed JSON-RPC response")
        if parsed.get("error"):
            err = parsed["error"]
            raise MemoryError(
                "{}: {}".format(method, err.get("message", "JSON-RPC error")),
                err.get("code"),
            )
        return parsed.get("result")

    def call_tool(self, name: str, args: dict[str, Any] | None = None) -> Any:
        """Invoke one memory.* tool via MCP ``tools/call``."""
        if name not in MEMORY_TOOLS:
            raise MemoryError(f"unknown memory tool: {name}")
        return self.rpc("tools/call", {"name": name, "arguments": args or {}})

    def recall(self, **args: Any) -> Any:
        return self.call_tool("memory.recall", args)

    def search(self, **args: Any) -> Any:
        return self.call_tool("memory.search", args)

    def neighbors(self, **args: Any) -> Any:
        return self.call_tool("memory.neighbors", args)

    def as_of(self, **args: Any) -> Any:
        return self.call_tool("memory.as_of", args)

    def verify(self, **args: Any) -> Any:
        return self.call_tool("memory.verify", args)

    def critique(self, **args: Any) -> Any:
        return self.call_tool("memory.critique", args)

    def analogy(self, **args: Any) -> Any:
        return self.call_tool("memory.analogy", args)

    def assert_(self, **args: Any) -> Any:
        return self.call_tool("memory.assert", args)

    def merge_diff(self, **args: Any) -> Any:
        return self.call_tool("memory.merge_diff", args)

    def propose_edge(self, **args: Any) -> Any:
        return self.call_tool("memory.propose_edge", args)

    def confirm_edge(self, **args: Any) -> Any:
        return self.call_tool("memory.confirm_edge", args)
