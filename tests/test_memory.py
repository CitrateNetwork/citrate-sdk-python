"""Memory client — typed REST + BYOM MCP over a citrate-memories gateway (Python parity)."""

from __future__ import annotations

import json

from citrate_sdk.memory import ByomMemoryClient, MemoryClient, MemoryError

ORIGIN = "https://mem-gateway.example.com"


def _raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


def test_fail_closed_without_origin():
    assert _raises(MemoryError, lambda: MemoryClient(origin=""))


def test_health_needs_no_token():
    seen = {}

    def transport(method, url, headers, body):
        seen["url"] = url
        return 200, {"ok": True, "service": "mem-gateway"}

    c = MemoryClient(origin=ORIGIN, transport=transport)
    h = c.health()
    assert seen["url"] == ORIGIN + "/api/health"
    assert h["ok"] is True


def test_org_routes_fail_closed_without_id_token():
    c = MemoryClient(origin=ORIGIN, transport=lambda m, u, h, b: (200, {}))
    assert _raises(MemoryError, lambda: c.org("acme").recall("r"))


def test_recall_builds_url_with_budget_and_bearer():
    seen = {}

    def transport(method, url, headers, body):
        seen["url"] = url
        seen["auth"] = headers.get("authorization")
        return 200, {
            "repo": "r",
            "watermark": None,
            "total_in_tenant": 3,
            "count": 0,
            "items": [],
        }

    c = MemoryClient(origin=ORIGIN, id_token="id.jwt", transport=transport)
    r = c.org("citrate-federation").recall("citrate-chain", budget=5)
    assert (
        seen["url"]
        == ORIGIN + "/api/orgs/citrate-federation/recall?repo=citrate-chain&budget=5"
    )
    assert seen["auth"] == "Bearer id.jwt"
    assert r["total_in_tenant"] == 3


def test_search_requires_q_and_passes_include_in_flight():
    seen = {}

    def transport(method, url, headers, body):
        seen["url"] = url
        return 200, {
            "repo": "r",
            "watermark": None,
            "total_in_tenant": 0,
            "count": 0,
            "items": [],
        }

    org = MemoryClient(origin=ORIGIN, id_token="t", transport=transport).org("o")
    assert _raises(MemoryError, lambda: org.search("r", ""))
    org.search("r", "consensus", include_in_flight=True)
    assert "q=consensus" in seen["url"]
    assert "include_in_flight=true" in seen["url"]


def test_assert_posts_body_and_returns_receipt():
    seen = {}

    def transport(method, url, headers, body):
        seen["method"] = method
        seen["body"] = body
        return 200, {
            "id": "ab12",
            "repo": "r",
            "author": "ed25:pub",
            "embedded": True,
            "warning": None,
        }

    org = MemoryClient(origin=ORIGIN, id_token="t", transport=transport).org("o")
    res = org.assert_("r", "the reroll is address-neutral", kind="finding")
    assert seen["method"] == "POST"
    assert json.loads(seen["body"]) == {
        "repo": "r",
        "content": "the reroll is address-neutral",
        "kind": "finding",
    }
    assert res["embedded"] is True


def test_status_codes_map_to_typed_errors():
    for status, needle in [
        (401, "unauthorized"),
        (403, "forbidden"),
        (404, "not found"),
        (429, "rate limited"),
        (503, "upstream"),
    ]:
        def transport(m, u, h, b, s=status):
            return (s, {})

        org = MemoryClient(origin=ORIGIN, id_token="t", transport=transport).org("o")
        try:
            org.recall("r")
            raise AssertionError(f"expected MemoryError for {status}")
        except MemoryError as e:
            assert needle in str(e)
            assert e.status == status


def test_byom_fail_closed_without_sub_or_token():
    assert _raises(
        MemoryError, lambda: ByomMemoryClient(origin=ORIGIN, sub="", connect_token="t")
    )
    assert _raises(
        MemoryError, lambda: ByomMemoryClient(origin=ORIGIN, sub="s", connect_token="")
    )


def test_byom_call_tool_wraps_json_rpc():
    seen = {}

    def transport(method, url, headers, body):
        seen["url"] = url
        seen["body"] = body
        seen["auth"] = headers.get("authorization")
        return 200, {"jsonrpc": "2.0", "id": 1, "result": {"items": []}}

    byom = ByomMemoryClient(
        origin=ORIGIN, sub="user-123", connect_token="connect.tok", transport=transport
    )
    result = byom.recall(repo="citrate-chain")
    assert seen["url"] == ORIGIN + "/mcp/u/user-123"
    assert seen["auth"] == "Bearer connect.tok"
    sent = json.loads(seen["body"])
    assert sent["method"] == "tools/call"
    assert sent["params"] == {
        "name": "memory.recall",
        "arguments": {"repo": "citrate-chain"},
    }
    assert result["items"] == []


def test_byom_surfaces_json_rpc_error():
    def transport(method, url, headers, body):
        return 200, {
            "jsonrpc": "2.0",
            "id": 1,
            "error": {"code": -32001, "message": "grant rejected"},
        }

    byom = ByomMemoryClient(
        origin=ORIGIN, sub="s", connect_token="t", transport=transport
    )
    try:
        byom.verify(id="ab")
        raise AssertionError("expected MemoryError")
    except MemoryError as e:
        assert "grant rejected" in str(e)
        assert e.status == -32001
