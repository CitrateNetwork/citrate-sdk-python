"""DEVX-S2 / F4 — OpenAI-compatible gateway client (Python parity)."""
from __future__ import annotations

from citrate_sdk._generated import contract
from citrate_sdk.gateway import GatewayClient, GatewayError

BASE = contract.gateway()["baseUrl"]


def _raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


def test_fail_closed_without_key():
    assert _raises(GatewayError, lambda: GatewayClient(api_key=""))


def test_chat_completion_posts_to_artifact_base():
    seen = {}

    def transport(method, url, headers, body):
        seen["url"] = url
        seen["auth"] = headers.get("authorization")
        return 200, {"id": "cmpl-1"}

    c = GatewayClient(api_key="cgk_test", transport=transport)
    res = c.chat_completions("gemma", [{"role": "user", "content": "hi"}])
    assert seen["url"] == BASE + "/v1/chat/completions"
    assert seen["auth"] == "Bearer cgk_test"
    assert res["id"] == "cmpl-1"


def test_status_codes_map_to_typed_errors():
    for status, needle in [(401, "unauthorized"), (402, "balance"), (429, "rate limited"), (503, "unavailable")]:
        c = GatewayClient(api_key="cgk_x", transport=lambda m, u, h, b, s=status: (s, {}))
        try:
            c.list_models()
            assert False, "expected GatewayError for %d" % status
        except GatewayError as e:
            assert needle in str(e)
            assert e.status == status
