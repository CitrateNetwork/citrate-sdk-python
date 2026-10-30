"""Chain-id and genesis pins for the write paths (PBA-L6b-042, r1006).

SPY-B-005 pinned the chain id for ``CitrateClient`` (which signs locally), but
the Learning/Staking/Classroom/Compute/Treasury/Farming managers send writes
with node-side ``eth_sendTransaction`` and never asked the node which chain it
is on. A manager pointed at another network's node that holds the same account
moved funds there. ``pinned_send`` asserts ``eth_chainId`` against the expected
chain once per manager, then sends with ``chainId`` in the tx so an honest node
also rejects a mismatch itself.

r1005 and r1006 share chain id 40204, so the chain id alone cannot tell them
apart. ``assert_genesis`` reads block 0 (``eth_getBlockByNumber``) and compares
its hash with the genesis of the vendored address book; ``pinned_send`` and
``CitrateClient`` run it once before the first send.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any, cast

from ._generated import contract as _contract
from .errors import CitrateError, WrongNetworkError

_HASH_RE = re.compile(r"0x[0-9a-f]{64}")


class _Unset:
    """Sentinel: no expected genesis was passed (use the vendored one)."""


UNSET: Any = _Unset()


def is_unset(value: Any) -> bool:
    return isinstance(value, _Unset)


def expected_chain_id(chain_id: int | None) -> int:
    return int(chain_id) if chain_id is not None else _contract.chain_id()


def resolve_expected_genesis(value: Any, expected_chain: int) -> str | None:
    """The block-0 hash a client/manager must see, or ``None`` for no check.

    ``UNSET`` (not passed): the vendored book's genesis when the pinned chain is the
    vendored chain, else ``None`` (a caller-chosen dev chain). ``None``: no check.
    A string: that 32-byte hash (any case).
    """
    if value is None:
        return None
    if isinstance(value, _Unset):
        return _contract.genesis_hash() if expected_chain == _contract.chain_id() else None
    v = str(value).lower()
    if not _HASH_RE.fullmatch(v):
        raise CitrateError(f"expected_genesis_hash must be a 0x-prefixed 32-byte hex hash or None, got {value!r}")
    return v


def assert_genesis(rpc_call: Callable[[str, list[Any]], Any], expected: str) -> None:
    """Read block 0 and raise ``WrongNetworkError`` unless its hash is ``expected``.

    Fails closed: an unreadable or missing block 0 is a refusal, not a pass.
    """
    try:
        block = rpc_call("eth_getBlockByNumber", ["0x0", False])
    except Exception as e:  # noqa: BLE001 - any transport/RPC failure is a refusal
        raise WrongNetworkError(
            f"cannot read block 0 from the RPC to verify the network ({e}); "
            "refusing to use the vendored address book",
            {"expected": expected},
        ) from e
    actual = block.get("hash") if isinstance(block, dict) else None
    if not isinstance(actual, str) or not actual:
        raise WrongNetworkError(
            "the RPC returned no block 0 hash; refusing to use the vendored address book",
            {"expected": expected},
        )
    actual = actual.lower()
    if actual != expected:
        raise WrongNetworkError(
            f"the RPC is on another network: its block 0 is {actual}, but this SDK's address book is "
            f"for genesis {expected}. Refusing to send to contracts that do not exist there. Point "
            "the client at a node of that network, or pass expected_genesis_hash to match yours.",
            {"expected": expected, "actual": actual},
        )


def pinned_send(manager: Any, tx: dict[str, Any]) -> str:
    """Assert the node's chain and genesis (cached per manager) and send ``tx``."""
    expected = cast(int, manager._expected_chain_id)
    if not getattr(manager, "_chain_verified", False):
        raw = manager._rpc_call("eth_chainId", [])
        try:
            reported = int(raw, 16) if isinstance(raw, str) else int(raw)
        except (TypeError, ValueError):
            raise CitrateError(f"RPC returned an unparseable eth_chainId {raw!r}; refusing to send (PBA-L6b-042).")
        if reported != expected:
            raise CitrateError(
                f"RPC chain-id mismatch: node reports {reported} but the configured/vendored "
                f"chain-id is {expected}. Refusing to send a transaction to another network "
                "(PBA-L6b-042)."
            )
        genesis = getattr(manager, "_expected_genesis", UNSET)
        if isinstance(genesis, _Unset):
            genesis = resolve_expected_genesis(UNSET, expected)
        if genesis is not None:
            assert_genesis(manager._rpc_call, genesis)
        manager._chain_verified = True
    return cast(str, manager._rpc_call("eth_sendTransaction", [dict(tx, chainId=hex(expected))]))
