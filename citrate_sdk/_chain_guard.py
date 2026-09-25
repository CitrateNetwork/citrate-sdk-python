"""Chain-id pin for the node-signed manager write paths (PBA-L6b-042).

SPY-B-005 pinned the chain id for ``CitrateClient`` (which signs locally), but
the Learning/Staking/Classroom/Compute/Treasury/Farming managers send writes
with node-side ``eth_sendTransaction`` and never asked the node which chain it
is on. A manager pointed at another network's node that holds the same account
moved funds there. ``pinned_send`` asserts ``eth_chainId`` against the expected
chain once per manager, then sends with ``chainId`` in the tx so an honest node
also rejects a mismatch itself.
"""
from __future__ import annotations

from typing import Any, cast

from ._generated import contract as _contract
from .errors import CitrateError


def expected_chain_id(chain_id: int | None) -> int:
    return int(chain_id) if chain_id is not None else _contract.chain_id()


def pinned_send(manager: Any, tx: dict[str, Any]) -> str:
    """Assert the node's chain (cached per manager) and send ``tx``."""
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
        manager._chain_verified = True
    return cast(str, manager._rpc_call("eth_sendTransaction", [dict(tx, chainId=hex(expected))]))
