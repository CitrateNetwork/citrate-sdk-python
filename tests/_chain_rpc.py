"""Test helper: an rpc_call mock that answers like a node of the vendored network.

PBA-L6b-042 made every manager write assert ``eth_chainId`` before sending, and the r1006
genesis guard reads block 0 too (r1005 and r1006 share chain id 40204), so write-path mocks
must answer both like a real node of the network the vendored book is for.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from citrate_sdk._generated import contract as _contract


def node_answer(method: str) -> Any:
    """The vendored network's answer for the identity RPCs, or ``None`` for anything else."""
    if method == "eth_chainId":
        return hex(_contract.chain_id())
    if method == "eth_getBlockByNumber":
        return {"number": "0x0", "hash": _contract.genesis_hash()}
    return None


def chain_rpc(result: Any) -> MagicMock:
    return MagicMock(side_effect=lambda method, params: node_answer(method) or result)
