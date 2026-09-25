"""Test helper: an rpc_call mock that answers eth_chainId with the pinned chain.

PBA-L6b-042 made every manager write assert ``eth_chainId`` before sending, so
write-path mocks must answer it like a real 40204 node does.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from citrate_sdk._generated import contract as _contract


def chain_rpc(result: Any) -> MagicMock:
    return MagicMock(side_effect=lambda method, params: hex(_contract.chain_id()) if method == "eth_chainId" else result)
