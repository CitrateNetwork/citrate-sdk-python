"""PBA-L6b-042: the SPY-B-005 chain-id pin applied only to CitrateClient.

The Learning/Staking/Classroom/Compute/Treasury/Farming managers send writes
with node-side ``eth_sendTransaction`` and never asked the node which chain it
is on, so a manager pointed at the wrong network's node (holding the same
account) moved funds there. Every manager write now asserts ``eth_chainId``
against the pinned chain (default: the federation artifact, 40204; overridable
with ``chain_id=``) before the first send, and puts ``chainId`` in the tx.
"""
from __future__ import annotations

from typing import Any

import pytest

from citrate_sdk.compute import ComputeManager
from citrate_sdk.errors import CitrateError
from citrate_sdk.farming import FarmingManager
from citrate_sdk.learning import ClassroomManager, LearningManager, StakingManager
from citrate_sdk.treasury import TreasuryManager

ACCT = "0x" + "01" * 20
A = "0x" + "02" * 20
ADDRS = dict.fromkeys(("computePool", "learningPool", "stablecoinTreasury", "bulkComputeGateway", "testnetFarmingAccounting", "learningCycleManager", "contributionAccounting", "disputeResolution"), A)


def _rpc(chain: int) -> tuple[Any, list[str]]:
    methods: list[str] = []

    def rpc(method: str, params: Any) -> Any:
        methods.append(method)
        if method == "eth_chainId":
            return hex(chain)
        return "0xhash"
    return rpc, methods


WRITES = [
    ("learning.join_pool", lambda r, **k: LearningManager(r, default_account=ACCT, contract_addresses=ADDRS, **k).join_pool(1, "1")),
    ("staking.deposit", lambda r, **k: StakingManager(r, default_account=ACCT, staking_address=A, **k).deposit("1")),
    ("classroom.unenroll", lambda r, **k: ClassroomManager(r, default_account=ACCT, classroom_address=A, **k).unenroll()),
    ("compute.heartbeat", lambda r, **k: ComputeManager(r, default_account=ACCT, contract_addresses=ADDRS, **k).heartbeat()),
    ("treasury.deposit", lambda r, **k: TreasuryManager(r, default_account=ACCT, contract_addresses=ADDRS, **k).deposit_stablecoin(A, 1)),
    ("farming.claim", lambda r, **k: FarmingManager(r, default_account=ACCT, contract_addresses=ADDRS, **k).claim()),
]


@pytest.mark.parametrize(("name", "write"), WRITES)
def test_wrong_chain_refused_before_send(name: str, write: Any) -> None:
    rpc, methods = _rpc(1)
    with pytest.raises(CitrateError, match="chain-id mismatch"):
        write(rpc)
    assert "eth_sendTransaction" not in methods, name


@pytest.mark.parametrize(("name", "write"), WRITES)
def test_right_chain_sends_with_chain_id_field(name: str, write: Any) -> None:
    sent: list[Any] = []

    def rpc(method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return hex(40204)
        sent.append(params[0])
        return "0xhash"

    write(rpc)
    assert sent and sent[-1]["chainId"] == hex(40204), name


def test_chain_is_checked_once_per_manager_and_override_works() -> None:
    rpc, methods = _rpc(31337)
    mgr = ComputeManager(rpc, default_account=ACCT, contract_addresses=ADDRS, chain_id=31337)
    mgr.heartbeat()
    mgr.heartbeat()
    assert methods.count("eth_chainId") == 1 and methods.count("eth_sendTransaction") == 2


def test_garbage_chain_id_is_refused() -> None:
    def rpc(method: str, params: Any) -> Any:
        return "0xnope" if method == "eth_chainId" else "0xhash"
    with pytest.raises(CitrateError, match="chain"):
        ComputeManager(rpc, default_account=ACCT, contract_addresses=ADDRS).heartbeat()
