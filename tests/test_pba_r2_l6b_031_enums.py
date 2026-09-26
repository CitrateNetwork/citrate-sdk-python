"""PBA-L6b-031: unknown access/tier/mode strings silently became index 0.

``LearningManager.create_pool(access="invite-only")`` created an OPEN pool;
``ComputeManager.post_job(tier="zk")`` posted a Commitment-tier job while still
escrowing ``max_price``; an unknown pool mode became InferencePool. Unknown
values now raise ValueError before any transaction; the canonical names still
work, and a case-insensitive exact match is accepted.
"""
from __future__ import annotations

from typing import Any

import pytest

from citrate_sdk.compute import ComputeManager
from citrate_sdk.learning import LearningManager


def _rpc(sent: list[Any]) -> Any:
    def rpc(method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return hex(40204)
        sent.append((method, params))
        return "0xhash"
    return rpc


ACCT = "0x" + "01" * 20
ADDRS = {"computePool": "0x" + "02" * 20, "learningPool": "0x" + "03" * 20}


@pytest.mark.parametrize("access", ["invite-only", "Private", "", "OPEN "])
def test_unknown_access_raises_before_sending(access: str) -> None:
    sent: list[Any] = []
    mgr = LearningManager(_rpc(sent), default_account=ACCT, contract_addresses=ADDRS)
    with pytest.raises(ValueError, match="access"):
        mgr.create_pool("p", "d", access, "1")
    assert sent == []


@pytest.mark.parametrize("tier", ["zkp", "tee2", "", "Commit"])
def test_unknown_tier_raises_before_escrow(tier: str) -> None:
    sent: list[Any] = []
    mgr = ComputeManager(_rpc(sent), default_account=ACCT, contract_addresses=ADDRS)
    with pytest.raises(ValueError, match="tier"):
        mgr.post_job("0x" + "aa" * 32, "in", "1", tier)
    assert sent == []


def test_unknown_mode_raises() -> None:
    sent: list[Any] = []
    mgr = ComputeManager(_rpc(sent), default_account=ACCT, contract_addresses=ADDRS)
    with pytest.raises(ValueError, match="mode"):
        mgr.create_pool("p", "Sharded", 1, 1, "1")
    assert sent == []


@pytest.mark.parametrize(("tier", "index"), [("Commitment", 0), ("ZK", 1), ("zk", 1), ("TEE", 2), ("tee", 2)])
def test_known_tiers_encode_their_index(tier: str, index: int) -> None:
    sent: list[Any] = []
    mgr = ComputeManager(_rpc(sent), default_account=ACCT, contract_addresses=ADDRS)
    commitment = "0x" + (1).to_bytes(32, "big").hex() if index == 1 else None
    mgr.post_job("0x" + "0a" * 32, "in", "1", tier, input_commitment=commitment)
    data = bytes.fromhex(sent[-1][1][0]["data"][2:])
    # postJob(bytes32,bytes,uint256,uint8,...): tier is the 4th head word.
    assert int.from_bytes(data[4 + 96: 4 + 128], "big") == index


@pytest.mark.parametrize(("access", "index"), [("Open", 0), ("InviteOnly", 1), ("inviteonly", 1), ("ApplicationRequired", 2)])
def test_known_access_encodes_its_index(access: str, index: int) -> None:
    sent: list[Any] = []
    mgr = LearningManager(_rpc(sent), default_account=ACCT, contract_addresses=ADDRS)
    mgr.create_pool("p", "d", access, "1")
    data = bytes.fromhex(sent[-1][1][0]["data"][2:])
    # createPool(string,string,uint8,uint256): access is the 3rd head word.
    assert int.from_bytes(data[4 + 64: 4 + 96], "big") == index


@pytest.mark.parametrize(("mode", "index"), [("InferencePool", 0), ("DataParallel", 1), ("pipelineparallel", 2)])
def test_known_modes_encode_their_index(mode: str, index: int) -> None:
    sent: list[Any] = []
    mgr = ComputeManager(_rpc(sent), default_account=ACCT, contract_addresses=ADDRS)
    mgr.create_pool("p", mode, 1, 1, "1")
    data = bytes.fromhex(sent[-1][1][0]["data"][2:])
    assert int.from_bytes(data[4 + 32: 4 + 64], "big") == index
