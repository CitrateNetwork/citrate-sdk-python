"""End-to-end compute compat against the chain-main contracts on a local anvil.

Skipped unless ``CITRATE_R2_ANVIL_ADDRS`` points at the addresses JSON written
by the chain-main deploy (keys: ComputeMarketplace, ComputePool,
ComputePoolTraining, InferenceRouter) and ``CITRATE_R2_ANVIL_RPC`` (default
http://127.0.0.1:8599) serves a chain whose id is 40204 with anvil's unlocked
default accounts. Uses default accounts 3 and 4 only.
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, cast

import pytest

from citrate_sdk.abi import keccak256
from citrate_sdk.compute import (
    LEAVE_COOLDOWN_BLOCKS,
    ComputeManager,
    LeaveNotReadyError,
    NothingToClaimError,
    ZKCommitmentError,
)

ADDRS_PATH = os.environ.get("CITRATE_R2_ANVIL_ADDRS")
RPC_URL = os.environ.get("CITRATE_R2_ANVIL_RPC", "http://127.0.0.1:8599")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(not ADDRS_PATH, reason="CITRATE_R2_ANVIL_ADDRS not set"),
]

ACCT3 = "0x90F79bf6EB2c4f870365E785982E1f101E93b906"
ACCT4 = "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65"
MODEL = "0x" + (0xC0FFEE).to_bytes(32, "big").hex()
COMMIT = "0x" + (0x1234567).to_bytes(32, "big").hex()


def rpc(method: str, params: list[Any]) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}).encode()
    req = urllib.request.Request(RPC_URL, body, {"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:  # noqa: S310 - local anvil only
        out = json.loads(r.read())
    if "error" in out:
        raise RuntimeError(out["error"])
    return out["result"]


def receipt(tx: str) -> dict[str, Any]:
    # The anvil is shared with other lanes; poll briefly for the receipt.
    for _ in range(100):
        r = rpc("eth_getTransactionReceipt", [tx])
        if r is not None:
            return cast(dict[str, Any], r)
        time.sleep(0.2)
    raise AssertionError(f"no receipt for {tx}")


def addrs() -> dict[str, str]:
    assert ADDRS_PATH
    with open(ADDRS_PATH) as f:
        return cast(dict[str, str], json.load(f))


def mgr(account: str) -> ComputeManager:
    a = addrs()
    return ComputeManager(
        rpc,
        default_account=account,
        gas_limit=3_000_000,
        contract_addresses={
            "computePool": a["ComputePool"],
            "computeMarketplace": a["ComputeMarketplace"],
            "inferenceRouter": a["InferenceRouter"],
            "computePoolTraining": a["ComputePoolTraining"],
        },
        chain_id=40204,
    )


def job_input_hash(job_id: int) -> str:
    a = addrs()
    sel = keccak256(b"jobBinding(uint256)")[:4].hex()
    data = "0x" + sel + job_id.to_bytes(32, "big").hex()
    out = str(rpc("eth_call", [{"to": a["ComputeVerifier"], "data": data}, "latest"]))
    return "0x" + out[2:66]


def next_job_id() -> int:
    a = addrs()
    sel = keccak256(b"nextJobId()")[:4].hex()
    return int(rpc("eth_call", [{"to": a["ComputeMarketplace"], "data": "0x" + sel}, "latest"]), 16)


@pytest.mark.parametrize(("tier", "price"), [("ZK", "1"), ("Commitment", "10.5")])
def test_zk_and_auto_zk_jobs_post_with_bn254_commitment(tier: str, price: str) -> None:
    jid = next_job_id()
    tx = mgr(ACCT3).post_job(MODEL, "hello world", price, tier, input_commitment=COMMIT)
    assert int(receipt(tx)["status"], 16) == 1
    # The verifier bound exactly the commitment as the job's input commitment.
    assert job_input_hash(jid) == COMMIT


def test_zk_job_without_commitment_never_reaches_chain() -> None:
    with pytest.raises(ZKCommitmentError):
        mgr(ACCT3).post_job(MODEL, "hello world", "1", "ZK")


def test_commitment_tier_job_still_posts_raw_input() -> None:
    tx = mgr(ACCT3).post_job(MODEL, "hello world", "1", "Commitment")
    assert int(receipt(tx)["status"], 16) == 1


def test_two_step_pool_exit() -> None:
    m = mgr(ACCT4)
    tx = m.create_pool("r2-compat", "InferencePool", 1, 1, "0.01")
    assert int(receipt(tx)["status"], 16) == 1
    pool_id = _last_pool_id()
    assert int(receipt(m.join_pool(pool_id, 1, stake="10"))["status"], 16) == 1

    # Step 1: leave_pool with nothing pending sends requestLeave.
    assert int(receipt(m.leave_pool(pool_id))["status"], 16) == 1
    st = m.leave_status(pool_id)
    assert st["requested_at"] > 0 and st["ready"] is False
    with pytest.raises(LeaveNotReadyError):
        m.leave_pool(pool_id)

    rpc("anvil_mine", [hex(LEAVE_COOLDOWN_BLOCKS)])
    assert m.leave_status(pool_id)["ready"] is True
    before = int(rpc("eth_getBalance", [ACCT4, "latest"]), 16)
    assert int(receipt(m.leave_pool(pool_id))["status"], 16) == 1
    assert m.leave_status(pool_id)["requested_at"] == 0
    assert int(rpc("eth_getBalance", [ACCT4, "latest"]), 16) > before  # stake returned


def _last_pool_id() -> int:
    a = addrs()
    sel = keccak256(b"nextPoolId()")[:4].hex()
    return int(rpc("eth_call", [{"to": a["ComputePool"], "data": "0x" + sel}, "latest"]), 16) - 1


def test_refund_views_and_claims_match_deployed_abi() -> None:
    m = mgr(ACCT3)
    assert m.refund_owed() == 0
    assert m.native_refund_owed() == 0
    assert m.requester_refund_pending(0) == 0
    for claim, args in (("claim_refund", ()), ("claim_native_refund", ()), ("claim_requester_refund", (0,))):
        with pytest.raises(NothingToClaimError):
            getattr(m, claim)(*args)
