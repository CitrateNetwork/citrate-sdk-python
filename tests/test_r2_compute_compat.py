"""Compute marketplace client compatibility with the chain-main contracts.

Covers the client side of the current ComputeMarketplace / ComputeVerifier /
ComputePool / ComputePoolTraining / InferenceRouter ABI:

* ZK-tier jobs (requested ZK, or Commitment above 10 SALT, which the verifier
  settles as ZK) carry a 32-byte canonical BN254 input commitment as
  ``inputHash``; the client refuses to post anything else.
* Leaving a ComputePool is two steps: ``requestLeave`` then ``leavePool``
  after ``LEAVE_COOLDOWN`` blocks.
* Refund claims: ``InferenceRouter.claimRefund``,
  ``ComputeMarketplace.claimNativeRefund``,
  ``ComputePoolTraining.claimRequesterRefund``.
"""
from __future__ import annotations

from typing import Any

import pytest

from citrate_sdk._generated import contract as _contract
from citrate_sdk.abi import AbiInterface, keccak256, to_wei
from citrate_sdk.compute import (
    BN254_SCALAR_MODULUS,
    COMPUTE_POOL_ABI,
    DISPUTE_WINDOW_BLOCKS,
    LEAVE_COOLDOWN_BLOCKS,
    ZK_AUTO_UPGRADE_THRESHOLD_WEI,
    ComputeManager,
    LeaveNotReadyError,
    NothingToClaimError,
    ZKCommitmentError,
    effective_tier,
)

POOL = "0x" + "aa" * 20
MARKET = "0x" + "ab" * 20
ROUTER = "0x" + "cc" * 20
TRAINING = "0x" + "dd" * 20
ACCT = "0x" + "11" * 20
MODEL = "0x" + "0a" * 32
COMMIT = "0x" + (12345).to_bytes(32, "big").hex()

_iface = AbiInterface(COMPUTE_POOL_ABI)


def _word(v: int) -> str:
    return "0x" + v.to_bytes(32, "big").hex()


class Rpc:
    """eth_chainId + eth_blockNumber + per-selector eth_call answers; records sends."""

    def __init__(self, calls: dict[str, int] | None = None, block: int = 1_000) -> None:
        self.calls = calls or {}
        self.block = block
        self.sent: list[dict[str, Any]] = []

    def __call__(self, method: str, params: list[Any]) -> Any:
        if method == "eth_chainId":
            return hex(_contract.chain_id())
        if method == "eth_blockNumber":
            return hex(self.block)
        if method == "eth_call":
            sel = params[0]["data"][2:10]
            return _word(self.calls.get(sel, 0))
        if method == "eth_sendTransaction":
            self.sent.append(params[0])
            return "0x" + "ee" * 32
        raise AssertionError(f"unexpected rpc {method}")


def _sel(sig: str) -> str:
    return keccak256(sig.encode())[:4].hex()


def _mgr(rpc: Rpc) -> ComputeManager:
    return ComputeManager(
        rpc,
        default_account=ACCT,
        contract_addresses={
            "computePool": POOL,
            "computeMarketplace": MARKET,
            "inferenceRouter": ROUTER,
            "computePoolTraining": TRAINING,
        },
    )


def _posted_input_hash(tx: dict[str, Any]) -> bytes:
    data = bytes.fromhex(tx["data"][2:])[4:]
    off = int.from_bytes(data[32:64], "big")
    ln = int.from_bytes(data[off: off + 32], "big")
    return data[off + 32: off + 32 + ln]


# --------------------------------------------------------------------------
# constants mirror the contracts
# --------------------------------------------------------------------------

def test_constants_match_chain_main() -> None:
    assert BN254_SCALAR_MODULUS == int(
        "21888242871839275222246405745257275088548364400416034343698204186575808495617"
    )
    assert ZK_AUTO_UPGRADE_THRESHOLD_WEI == 10 * 10**18
    assert LEAVE_COOLDOWN_BLOCKS == 150
    assert DISPUTE_WINDOW_BLOCKS == 100


@pytest.mark.parametrize(
    ("tier", "price", "expected"),
    [
        ("Commitment", "10", "Commitment"),
        ("Commitment", "10.000000000000000001", "ZK"),
        ("Commitment", "1", "Commitment"),
        ("ZK", "1", "ZK"),
        ("TEE", "50", "TEE"),
    ],
)
def test_effective_tier(tier: str, price: str, expected: str) -> None:
    assert effective_tier(tier, to_wei(price)) == expected


# --------------------------------------------------------------------------
# post_job: BN254 input commitment for ZK / auto-ZK
# --------------------------------------------------------------------------

def test_zk_job_posts_the_commitment_not_the_input() -> None:
    rpc = Rpc()
    _mgr(rpc).post_job(MODEL, "hello world", "1", "ZK", input_commitment=COMMIT)
    assert _posted_input_hash(rpc.sent[-1]) == bytes.fromhex(COMMIT[2:])
    assert rpc.sent[-1]["to"] == MARKET


def test_auto_upgraded_job_requires_commitment() -> None:
    rpc = Rpc()
    with pytest.raises(ZKCommitmentError, match="input_commitment"):
        _mgr(rpc).post_job(MODEL, "hello world", "10.5", "Commitment")
    assert rpc.sent == []
    _mgr(rpc).post_job(MODEL, "hello world", "10.5", "Commitment", input_commitment=COMMIT)
    assert _posted_input_hash(rpc.sent[-1]) == bytes.fromhex(COMMIT[2:])


def test_zk_job_without_commitment_is_refused_before_sending() -> None:
    rpc = Rpc()
    with pytest.raises(ZKCommitmentError):
        _mgr(rpc).post_job(MODEL, "hello world", "1", "ZK")
    assert rpc.sent == []


@pytest.mark.parametrize(
    "bad",
    [
        "0x" + "00" * 32,                                     # zero
        "0x" + BN254_SCALAR_MODULUS.to_bytes(32, "big").hex(),  # == r
        "0x" + "ff" * 32,                                     # > r
        "0x" + "01" * 31,                                     # 31 bytes
        "0x" + "01" * 33,                                     # 33 bytes
        "0xzz" + "01" * 31,                                   # not hex
    ],
)
def test_non_canonical_commitment_is_refused(bad: str) -> None:
    rpc = Rpc()
    with pytest.raises(ZKCommitmentError):
        _mgr(rpc).post_job(MODEL, "x", "1", "ZK", input_commitment=bad)
    assert rpc.sent == []


def test_largest_canonical_commitment_is_accepted() -> None:
    rpc = Rpc()
    top = "0x" + (BN254_SCALAR_MODULUS - 1).to_bytes(32, "big").hex()
    _mgr(rpc).post_job(MODEL, "x", "1", "ZK", input_commitment=top)
    assert _posted_input_hash(rpc.sent[-1]) == bytes.fromhex(top[2:])


def test_commitment_as_bytes_is_accepted() -> None:
    rpc = Rpc()
    _mgr(rpc).post_job(MODEL, "x", "1", "ZK", input_commitment=(7).to_bytes(32, "big"))
    assert _posted_input_hash(rpc.sent[-1]) == (7).to_bytes(32, "big")


def test_zk_job_model_hash_must_be_canonical() -> None:
    rpc = Rpc()
    with pytest.raises(ZKCommitmentError, match="model_hash"):
        _mgr(rpc).post_job("0x" + "ff" * 32, "x", "1", "ZK", input_commitment=COMMIT)
    assert rpc.sent == []


def test_commitment_on_non_zk_job_is_refused() -> None:
    rpc = Rpc()
    with pytest.raises(ZKCommitmentError, match="ZK"):
        _mgr(rpc).post_job(MODEL, "x", "1", "Commitment", input_commitment=COMMIT)
    assert rpc.sent == []


def test_commitment_tier_job_keeps_input_bytes() -> None:
    rpc = Rpc()
    _mgr(rpc).post_job(MODEL, "hello world", "10", "Commitment")
    assert _posted_input_hash(rpc.sent[-1]) == b"hello world"


def test_marketplace_address_falls_back_to_compute_pool() -> None:
    rpc = Rpc()
    ComputeManager(rpc, default_account=ACCT, contract_addresses={"computePool": POOL}).post_job(
        MODEL, "x", "1", "Commitment"
    )
    assert rpc.sent[-1]["to"] == POOL


# --------------------------------------------------------------------------
# leave: requestLeave → cooldown → leavePool
# --------------------------------------------------------------------------

LEAVE_REQ = _sel("leaveRequestedAt(uint256,address)")


def test_request_leave_calldata() -> None:
    rpc = Rpc()
    _mgr(rpc).request_leave(9)
    assert rpc.sent[-1]["data"][2:10] == _sel("requestLeave(uint256)")
    assert rpc.sent[-1]["to"] == POOL


def test_leave_pool_without_request_sends_request_leave() -> None:
    rpc = Rpc({LEAVE_REQ: 0})
    _mgr(rpc).leave_pool(9)
    assert rpc.sent[-1]["data"][2:10] == _sel("requestLeave(uint256)")


def test_leave_pool_inside_cooldown_raises_with_ready_block() -> None:
    rpc = Rpc({LEAVE_REQ: 900}, block=1_049)
    with pytest.raises(LeaveNotReadyError) as ei:
        _mgr(rpc).leave_pool(9)
    assert ei.value.executable_at == 1_050
    assert rpc.sent == []


def test_leave_pool_after_cooldown_completes() -> None:
    for head in (1_050, 1_051):
        rpc = Rpc({LEAVE_REQ: 900}, block=head)
        _mgr(rpc).leave_pool(9)
        assert rpc.sent[-1]["data"] == _iface.encode_function_data("leavePool", [9])


def test_leave_status() -> None:
    rpc = Rpc({LEAVE_REQ: 900}, block=1_000)
    st = _mgr(rpc).leave_status(9)
    assert st == {"requested_at": 900, "executable_at": 1_050, "ready": False}
    rpc.block = 1_050
    assert _mgr(rpc).leave_status(9)["ready"] is True
    assert _mgr(Rpc({LEAVE_REQ: 0})).leave_status(9) == {
        "requested_at": 0, "executable_at": None, "ready": False,
    }


# --------------------------------------------------------------------------
# refund claims
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("claim", "view", "view_sig", "claim_sig", "to", "args"),
    [
        ("claim_refund", "refund_owed", "refundOwed(address)", "claimRefund()", ROUTER, ()),
        ("claim_native_refund", "native_refund_owed", "nativeRefundOwed(address)",
         "claimNativeRefund()", MARKET, ()),
        ("claim_requester_refund", "requester_refund_pending", "requesterRefundPending(uint256)",
         "claimRequesterRefund(uint256)", TRAINING, (4,)),
    ],
)
def test_refund_claims(claim: str, view: str, view_sig: str, claim_sig: str, to: str,
                       args: tuple[int, ...]) -> None:
    rpc = Rpc({_sel(view_sig): 5})
    mgr = _mgr(rpc)
    assert getattr(mgr, view)(*args) == 5
    getattr(mgr, claim)(*args)
    tx = rpc.sent[-1]
    assert tx["to"] == to
    assert tx["data"][2:10] == _sel(claim_sig)
    if args:
        assert int(tx["data"][10:74], 16) == args[0]
    # Nothing owed → refuse before sending a transaction that would revert.
    rpc2 = Rpc({_sel(view_sig): 0})
    with pytest.raises(NothingToClaimError):
        getattr(_mgr(rpc2), claim)(*args)
    assert rpc2.sent == []


def test_refund_views_default_to_the_configured_account() -> None:
    seen: list[str] = []

    class Spy(Rpc):
        def __call__(self, method: str, params: list[Any]) -> Any:
            if method == "eth_call":
                seen.append(params[0]["data"])
            return super().__call__(method, params)

    _mgr(Spy()).refund_owed()
    assert seen[-1][-40:] == ACCT[2:]
    _mgr(Spy()).native_refund_owed("0x" + "22" * 20)
    assert seen[-1][-40:] == "22" * 20


def test_missing_refund_contract_addresses_raise() -> None:
    from citrate_sdk.errors import ConfigurationError

    mgr = ComputeManager(Rpc(), default_account=ACCT, contract_addresses={})
    with pytest.raises(ConfigurationError, match="InferenceRouter"):
        mgr.claim_refund()
    with pytest.raises(ConfigurationError, match="ComputePoolTraining"):
        mgr.claim_requester_refund(1)
