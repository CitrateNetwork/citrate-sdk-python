"""
Tests for the ComputeManager.

Verifies that each method:
  - Constructs the correct ABI-encoded calldata (matching the JS SDK's function selectors)
  - Calls the correct contract address
  - Properly decodes return values
  - Raises ConfigurationError when contract addresses are missing
"""

from unittest.mock import MagicMock

import pytest

from citrate_sdk.abi import AbiInterface, keccak256, to_wei
from citrate_sdk.compute import (
    COMPUTE_POOL_ABI,
    DISPUTE_ABI,
    ComputeManager,
)
from citrate_sdk.errors import ConfigurationError
from tests._chain_rpc import chain_rpc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_COMPUTE_ADDR = "0x" + "aa" * 20
FAKE_DISPUTE_ADDR = "0x" + "bb" * 20
DEFAULT_ACCOUNT = "0x" + "11" * 20

_compute_iface = AbiInterface(COMPUTE_POOL_ABI)
_dispute_iface = AbiInterface(DISPUTE_ABI)


def _encode_uint256(val: int) -> str:
    return "0x" + val.to_bytes(32, "big").hex()


# ---------------------------------------------------------------------------
# ComputeManager Tests
# ---------------------------------------------------------------------------

class TestComputeManager:
    """Tests for ComputeManager."""

    def _make_manager(self, rpc_call=None):
        return ComputeManager(
            rpc_call=rpc_call or MagicMock(),
            default_account=DEFAULT_ACCOUNT,
            contract_addresses={
                "computePool": FAKE_COMPUTE_ADDR,
                "disputeResolution": FAKE_DISPUTE_ADDR,
            },
        )

    def test_missing_compute_address(self):
        """Raises ConfigurationError when computePool address not set."""
        mgr = ComputeManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="ComputePool"):
            mgr.list_jobs()

    def test_missing_dispute_address(self):
        """Raises ConfigurationError when disputeResolution address not set."""
        mgr = ComputeManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="DisputeResolution"):
            mgr.dispute_result(job_id=1, bond="1")

    def test_post_job_calldata(self):
        """post_job sends correct calldata, value, and contract address."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        model_hash = "0x" + "0b" * 32  # ZK jobs need a model hash below the BN254 modulus
        # ZK tier: inputHash is the circuit's 32-byte BN254 input commitment.
        commitment = "0x" + (42).to_bytes(32, "big").hex()
        mgr.post_job(model_hash, "hello world", "1.5", "ZK", input_commitment=commitment)
        tx = rpc.call_args_list[-1][0][1][0]
        assert tx["to"] == FAKE_COMPUTE_ADDR
        assert int(tx["value"], 16) == to_wei("1.5")
        # Verify function selector
        expected_selector = keccak256(b"postJob(bytes32,bytes,uint256,uint8,uint256,uint256)")[:4].hex()
        assert tx["data"][2:10] == expected_selector
        assert commitment[2:] in tx["data"]
        assert b"hello world".hex() not in tx["data"]

    def test_bid_on_job_calldata(self):
        """bid_on_job sends correct calldata."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.bid_on_job(job_id=3, price="0.5", latency=30)
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _compute_iface.encode_function_data("bidOnJob", [
            3, to_wei("0.5"), 30,
        ])
        assert tx["data"] == expected

    def test_submit_result_calldata(self):
        """submit_result encodes output and proof as bytes."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.submit_result(job_id=7, output="result data", proof="proof data")
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _compute_iface.encode_function_data("submitResult", [
            7, b"result data", b"proof data",
        ])
        assert tx["data"] == expected

    def test_register_provider_calldata(self):
        """register_provider sends correct calldata and stake as value."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.register_provider(
            stake="100",
            models=["model-a", "model-b"],
            endpoint="https://my-gpu.example.com",
        )
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _compute_iface.encode_function_data("registerProvider", [
            ["model-a", "model-b"], "https://my-gpu.example.com",
        ])
        assert tx["data"] == expected
        assert int(tx["value"], 16) == to_wei("100")

    def test_heartbeat_calldata(self):
        """heartbeat sends correct calldata."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.heartbeat()
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _compute_iface.encode_function_data("heartbeat")
        assert tx["data"] == expected

    def test_create_pool_calldata(self):
        """create_pool encodes mode enum and price correctly."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.create_pool("GPU Cluster", "DataParallel", 5, 1000, "2.5")
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _compute_iface.encode_function_data("createPool", [
            "GPU Cluster", 1, 5, 1000, to_wei("2.5"),
        ])
        assert tx["data"] == expected

    def test_join_pool_calldata(self):
        """join_pool sends correct poolId and gpuCount."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.join_pool(pool_id=2, gpu_count=4)
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _compute_iface.encode_function_data("joinPool", [2, 4])
        assert tx["data"] == expected

    def test_leave_pool_calldata(self):
        """leave_pool sends correct calldata."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.request_leave(pool_id=9)
        tx = rpc.call_args_list[-1][0][1][0]
        expected = "0x" + keccak256(b"requestLeave(uint256)")[:4].hex() + (9).to_bytes(32, "big").hex()
        assert tx["data"] == expected

    def test_dispute_result_calldata(self):
        """dispute_result sends to dispute contract with bond as value."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.dispute_result(job_id=5, bond="3")
        tx = rpc.call_args_list[-1][0][1][0]
        expected = _dispute_iface.encode_function_data("disputeResult", [5])
        assert tx["data"] == expected
        assert tx["to"] == FAKE_DISPUTE_ADDR
        assert int(tx["value"], 16) == to_wei("3")

    def test_list_jobs_empty(self):
        """list_jobs returns [] when nextJobId is 0."""
        rpc = MagicMock(return_value=_encode_uint256(0))
        mgr = self._make_manager(rpc)
        jobs = mgr.list_jobs()
        assert jobs == []

    def test_get_pools_empty(self):
        """get_pools returns [] when nextPoolId is 0."""
        rpc = MagicMock(return_value=_encode_uint256(0))
        mgr = self._make_manager(rpc)
        pools = mgr.get_pools()
        assert pools == []

    def test_get_provider_info_no_address(self):
        """get_provider_info raises when no address and no default account."""
        mgr = ComputeManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"computePool": FAKE_COMPUTE_ADDR},
        )
        with pytest.raises(ConfigurationError, match="No address"):
            mgr.get_provider_info()

    def test_no_default_account_write(self):
        """Write operations raise when no default account."""
        mgr = ComputeManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"computePool": FAKE_COMPUTE_ADDR},
        )
        with pytest.raises(ConfigurationError, match="defaultAccount"):
            mgr.heartbeat()


# ---------------------------------------------------------------------------
# ABI selector verification
# ---------------------------------------------------------------------------

class TestComputeAbiSelectors:
    """Verify compute function selectors match keccak256 of canonical signatures."""

    def test_post_job_selector(self):
        sig = b"postJob(bytes32,bytes,uint256,uint8,uint256,uint256)"
        expected = keccak256(sig)[:4].hex()
        model_hash = bytes(32)
        data = _compute_iface.encode_function_data("postJob", [model_hash, b"", 0, 0, 0, 0])
        assert data[2:10] == expected

    def test_heartbeat_selector(self):
        sig = b"heartbeat()"
        expected = keccak256(sig)[:4].hex()
        data = _compute_iface.encode_function_data("heartbeat")
        assert data[2:10] == expected

    def test_dispute_result_selector(self):
        sig = b"disputeResult(uint256)"
        expected = keccak256(sig)[:4].hex()
        data = _dispute_iface.encode_function_data("disputeResult", [0])
        assert data[2:10] == expected

    def test_get_job_selector(self):
        sig = b"getJob(uint256)"
        expected = keccak256(sig)[:4].hex()
        data = _compute_iface.encode_function_data("getJob", [0])
        assert data[2:10] == expected

    def test_register_provider_selector(self):
        sig = b"registerProvider(string[],string)"
        expected = keccak256(sig)[:4].hex()
        data = _compute_iface.encode_function_data("registerProvider", [[], ""])
        assert data[2:10] == expected
