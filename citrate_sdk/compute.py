"""
COMPUTE-4: SDK Compute Extensions (Python)

Provides the ComputeManager class for interacting with Citrate's compute marketplace:
  - Job lifecycle (post, bid, submit, list)
  - Provider management (register, heartbeat, info)
  - Pool management (create, join, leave, list)
  - Dispute resolution (file dispute, query)

All methods wire to real on-chain contracts via the SDK's RPC client.
No mock returns -- every call encodes the actual Solidity ABI and sends
via eth_call (reads) or eth_sendTransaction (writes).

Mirrors sdk/javascript/src/compute.ts exactly (method names in snake_case).

Data sources:
  - ComputePool.sol: Pool management, provider GPU allocation
  - HeartbeatMonitor.sol: Provider liveness heartbeats
  - DisputeResolution.sol: Result dispute lifecycle
"""

from __future__ import annotations

from typing import Any, cast

from .abi import AbiInterface, enum_index, from_wei, to_wei
from .errors import ConfigurationError
from .types import ComputeJob, ComputePool, Dispute, ProviderInfo

# ============================================================================
# Contract ABIs (minimal -- only the methods we call)
# Identical to the JS SDK's human-readable ABI arrays.
# ============================================================================

COMPUTE_POOL_ABI = [
    "function nextJobId() view returns (uint256)",
    "function getJob(uint256 jobId) view returns (uint256 id, address requester, bytes32 modelHash, uint256 maxPrice, uint8 tier, uint8 state, address assignedProvider, uint256 escrow, uint256 bidDeadline, uint256 executionDeadline, uint256 createdAt, uint256 bidCount)",
    "function postJob(bytes32 modelHash, bytes inputData, uint256 maxPrice, uint8 tier, uint256 bidWindow, uint256 execWindow) payable returns (uint256 jobId)",
    "function bidOnJob(uint256 jobId, uint256 price, uint256 estimatedLatency)",
    "function submitResult(uint256 jobId, bytes output, bytes proof)",
    "function registerProvider(string[] models, string endpoint) payable",
    "function getProviderInfo(address provider) view returns (bool isRegistered, uint256 stake, uint256 totalJobsCompleted, uint256 totalJobsFailed, uint256 reputationScore, uint256 currentActiveJobs, uint256 maxConcurrentJobs)",
    "function heartbeat()",
    "function nextPoolId() view returns (uint256)",
    "function getPool(uint256 poolId) view returns (uint256 id, string name, uint8 mode, address creator, uint8 state, uint256 minProviders, uint256 totalGPUs, uint256 guaranteedThroughput, uint256 pricePerUnit, uint256 memberCount, uint256 activeJobCount, uint256 totalStaked)",
    "function createPool(string name, uint8 mode, uint256 minProviders, uint256 throughput, uint256 price) payable returns (uint256 poolId)",
    "function joinPool(uint256 poolId, uint256 gpuCount) payable",
    "function leavePool(uint256 poolId)",
]

DISPUTE_ABI = [
    "function disputeResult(uint256 jobId) payable returns (uint256 disputeId)",
    "function getDispute(uint256 disputeId) view returns (uint256 jobId, address challenger, address defender, uint256 challengerBond, uint256 defenderBond, uint256 rangeStart, uint256 rangeEnd, uint256 round, uint8 state, uint8 outcome, uint256 deadline)",
]

# ============================================================================
# Helpers / Constants
# ============================================================================

JOB_TIERS = ("Commitment", "ZK", "TEE")
JOB_STATES = ("Posted", "Bidding", "Executing", "Completed", "Disputed", "Failed")
POOL_MODES = ("InferencePool", "DataParallel", "PipelineParallel")
POOL_STATES = ("Active", "Paused", "Dissolved")
DISPUTE_STATES = ("Open", "ChallengerWins", "DefenderWins", "Settled")
DISPUTE_OUTCOMES = ("Pending", "ChallengerWins", "DefenderWins", "Draw")


# ============================================================================
# ComputeManager
# ============================================================================

class ComputeManager:
    """Manages compute marketplace operations: job lifecycle, provider registration,
    GPU pool management, and dispute resolution.

    Data sources:
      - ComputePool contract: jobs, providers, pools
      - DisputeResolution contract: dispute lifecycle
      - HeartbeatMonitor contract: provider liveness
    """

    def __init__(
        self,
        rpc_call: Any,
        default_account: str | None = None,
        gas_limit: int = 500_000,
        gas_price: str = "0x3b9aca00",
        contract_addresses: dict[str, str] | None = None,
    ) -> None:
        self._rpc_call = rpc_call
        self._default_account = default_account
        self._gas_limit = gas_limit
        self._gas_price = gas_price

        addrs = contract_addresses or {}
        self._compute_addr = addrs.get("computePool")
        self._dispute_addr = addrs.get("disputeResolution")

        self._compute_iface = AbiInterface(COMPUTE_POOL_ABI)
        self._dispute_iface = AbiInterface(DISPUTE_ABI)

    # --- Internal helpers ---

    def _require_compute_address(self) -> str:
        if not self._compute_addr:
            raise ConfigurationError(
                "ComputePool contract address not configured. Set it via contract_addresses."
            )
        return self._compute_addr

    def _require_dispute_address(self) -> str:
        if not self._dispute_addr:
            raise ConfigurationError(
                "DisputeResolution contract address not configured. Set it via contract_addresses."
            )
        return self._dispute_addr

    def _eth_call(self, to: str, data: str) -> str:
        result = self._rpc_call("eth_call", [{"to": to, "data": data}, "latest"])
        return cast(str, result)

    def _send_transaction(self, to: str, data: str, value: str = "0x0") -> str:
        if not self._default_account:
            raise ConfigurationError("defaultAccount not configured; required for write operations.")
        tx = {
            "from": self._default_account,
            "to": to,
            "data": data,
            "value": value,
            "gas": hex(self._gas_limit),
            "gasPrice": self._gas_price,
        }
        return cast(str, self._rpc_call("eth_sendTransaction", [tx]))

    # -------------------------------------------------------------------
    # Job Lifecycle
    # -------------------------------------------------------------------

    def post_job(
        self,
        model_hash: str,
        input_data: str,
        max_price: str,
        tier: str,
    ) -> str:
        """Post a new compute job to the marketplace.

        Data source: ComputePool.postJob() via eth_sendTransaction with msg.value.

        Args:
            model_hash: 32-byte model hash (hex string, optional 0x prefix).
            input_data: UTF-8 input payload for the compute job.
            max_price: Maximum price in ether-denominated decimal string.
            tier: One of 'Commitment', 'ZK', 'TEE'.

        Returns:
            Transaction hash (job ID emitted in JobPosted event).
        """
        addr = self._require_compute_address()
        h = model_hash if model_hash.startswith("0x") else f"0x{model_hash}"
        hash_bytes = bytes.fromhex(h[2:])
        tier_num = enum_index(JOB_TIERS, tier, "tier")
        max_price_wei = to_wei(max_price)
        input_bytes = input_data.encode("utf-8")
        data = self._compute_iface.encode_function_data("postJob", [
            hash_bytes, input_bytes, max_price_wei, tier_num, 50, 100,
        ])
        value = hex(max_price_wei)
        return self._send_transaction(addr, data, value)

    def bid_on_job(self, job_id: int, price: str, latency: int) -> str:
        """Place a bid on an active compute job.

        Data source: ComputePool.bidOnJob() via eth_sendTransaction.

        Args:
            job_id: The job identifier.
            price: Bid price in ether-denominated decimal string.
            latency: Estimated latency in seconds.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        price_wei = to_wei(price)
        data = self._compute_iface.encode_function_data("bidOnJob", [
            job_id, price_wei, latency,
        ])
        return self._send_transaction(addr, data)

    def get_job(self, job_id: int) -> ComputeJob:
        """Get information about a specific compute job.

        Data source: ComputePool.getJob(uint256) via eth_call.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("getJob", [job_id])
        result = self._eth_call(addr, data)
        decoded = self._compute_iface.decode_function_result("getJob", result)
        # (id, requester, modelHash, maxPrice, tier, state, assignedProvider, escrow,
        #  bidDeadline, executionDeadline, createdAt, bidCount)
        (
            jid, requester, model_hash, max_price, tier_num, state_num,
            assigned_provider, escrow, bid_deadline, exec_deadline, created_at, bid_count,
        ) = decoded

        return ComputeJob(
            id=int(jid),
            requester=requester,
            model_hash="0x" + model_hash.hex() if isinstance(model_hash, bytes) else model_hash,
            max_price=from_wei(int(max_price)),
            tier=JOB_TIERS[int(tier_num)] if int(tier_num) < len(JOB_TIERS) else "Commitment",
            state=JOB_STATES[int(state_num)] if int(state_num) < len(JOB_STATES) else "Posted",
            assigned_provider=assigned_provider,
            escrow=from_wei(int(escrow)),
            bid_deadline=int(bid_deadline),
            execution_deadline=int(exec_deadline),
            created_at=int(created_at),
            bid_count=int(bid_count),
        )

    def list_jobs(self, filter: str | None = None) -> list[ComputeJob]:
        """List compute jobs, optionally filtered by state.

        Data source: ComputePool.nextJobId() + getJob(uint256) via eth_call.

        Args:
            filter: Optional state filter (e.g. 'Posted', 'Executing').
        """
        addr = self._require_compute_address()

        next_id_data = self._compute_iface.encode_function_data("nextJobId")
        next_id_result = self._eth_call(addr, next_id_data)
        (next_id,) = self._compute_iface.decode_function_result("nextJobId", next_id_result)
        count = int(next_id)

        if count == 0:
            return []

        jobs: list[ComputeJob] = []
        max_jobs = min(count, 100)

        for i in range(max_jobs):
            try:
                job = self.get_job(i)
                if filter is None or job.state == filter:
                    jobs.append(job)
            except Exception:
                # Skip jobs that fail to decode (same as JS SDK behaviour)
                continue

        return jobs

    def submit_result(self, job_id: int, output: str, proof: str) -> str:
        """Submit a result for an assigned compute job.

        Data source: ComputePool.submitResult() via eth_sendTransaction.

        Args:
            job_id: The job identifier.
            output: UTF-8 output payload.
            proof: UTF-8 proof payload.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        output_bytes = output.encode("utf-8")
        proof_bytes = proof.encode("utf-8")
        data = self._compute_iface.encode_function_data("submitResult", [
            job_id, output_bytes, proof_bytes,
        ])
        return self._send_transaction(addr, data)

    # -------------------------------------------------------------------
    # Provider Management
    # -------------------------------------------------------------------

    def register_provider(self, stake: str, models: list[str], endpoint: str) -> str:
        """Register as a compute provider.

        Data source: ComputePool.registerProvider() via eth_sendTransaction with msg.value.

        Args:
            stake: SALT stake amount as decimal string.
            models: List of model identifiers the provider supports.
            endpoint: Provider's inference endpoint URL.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("registerProvider", [
            models, endpoint,
        ])
        value = hex(to_wei(stake))
        return self._send_transaction(addr, data, value)

    def get_provider_info(self, address: str | None = None) -> ProviderInfo:
        """Get provider information for an address (or the default account).

        Data source: ComputePool.getProviderInfo(address) via eth_call.
        """
        addr = self._require_compute_address()
        provider = address or self._default_account
        if not provider:
            raise ConfigurationError("No address provided and no defaultAccount configured.")

        data = self._compute_iface.encode_function_data("getProviderInfo", [provider])
        result = self._eth_call(addr, data)
        decoded = self._compute_iface.decode_function_result("getProviderInfo", result)
        (
            is_registered, stake, total_completed, total_failed,
            rep_score, current_active, max_concurrent,
        ) = decoded

        return ProviderInfo(
            is_registered=bool(is_registered),
            stake=from_wei(int(stake)),
            total_jobs_completed=int(total_completed),
            total_jobs_failed=int(total_failed),
            reputation_score=int(rep_score),
            current_active_jobs=int(current_active),
            max_concurrent_jobs=int(max_concurrent),
        )

    def heartbeat(self) -> str:
        """Send a heartbeat to prove provider liveness.

        Data source: ComputePool.heartbeat() via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("heartbeat")
        return self._send_transaction(addr, data)

    # -------------------------------------------------------------------
    # Pool Management
    # -------------------------------------------------------------------

    def create_pool(
        self,
        name: str,
        mode: str,
        min_providers: int,
        throughput: int,
        price: str,
    ) -> str:
        """Create a new compute pool.

        Data source: ComputePool.createPool() via eth_sendTransaction.

        Args:
            name: Pool display name.
            mode: One of 'InferencePool', 'DataParallel', 'PipelineParallel'.
            min_providers: Minimum number of providers.
            throughput: Guaranteed throughput target.
            price: Price per unit in ether-denominated decimal string.

        Returns:
            Transaction hash (pool ID emitted in PoolCreated event).
        """
        addr = self._require_compute_address()
        mode_num = enum_index(POOL_MODES, mode, "pool mode")
        price_wei = to_wei(price)
        data = self._compute_iface.encode_function_data("createPool", [
            name, mode_num, min_providers, throughput, price_wei,
        ])
        return self._send_transaction(addr, data)

    def join_pool(self, pool_id: int, gpu_count: int) -> str:
        """Join a compute pool with GPU allocation.

        Data source: ComputePool.joinPool() via eth_sendTransaction.

        Args:
            pool_id: The pool identifier.
            gpu_count: Number of GPUs to allocate.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("joinPool", [pool_id, gpu_count])
        return self._send_transaction(addr, data)

    def leave_pool(self, pool_id: int) -> str:
        """Leave a compute pool and reclaim stake.

        Data source: ComputePool.leavePool() via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("leavePool", [pool_id])
        return self._send_transaction(addr, data)

    def get_pools(self) -> list[ComputePool]:
        """List all compute pools.

        Data source: ComputePool.nextPoolId() + getPool(uint256) via eth_call.
        """
        addr = self._require_compute_address()

        next_id_data = self._compute_iface.encode_function_data("nextPoolId")
        next_id_result = self._eth_call(addr, next_id_data)
        (next_id,) = self._compute_iface.decode_function_result("nextPoolId", next_id_result)
        count = int(next_id)

        if count == 0:
            return []

        pools: list[ComputePool] = []
        max_pools = min(count, 100)

        for i in range(max_pools):
            try:
                data = self._compute_iface.encode_function_data("getPool", [i])
                result = self._eth_call(addr, data)
                decoded = self._compute_iface.decode_function_result("getPool", result)
                # (id, name, mode, creator, state, minProviders, totalGPUs,
                #  guaranteedThroughput, pricePerUnit, memberCount, activeJobCount, totalStaked)
                (
                    pid, name, mode_num, creator, state_num, min_providers,
                    total_gpus, throughput, price_per_unit, member_count,
                    active_job_count, total_staked,
                ) = decoded

                pools.append(ComputePool(
                    id=int(pid),
                    name=name,
                    mode=POOL_MODES[int(mode_num)] if int(mode_num) < len(POOL_MODES) else "InferencePool",
                    creator=creator,
                    state=POOL_STATES[int(state_num)] if int(state_num) < len(POOL_STATES) else "Active",
                    min_providers=int(min_providers),
                    total_gpus=int(total_gpus),
                    guaranteed_throughput=int(throughput),
                    price_per_unit=from_wei(int(price_per_unit)),
                    member_count=int(member_count),
                    active_job_count=int(active_job_count),
                    total_staked=from_wei(int(total_staked)),
                ))
            except Exception:
                # Skip pools that fail to decode
                continue

        return pools

    # -------------------------------------------------------------------
    # Disputes
    # -------------------------------------------------------------------

    def dispute_result(self, job_id: int, bond: str) -> str:
        """File a dispute on a compute job result.

        Data source: DisputeResolution.disputeResult() via eth_sendTransaction with bond.

        Args:
            job_id: The job identifier to dispute.
            bond: Bond amount in ether-denominated decimal string.

        Returns:
            Transaction hash.
        """
        addr = self._require_dispute_address()
        data = self._dispute_iface.encode_function_data("disputeResult", [job_id])
        value = hex(to_wei(bond))
        return self._send_transaction(addr, data, value)

    def get_dispute(self, dispute_id: int) -> Dispute:
        """Get information about a specific dispute.

        Data source: DisputeResolution.getDispute(uint256) via eth_call.
        """
        addr = self._require_dispute_address()
        data = self._dispute_iface.encode_function_data("getDispute", [dispute_id])
        result = self._eth_call(addr, data)
        decoded = self._dispute_iface.decode_function_result("getDispute", result)
        # (jobId, challenger, defender, challengerBond, defenderBond,
        #  rangeStart, rangeEnd, round, state, outcome, deadline)
        (
            job_id, challenger, defender, challenger_bond, defender_bond,
            range_start, range_end, round_num, state_num, outcome_num, deadline,
        ) = decoded

        return Dispute(
            job_id=int(job_id),
            challenger=challenger,
            defender=defender,
            challenger_bond=from_wei(int(challenger_bond)),
            defender_bond=from_wei(int(defender_bond)),
            range_start=int(range_start),
            range_end=int(range_end),
            round=int(round_num),
            state=DISPUTE_STATES[int(state_num)] if int(state_num) < len(DISPUTE_STATES) else "Open",
            outcome=DISPUTE_OUTCOMES[int(outcome_num)] if int(outcome_num) < len(DISPUTE_OUTCOMES) else "Pending",
            deadline=int(deadline),
        )
