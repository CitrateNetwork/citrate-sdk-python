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

from ._chain_guard import expected_chain_id, pinned_send
from .abi import AbiInterface, enum_index, from_wei, to_wei
from .errors import CitrateError, ConfigurationError, ValidationError
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
    "function requestLeave(uint256 poolId)",
    "function leaveRequestedAt(uint256 poolId, address provider) view returns (uint256)",
]

# ComputeMarketplace: native escrow refunds that could not be pushed.
MARKETPLACE_REFUND_ABI = [
    "function nativeRefundOwed(address requester) view returns (uint256)",
    "function claimNativeRefund()",
]

# InferenceRouter: refunds credited on cancel / expiry.
INFERENCE_ROUTER_REFUND_ABI = [
    "function refundOwed(address requester) view returns (uint256)",
    "function claimRefund()",
]

# ComputePoolTraining: requester escrow refunds deferred at finalize.
TRAINING_REFUND_ABI = [
    "function requesterRefundPending(uint256 jobId) view returns (uint128)",
    "function claimRequesterRefund(uint256 jobId)",
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

#: BN254 scalar field modulus (ComputeVerifier.BN254_SCALAR_MODULUS).
BN254_SCALAR_MODULUS = (
    21888242871839275222246405745257275088548364400416034343698204186575808495617
)
#: ComputeVerifier.VALUE_THRESHOLD: a Commitment-tier request whose maxPrice is
#: strictly above this is verified under the ZK tier.
ZK_AUTO_UPGRADE_THRESHOLD_WEI = 10 * 10**18
#: ComputePool.LEAVE_COOLDOWN: blocks between requestLeave and leavePool.
LEAVE_COOLDOWN_BLOCKS = 150
#: ComputeMarketplace.DISPUTE_WINDOW: blocks after a Valid verification before
#: completeJob is accepted.
DISPUTE_WINDOW_BLOCKS = 100


class ZKCommitmentError(ValidationError):
    """A ZK-tier job needs a canonical 32-byte BN254 input commitment."""


class LeaveNotReadyError(CitrateError):
    """leavePool would revert: the LEAVE_COOLDOWN has not elapsed yet."""

    def __init__(self, pool_id: int, executable_at: int, current_block: int) -> None:
        self.pool_id = pool_id
        self.executable_at = executable_at
        self.current_block = current_block
        super().__init__(
            f"pool {pool_id}: leave cooldown ends at block {executable_at} "
            f"(current block {current_block})"
        )


class NothingToClaimError(CitrateError):
    """The claim would revert: nothing is owed to the caller."""


def effective_tier(tier: str, max_price_wei: int) -> str:
    """The tier ComputeVerifier settles a job under.

    A Commitment request above ZK_AUTO_UPGRADE_THRESHOLD_WEI is verified as ZK;
    every other request keeps its tier.
    """
    name = JOB_TIERS[enum_index(JOB_TIERS, tier, "tier")]
    if name == "Commitment" and max_price_wei > ZK_AUTO_UPGRADE_THRESHOLD_WEI:
        return "ZK"
    return name


def _canonical_field_element(value: str | bytes, what: str) -> bytes:
    """Return ``value`` as 32 bytes if it is a non-zero BN254 scalar < r."""
    if isinstance(value, bytes):
        raw = value
    else:
        text = value[2:] if value.startswith(("0x", "0X")) else value
        try:
            raw = bytes.fromhex(text)
        except ValueError as exc:
            raise ZKCommitmentError(f"{what} is not hex") from exc
    if len(raw) != 32:
        raise ZKCommitmentError(f"{what} must be exactly 32 bytes, got {len(raw)}")
    n = int.from_bytes(raw, "big")
    if n == 0 or n >= BN254_SCALAR_MODULUS:
        raise ZKCommitmentError(f"{what} must be a non-zero BN254 scalar below the field modulus")
    return raw


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
        *,
        chain_id: int | None = None,
    ) -> None:
        self._rpc_call = rpc_call
        # PBA-L6b-042: writes assert eth_chainId against this before sending.
        self._expected_chain_id = expected_chain_id(chain_id)
        self._chain_verified = False
        self._default_account = default_account
        self._gas_limit = gas_limit
        self._gas_price = gas_price

        addrs = contract_addresses or {}
        self._compute_addr = addrs.get("computePool")
        self._dispute_addr = addrs.get("disputeResolution")

        # ComputeMarketplace hosts postJob; older configs point computePool at it.
        self._marketplace_addr = addrs.get("computeMarketplace") or self._compute_addr
        self._router_addr = addrs.get("inferenceRouter")
        self._training_addr = addrs.get("computePoolTraining")

        self._compute_iface = AbiInterface(COMPUTE_POOL_ABI)
        self._dispute_iface = AbiInterface(DISPUTE_ABI)
        self._market_refund_iface = AbiInterface(MARKETPLACE_REFUND_ABI)
        self._router_refund_iface = AbiInterface(INFERENCE_ROUTER_REFUND_ABI)
        self._training_refund_iface = AbiInterface(TRAINING_REFUND_ABI)

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

    def _require_marketplace_address(self) -> str:
        if not self._marketplace_addr:
            raise ConfigurationError(
                "ComputeMarketplace contract address not configured. Set computeMarketplace "
                "(or computePool) via contract_addresses."
            )
        return self._marketplace_addr

    def _require_router_address(self) -> str:
        if not self._router_addr:
            raise ConfigurationError(
                "InferenceRouter contract address not configured. Set it via contract_addresses."
            )
        return self._router_addr

    def _require_training_address(self) -> str:
        if not self._training_addr:
            raise ConfigurationError(
                "ComputePoolTraining contract address not configured. Set it via contract_addresses."
            )
        return self._training_addr

    def _account(self, address: str | None) -> str:
        who = address or self._default_account
        if not who:
            raise ConfigurationError("No address provided and no defaultAccount configured.")
        return who

    def _block_number(self) -> int:
        return int(cast(str, self._rpc_call("eth_blockNumber", [])), 16)

    def _read_uint(self, iface: AbiInterface, to: str, fn: str, args: list[Any]) -> int:
        result = self._eth_call(to, iface.encode_function_data(fn, args))
        (value,) = iface.decode_function_result(fn, result)
        return int(value)

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
        return pinned_send(self, tx)

    # -------------------------------------------------------------------
    # Job Lifecycle
    # -------------------------------------------------------------------

    def post_job(
        self,
        model_hash: str,
        input_data: str,
        max_price: str,
        tier: str,
        *,
        input_commitment: str | bytes | None = None,
    ) -> str:
        """Post a new compute job to the marketplace.

        Data source: ComputeMarketplace.postJob() via eth_sendTransaction with msg.value.

        Args:
            model_hash: 32-byte model hash (hex string, optional 0x prefix).
            input_data: UTF-8 input payload for the compute job. Posted as
                ``inputHash`` for Commitment and TEE jobs; for ZK jobs the input
                is delivered off-chain and only ``input_commitment`` is posted.
            max_price: Maximum price in ether-denominated decimal string.
            tier: One of 'Commitment', 'ZK', 'TEE'.
            input_commitment: Required when the job is verified under the ZK
                tier (tier 'ZK', or 'Commitment' above 10 SALT): the inference
                circuit's 32-byte input commitment, a non-zero BN254 scalar
                below the field modulus, produced by the prover tooling. A hash
                of the raw input is not accepted by the verifier.

        Returns:
            Transaction hash (job ID emitted in JobPosted event).

        Raises:
            ZKCommitmentError: ZK job without a canonical commitment, a
                non-canonical model hash on a ZK job, or a commitment passed
                for a non-ZK job. Raised before any transaction is sent.
        """
        addr = self._require_marketplace_address()
        h = model_hash if model_hash.startswith("0x") else f"0x{model_hash}"
        hash_bytes = bytes.fromhex(h[2:])
        tier_num = enum_index(JOB_TIERS, tier, "tier")
        max_price_wei = to_wei(max_price)
        if effective_tier(tier, max_price_wei) == "ZK":
            if input_commitment is None:
                raise ZKCommitmentError(
                    "this job is verified under the ZK tier (tier 'ZK', or 'Commitment' above "
                    "10 SALT): pass input_commitment, the circuit's 32-byte BN254 input commitment"
                )
            input_bytes = _canonical_field_element(input_commitment, "input_commitment")
            if int.from_bytes(hash_bytes, "big") >= BN254_SCALAR_MODULUS:
                raise ZKCommitmentError("model_hash must be below the BN254 field modulus for a ZK job")
        elif input_commitment is not None:
            raise ZKCommitmentError("input_commitment is only used for ZK-tier jobs")
        else:
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

    def join_pool(self, pool_id: int, gpu_count: int, *, stake: str | None = None) -> str:
        """Join a compute pool with GPU allocation.

        Data source: ComputePool.joinPool() via eth_sendTransaction with msg.value.

        Args:
            pool_id: The pool identifier.
            gpu_count: Number of GPUs to allocate.
            stake: SALT staked with the membership, as a decimal string. The
                pool requires at least ``gpu_count * MIN_STAKE_PER_GPU``
                (10 SALT per GPU); without it the join reverts.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("joinPool", [pool_id, gpu_count])
        value = hex(to_wei(stake)) if stake is not None else "0x0"
        return self._send_transaction(addr, data, value)

    def request_leave(self, pool_id: int) -> str:
        """Start leaving a compute pool (step 1 of 2).

        Data source: ComputePool.requestLeave() via eth_sendTransaction. The
        member stays active and slashable until ``leavePool`` completes the
        exit, which is accepted LEAVE_COOLDOWN_BLOCKS blocks later.

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        data = self._compute_iface.encode_function_data("requestLeave", [pool_id])
        return self._send_transaction(addr, data)

    def leave_status(self, pool_id: int, address: str | None = None) -> dict[str, Any]:
        """Pending-exit state for ``address`` (default account) in ``pool_id``.

        Data source: ComputePool.leaveRequestedAt(uint256,address) + eth_blockNumber.

        Returns:
            ``{"requested_at": int, "executable_at": int | None, "ready": bool}``;
            ``requested_at`` is 0 when no exit is pending.
        """
        addr = self._require_compute_address()
        who = self._account(address)
        requested_at = self._read_uint(
            self._compute_iface, addr, "leaveRequestedAt", [pool_id, who]
        )
        if requested_at == 0:
            return {"requested_at": 0, "executable_at": None, "ready": False}
        executable_at = requested_at + LEAVE_COOLDOWN_BLOCKS
        return {
            "requested_at": requested_at,
            "executable_at": executable_at,
            "ready": self._block_number() >= executable_at,
        }

    def leave_pool(self, pool_id: int) -> str:
        """Leave a compute pool and reclaim stake (two-step exit).

        Data source: ComputePool.leaveRequestedAt / requestLeave / leavePool.

        * No exit pending: sends ``requestLeave`` (step 1) and returns its hash.
          Call again once the cooldown has elapsed.
        * Exit pending and LEAVE_COOLDOWN_BLOCKS elapsed: sends ``leavePool``.
        * Exit pending inside the cooldown: raises LeaveNotReadyError (no
          transaction is sent).

        Returns:
            Transaction hash.
        """
        addr = self._require_compute_address()
        status = self.leave_status(pool_id)
        if status["requested_at"] == 0:
            return self.request_leave(pool_id)
        if not status["ready"]:
            raise LeaveNotReadyError(pool_id, status["executable_at"], self._block_number())
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
    # Refund claims
    # -------------------------------------------------------------------

    def refund_owed(self, address: str | None = None) -> int:
        """Wei credited to ``address`` (default account) by InferenceRouter.

        Data source: InferenceRouter.refundOwed(address) via eth_call.
        """
        return self._read_uint(
            self._router_refund_iface, self._require_router_address(), "refundOwed",
            [self._account(address)],
        )

    def claim_refund(self) -> str:
        """Withdraw InferenceRouter refunds credited to the default account.

        Data source: InferenceRouter.claimRefund() via eth_sendTransaction.

        Raises:
            NothingToClaimError: nothing is owed (the call would revert).
        """
        addr = self._require_router_address()
        if self.refund_owed() == 0:
            raise NothingToClaimError("InferenceRouter: no refund owed")
        return self._send_transaction(addr, self._router_refund_iface.encode_function_data("claimRefund"))

    def native_refund_owed(self, address: str | None = None) -> int:
        """Wei of job escrow refunds ComputeMarketplace could not push to ``address``.

        Data source: ComputeMarketplace.nativeRefundOwed(address) via eth_call.
        """
        return self._read_uint(
            self._market_refund_iface, self._require_marketplace_address(), "nativeRefundOwed",
            [self._account(address)],
        )

    def claim_native_refund(self) -> str:
        """Withdraw ComputeMarketplace escrow refunds owed to the default account.

        Data source: ComputeMarketplace.claimNativeRefund() via eth_sendTransaction.

        Raises:
            NothingToClaimError: nothing is owed (the call would revert).
        """
        addr = self._require_marketplace_address()
        if self.native_refund_owed() == 0:
            raise NothingToClaimError("ComputeMarketplace: no native refund owed")
        return self._send_transaction(
            addr, self._market_refund_iface.encode_function_data("claimNativeRefund")
        )

    def requester_refund_pending(self, job_id: int) -> int:
        """Wei of a training job's requester escrow refund deferred at finalize.

        Data source: ComputePoolTraining.requesterRefundPending(uint256) via eth_call.
        """
        return self._read_uint(
            self._training_refund_iface, self._require_training_address(),
            "requesterRefundPending", [job_id],
        )

    def claim_requester_refund(self, job_id: int) -> str:
        """Claim a training job's deferred requester refund (requester only).

        Data source: ComputePoolTraining.claimRequesterRefund(uint256) via eth_sendTransaction.

        Raises:
            NothingToClaimError: nothing is pending for the job (the call would revert).
        """
        addr = self._require_training_address()
        if self.requester_refund_pending(job_id) == 0:
            raise NothingToClaimError(f"ComputePoolTraining: no refund pending for job {job_id}")
        return self._send_transaction(
            addr, self._training_refund_iface.encode_function_data("claimRequesterRefund", [job_id])
        )

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
