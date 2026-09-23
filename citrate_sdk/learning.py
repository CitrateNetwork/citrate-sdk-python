"""
LC.5.3: SDK Learning Extensions (Python)

Provides classes for interacting with Citrate's learning subsystem:
  - LearningManager: Learning pool lifecycle and contribution queries
  - StakingManager: Liquid staking (SALT -> stSALT) operations
  - ClassroomManager: Classroom creation, enrollment, and model whitelisting

All methods wire to real on-chain contracts via the SDK's RPC client.
No mock returns -- every call encodes the actual Solidity ABI and sends
via eth_call (reads) or eth_sendTransaction (writes).

Mirrors sdk/javascript/src/learning.ts exactly (method names in snake_case).
"""

from __future__ import annotations

import time
from typing import Any

from .abi import AbiInterface, from_wei, keccak256_text, to_wei
from .errors import ConfigurationError
from .types import (
    ClassroomInfo,
    ContributionDetail,
    Contributions,
    CycleStatus,
    LearningPool,
    PendingWithdrawal,
    StakingInfo,
)

# ============================================================================
# Contract ABIs (minimal -- only the methods we call)
# Identical to the JS SDK's human-readable ABI arrays.
# ============================================================================

LEARNING_POOL_ABI = [
    "function nextPoolId() view returns (uint256)",
    "function getPool(uint256 poolId) view returns (uint256 id, string name, string description, address creator, uint8 state, uint8 access, uint256 minStake, uint256 memberCount, uint256 createdAt)",
    "function isMember(uint256 poolId, address member) view returns (bool)",
    "function stakes(uint256 poolId, address member) view returns (uint256)",
    "function joinPool(uint256 poolId) payable",
    "function leavePool(uint256 poolId)",
    "function createPool(string name, string description, uint8 access, uint256 minStake) payable returns (uint256 poolId)",
    "function whitelistModel(uint256 poolId, bytes32 modelHash)",
    "function removeModel(uint256 poolId, bytes32 modelHash)",
    "function isModelWhitelisted(uint256 poolId, bytes32 modelHash) view returns (bool)",
    "function getMemberStake(uint256 poolId, address member) view returns (uint256)",
]

LEARNING_CYCLE_ABI = [
    "function currentCycleId() view returns (uint256)",
    "function getCycleInfo(uint256 cycleId) view returns (uint256 checkpointHeight, uint8 state, uint256 participantCount, uint256 mentorCount, uint256 totalRewards, bool rewardsDistributed, address aggregator)",
    "function getCycleState(uint256 cycleId) view returns (uint8)",
    "function getParticipants(uint256 cycleId) view returns (address[])",
    "function getMentors(uint256 cycleId) view returns (address[])",
    "function getReward(uint256 cycleId, address participant) view returns (uint256)",
    "function hasClaimed(uint256 cycleId, address participant) view returns (bool)",
    "function isParticipant(uint256 cycleId, address addr) view returns (bool)",
    "function isMentor(uint256 cycleId, address addr) view returns (bool)",
    "function registerParticipant(uint256 cycleId)",
    "function claimCycleReward(uint256 cycleId)",
]

CONTRIBUTION_ABI = [
    "function getScore(address contributor) view returns (uint256)",
    "function getContribution(address contributor, uint8 ctype) view returns (uint256)",
    "function pendingReward(address contributor) view returns (uint256)",
    "function contributorCount() view returns (uint256)",
    "function claimable(address) view returns (uint256)",
    "function distributed(address) view returns (uint256)",
    "function claimRewards()",
    "function scores(address) view returns (uint256)",
    "function currentEpoch() view returns (uint256)",
    "function totalScore() view returns (uint256)",
    "function totalDistributed() view returns (uint256)",
]

LIQUID_STAKING_ABI = [
    "function deposit() payable returns (uint256 sharesOut)",
    "function requestWithdrawal(uint256 shareAmount) returns (uint256 requestId)",
    "function claimWithdrawal(uint256 requestId)",
    "function shares(address staker) view returns (uint256)",
    "function totalPooled() view returns (uint256)",
    "function totalShares() view returns (uint256)",
    "function getSharePrice() view returns (uint256)",
    "function balanceOf(address staker) view returns (uint256)",
    "function previewDeposit(uint256 amount) view returns (uint256)",
    "function previewWithdraw(uint256 shareAmount) view returns (uint256)",
    "function withdrawals(uint256 requestId) view returns (address staker, uint256 shareAmount, uint256 saltAmount, uint256 requestBlock, bool claimed)",
    "function nextWithdrawalId() view returns (uint256)",
]

CLASSROOM_REGISTRY_ABI = [
    "function createClassroom(string name, uint256 maxStudents, bytes32 inviteCodeHash)",
    "function enrollWithCode(bytes32 inviteCodeHash)",
    "function unenroll()",
    "function removeStudent(address student)",
    "function whitelistModel(bytes32 modelHash)",
    "function removeModel(bytes32 modelHash)",
    "function rotateInviteCode(bytes32 newCodeHash)",
    "function getClassroom(address teacher) view returns (address teacher_addr, string name, uint256 maxStudents, uint256 studentCount, uint256 createdAt, bool exists)",
    "function isStudentEnrolled(address teacher, address student) view returns (bool)",
    "function getStudentTeacher(address student) view returns (address)",
    "function isModelWhitelistedFor(address teacher, bytes32 modelHash) view returns (bool)",
    "function canStudentAccessModel(address student, bytes32 modelHash) view returns (bool)",
    "function classroomExists(address teacher) view returns (bool)",
    "function activeInviteCode(address teacher) view returns (bytes32)",
]

# ============================================================================
# Helpers / Constants
# ============================================================================

POOL_STATES = ("Active", "Closed", "ActiveCycle")
ACCESS_TYPES = ("Open", "InviteOnly", "ApplicationRequired")
CYCLE_STATES = ("Open", "Collecting", "Aggregating", "AdapterGen", "Finalized")
CONTRIBUTION_TYPES = (
    "Validation",
    "ModelHosting",
    "AdapterCreation",
    "DataProvision",
    "AppDevelopment",
    "BridgeInfra",
    "Governance",
)

ZERO_ADDRESS = "0x" + "0" * 40


# ============================================================================
# Base mixin for RPC helpers — shared by all three managers
# ============================================================================

class _RpcMixin:
    """Shared eth_call / eth_sendTransaction helpers.

    Expects the concrete class to have:
      - self._rpc_call(method, params) -> Any
      - self._default_account: Optional[str]
      - self._gas_limit: int
      - self._gas_price: str
    """

    # These will be set by concrete __init__ methods
    _rpc_call: Any
    _default_account: str | None
    _gas_limit: int
    _gas_price: str

    def _eth_call(self, to: str, data: str) -> str:
        """Execute an eth_call (read-only) and return the hex result."""
        result = self._rpc_call("eth_call", [{"to": to, "data": data}, "latest"])
        return result

    def _send_transaction(self, to: str, data: str, value: str = "0x0") -> str:
        """Send an eth_sendTransaction (state-changing) and return the tx hash."""
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
        return self._rpc_call("eth_sendTransaction", [tx])


# ============================================================================
# LearningManager
# ============================================================================

class LearningManager(_RpcMixin):
    """Manages learning pool lifecycle, cycle queries, and contribution tracking.

    Data sources:
      - LearningPool contract: pool CRUD, membership
      - LearningCycleManager contract: cycle lifecycle, rewards
      - ContributionAccounting contract: scores, contributions, claimable
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
        self._learning_pool_addr = addrs.get("learningPool")
        self._cycle_addr = addrs.get("learningCycleManager")
        self._contrib_addr = addrs.get("contributionAccounting")

        self._iface = AbiInterface(LEARNING_POOL_ABI)
        self._cycle_iface = AbiInterface(LEARNING_CYCLE_ABI)
        self._contrib_iface = AbiInterface(CONTRIBUTION_ABI)

    # --- Helpers ---

    def _require_learning_pool(self) -> str:
        if not self._learning_pool_addr:
            raise ConfigurationError("learningPool contract address not configured. Set it via contract_addresses.")
        return self._learning_pool_addr

    def _require_cycle(self) -> str:
        if not self._cycle_addr:
            raise ConfigurationError("learningCycleManager contract address not configured. Set it via contract_addresses.")
        return self._cycle_addr

    def _require_contrib(self) -> str:
        if not self._contrib_addr:
            raise ConfigurationError("contributionAccounting contract address not configured. Set it via contract_addresses.")
        return self._contrib_addr

    # --- Pool methods ---

    def list_pools(self) -> list[LearningPool]:
        """List all available learning pools.

        Data source: LearningPool.nextPoolId() + getPool(uint256) via eth_call.
        """
        addr = self._require_learning_pool()

        # Get pool count
        data = self._iface.encode_function_data("nextPoolId")
        result = self._eth_call(addr, data)
        (next_id,) = self._iface.decode_function_result("nextPoolId", result)
        count = int(next_id)

        if count == 0:
            return []

        pools: list[LearningPool] = []
        max_pools = min(count, 100)

        for i in range(max_pools):
            try:
                call_data = self._iface.encode_function_data("getPool", [i])
                call_result = self._eth_call(addr, call_data)
                decoded = self._iface.decode_function_result("getPool", call_result)
                # decoded: (id, name, description, creator, state, access, minStake, memberCount, createdAt)
                pool_id, name, description, creator, state_num, access_num, min_stake, member_count, created_at = decoded
                pools.append(LearningPool(
                    id=int(pool_id),
                    name=name,
                    description=description,
                    creator=creator,
                    state=POOL_STATES[int(state_num)] if int(state_num) < len(POOL_STATES) else "Active",
                    access=ACCESS_TYPES[int(access_num)] if int(access_num) < len(ACCESS_TYPES) else "Open",
                    min_stake=from_wei(int(min_stake)),
                    member_count=int(member_count),
                    created_at=int(created_at),
                ))
            except Exception:
                # Skip pools that fail to decode (same as JS SDK behaviour)
                continue

        return pools

    def join_pool(self, pool_id: int, stake_amount: str) -> str:
        """Join a learning pool by staking SALT.

        Data source: LearningPool.joinPool(uint256) via eth_sendTransaction with msg.value.

        Args:
            pool_id: The pool identifier.
            stake_amount: SALT amount as decimal string (e.g. "100.5").

        Returns:
            Transaction hash.
        """
        addr = self._require_learning_pool()
        data = self._iface.encode_function_data("joinPool", [pool_id])
        value = hex(to_wei(stake_amount))
        return self._send_transaction(addr, data, value)

    def leave_pool(self, pool_id: int) -> str:
        """Leave a learning pool and reclaim staked SALT.

        Data source: LearningPool.leavePool(uint256) via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_learning_pool()
        data = self._iface.encode_function_data("leavePool", [pool_id])
        return self._send_transaction(addr, data)

    def create_pool(
        self,
        name: str,
        description: str,
        access: str,
        min_stake: str,
    ) -> str:
        """Create a new learning pool.

        Data source: LearningPool.createPool(string,string,uint8,uint256) via eth_sendTransaction.

        Args:
            name: Pool display name.
            description: Pool description.
            access: One of 'Open', 'InviteOnly', 'ApplicationRequired'.
            min_stake: Minimum stake in ether-denominated decimal string.

        Returns:
            Transaction hash (pool ID emitted in PoolCreated event).
        """
        addr = self._require_learning_pool()
        access_num = ACCESS_TYPES.index(access) if access in ACCESS_TYPES else 0
        min_stake_wei = to_wei(min_stake)
        data = self._iface.encode_function_data("createPool", [
            name, description, access_num, min_stake_wei,
        ])
        value = hex(min_stake_wei)
        return self._send_transaction(addr, data, value)

    # --- Cycle methods ---

    def get_cycle_status(self) -> CycleStatus:
        """Get current learning cycle status.

        Data source: LearningCycleManager.currentCycleId() + getCycleInfo() via eth_call.
        """
        addr = self._require_cycle()

        id_data = self._cycle_iface.encode_function_data("currentCycleId")
        id_result = self._eth_call(addr, id_data)
        (current_id,) = self._cycle_iface.decode_function_result("currentCycleId", id_result)
        cycle_id = int(current_id)

        if cycle_id == 0:
            return CycleStatus(
                cycle_id=0,
                checkpoint_height=0,
                state="Open",
                participant_count=0,
                mentor_count=0,
                total_rewards="0",
                rewards_distributed=False,
                aggregator=ZERO_ADDRESS,
            )

        info_data = self._cycle_iface.encode_function_data("getCycleInfo", [cycle_id])
        info_result = self._eth_call(addr, info_data)
        decoded = self._cycle_iface.decode_function_result("getCycleInfo", info_result)
        # (checkpointHeight, state, participantCount, mentorCount, totalRewards, rewardsDistributed, aggregator)
        cp_height, state_num, participant_count, mentor_count, total_rewards, rewards_dist, aggregator = decoded

        return CycleStatus(
            cycle_id=cycle_id,
            checkpoint_height=int(cp_height),
            state=CYCLE_STATES[int(state_num)] if int(state_num) < len(CYCLE_STATES) else "Open",
            participant_count=int(participant_count),
            mentor_count=int(mentor_count),
            total_rewards=from_wei(int(total_rewards)),
            rewards_distributed=bool(rewards_dist),
            aggregator=aggregator,
        )

    def register_for_cycle(self, cycle_id: int) -> str:
        """Register as a participant in a learning cycle.

        Data source: LearningCycleManager.registerParticipant(uint256) via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_cycle()
        data = self._cycle_iface.encode_function_data("registerParticipant", [cycle_id])
        return self._send_transaction(addr, data)

    def claim_cycle_reward(self, cycle_id: int) -> str:
        """Claim rewards from a finalized cycle.

        Data source: LearningCycleManager.claimCycleReward(uint256) via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_cycle()
        data = self._cycle_iface.encode_function_data("claimCycleReward", [cycle_id])
        return self._send_transaction(addr, data)

    # --- Contribution methods ---

    def get_contributions(self, address: str) -> Contributions:
        """Get contribution scores and breakdown for an address.

        Data source: ContributionAccounting.getScore(), .getContribution(), .claimable(),
                     .distributed(), .pendingReward() via eth_call.
        """
        addr = self._require_contrib()

        # Score
        score_data = self._contrib_iface.encode_function_data("getScore", [address])
        score_result = self._eth_call(addr, score_data)
        (score,) = self._contrib_iface.decode_function_result("getScore", score_result)

        # Claimable
        claimable_data = self._contrib_iface.encode_function_data("claimable", [address])
        claimable_result = self._eth_call(addr, claimable_data)
        (claimable_val,) = self._contrib_iface.decode_function_result("claimable", claimable_result)

        # Distributed
        distrib_data = self._contrib_iface.encode_function_data("distributed", [address])
        distrib_result = self._eth_call(addr, distrib_data)
        (distrib_val,) = self._contrib_iface.decode_function_result("distributed", distrib_result)

        # Pending reward
        pending_data = self._contrib_iface.encode_function_data("pendingReward", [address])
        pending_result = self._eth_call(addr, pending_data)
        (pending_val,) = self._contrib_iface.decode_function_result("pendingReward", pending_result)

        # Per-type contributions
        per_type: list[ContributionDetail] = []
        for i in range(7):
            contrib_data = self._contrib_iface.encode_function_data("getContribution", [address, i])
            contrib_result = self._eth_call(addr, contrib_data)
            (count,) = self._contrib_iface.decode_function_result("getContribution", contrib_result)
            per_type.append(ContributionDetail(
                type=CONTRIBUTION_TYPES[i],
                count=str(int(count)),
            ))

        return Contributions(
            address=address,
            score=str(int(score)),
            claimable=from_wei(int(claimable_val)),
            distributed=from_wei(int(distrib_val)),
            pending_reward=from_wei(int(pending_val)),
            per_type=per_type,
        )

    def claim_contribution_rewards(self) -> str:
        """Claim accumulated contribution rewards.

        Data source: ContributionAccounting.claimRewards() via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_contrib()
        data = self._contrib_iface.encode_function_data("claimRewards")
        return self._send_transaction(addr, data)


# ============================================================================
# StakingManager
# ============================================================================

class StakingManager(_RpcMixin):
    """Manages liquid staking operations: SALT -> stSALT deposits,
    withdrawal requests, and staking info queries.

    Data source: LiquidStakingPool contract via eth_call / eth_sendTransaction.
    """

    def __init__(
        self,
        rpc_call: Any,
        default_account: str | None = None,
        gas_limit: int = 500_000,
        gas_price: str = "0x3b9aca00",
        staking_address: str | None = None,
    ) -> None:
        self._rpc_call = rpc_call
        self._default_account = default_account
        self._gas_limit = gas_limit
        self._gas_price = gas_price
        self._staking_address = staking_address
        self._iface = AbiInterface(LIQUID_STAKING_ABI)

    def _require_address(self) -> str:
        if not self._staking_address:
            raise ConfigurationError("LiquidStakingPool contract address not configured.")
        return self._staking_address

    def deposit(self, amount: str) -> str:
        """Deposit SALT into the liquid staking pool and receive stSALT shares.

        Data source: LiquidStakingPool.deposit() via eth_sendTransaction with msg.value.

        Args:
            amount: SALT amount as decimal string (e.g. "100.5").

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("deposit")
        value = hex(to_wei(amount))
        return self._send_transaction(addr, data, value)

    def withdraw(self, shares: str) -> str:
        """Request withdrawal of stSALT shares. Subject to 7-day lockup.

        Data source: LiquidStakingPool.requestWithdrawal(uint256) via eth_sendTransaction.

        Args:
            shares: stSALT share amount as decimal string.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        shares_wei = to_wei(shares)
        data = self._iface.encode_function_data("requestWithdrawal", [shares_wei])
        return self._send_transaction(addr, data)

    def claim_withdrawal(self, request_id: int) -> str:
        """Claim a completed withdrawal (after 7-day lockup).

        Data source: LiquidStakingPool.claimWithdrawal(uint256) via eth_sendTransaction.

        Args:
            request_id: Withdrawal request ID.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("claimWithdrawal", [request_id])
        return self._send_transaction(addr, data)

    def get_info(self, user_address: str | None = None) -> StakingInfo:
        """Get comprehensive staking info: pool stats and user balances.

        Data source: LiquidStakingPool view functions via eth_call.
        """
        addr = self._require_address()
        user = user_address or self._default_account

        # Total pooled
        pooled_data = self._iface.encode_function_data("totalPooled")
        pooled_result = self._eth_call(addr, pooled_data)
        (total_pooled,) = self._iface.decode_function_result("totalPooled", pooled_result)

        # Total shares
        shares_data = self._iface.encode_function_data("totalShares")
        shares_result = self._eth_call(addr, shares_data)
        (total_shares,) = self._iface.decode_function_result("totalShares", shares_result)

        # Share price
        price_data = self._iface.encode_function_data("getSharePrice")
        price_result = self._eth_call(addr, price_data)
        (share_price,) = self._iface.decode_function_result("getSharePrice", price_result)

        user_shares = 0
        user_staked_value = 0

        if user:
            # User shares
            user_shares_data = self._iface.encode_function_data("shares", [user])
            user_shares_result = self._eth_call(addr, user_shares_data)
            (user_shares,) = self._iface.decode_function_result("shares", user_shares_result)

            # User staked value
            bal_data = self._iface.encode_function_data("balanceOf", [user])
            bal_result = self._eth_call(addr, bal_data)
            (user_staked_value,) = self._iface.decode_function_result("balanceOf", bal_result)

        return StakingInfo(
            user_shares=from_wei(int(user_shares)),
            user_staked_value=from_wei(int(user_staked_value)),
            total_pooled=from_wei(int(total_pooled)),
            total_shares=from_wei(int(total_shares)),
            share_price=from_wei(int(share_price)),
        )

    def preview_deposit(self, amount: str) -> str:
        """Preview how many stSALT shares a deposit would yield.

        Data source: LiquidStakingPool.previewDeposit(uint256) via eth_call.
        """
        addr = self._require_address()
        amount_wei = to_wei(amount)
        data = self._iface.encode_function_data("previewDeposit", [amount_wei])
        result = self._eth_call(addr, data)
        (shares,) = self._iface.decode_function_result("previewDeposit", result)
        return from_wei(int(shares))

    def preview_withdraw(self, shares: str) -> str:
        """Preview how much SALT a withdrawal would yield.

        Data source: LiquidStakingPool.previewWithdraw(uint256) via eth_call.
        """
        addr = self._require_address()
        shares_wei = to_wei(shares)
        data = self._iface.encode_function_data("previewWithdraw", [shares_wei])
        result = self._eth_call(addr, data)
        (salt,) = self._iface.decode_function_result("previewWithdraw", result)
        return from_wei(int(salt))

    def get_withdrawal(self, request_id: int) -> PendingWithdrawal:
        """Get details of a pending withdrawal request.

        Data source: LiquidStakingPool.withdrawals(uint256) via eth_call.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("withdrawals", [request_id])
        result = self._eth_call(addr, data)
        decoded = self._iface.decode_function_result("withdrawals", result)
        staker, share_amount, salt_amount, request_block, claimed = decoded

        return PendingWithdrawal(
            request_id=request_id,
            staker=staker,
            share_amount=from_wei(int(share_amount)),
            salt_amount=from_wei(int(salt_amount)),
            request_block=int(request_block),
            claimed=bool(claimed),
        )


# ============================================================================
# ClassroomManager
# ============================================================================

class ClassroomManager(_RpcMixin):
    """Manages classroom creation, student enrollment, and model whitelisting.

    Data source: ClassroomRegistry contract via eth_call / eth_sendTransaction.
    """

    def __init__(
        self,
        rpc_call: Any,
        default_account: str | None = None,
        gas_limit: int = 300_000,
        gas_price: str = "0x3b9aca00",
        classroom_address: str | None = None,
    ) -> None:
        self._rpc_call = rpc_call
        self._default_account = default_account
        self._gas_limit = gas_limit
        self._gas_price = gas_price
        self._classroom_address = classroom_address
        self._iface = AbiInterface(CLASSROOM_REGISTRY_ABI)

    def _require_address(self) -> str:
        if not self._classroom_address:
            raise ConfigurationError("ClassroomRegistry contract address not configured.")
        return self._classroom_address

    def create(self, name: str, max_students: int, invite_code: str | None = None) -> str:
        """Create a new classroom.

        Data source: ClassroomRegistry.createClassroom(string, uint256, bytes32) via eth_sendTransaction.

        Args:
            name: Classroom display name.
            max_students: Maximum enrollment capacity.
            invite_code: Plain-text invite code (will be hashed on-chain). Auto-generated if omitted.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        code = invite_code or f"classroom-{int(time.time() * 1000)}"
        code_hash = keccak256_text(code)
        code_hash_bytes = bytes.fromhex(code_hash[2:])
        data = self._iface.encode_function_data("createClassroom", [
            name, max_students, code_hash_bytes,
        ])
        return self._send_transaction(addr, data)

    def enroll(self, invite_code: str) -> str:
        """Enroll as a student in a classroom using an invite code.

        Data source: ClassroomRegistry.enrollWithCode(bytes32) via eth_sendTransaction.

        Args:
            invite_code: Plain-text invite code provided by teacher.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        code_hash = keccak256_text(invite_code)
        code_hash_bytes = bytes.fromhex(code_hash[2:])
        data = self._iface.encode_function_data("enrollWithCode", [code_hash_bytes])
        return self._send_transaction(addr, data)

    def unenroll(self) -> str:
        """Unenroll from current classroom (student-initiated).

        Data source: ClassroomRegistry.unenroll() via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("unenroll")
        return self._send_transaction(addr, data)

    def deploy_model(self, model_hash: str) -> str:
        """Deploy (whitelist) a model in the teacher's classroom.

        Data source: ClassroomRegistry.whitelistModel(bytes32) via eth_sendTransaction.

        Args:
            model_hash: 32-byte model hash (hex string with optional 0x prefix).

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        h = model_hash if model_hash.startswith("0x") else f"0x{model_hash}"
        hash_bytes = bytes.fromhex(h[2:])
        data = self._iface.encode_function_data("whitelistModel", [hash_bytes])
        return self._send_transaction(addr, data)

    def remove_model(self, model_hash: str) -> str:
        """Remove a model from the classroom whitelist.

        Data source: ClassroomRegistry.removeModel(bytes32) via eth_sendTransaction.

        Args:
            model_hash: 32-byte model hash.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        h = model_hash if model_hash.startswith("0x") else f"0x{model_hash}"
        hash_bytes = bytes.fromhex(h[2:])
        data = self._iface.encode_function_data("removeModel", [hash_bytes])
        return self._send_transaction(addr, data)

    def rotate_invite_code(self, new_invite_code: str) -> str:
        """Rotate the classroom's invite code (teacher only).

        Data source: ClassroomRegistry.rotateInviteCode(bytes32) via eth_sendTransaction.

        Args:
            new_invite_code: New plain-text invite code.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        code_hash = keccak256_text(new_invite_code)
        code_hash_bytes = bytes.fromhex(code_hash[2:])
        data = self._iface.encode_function_data("rotateInviteCode", [code_hash_bytes])
        return self._send_transaction(addr, data)

    def get_classroom(self, teacher_address: str) -> ClassroomInfo:
        """Get classroom info for a teacher.

        Data source: ClassroomRegistry.getClassroom(address) via eth_call.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("getClassroom", [teacher_address])
        result = self._eth_call(addr, data)
        decoded = self._iface.decode_function_result("getClassroom", result)
        teacher_addr, name, max_students, student_count, created_at, exists = decoded

        return ClassroomInfo(
            teacher=teacher_addr,
            name=name,
            max_students=int(max_students),
            student_count=int(student_count),
            created_at=int(created_at),
            exists=bool(exists),
        )

    def can_student_access_model(self, student_address: str, model_hash: str) -> bool:
        """Check if a student can access a specific model.

        Data source: ClassroomRegistry.canStudentAccessModel(address, bytes32) via eth_call.
        """
        addr = self._require_address()
        h = model_hash if model_hash.startswith("0x") else f"0x{model_hash}"
        hash_bytes = bytes.fromhex(h[2:])
        data = self._iface.encode_function_data("canStudentAccessModel", [student_address, hash_bytes])
        result = self._eth_call(addr, data)
        (can_access,) = self._iface.decode_function_result("canStudentAccessModel", result)
        return bool(can_access)

    def get_student_teacher(self, student_address: str) -> str:
        """Check which teacher a student is enrolled with (address(0) if none).

        Data source: ClassroomRegistry.getStudentTeacher(address) via eth_call.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("getStudentTeacher", [student_address])
        result = self._eth_call(addr, data)
        (teacher,) = self._iface.decode_function_result("getStudentTeacher", result)
        return teacher
