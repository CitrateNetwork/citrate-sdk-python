"""
Type definitions for Citrate SDK learning, staking, classroom, and compute modules.

Mirrors the TypeScript SDK types from sdk/javascript/src/learning.ts and
sdk/javascript/src/compute.ts.
"""

from dataclasses import dataclass, field
from typing import List, Optional


# ============================================================================
# Learning Types
# ============================================================================


@dataclass
class LearningPool:
    """Learning pool metadata returned by LearningPool.getPool() via eth_call."""

    id: int
    name: str
    description: str
    creator: str
    state: str  # 'Active' | 'Closed' | 'ActiveCycle'
    access: str  # 'Open' | 'InviteOnly' | 'ApplicationRequired'
    min_stake: str  # Ether-denominated decimal string
    member_count: int
    created_at: int


@dataclass
class CycleStatus:
    """Learning cycle status from LearningCycleManager.getCycleInfo() via eth_call."""

    cycle_id: int
    checkpoint_height: int
    state: str  # 'Open' | 'Collecting' | 'Aggregating' | 'AdapterGen' | 'Finalized'
    participant_count: int
    mentor_count: int
    total_rewards: str  # Ether-denominated decimal string
    rewards_distributed: bool
    aggregator: str


@dataclass
class ContributionDetail:
    """Per-type contribution count."""

    type: str
    count: str


@dataclass
class Contributions:
    """Contribution scores and breakdown from ContributionAccounting via eth_call."""

    address: str
    score: str
    claimable: str  # Ether-denominated
    distributed: str  # Ether-denominated
    pending_reward: str  # Ether-denominated
    per_type: List[ContributionDetail] = field(default_factory=list)


# ============================================================================
# Staking Types
# ============================================================================


@dataclass
class StakingInfo:
    """Liquid staking pool info from LiquidStakingPool view functions via eth_call."""

    user_shares: str  # Ether-denominated
    user_staked_value: str  # Ether-denominated
    total_pooled: str  # Ether-denominated
    total_shares: str  # Ether-denominated
    share_price: str  # Ether-denominated


@dataclass
class PendingWithdrawal:
    """Pending withdrawal request from LiquidStakingPool.withdrawals() via eth_call."""

    request_id: int
    staker: str
    share_amount: str  # Ether-denominated
    salt_amount: str  # Ether-denominated
    request_block: int
    claimed: bool


# ============================================================================
# Classroom Types
# ============================================================================


@dataclass
class ClassroomInfo:
    """Classroom info from ClassroomRegistry.getClassroom() via eth_call."""

    teacher: str
    name: str
    max_students: int
    student_count: int
    created_at: int
    exists: bool


# ============================================================================
# Compute Types
# ============================================================================


@dataclass
class ComputeJob:
    """Compute job metadata from ComputePool.getJob() via eth_call."""

    id: int
    requester: str
    model_hash: str
    max_price: str  # Ether-denominated
    tier: str  # 'Commitment' | 'ZK' | 'TEE'
    state: str  # 'Posted' | 'Bidding' | 'Executing' | 'Completed' | 'Disputed' | 'Failed'
    assigned_provider: str
    escrow: str  # Ether-denominated
    bid_deadline: int
    execution_deadline: int
    created_at: int
    bid_count: int


@dataclass
class ProviderInfo:
    """Compute provider info from ComputePool.getProviderInfo() via eth_call."""

    is_registered: bool
    stake: str  # Ether-denominated
    total_jobs_completed: int
    total_jobs_failed: int
    reputation_score: int
    current_active_jobs: int
    max_concurrent_jobs: int


@dataclass
class ComputePool:
    """Compute pool metadata from ComputePool.getPool() via eth_call."""

    id: int
    name: str
    mode: str  # 'InferencePool' | 'DataParallel' | 'PipelineParallel'
    creator: str
    state: str  # 'Active' | 'Paused' | 'Dissolved'
    min_providers: int
    total_gpus: int
    guaranteed_throughput: int
    price_per_unit: str  # Ether-denominated
    member_count: int
    active_job_count: int
    total_staked: str  # Ether-denominated


@dataclass
class Dispute:
    """Dispute info from DisputeResolution.getDispute() via eth_call."""

    job_id: int
    challenger: str
    defender: str
    challenger_bond: str  # Ether-denominated
    defender_bond: str  # Ether-denominated
    range_start: int
    range_end: int
    round: int
    state: str  # 'Open' | 'ChallengerWins' | 'DefenderWins' | 'Settled'
    outcome: str  # 'Pending' | 'ChallengerWins' | 'DefenderWins' | 'Draw'
    deadline: int
