"""
Core economic simulation engine for Citrate SALT tokenomics.

Runs an agent-based model over configurable time horizons, tracking:
- Supply dynamics (minting, burning, circulating)
- Staking behavior and APY
- Fee revenue and 7-way distribution
- Adoption curves (validators, schools, providers)
- Price model grounded in compute-cost floor

Invariant maintained every epoch:
    circulating_supply == total_minted - total_burned - total_staked
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field

import numpy as np

from . import parameters as P
from .agents import (
    ComputeProviderAgent,
    ModelCreatorAgent,
    SchoolAgent,
    SpeculatorAgent,
    StakerAgent,
    ValidatorAgent,
)

# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------

@dataclass
class EpochSnapshot:
    """Complete economic state at one epoch boundary."""

    epoch: int = 0
    block_height: int = 0
    circulating_supply: float = 0.0
    total_minted: float = 0.0
    total_burned: float = 0.0
    total_staked: float = 0.0
    staking_ratio: float = 0.0
    apy: float = 0.0
    fee_revenue: float = 0.0
    compute_demand: int = 0  # inferences per epoch
    salt_price_usd: float = 0.0
    floor_price_usd: float = 0.0
    validator_count: int = 0
    school_count: int = 0
    model_creator_count: int = 0
    staker_count: int = 0
    speculator_count: int = 0
    compute_provider_count: int = 0
    total_compute_capacity: int = 0
    compute_utilization: float = 0.0
    # Revenue breakdown (SALT distributed this epoch)
    validator_revenue: float = 0.0
    creator_revenue: float = 0.0
    infra_revenue: float = 0.0
    treasury_revenue: float = 0.0
    staker_revenue: float = 0.0
    facilitator_revenue: float = 0.0
    # Burn breakdown
    bme_burned: float = 0.0
    gas_burned: float = 0.0
    # Institutional
    institutional_rewards: float = 0.0
    total_adapters: int = 0
    total_models_hosted: int = 0


@dataclass
class SimulationResult:
    """Complete simulation output with per-epoch snapshots."""

    scenario: str
    epochs: list[EpochSnapshot] = field(default_factory=list)
    total_years: int = 0
    total_epochs_run: int = 0

    @property
    def final(self) -> EpochSnapshot:
        """Last epoch snapshot."""
        return self.epochs[-1]

    def at_year(self, year: int) -> EpochSnapshot | None:
        """Return snapshot closest to the given year boundary."""
        target_epoch = year * P.EPOCHS_PER_YEAR
        for snap in self.epochs:
            if snap.epoch >= target_epoch:
                return snap
        return self.epochs[-1] if self.epochs else None

    def to_arrays(self) -> dict[str, np.ndarray]:
        """Extract all numeric fields as numpy arrays for charting."""
        if not self.epochs:
            return {}
        arrays: dict[str, np.ndarray] = {}
        fields_to_extract = [
            "epoch", "block_height", "circulating_supply", "total_minted",
            "total_burned", "total_staked", "staking_ratio", "apy",
            "fee_revenue", "compute_demand", "salt_price_usd", "floor_price_usd",
            "validator_count", "school_count", "compute_utilization",
            "validator_revenue", "creator_revenue", "infra_revenue",
            "treasury_revenue", "staker_revenue", "facilitator_revenue",
            "bme_burned", "gas_burned", "institutional_rewards",
        ]
        for f in fields_to_extract:
            arrays[f] = np.array([getattr(s, f) for s in self.epochs], dtype=np.float64)
        return arrays


# ---------------------------------------------------------------------------
# Scenario configurations
# ---------------------------------------------------------------------------

_SCENARIOS = {
    "low": {
        "initial_validators": 20,
        "initial_schools": 5,
        "initial_model_creators": 10,
        "initial_stakers": 50,
        "initial_speculators": 100,
        "initial_compute_providers": 15,
        "validator_growth_per_year": 5,
        "school_growth_per_year": 2,
        "model_creator_growth_per_year": 3,
        "staker_growth_per_year": 10,
        "speculator_growth_per_year": 20,
        "compute_provider_growth_per_year": 5,
        "initial_inference_demand_per_epoch": 5_000,
        "demand_growth_annual_pct": 30,
        "initial_salt_price_usd": 0.10,
        "initial_tx_per_epoch": 500,
        "tx_growth_annual_pct": 20,
    },
    "medium": {
        "initial_validators": 50,
        "initial_schools": 10,
        "initial_model_creators": 25,
        "initial_stakers": 200,
        "initial_speculators": 300,
        "initial_compute_providers": 40,
        "validator_growth_per_year": 15,
        "school_growth_per_year": 5,
        "model_creator_growth_per_year": 10,
        "staker_growth_per_year": 50,
        "speculator_growth_per_year": 60,
        "compute_provider_growth_per_year": 15,
        "initial_inference_demand_per_epoch": 20_000,
        "demand_growth_annual_pct": 80,
        "initial_salt_price_usd": 0.25,
        "initial_tx_per_epoch": 2_000,
        "tx_growth_annual_pct": 50,
    },
    "high": {
        "initial_validators": 100,
        "initial_schools": 25,
        "initial_model_creators": 60,
        "initial_stakers": 500,
        "initial_speculators": 800,
        "initial_compute_providers": 80,
        "validator_growth_per_year": 40,
        "school_growth_per_year": 15,
        "model_creator_growth_per_year": 30,
        "staker_growth_per_year": 150,
        "speculator_growth_per_year": 200,
        "compute_provider_growth_per_year": 40,
        "initial_inference_demand_per_epoch": 100_000,
        "demand_growth_annual_pct": 150,
        "initial_salt_price_usd": 0.50,
        "initial_tx_per_epoch": 10_000,
        "tx_growth_annual_pct": 100,
    },
}


# ---------------------------------------------------------------------------
# Simulation engine
# ---------------------------------------------------------------------------

class EconomicSimulation:
    """
    Agent-based economic simulation for SALT tokenomics.

    Models multi-year dynamics of supply, demand, staking, fees, burns,
    and price discovery across configurable adoption scenarios.
    """

    # How often (in epochs) to run the expensive agent-strategy updates.
    # Between updates, the simulation still tracks supply, fees, and burns
    # accurately. Agent decisions (stake/unstake) happen on this cadence.
    AGENT_UPDATE_INTERVAL: int = 20

    def __init__(self, scenario: str = "medium", seed: int = 42) -> None:
        if scenario not in _SCENARIOS:
            raise ValueError(f"Unknown scenario '{scenario}'. Use: {list(_SCENARIOS.keys())}")
        self.scenario = scenario
        self.config = dict(_SCENARIOS[scenario])  # copy so sensitivity can mutate
        self.seed = seed
        self.rng = random.Random(seed)

        # Accumulators
        self.total_minted: float = 0.0
        self.total_burned: float = 0.0
        self.block_height: int = 0
        self.current_epoch: int = 0

        # Agent pools
        self.validators: list[ValidatorAgent] = []
        self.model_creators: list[ModelCreatorAgent] = []
        self.schools: list[SchoolAgent] = []
        self.stakers: list[StakerAgent] = []
        self.speculators: list[SpeculatorAgent] = []
        self.compute_providers: list[ComputeProviderAgent] = []

        # Price state
        self.salt_price_usd: float = self.config["initial_salt_price_usd"]
        self.compute_demand_per_epoch: int = self.config["initial_inference_demand_per_epoch"]
        self.tx_per_epoch: int = self.config["initial_tx_per_epoch"]

        # Tracking
        self._agent_id_counter: int = 0

        # Pre-computed per-epoch growth multipliers (set in run())
        self._demand_growth_mult: float = 1.0
        self._tx_growth_mult: float = 1.0

        # Cached aggregate values (refreshed every AGENT_UPDATE_INTERVAL)
        self._cached_total_staked: float = 0.0
        self._cached_total_agent_holdings: float = 0.0
        self._cached_total_capacity: int = 0
        self._cached_school_demand: int = 0
        self._cached_active_counts: dict[str, int] = {}
        self._cached_total_models: int = 0
        self._cached_total_provider_capacity: int = 0

        # Accumulated rewards between agent-update ticks (avoids per-epoch iteration)
        self._pending_validator_reward: float = 0.0
        self._pending_creator_reward: float = 0.0
        self._pending_infra_reward: float = 0.0
        self._pending_staker_reward: float = 0.0
        self._pending_institutional_minted: float = 0.0

    def _next_agent_id(self) -> int:
        self._agent_id_counter += 1
        return self._agent_id_counter

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def _initialize_agents(self) -> None:
        """Seed the initial agent populations and track their balances as minted."""
        cfg = self.config

        for _ in range(cfg["initial_validators"]):
            agent = ValidatorAgent(agent_id=self._next_agent_id())
            self.validators.append(agent)
            self.total_minted += agent.total_holdings

        for _ in range(cfg["initial_model_creators"]):
            agent = ModelCreatorAgent(agent_id=self._next_agent_id())
            self.model_creators.append(agent)
            self.total_minted += agent.total_holdings

        for _ in range(cfg["initial_schools"]):
            agent = SchoolAgent(agent_id=self._next_agent_id())
            self.schools.append(agent)
            self.total_minted += agent.total_holdings

        for _ in range(cfg["initial_stakers"]):
            agent = StakerAgent(agent_id=self._next_agent_id())
            self.stakers.append(agent)
            self.total_minted += agent.total_holdings

        for _ in range(cfg["initial_speculators"]):
            agent = SpeculatorAgent(agent_id=self._next_agent_id())
            self.speculators.append(agent)
            self.total_minted += agent.total_holdings

        for _ in range(cfg["initial_compute_providers"]):
            agent = ComputeProviderAgent(agent_id=self._next_agent_id())
            self.compute_providers.append(agent)
            self.total_minted += agent.total_holdings

        self._refresh_caches()

    # ------------------------------------------------------------------
    # Cache management
    # ------------------------------------------------------------------

    def _refresh_caches(self) -> None:
        """Recompute cached aggregates from agent state."""
        self._cached_total_staked = sum(
            a.staked for a in self.validators
        ) + sum(
            a.staked for a in self.model_creators
        ) + sum(
            a.staked for a in self.schools
        ) + sum(
            a.staked for a in self.stakers
        ) + sum(
            a.staked for a in self.speculators
        ) + sum(
            a.staked for a in self.compute_providers
        )

        self._cached_total_agent_holdings = sum(
            a.total_holdings for a in self.validators
        ) + sum(
            a.total_holdings for a in self.model_creators
        ) + sum(
            a.total_holdings for a in self.schools
        ) + sum(
            a.total_holdings for a in self.stakers
        ) + sum(
            a.total_holdings for a in self.speculators
        ) + sum(
            a.total_holdings for a in self.compute_providers
        )

        self._cached_total_capacity = sum(
            p.capacity for p in self.compute_providers if p.active
        )

        self._cached_school_demand = sum(
            s.calculate_epoch_demand() for s in self.schools if s.active
        )

        self._cached_active_counts = {
            "validator": sum(1 for v in self.validators if v.active),
            "school": sum(1 for s in self.schools if s.active),
            "model_creator": sum(1 for c in self.model_creators if c.active),
            "staker": sum(1 for s in self.stakers if s.active),
            "speculator": sum(1 for s in self.speculators if s.active),
            "compute_provider": sum(1 for p in self.compute_providers if p.active),
        }

        self._cached_total_models = sum(
            c.models_deployed for c in self.model_creators if c.active
        )

    # ------------------------------------------------------------------
    # Agent growth (new participants join)
    # ------------------------------------------------------------------

    def _grow_agents(self, epoch: int) -> None:
        """Add new agents at a rate consistent with the scenario."""
        cfg = self.config
        epochs_per_growth = max(1, P.EPOCHS_PER_YEAR // 12)  # monthly growth ticks

        if epoch % epochs_per_growth != 0:
            return

        monthly_factor = 1.0 / 12.0

        # Validators
        new_v = int(cfg["validator_growth_per_year"] * monthly_factor + 0.5)
        for _ in range(new_v):
            agent = ValidatorAgent(agent_id=self._next_agent_id())
            self.validators.append(agent)
            self.total_minted += agent.total_holdings

        # Schools (linear growth)
        new_s = int(cfg["school_growth_per_year"] * monthly_factor + 0.5)
        for _ in range(new_s):
            agent = SchoolAgent(agent_id=self._next_agent_id())
            self.schools.append(agent)
            self.total_minted += agent.total_holdings

        # Model creators
        new_mc = int(cfg["model_creator_growth_per_year"] * monthly_factor + 0.5)
        for _ in range(new_mc):
            agent = ModelCreatorAgent(agent_id=self._next_agent_id())
            self.model_creators.append(agent)
            self.total_minted += agent.total_holdings

        # Stakers
        new_st = int(cfg["staker_growth_per_year"] * monthly_factor + 0.5)
        for _ in range(new_st):
            agent = StakerAgent(agent_id=self._next_agent_id())
            self.stakers.append(agent)
            self.total_minted += agent.total_holdings

        # Speculators
        new_sp = int(cfg["speculator_growth_per_year"] * monthly_factor + 0.5)
        for _ in range(new_sp):
            agent = SpeculatorAgent(agent_id=self._next_agent_id())
            self.speculators.append(agent)
            self.total_minted += agent.total_holdings

        # Compute providers (demand-driven)
        utilization = self._compute_utilization()
        if utilization > 0.6:
            new_cp = int(cfg["compute_provider_growth_per_year"] * monthly_factor + 0.5)
            for _ in range(new_cp):
                agent = ComputeProviderAgent(agent_id=self._next_agent_id())
                self.compute_providers.append(agent)
                self.total_minted += agent.total_holdings

    # ------------------------------------------------------------------
    # Block reward calculation
    # ------------------------------------------------------------------

    def _calculate_block_reward(self, block_height: int) -> float:
        """
        10 SALT base, halving every 2.1M blocks, tail emission 0.1 SALT.

        After MAX_HALVINGS halvings, reward is fixed at TAIL_EMISSION.
        Mining pool has a hard cap of MINING_POOL_SUPPLY.
        """
        halvings = min(block_height // P.HALVING_INTERVAL, P.MAX_HALVINGS)

        if halvings >= P.MAX_HALVINGS:
            return P.TAIL_EMISSION

        reward = P.BASE_BLOCK_REWARD / (2 ** halvings)

        # Never go below tail emission
        if reward < P.TAIL_EMISSION:
            return P.TAIL_EMISSION

        # Check mining pool cap
        remaining_mining = P.MINING_POOL_SUPPLY - self.total_minted
        if remaining_mining <= 0:
            return P.TAIL_EMISSION

        return min(reward, remaining_mining)

    def _calculate_epoch_block_rewards(self) -> float:
        """
        Calculate total block rewards for one epoch (BLOCKS_PER_EPOCH blocks).

        Optimized: within a single epoch all blocks are in the same halving
        era (epoch spans 1000 blocks, halving every 2.1M), so we can
        compute the reward once and multiply.
        """
        start_height = self.block_height
        end_height = start_height + P.BLOCKS_PER_EPOCH

        # Check if a halving boundary falls within this epoch
        start_era = start_height // P.HALVING_INTERVAL
        end_era = (end_height - 1) // P.HALVING_INTERVAL

        if start_era == end_era:
            # All blocks in same era -- fast path
            reward_per_block = self._calculate_block_reward(start_height)
            total = reward_per_block * P.BLOCKS_PER_EPOCH
        else:
            # Halving boundary within epoch -- split calculation
            boundary = (start_era + 1) * P.HALVING_INTERVAL
            blocks_before = boundary - start_height
            blocks_after = end_height - boundary
            reward_before = self._calculate_block_reward(start_height)
            reward_after = self._calculate_block_reward(boundary)
            total = reward_before * blocks_before + reward_after * blocks_after

        self.block_height = end_height
        self.total_minted += total
        return total

    # ------------------------------------------------------------------
    # Compute demand & utilization
    # ------------------------------------------------------------------

    def _compute_utilization(self) -> float:
        """Current network compute utilization = demand / capacity."""
        cap = self._cached_total_capacity
        if cap == 0:
            return 1.0
        return min(1.0, self.compute_demand_per_epoch / cap)

    # ------------------------------------------------------------------
    # Fee calculation
    # ------------------------------------------------------------------

    def _calculate_epoch_fees(self) -> tuple[float, float, float]:
        """
        Calculate epoch fee revenue from three sources:
        1. Gas fees (standard transactions)
        2. AI inference fees (2x multiplier)
        3. Compute marketplace fees (BME + treasury cut)

        Returns: (gas_fees, ai_fees, compute_fees) in SALT
        """
        # Gas pricing with EIP-1559-style adjustment
        utilization = min(1.0, self.tx_per_epoch / (P.BLOCKS_PER_EPOCH * 150))
        gas_multiplier = 1.0
        if utilization > P.TARGET_UTILIZATION:
            excess = utilization - P.TARGET_UTILIZATION
            gas_multiplier = 1.0 + excess * 5.0
        elif utilization < P.TARGET_UTILIZATION * 0.5:
            gas_multiplier = 0.5

        avg_gas_per_tx = 21_000
        gas_price_salt = P.BASE_GAS_PRICE_GWEI * 1e-9 * gas_multiplier
        gas_fees = self.tx_per_epoch * avg_gas_per_tx * gas_price_salt

        avg_inference_cost_salt = 0.001 * P.AI_INFERENCE_MULTIPLIER
        ai_fees = self.compute_demand_per_epoch * avg_inference_cost_salt

        avg_job_value_salt = 0.005
        compute_fees = self.compute_demand_per_epoch * avg_job_value_salt * (
            P.BME_BURN_RATE + P.TREASURY_FEE_RATE
        )

        return gas_fees, ai_fees, compute_fees

    # ------------------------------------------------------------------
    # Revenue distribution
    # ------------------------------------------------------------------

    def _distribute_revenue(
        self,
        total_fee_revenue: float,
    ) -> dict[str, float]:
        """7-way revenue split per the canonical BPS ratios."""
        return {
            "validator": total_fee_revenue * P.VALIDATOR_SHARE_BPS / 10_000,
            "creator": total_fee_revenue * P.MODEL_CREATOR_SHARE_BPS / 10_000,
            "infra": total_fee_revenue * P.INFRA_SHARE_BPS / 10_000,
            "treasury": total_fee_revenue * P.TREASURY_SHARE_BPS / 10_000,
            "staker": total_fee_revenue * P.STAKER_SHARE_BPS / 10_000,
            "facilitator": total_fee_revenue * P.FACILITATOR_SHARE_BPS / 10_000,
        }

    def _accumulate_rewards(self, shares: dict[str, float], block_reward_total: float) -> None:
        """Accumulate rewards for later batch distribution to agents."""
        self._pending_validator_reward += block_reward_total + shares["validator"]
        self._pending_creator_reward += shares["creator"]
        self._pending_infra_reward += shares["infra"]
        self._pending_staker_reward += shares["staker"]

        # Institutional rewards (accounted as minted)
        epochs_per_month = P.EPOCHS_PER_YEAR / 12
        n_schools = self._cached_active_counts.get("school", 0)
        if n_schools > 0:
            # Use cached school counts for the aggregate
            base_inst = P.INSTITUTIONAL_BLOCK_REWARD / epochs_per_month * n_schools
            self.total_minted += base_inst
            self._pending_institutional_minted += base_inst

    def _flush_rewards_to_agents(self) -> None:
        """Distribute accumulated rewards to individual agents (batch)."""
        # Validators
        active_validators = [v for v in self.validators if v.active]
        n_val = len(active_validators)
        if n_val > 0 and self._pending_validator_reward > 0:
            per_val = self._pending_validator_reward / n_val
            for v in active_validators:
                v.receive_reward(per_val)
        self._pending_validator_reward = 0.0

        # Model creators: proportional to models deployed
        total_models = self._cached_total_models
        if total_models > 0 and self._pending_creator_reward > 0:
            per_model = self._pending_creator_reward / total_models
            for c in self.model_creators:
                if c.active and c.models_deployed > 0:
                    c.receive_reward(per_model * c.models_deployed)
        self._pending_creator_reward = 0.0

        # Compute providers: proportional to capacity
        total_capacity = self._cached_total_capacity
        if total_capacity > 0 and self._pending_infra_reward > 0:
            per_cap = self._pending_infra_reward / total_capacity
            for p in self.compute_providers:
                if p.active:
                    p.receive_reward(per_cap * p.capacity)
        self._pending_infra_reward = 0.0

        # Stakers: proportional to stake
        total_staker_stake = sum(s.staked for s in self.stakers if s.active)
        if total_staker_stake > 0 and self._pending_staker_reward > 0:
            per_staked = self._pending_staker_reward / total_staker_stake
            for s in self.stakers:
                if s.active and s.staked > 0:
                    s.receive_reward(per_staked * s.staked)
        self._pending_staker_reward = 0.0

        # Schools: institutional rewards (models + adapters)
        epochs_per_month = P.EPOCHS_PER_YEAR / 12
        for s in self.schools:
            if s.active:
                model_reward = s.models_hosted * P.INSTITUTIONAL_MODEL_HOSTING / epochs_per_month
                adapter_reward = s.adapters_created * P.INSTITUTIONAL_ADAPTER_REWARD / epochs_per_month
                inst = (model_reward + adapter_reward) * self.AGENT_UPDATE_INTERVAL
                # Base reward was already accumulated in _accumulate_rewards
                base_share = self._pending_institutional_minted / max(1, self._cached_active_counts.get("school", 1))
                s.receive_reward(base_share + inst)
                self.total_minted += inst
        self._pending_institutional_minted = 0.0

    # ------------------------------------------------------------------
    # Burn mechanics
    # ------------------------------------------------------------------

    def _apply_burns(self, gas_fees: float) -> tuple[float, float]:
        """
        Apply burn mechanics:
        1. BME burn: 2.5% of each compute job value
        2. Gas fee burn: 20% of transaction gas fees (EIP-1559 style)
        """
        avg_job_value_salt = 0.005
        bme_burned = self.compute_demand_per_epoch * avg_job_value_salt * P.BME_BURN_RATE
        gas_burned = gas_fees * P.GAS_FEE_BURN_RATE
        self.total_burned += bme_burned + gas_burned
        return bme_burned, gas_burned

    # ------------------------------------------------------------------
    # APY calculation
    # ------------------------------------------------------------------

    def _calculate_apy(self) -> float:
        """Staking APY = (annual_staking_rewards / total_staked) * 100."""
        total_staked = self._cached_total_staked
        if total_staked <= 0:
            return 0.0

        current_reward = self._calculate_block_reward(self.block_height)
        annual_block_rewards = current_reward * P.BLOCKS_PER_YEAR

        gas_fees, ai_fees, compute_fees = self._calculate_epoch_fees()
        annual_fee_revenue = (gas_fees + ai_fees + compute_fees) * P.EPOCHS_PER_YEAR

        staking_fee_share = annual_fee_revenue * (
            P.VALIDATOR_SHARE_BPS + P.STAKER_SHARE_BPS
        ) / 10_000

        apy = ((annual_block_rewards + staking_fee_share) / total_staked) * 100.0
        return min(apy, 500.0)

    # ------------------------------------------------------------------
    # Price model
    # ------------------------------------------------------------------

    def _update_price(self, epoch: int) -> None:
        """Price model driven by floor, supply/demand, adoption, burn rate."""
        floor = self._calculate_floor_price()

        staking_ratio = self._staking_ratio()
        supply_factor = 1.0 + staking_ratio * 0.5

        utilization = self._compute_utilization()
        demand_factor = 1.0 + utilization * 0.3

        total_active = (
            self._cached_active_counts.get("validator", 0)
            + self._cached_active_counts.get("school", 0)
            + self._cached_active_counts.get("compute_provider", 0)
            + self._cached_active_counts.get("model_creator", 0)
        )
        adoption_factor = 1.0 + math.log1p(total_active) * 0.02

        if self.total_minted > 0:
            burn_ratio = self.total_burned / max(1.0, self.total_minted)
            burn_factor = 1.0 + burn_ratio * 0.2
        else:
            burn_factor = 1.0

        fundamental_price = floor * supply_factor * demand_factor * adoption_factor * burn_factor

        noise = self.rng.gauss(0, 0.02)
        reversion_speed = 0.05
        self.salt_price_usd = (
            self.salt_price_usd * (1.0 - reversion_speed)
            + fundamental_price * reversion_speed
        ) * (1.0 + noise)

        self.salt_price_usd = max(self.salt_price_usd, 0.001)

    def _calculate_floor_price(self) -> float:
        """SALT floor price = compute_cost_usd / salt_per_pflop_hour."""
        years_elapsed = self.current_epoch / P.EPOCHS_PER_YEAR
        compute_cost_usd = 2.50 * (0.80 ** years_elapsed)

        base_salt_per_pfhr = 100.0
        active_providers = self._cached_active_counts.get("compute_provider", 1)
        efficiency_factor = 1.0 / (1.0 + math.log1p(active_providers) * 0.1)
        salt_per_pfhr = base_salt_per_pfhr * efficiency_factor

        if salt_per_pfhr <= 0:
            return 0.001
        return compute_cost_usd / salt_per_pfhr

    # ------------------------------------------------------------------
    # Demand growth
    # ------------------------------------------------------------------

    def _grow_demand(self) -> None:
        """Grow inference demand and transaction volume per epoch."""
        self.compute_demand_per_epoch = int(
            self.compute_demand_per_epoch * self._demand_growth_mult
        )
        self.tx_per_epoch = int(
            self.tx_per_epoch * self._tx_growth_mult
        )
        # Add school-driven demand (from cache)
        self.compute_demand_per_epoch += self._cached_school_demand

    # ------------------------------------------------------------------
    # Aggregate helpers
    # ------------------------------------------------------------------

    def _total_staked(self) -> float:
        return self._cached_total_staked

    def _circulating_supply(self) -> float:
        """circulating = total_minted - total_burned - total_staked"""
        return self.total_minted - self.total_burned - self._cached_total_staked

    def _staking_ratio(self) -> float:
        """Fraction of total agent holdings that is staked."""
        holdings = self._cached_total_agent_holdings
        if holdings <= 0:
            return 0.0
        return min(1.0, self._cached_total_staked / holdings)

    # ------------------------------------------------------------------
    # Agent strategy updates (expensive -- run periodically)
    # ------------------------------------------------------------------

    def _update_all_agent_strategies(self, epoch: int) -> None:
        """Run strategy updates on all agents and refresh caches."""
        apy = self._calculate_apy()
        utilization = self._compute_utilization()
        price = self.salt_price_usd
        demand = self.compute_demand_per_epoch

        for v in self.validators:
            v.update_strategy(epoch, apy, price, demand, utilization)
        for c in self.model_creators:
            c.update_strategy(epoch, apy, price, demand, utilization)
        for s in self.schools:
            s.update_strategy(epoch, apy, price, demand, utilization)
        for s in self.stakers:
            s.update_strategy(epoch, apy, price, demand, utilization)
        for s in self.speculators:
            s.update_strategy(epoch, apy, price, demand, utilization)
        for p in self.compute_providers:
            p.update_strategy(epoch, apy, price, demand, utilization)

        self._refresh_caches()

    # ------------------------------------------------------------------
    # Epoch processing
    # ------------------------------------------------------------------

    def _process_epoch(self, epoch: int) -> EpochSnapshot:
        """
        Per-epoch processing pipeline:
        1. Calculate block rewards (with halving) -- vectorized
        2. Process compute demand growth
        3. Collect fees (gas + AI + compute marketplace)
        4. Distribute revenue (7-way split)
        5. Apply BME burn (2.5%) and gas fee burn (20%)
        6. Update price model
        7. Grow agent populations (monthly)
        8. Update agent strategies (every AGENT_UPDATE_INTERVAL epochs)
        """
        self.current_epoch = epoch

        # 1. Block rewards (vectorized per epoch)
        epoch_block_reward_total = self._calculate_epoch_block_rewards()

        # 2. Grow demand
        self._grow_demand()

        # 3. Calculate fees
        gas_fees, ai_fees, compute_fees = self._calculate_epoch_fees()
        total_fee_revenue = gas_fees + ai_fees + compute_fees

        # 4. Distribute revenue (accumulate, don't iterate agents)
        shares = self._distribute_revenue(total_fee_revenue)
        self._accumulate_rewards(shares, epoch_block_reward_total)
        self.total_minted += total_fee_revenue

        # 5. Burns
        bme_burned, gas_burned = self._apply_burns(gas_fees)

        # 6. Update price
        self._update_price(epoch)

        # 7. Grow agents (monthly cadence)
        self._grow_agents(epoch)

        # 8. Flush accumulated rewards to agents + strategy updates (periodic)
        if epoch % self.AGENT_UPDATE_INTERVAL == 0:
            self._flush_rewards_to_agents()
            self._update_all_agent_strategies(epoch)

        apy = self._calculate_apy()
        utilization = self._compute_utilization()

        # Institutional summary
        inst_rewards = 0.0
        total_adapters = 0
        total_models_hosted = 0
        for s in self.schools:
            if s.active:
                total_adapters += s.adapters_created
                total_models_hosted += s.models_hosted
                inst_rewards += s.cumulative_rewards

        return EpochSnapshot(
            epoch=epoch,
            block_height=self.block_height,
            circulating_supply=self._circulating_supply(),
            total_minted=self.total_minted,
            total_burned=self.total_burned,
            total_staked=self._cached_total_staked,
            staking_ratio=self._staking_ratio(),
            apy=apy,
            fee_revenue=total_fee_revenue,
            compute_demand=self.compute_demand_per_epoch,
            salt_price_usd=self.salt_price_usd,
            floor_price_usd=self._calculate_floor_price(),
            validator_count=self._cached_active_counts.get("validator", 0),
            school_count=self._cached_active_counts.get("school", 0),
            model_creator_count=self._cached_active_counts.get("model_creator", 0),
            staker_count=self._cached_active_counts.get("staker", 0),
            speculator_count=self._cached_active_counts.get("speculator", 0),
            compute_provider_count=self._cached_active_counts.get("compute_provider", 0),
            total_compute_capacity=self._cached_total_capacity,
            compute_utilization=utilization,
            validator_revenue=shares["validator"],
            creator_revenue=shares["creator"],
            infra_revenue=shares["infra"],
            treasury_revenue=shares["treasury"],
            staker_revenue=shares["staker"],
            facilitator_revenue=shares["facilitator"],
            bme_burned=bme_burned,
            gas_burned=gas_burned,
            institutional_rewards=inst_rewards,
            total_adapters=total_adapters,
            total_models_hosted=total_models_hosted,
        )

    # ------------------------------------------------------------------
    # Main entry point
    # ------------------------------------------------------------------

    def run(self, years: int = 10, snapshot_interval: int = 100) -> SimulationResult:
        """
        Run the full economic simulation.

        Args:
            years: Number of years to simulate (default 10).
            snapshot_interval: Record a snapshot every N epochs (default 100).
                Lower values give more resolution but use more memory.

        Returns:
            SimulationResult with per-epoch snapshots.
        """
        total_epochs = years * P.EPOCHS_PER_YEAR
        self._initialize_agents()

        # Pre-compute growth multipliers
        cfg = self.config
        self._demand_growth_mult = (
            1.0 + cfg["demand_growth_annual_pct"] / 100.0
        ) ** (1.0 / P.EPOCHS_PER_YEAR)
        self._tx_growth_mult = (
            1.0 + cfg["tx_growth_annual_pct"] / 100.0
        ) ** (1.0 / P.EPOCHS_PER_YEAR)

        result = SimulationResult(
            scenario=self.scenario,
            total_years=years,
            total_epochs_run=total_epochs,
        )

        for epoch in range(total_epochs):
            snapshot = self._process_epoch(epoch)

            if epoch % snapshot_interval == 0 or epoch == total_epochs - 1:
                result.epochs.append(snapshot)

        return result

    # ------------------------------------------------------------------
    # Sensitivity analysis
    # ------------------------------------------------------------------

    @staticmethod
    def run_sensitivity(
        dimension: str,
        values: list[float],
        base_scenario: str = "medium",
        years: int = 10,
        seed: int = 42,
    ) -> dict[float, SimulationResult]:
        """
        Run the simulation across a range of values for one parameter.

        Supported dimensions:
            - 'adoption_rate': scale all growth rates
            - 'staking_ratio': initial staker count multiplier
            - 'burn_rate': BME burn rate override
            - 'block_reward': base block reward override

        Returns dict mapping parameter value -> SimulationResult.
        """
        results: dict[float, SimulationResult] = {}

        for val in values:
            sim = EconomicSimulation(scenario=base_scenario, seed=seed)

            if dimension == "adoption_rate":
                for key in list(sim.config.keys()):
                    if "growth" in key:
                        sim.config[key] = int(sim.config[key] * val)
                    if "demand_growth" in key:
                        sim.config[key] = sim.config[key] * val
            elif dimension == "staking_ratio":
                sim.config["initial_stakers"] = int(
                    sim.config["initial_stakers"] * val
                )
            elif dimension == "burn_rate":
                sim._override_bme_burn_rate = val
            elif dimension == "block_reward":
                sim._override_base_block_reward = val
            else:
                raise ValueError(
                    f"Unknown sensitivity dimension: {dimension}. "
                    f"Use: adoption_rate, staking_ratio, burn_rate, block_reward"
                )

            result = sim.run(years=years, snapshot_interval=500)
            results[val] = result

        return results
