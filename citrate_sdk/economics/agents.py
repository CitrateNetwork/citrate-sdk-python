"""
Agent definitions for the Citrate economic simulation.

Each agent type models a distinct participant in the SALT economy.
Agents hold balances, make staking decisions, and respond to market
conditions (APY, price momentum, compute demand) on a per-epoch basis.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from . import parameters as P

# ---------------------------------------------------------------------------
# Base agent
# ---------------------------------------------------------------------------

@dataclass
class Agent:
    """Base agent with SALT balance, staked amount, and strategy state."""

    agent_id: int
    agent_type: str
    balance: float = 0.0
    staked: float = 0.0
    cumulative_rewards: float = 0.0
    active: bool = True
    # Strategy parameters (randomized slightly per instance)
    opportunity_cost_apy: float = 8.0  # baseline expected return elsewhere
    risk_tolerance: float = 0.5  # 0=conservative, 1=aggressive

    def __post_init__(self) -> None:
        # Jitter strategy params so agents are not identical
        rng = random.Random(self.agent_id)
        self.opportunity_cost_apy *= rng.uniform(0.7, 1.3)
        self.risk_tolerance = max(0.0, min(1.0, self.risk_tolerance + rng.gauss(0, 0.15)))

    @property
    def total_holdings(self) -> float:
        return self.balance + self.staked

    def receive_reward(self, amount: float) -> None:
        """Credit reward tokens to liquid balance."""
        self.balance += amount
        self.cumulative_rewards += amount

    def stake_tokens(self, amount: float) -> float:
        """Move tokens from balance to staked. Returns actual amount staked."""
        actual = min(amount, self.balance)
        if actual <= 0:
            return 0.0
        self.balance -= actual
        self.staked += actual
        return actual

    def unstake_tokens(self, amount: float) -> float:
        """Move tokens from staked to balance. Returns actual amount unstaked."""
        actual = min(amount, self.staked)
        if actual <= 0:
            return 0.0
        self.staked -= actual
        self.balance += actual
        return actual

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        """Override in subclasses for per-epoch decision-making."""
        pass


# ---------------------------------------------------------------------------
# Validator
# ---------------------------------------------------------------------------

@dataclass
class ValidatorAgent(Agent):
    """
    Stakes 32K+ SALT, proposes blocks, earns 23% of fees + block rewards.

    Strategy: stake more when APY exceeds opportunity cost, unstake when
    APY drops below the floor threshold. Target stake is adaptive.
    """

    agent_type: str = "validator"
    min_stake: float = float(P.MIN_VALIDATOR_STAKE)
    target_stake: float = float(P.MIN_VALIDATOR_STAKE)
    blocks_proposed: int = 0

    def __post_init__(self) -> None:
        super().__post_init__()
        # Validators start with enough to stake
        if self.balance < self.min_stake and self.staked < self.min_stake:
            self.balance = self.min_stake * 1.2
        if self.staked < self.min_stake and self.balance >= self.min_stake:
            self.stake_tokens(self.min_stake)

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        if not self.active:
            return

        # If APY is attractive relative to opportunity cost, add stake
        if apy > self.opportunity_cost_apy * 1.2:
            additional = self.balance * 0.3 * self.risk_tolerance
            if additional > 100:
                self.stake_tokens(additional)
                self.target_stake = self.staked

        # If APY drops below floor, partially unstake
        elif apy < self.opportunity_cost_apy * 0.5:
            to_remove = (self.staked - self.min_stake) * 0.1
            if to_remove > 0:
                self.unstake_tokens(to_remove)
                self.target_stake = max(self.min_stake, self.staked)

    def apply_slash(self, slash_bps: int) -> float:
        """Apply slashing penalty. Returns amount slashed."""
        amount = self.staked * slash_bps / 10_000
        self.staked -= amount
        if self.staked < self.min_stake:
            self.active = False
        return amount


# ---------------------------------------------------------------------------
# Model Creator
# ---------------------------------------------------------------------------

@dataclass
class ModelCreatorAgent(Agent):
    """
    Deploys AI models on-chain, earns 30% of inference fees.

    Model deployment follows logarithmic growth: fast early adoption,
    slower as the catalog matures. Revenue scales with inference volume.
    """

    agent_type: str = "model_creator"
    models_deployed: int = 0
    max_models: int = 50
    hosting_cost_per_model: float = 5.0  # SALT per epoch

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.balance == 0:
            self.balance = 5_000.0
        # Deploy initial models
        initial = random.Random(self.agent_id).randint(1, 3)
        self.models_deployed = initial

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        if not self.active:
            return

        # Logarithmic model deployment: deploy when revenue justifies cost
        fee_per_model = (compute_demand / max(1, self.models_deployed)) * 0.001
        if fee_per_model > self.hosting_cost_per_model and self.models_deployed < self.max_models:
            # Deploy another model (logarithmic slowdown)
            deploy_prob = 1.0 / (1.0 + math.log1p(self.models_deployed))
            if random.Random(self.agent_id + epoch).random() < deploy_prob:
                self.models_deployed += 1

        # Stake surplus balance for passive income
        if apy > 5.0 and self.balance > 1_000:
            self.stake_tokens(self.balance * 0.2)


# ---------------------------------------------------------------------------
# School / Institutional
# ---------------------------------------------------------------------------

@dataclass
class SchoolAgent(Agent):
    """
    Institutional purchaser of bulk compute with stablecoins.
    Contributes data and fine-tuned adapters to the ecosystem.

    Growth: linear (10 initial institutions, +5 per year).
    Earns: 150 SALT/month base + model hosting + adapter creation rewards.
    """

    agent_type: str = "school"
    students: int = 500
    adapters_created: int = 0
    models_hosted: int = 0
    monthly_compute_budget_usd: float = 2_000.0  # USD

    def __post_init__(self) -> None:
        super().__post_init__()
        rng = random.Random(self.agent_id)
        self.students = rng.randint(200, 2000)
        self.monthly_compute_budget_usd = rng.uniform(500, 5000)
        if self.balance == 0:
            self.balance = 1_000.0

    def calculate_epoch_demand(self) -> int:
        """Inference requests per epoch from this institution."""
        # ~10 inferences per student per school day, scaled to epoch length
        daily_inferences = self.students * 10
        # 1 epoch = ~33 min, ~44 epochs per day
        return int(daily_inferences / 44)

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        if not self.active:
            return

        # Schools create adapters over time
        adapter_prob = 0.02  # ~1 adapter per 50 epochs
        if random.Random(self.agent_id + epoch).random() < adapter_prob:
            self.adapters_created += 1

        # Host models when they have enough capital
        if self.balance > 500 and self.models_hosted < 5:
            host_prob = 0.01
            if random.Random(self.agent_id + epoch + 1).random() < host_prob:
                self.models_hosted += 1


# ---------------------------------------------------------------------------
# Passive staker
# ---------------------------------------------------------------------------

@dataclass
class StakerAgent(Agent):
    """
    Delegates to the stSALT liquid staking pool, earns 15% of protocol fees.

    Strategy: stake when APY > 10%, unstake when APY < 5%.
    Behavior is price-driven -- more staking when price is rising.
    """

    agent_type: str = "staker"
    staking_threshold_high: float = 10.0  # APY % above which we stake
    staking_threshold_low: float = 5.0  # APY % below which we unstake
    _prev_price: float = 0.0

    def __post_init__(self) -> None:
        super().__post_init__()
        rng = random.Random(self.agent_id)
        self.staking_threshold_high = rng.uniform(7.0, 15.0)
        self.staking_threshold_low = rng.uniform(3.0, 7.0)
        if self.balance == 0:
            self.balance = rng.uniform(5_000, 100_000)

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        if not self.active:
            return

        price_trend = 1.0
        if self._prev_price > 0:
            price_trend = salt_price / self._prev_price
        self._prev_price = salt_price

        # Stake aggressively when APY is high and price is rising
        if apy > self.staking_threshold_high and price_trend >= 0.98:
            to_stake = self.balance * 0.5 * self.risk_tolerance
            if to_stake > 10:
                self.stake_tokens(to_stake)

        # Unstake when APY is low or price is crashing
        elif apy < self.staking_threshold_low or price_trend < 0.90:
            to_unstake = self.staked * 0.2
            if to_unstake > 10:
                self.unstake_tokens(to_unstake)

        # Moderate behavior: stake slowly when APY is moderate
        elif apy > (self.staking_threshold_high + self.staking_threshold_low) / 2:
            to_stake = self.balance * 0.05
            if to_stake > 10:
                self.stake_tokens(to_stake)


# ---------------------------------------------------------------------------
# Speculator
# ---------------------------------------------------------------------------

@dataclass
class SpeculatorAgent(Agent):
    """
    Buys and sells SALT based on price momentum.
    Creates trading volume but does not stake.
    """

    agent_type: str = "speculator"
    position_usd: float = 0.0  # fiat position for buying SALT
    _prev_price: float = 0.0
    _momentum: float = 0.0  # exponential moving average of returns

    def __post_init__(self) -> None:
        super().__post_init__()
        rng = random.Random(self.agent_id)
        self.position_usd = rng.uniform(1_000, 50_000)
        if self.balance == 0:
            self.balance = rng.uniform(1_000, 20_000)

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        if not self.active:
            return

        if salt_price <= 0:
            return

        # Calculate momentum (EMA of epoch returns)
        if self._prev_price > 0:
            ret = (salt_price - self._prev_price) / self._prev_price
            self._momentum = 0.8 * self._momentum + 0.2 * ret
        self._prev_price = salt_price

        rng = random.Random(self.agent_id + epoch)

        # Buy on positive momentum
        if self._momentum > 0.01 and self.position_usd > 0:
            buy_frac = min(0.3, self._momentum * 5) * self.risk_tolerance
            buy_usd = self.position_usd * buy_frac
            tokens_bought = buy_usd / salt_price
            self.position_usd -= buy_usd
            self.balance += tokens_bought

        # Sell on negative momentum
        elif self._momentum < -0.01 and self.balance > 0:
            sell_frac = min(0.3, abs(self._momentum) * 5) * self.risk_tolerance
            tokens_sold = self.balance * sell_frac
            self.balance -= tokens_sold
            self.position_usd += tokens_sold * salt_price

        # Random noise trades for volume
        if rng.random() < 0.1:
            noise_amt = self.balance * rng.uniform(0.01, 0.05)
            if rng.random() < 0.5:
                self.balance -= noise_amt
                self.position_usd += noise_amt * salt_price
            else:
                cost_usd = noise_amt * salt_price
                if cost_usd <= self.position_usd:
                    self.position_usd -= cost_usd
                    self.balance += noise_amt


# ---------------------------------------------------------------------------
# Compute provider
# ---------------------------------------------------------------------------

@dataclass
class ComputeProviderAgent(Agent):
    """
    Registers GPUs, serves inference jobs, earns infrastructure revenue.

    Strategy: join when compute demand > capacity * 0.7 (high utilization).
    Growth is demand-driven -- more providers come online as demand grows.
    """

    agent_type: str = "compute_provider"
    gpus: int = 1
    max_gpus: int = 8
    inferences_per_gpu_per_epoch: int = 500  # capacity per GPU per epoch
    operational_cost_per_gpu: float = 2.0  # SALT per epoch
    provider_stake: float = float(P.MIN_PROVIDER_STAKE)

    def __post_init__(self) -> None:
        super().__post_init__()
        rng = random.Random(self.agent_id)
        self.gpus = rng.randint(1, 4)
        self.max_gpus = rng.randint(4, 16)
        self.inferences_per_gpu_per_epoch = rng.randint(300, 800)
        if self.balance == 0:
            self.balance = P.MIN_PROVIDER_STAKE * 1.5
        # Stake the minimum
        if self.staked < P.MIN_PROVIDER_STAKE and self.balance >= P.MIN_PROVIDER_STAKE:
            self.stake_tokens(float(P.MIN_PROVIDER_STAKE))

    @property
    def capacity(self) -> int:
        """Total inferences this provider can serve per epoch."""
        return self.gpus * self.inferences_per_gpu_per_epoch

    def update_strategy(
        self,
        epoch: int,
        apy: float,
        salt_price: float,
        compute_demand: int,
        utilization: float,
    ) -> None:
        if not self.active:
            return

        # Scale up when demand is high
        if utilization > 0.7 and self.gpus < self.max_gpus:
            scale_prob = (utilization - 0.7) * 3.0 * self.risk_tolerance
            if random.Random(self.agent_id + epoch).random() < scale_prob:
                self.gpus += 1

        # Scale down when demand is very low (save operational costs)
        elif utilization < 0.3 and self.gpus > 1:
            scale_prob = (0.3 - utilization) * 2.0
            if random.Random(self.agent_id + epoch + 1).random() < scale_prob:
                self.gpus -= 1

        # Exit if consistently unprofitable
        op_cost = self.gpus * self.operational_cost_per_gpu
        if self.balance < op_cost * 10 and utilization < 0.2:
            self.active = False
