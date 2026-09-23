"""
Citrate Economic Simulation Module

Agent-based economic simulation for Citrate's SALT tokenomics.
Models supply dynamics, staking behavior, fee revenue, burn mechanics,
and adoption scenarios over multi-year horizons.

Usage:
    from citrate_sdk.economics import EconomicSimulation

    sim = EconomicSimulation(scenario='medium')
    result = sim.run(years=10)

    from citrate_sdk.economics.charts import plot_supply_curve
    plot_supply_curve(result, 'supply.png')
"""

from .agents import (
    Agent,
    ComputeProviderAgent,
    ModelCreatorAgent,
    SchoolAgent,
    SpeculatorAgent,
    StakerAgent,
    ValidatorAgent,
)
from .charts import (
    plot_burn_analysis,
    plot_death_spiral,
    plot_fee_revenue,
    plot_floor_price,
    plot_revenue_breakdown,
    plot_sensitivity_heatmap,
    plot_staking_apy,
    plot_supply_curve,
)
from .parameters import (
    AI_INFERENCE_MULTIPLIER,
    APPROVAL_BPS,
    BASE_BLOCK_REWARD,
    BASE_GAS_PRICE_GWEI,
    BLOCK_TIME_SECONDS,
    BLOCKS_PER_EPOCH,
    BME_BURN_RATE,
    BYZANTINE_SLASH_BPS,
    CONTRIBUTION_WEIGHTS,
    DECIMALS,
    ECOSYSTEM_FUND_PCT,
    EPOCHS_PER_YEAR,
    FACILITATOR_SHARE_BPS,
    HALVING_INTERVAL,
    INCONSISTENCY_SLASH_BPS,
    INFRA_SHARE_BPS,
    INSTITUTIONAL_ADAPTER_REWARD,
    INSTITUTIONAL_BLOCK_REWARD,
    INSTITUTIONAL_MODEL_HOSTING,
    LATENCY_SLASH_BPS,
    MAX_HALVINGS,
    MIN_PROVIDER_STAKE,
    MIN_VALIDATOR_STAKE,
    MINING_POOL_PCT,
    MODEL_CREATOR_SHARE_BPS,
    PROPOSAL_THRESHOLD,
    QUORUM_BPS,
    SIMULATION_YEARS,
    STAKER_SHARE_BPS,
    TAIL_EMISSION,
    TARGET_UTILIZATION,
    TEAM_PCT,
    TOTAL_SUPPLY,
    TREASURY_FEE_RATE,
    TREASURY_PCT,
    TREASURY_SHARE_BPS,
    VALIDATOR_SHARE_BPS,
    WITHDRAWAL_DELAY_BLOCKS,
)
from .simulation import (
    EconomicSimulation,
    EpochSnapshot,
    SimulationResult,
)

__all__ = [
    # Parameters
    "TOTAL_SUPPLY",
    "DECIMALS",
    "BLOCK_TIME_SECONDS",
    "MINING_POOL_PCT",
    "ECOSYSTEM_FUND_PCT",
    "TREASURY_PCT",
    "TEAM_PCT",
    "BASE_BLOCK_REWARD",
    "HALVING_INTERVAL",
    "MAX_HALVINGS",
    "TAIL_EMISSION",
    "VALIDATOR_SHARE_BPS",
    "MODEL_CREATOR_SHARE_BPS",
    "INFRA_SHARE_BPS",
    "TREASURY_SHARE_BPS",
    "STAKER_SHARE_BPS",
    "FACILITATOR_SHARE_BPS",
    "BME_BURN_RATE",
    "TREASURY_FEE_RATE",
    "MIN_PROVIDER_STAKE",
    "MIN_VALIDATOR_STAKE",
    "WITHDRAWAL_DELAY_BLOCKS",
    "LATENCY_SLASH_BPS",
    "INCONSISTENCY_SLASH_BPS",
    "BYZANTINE_SLASH_BPS",
    "BASE_GAS_PRICE_GWEI",
    "TARGET_UTILIZATION",
    "AI_INFERENCE_MULTIPLIER",
    "CONTRIBUTION_WEIGHTS",
    "INSTITUTIONAL_BLOCK_REWARD",
    "INSTITUTIONAL_MODEL_HOSTING",
    "INSTITUTIONAL_ADAPTER_REWARD",
    "PROPOSAL_THRESHOLD",
    "QUORUM_BPS",
    "APPROVAL_BPS",
    "BLOCKS_PER_EPOCH",
    "EPOCHS_PER_YEAR",
    "SIMULATION_YEARS",
    # Agents
    "Agent",
    "ValidatorAgent",
    "ModelCreatorAgent",
    "SchoolAgent",
    "StakerAgent",
    "SpeculatorAgent",
    "ComputeProviderAgent",
    # Simulation
    "EconomicSimulation",
    "SimulationResult",
    "EpochSnapshot",
    # Charts
    "plot_supply_curve",
    "plot_staking_apy",
    "plot_fee_revenue",
    "plot_burn_analysis",
    "plot_floor_price",
    "plot_death_spiral",
    "plot_sensitivity_heatmap",
    "plot_revenue_breakdown",
]
