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

from .parameters import (
    TOTAL_SUPPLY,
    DECIMALS,
    BLOCK_TIME_SECONDS,
    MINING_POOL_PCT,
    ECOSYSTEM_FUND_PCT,
    TREASURY_PCT,
    TEAM_PCT,
    BASE_BLOCK_REWARD,
    HALVING_INTERVAL,
    MAX_HALVINGS,
    TAIL_EMISSION,
    VALIDATOR_SHARE_BPS,
    MODEL_CREATOR_SHARE_BPS,
    INFRA_SHARE_BPS,
    TREASURY_SHARE_BPS,
    STAKER_SHARE_BPS,
    FACILITATOR_SHARE_BPS,
    BME_BURN_RATE,
    TREASURY_FEE_RATE,
    MIN_PROVIDER_STAKE,
    MIN_VALIDATOR_STAKE,
    WITHDRAWAL_DELAY_BLOCKS,
    LATENCY_SLASH_BPS,
    INCONSISTENCY_SLASH_BPS,
    BYZANTINE_SLASH_BPS,
    BASE_GAS_PRICE_GWEI,
    TARGET_UTILIZATION,
    AI_INFERENCE_MULTIPLIER,
    CONTRIBUTION_WEIGHTS,
    INSTITUTIONAL_BLOCK_REWARD,
    INSTITUTIONAL_MODEL_HOSTING,
    INSTITUTIONAL_ADAPTER_REWARD,
    PROPOSAL_THRESHOLD,
    QUORUM_BPS,
    APPROVAL_BPS,
    BLOCKS_PER_EPOCH,
    EPOCHS_PER_YEAR,
    SIMULATION_YEARS,
)

from .agents import (
    Agent,
    ValidatorAgent,
    ModelCreatorAgent,
    SchoolAgent,
    StakerAgent,
    SpeculatorAgent,
    ComputeProviderAgent,
)

from .simulation import (
    EconomicSimulation,
    SimulationResult,
    EpochSnapshot,
)

from .charts import (
    plot_supply_curve,
    plot_staking_apy,
    plot_fee_revenue,
    plot_burn_analysis,
    plot_floor_price,
    plot_death_spiral,
    plot_sensitivity_heatmap,
    plot_revenue_breakdown,
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
