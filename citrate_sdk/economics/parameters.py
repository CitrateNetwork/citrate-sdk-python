"""
Canonical economic parameters for the Citrate (SALT) tokenomics model.

All values are sourced from the Rust implementation in
citrate_v0.01.1/core/economics/ and the on-chain contracts.
Basis-point values use the convention: 10000 BPS = 100%.
"""

# ---------------------------------------------------------------------------
# Token fundamentals
# ---------------------------------------------------------------------------

TOTAL_SUPPLY: int = 1_000_000_000  # 1 billion SALT
DECIMALS: int = 18
BLOCK_TIME_SECONDS: int = 2  # testnet target

# ---------------------------------------------------------------------------
# Distribution buckets (percentages of total supply)
# ---------------------------------------------------------------------------

MINING_POOL_PCT: int = 50
ECOSYSTEM_FUND_PCT: int = 25
TREASURY_PCT: int = 10
TEAM_PCT: int = 15

# ---------------------------------------------------------------------------
# Block rewards
# ---------------------------------------------------------------------------

BASE_BLOCK_REWARD: float = 10.0  # SALT per block
HALVING_INTERVAL: int = 2_100_000  # blocks (~4 years at 2 s block time)
MAX_HALVINGS: int = 64
TAIL_EMISSION: float = 0.1  # SALT per block perpetual after all halvings

# ---------------------------------------------------------------------------
# Revenue-sharing splits (basis points, must sum to 10000)
# ---------------------------------------------------------------------------

VALIDATOR_SHARE_BPS: int = 2300  # 23 %
MODEL_CREATOR_SHARE_BPS: int = 3000  # 30 %
INFRA_SHARE_BPS: int = 1500  # 15 %
TREASURY_SHARE_BPS: int = 1200  # 12 %
STAKER_SHARE_BPS: int = 1500  # 15 %
FACILITATOR_SHARE_BPS: int = 500  #  5 %

_TOTAL_SHARE_BPS = (
    VALIDATOR_SHARE_BPS
    + MODEL_CREATOR_SHARE_BPS
    + INFRA_SHARE_BPS
    + TREASURY_SHARE_BPS
    + STAKER_SHARE_BPS
    + FACILITATOR_SHARE_BPS
)
assert _TOTAL_SHARE_BPS == 10000, (
    f"Revenue shares must sum to 10000 BPS, got {_TOTAL_SHARE_BPS}"
)

# ---------------------------------------------------------------------------
# Compute marketplace
# ---------------------------------------------------------------------------

BME_BURN_RATE: float = 0.025  # 2.5 % of compute job value burned
TREASURY_FEE_RATE: float = 0.025  # 2.5 % of compute job value -> treasury
MIN_PROVIDER_STAKE: int = 1_000  # SALT
MARKET_MAKER_GAS_BPS: int = 1_000  # 10 % of gas fees → market maker (DLP)

# ---------------------------------------------------------------------------
# Staking
# ---------------------------------------------------------------------------

MIN_VALIDATOR_STAKE: int = 32_000  # SALT
WITHDRAWAL_DELAY_BLOCKS: int = 50_400  # ~7 days at 2 s blocks

# ---------------------------------------------------------------------------
# Slashing (basis points of staked amount)
# ---------------------------------------------------------------------------

LATENCY_SLASH_BPS: int = 500  #   5 %
INCONSISTENCY_SLASH_BPS: int = 2000  #  20 %
BYZANTINE_SLASH_BPS: int = 10000  # 100 %

# ---------------------------------------------------------------------------
# Dynamic gas pricing
# ---------------------------------------------------------------------------

BASE_GAS_PRICE_GWEI: int = 1
TARGET_UTILIZATION: float = 0.70  # 70 % block fullness target
AI_INFERENCE_MULTIPLIER: float = 2.0  # AI ops cost 2x base gas

# ---------------------------------------------------------------------------
# Contribution weights (basis points, 10000 = 1.0x multiplier)
# ---------------------------------------------------------------------------

CONTRIBUTION_WEIGHTS: dict[str, int] = {
    "Validation": 10000,  # 1.0x
    "ModelHosting": 15000,  # 1.5x
    "AdapterCreation": 20000,  # 2.0x
    "DataProvision": 15000,  # 1.5x
    "AppDevelopment": 10000,  # 1.0x
    "BridgeInfra": 10000,  # 1.0x
    "Governance": 5000,  # 0.5x
}

# ---------------------------------------------------------------------------
# Institutional incentives
# ---------------------------------------------------------------------------

INSTITUTIONAL_BLOCK_REWARD: int = 150  # SALT per month
INSTITUTIONAL_MODEL_HOSTING: int = 25  # SALT per model per epoch
INSTITUTIONAL_ADAPTER_REWARD: int = 10  # SALT per adapter created

# ---------------------------------------------------------------------------
# Governance thresholds
# ---------------------------------------------------------------------------

PROPOSAL_THRESHOLD: int = 10_000  # SALT required to submit a proposal
QUORUM_BPS: int = 1000  # 10 % of circulating supply
APPROVAL_BPS: int = 6000  # 60 % yes votes to pass

# ---------------------------------------------------------------------------
# Simulation timing
# ---------------------------------------------------------------------------

BLOCKS_PER_EPOCH: int = 1_000  # ~33 min at 2 s block time
EPOCHS_PER_YEAR: int = 15_768  # floor(365.25 * 86400 / (1000 * 2))
SIMULATION_YEARS: int = 10

# ---------------------------------------------------------------------------
# Gas-fee burn
# ---------------------------------------------------------------------------

GAS_FEE_BURN_RATE: float = 0.20  # 20 % of transaction gas fees burned

# ---------------------------------------------------------------------------
# Derived constants (convenience)
# ---------------------------------------------------------------------------

BLOCKS_PER_YEAR: int = BLOCKS_PER_EPOCH * EPOCHS_PER_YEAR  # 15,768,000
TOTAL_SIMULATION_EPOCHS: int = EPOCHS_PER_YEAR * SIMULATION_YEARS

# Mining pool allocation (tokens available for block rewards)
MINING_POOL_SUPPLY: float = TOTAL_SUPPLY * MINING_POOL_PCT / 100  # 500M SALT
