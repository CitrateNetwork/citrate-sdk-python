# Citrate Python SDK

The official Python SDK for the Citrate distributed AI network. Deploy AI models, manage learning pools, stake SALT, create classrooms, post compute jobs, and interact with the verified compute marketplace.

**Version**: 0.5.0 | **Chain ID**: 40204 (0x9d0c) | **Token**: SALT

## Installation

```bash
pip install citrate-sdk
```

## Quick Start

```python
from citrate_sdk import CitrateClient

# Connect to Citrate testnet
client = CitrateClient(
    rpc_url="https://rpc.citrate.ai",
    private_key="0x..."  # Optional: for signing transactions
)

# Check balance
balance = client.get_balance("0xYOUR_ADDRESS")
print(f"Balance: {balance} SALT")

# List learning pools
pools = client.learning.list_pools()
for pool in pools:
    print(f"{pool.name}: {pool.member_count} members")
```

## Features

- **AI Models** — Deploy, query, and run inference on on-chain AI models
- **Learning Pools** — Join federated learning pools, track OODA cycles, earn from contributions
- **Staking** — Deposit SALT → stSALT, withdraw, track share price and APY
- **Classrooms** — Create teacher classrooms, enroll students, manage model whitelists
- **Compute Marketplace** — Post jobs, bid, register as provider, create GPU pools
- **Encryption** — End-to-end encryption for model weights and inference data
- **IPFS** — Pin and manage model artifacts

## Managers

The SDK exposes managers for each domain:

| Manager | Access | Purpose |
|---------|--------|---------|
| `client.learning` | `LearningManager` | Learning pools, cycles, contributions |
| `client.staking` | `StakingManager` | stSALT deposit, withdraw, share price |
| `client.classroom` | `ClassroomManager` | Teacher classrooms, student enrollment |
| `client.compute` | `ComputeManager` | Compute marketplace, jobs, providers, pools |

### Learning Pools

```python
# List available pools
pools = client.learning.list_pools()

# Join a pool (stake SALT)
tx = client.learning.join_pool(pool_id=0, stake_amount="1000000000000000000")

# Get cycle status
cycle = client.learning.get_cycle_status()
print(f"Cycle {cycle.cycle_id}: {cycle.state}")

# Get your contribution scores
contribs = client.learning.get_contributions(address)
print(f"Score: {contribs.total_score}")
```

### Staking (stSALT)

```python
# Deposit SALT → receive stSALT
tx = client.staking.deposit("32000000000000000000000")  # 32,000 SALT

# Check staking info
info = client.staking.get_info()
print(f"Share price: {info.share_price}")
print(f"Your staked value: {info.user_staked_value}")

# Withdraw (7-day lockup)
tx = client.staking.withdraw("1000000000000000000")
```

### Classrooms

```python
# Create a classroom (teachers)
tx = client.classroom.create("AP Computer Science", max_students=30)

# Enroll with invite code (students)
tx = client.classroom.enroll("INVITE-CODE-123")

# Deploy model to classroom whitelist
tx = client.classroom.deploy_model("0xModelHash...")

# Check if student can access a model
can_access = client.classroom.can_student_access_model(student, model_hash)
```

### Compute Marketplace

```python
# Post a compute job
job_id = client.compute.post_job(
    model_hash="0x...",
    input_data="0x...",
    max_price="10000000000",
    tier="Commitment"  # or "ZKProof", "TEE"
)

# Register as a compute provider (1000 SALT minimum)
tx = client.compute.register_provider(
    stake="1000000000000000000000",
    models=["0xModel1"],
    endpoint="https://my-node.com"
)

# Create a GPU pool
tx = client.compute.create_pool("My Pool", "InferencePool", 3, 1000, "100000000")

# List available pools
pools = client.compute.get_pools()
```

## Models & Inference

```python
from citrate_sdk import ModelConfig, ModelType, AccessType

# Deploy a model
config = ModelConfig(
    name="My Model",
    model_type=ModelType.GGUF,
    access_type=AccessType.PUBLIC
)
deployment = client.deploy_model("./model.gguf", config)

# Run inference
result = client.inference(
    model_id=deployment.model_id,
    input_data={"text": "Hello world"}
)
print(f"Output: {result.output_data}")
```

## Network Configuration

```python
# Local devnet
client = CitrateClient("http://localhost:8545")
local_chain_id = client.get_chain_id()

# Testnet
client = CitrateClient("https://rpc.citrate.ai", private_key="0x...")
```

Use `get_chain_id()` on localhost instead of assuming every local profile uses the public testnet chain ID.

**Public testnet chain ID**: 40204 | **Token**: SALT | **Block time**: ~2 seconds

## Testing

```bash
pip install -e ".[dev]"
pytest tests/
pytest --cov=citrate_sdk tests/
```

## Support

- **GitHub**: [github.com/SaulBuilds/citrate](https://github.com/SaulBuilds/citrate)
- **Issues**: [github.com/SaulBuilds/citrate/issues](https://github.com/SaulBuilds/citrate/issues)
- **Discord**: [discord.gg/A3Uwe4BvdN](https://discord.gg/A3Uwe4BvdN)

## License

MIT License — see [LICENSE](../../LICENSE) for details.
