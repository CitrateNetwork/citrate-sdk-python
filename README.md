# citrate-sdk-python

*Part of the **[Citrate Network](https://citrate.ai)** — own the means of computation. · [Docs](https://docs.citrate.ai) · [Run a node](https://citrate.ai/download) · [Contribute → free membership](https://github.com/CitrateNetwork/.github/blob/main/CONTRIBUTING.md)*
> The Python SDK and `citrate` CLI for the Citrate Network (chain **40204**) — connect to the chain, deploy/run models, encrypt inference inputs, and call the inference gateway.

## What it is
`citrate-labs-sdk` is the Python client for the Citrate distributed-AI network: a JSON-RPC
`CitrateClient`, managers for compute/learning/staking/treasury/farming, an AES-GCM/HKDF
crypto envelope for encrypted inference, an OpenAI-compatible `GatewayClient`, and a
`citrate` command-line tool. Chain id 40204 is bound from a vendored federation-contract
artifact and enforced at signing time (a hostile RPC cannot make you sign for another
chain). It mirrors the canonical TypeScript SDK (`@citratelabs/sdk`) and may lag it.

Tokenomics are not yet determined; see [docs.citrate.ai](https://docs.citrate.ai).

This release carries the **r1006** address book (citrate-chain
`contracts/addresses/r1006/40204.json`, genesis block `0xa3651a27…6cdd4`). Two networks can share
chain id 40204 (r1005 and r1006 do), so before the client or a manager sends a transaction, and
before `verify_wallet_address_on_chain` trusts the factory, the SDK reads block 0 and raises
`WrongNetworkError` (`error_code="WRONG_NETWORK"`) unless its hash is that genesis.
`client.verify_network()` runs the check up front. `LiquidStakingPool` is not in r1006 block 0,
so `StakingManager` has no default address.

See the concepts in the docs: <https://docs.citrate.ai>.
Depends on a running chain node ([citrate-chain](https://github.com/CitrateNetwork/citrate-chain))
and, for inference, the gateway ([citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway)).

## Prerequisites
```bash
python3 --version   # >= 3.10 (3.10/3.11/3.12 supported)
python3 -m pip --version
# Optional: uv (a uv.lock is committed for reproducible installs)
#   pipx install uv   # or: curl -LsSf https://astral.sh/uv/install.sh | sh
# Optional, only for "Connect it locally": a local Citrate devnet node on :8545
```

## Build from source
```bash
git clone https://github.com/CitrateNetwork/citrate-sdk-python.git
cd citrate-sdk-python

# pip (editable install with dev extras)
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[dev]'

# --- or with uv (uses the committed uv.lock) ---
# uv sync

pytest                 # run the test suite
citrate contract       # smoke-test the CLI: prints the federation contract table
```
`pyproject.toml` is the single source of truth for dependencies (`requests`, `cryptography`,
`eth-account`, `web3`, `numpy`). The install exposes the `citrate` console script.

## Run locally
This is a library plus a CLI. Install it into your environment, then either import it or use
the CLI:

```bash
pip install citrate-labs-sdk        # from PyPI (published as citrate-labs-sdk)
citrate --help                      # subcommands: contract, wallet, entitlement, gateway
```

30-second Quickstart (against the public testnet, chain 40204):
```python
import os
from citrate_sdk import CitrateClient

client = CitrateClient(
    rpc_url="https://rpc.citrate.ai",             # testnet default (chain 40204)
    private_key=os.getenv("CITRATE_PRIVATE_KEY"), # optional; required to sign
)
print("chain id:", client.get_chain_id())          # 40204
```

Call the inference gateway (OpenAI-compatible; needs a `cgk_` key):
```python
from citrate_sdk.gateway import GatewayClient

gw = GatewayClient(api_key=os.environ["CITRATE_GATEWAY_API_KEY"])
print(gw.chat_completions(
    model="gemma-4-E4B-it-Q4_K_M",
    messages=[{"role": "user", "content": "Say hi from Citrate"}],
))
```
Runnable examples live in `examples/` (`basic_usage.py`, `encrypted_inference.py`,
`marketplace_demo.py`). Verify it's up: `get_chain_id()` returning `40204` confirms the RPC.

`deploy_model` never places key shares in deployment metadata; its key-share check on
caller-supplied metadata is a safety net against accidental inclusion, not a guarantee
against deliberately re-encoded data.

> Security: the client warns/fails on a remote plaintext `http://` RPC (keys and signed
> transactions would go out in cleartext). Loopback `http://` is always allowed; pass
> `allow_insecure_http=True` for a trusted TLS-less internal host.

## Connect it locally  ← the differentiator
Point the SDK at a local Citrate stack on one machine instead of the public testnet.

1. **Local chain** — run a Citrate devnet node (chain 40204) from
   [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) and deploy its contract
   book. It exposes JSON-RPC on `http://localhost:8545`.
2. **Point the SDK at it** (loopback needs no opt-in):
   ```python
   from citrate_sdk import CitrateClient
   client = CitrateClient(
       rpc_url="http://localhost:8545",
       private_key="0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",  # anvil acct #0
       expected_genesis_hash=None,  # a local devnet is not the r1006 genesis
   )
   assert client.get_chain_id() == 40204
   ```
   The client refuses to sign if the RPC's `eth_chainId` does not match the expected 40204;
   pass `chain_id=` to override for a custom local chain. A local devnet has its own genesis,
   so also pass `expected_genesis_hash=None` (or your devnet's block-0 hash) when it uses
   chain id 40204.
3. **Local inference gateway** (optional) — run
   [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway)
   and point the gateway client at it:
   ```python
   gw = GatewayClient(api_key="cgk_...", base_url="http://localhost:8080")
   ```
4. **End-to-end check** — run the basic example against your local node:
   ```bash
   CITRATE_RPC_URL=http://localhost:8545 python examples/basic_usage.py
   ```

For the full multi-repo bring-up (chain → identity → bundler → gateway → SDKs), see the
LOCAL_STACK guide at <https://docs.citrate.ai>.

## Verify contracts on CitrateScan
`citrate_sdk.verify` submits Solidity source to CitrateScan, the explorer for chain 40204, through
its Etherscan-compatible API (`https://explorer.citrate.ai/api`). It POSTs `verifysourcecode`,
polls `checkverifystatus`, and returns when the explorer has recompiled the source and matched it
to the code on chain. Input is a forge or hardhat build-info, a hardhat contract artifact, or a
solc standard JSON input. Only the sources the contract's metadata lists are sent, as forge and
hardhat-verify do.

```python
import os

from citrate_sdk import CitrateClient, deploy_and_verify, load_build_info, verify_contract

# forge: `forge build --build-info` writes out/build-info/<id>.json with the compiler input.
build_info, _ = load_build_info("out/build-info/<id>.json")
result = verify_contract(
    chain_id=40204,  # optional: sent as Etherscan v2 `chainid`; omit it for a local devnet explorer
    address="0xYourContractAddress",
    build_info=build_info,
    contract="src/MyContract.sol:MyContract",  # or "MyContract" when the name is unique
    constructor_args="0x...",  # optional: the explorer reads them from the creation transaction
)
print(result.status)  # "verified" or "already_verified"

# hardhat: pass the contract artifact; load_build_info follows its .dbg.json.
bi, contract = load_build_info("artifacts/contracts/MyContract.sol/MyContract.json")
verify_contract(chain_id=40204, address="0xYourContractAddress", build_info=bi, contract=contract)

# Deploy from the build-info with the client's key (same genesis/chain-id checks as every
# transaction), then verify with the creation transaction hash.
client = CitrateClient(rpc_url="https://rpc.citrate.ai", private_key=os.environ["CITRATE_PRIVATE_KEY"])
deployed = deploy_and_verify(
    client=client, chain_id=40204, build_info=build_info,
    contract="src/MyContract.sol:MyContract", args=[7, "hello"],
)
print(deployed.address, deployed.tx_hash, deployed.verification.status)
```

Keywords:
- `chain_id`: optional. When given, it is sent as Etherscan v2 `chainid` on the submission and on
  every status call. When omitted, no `chainid` is sent, so an explorer for a local devnet with
  another chain id works. This matches `citrate contract verify --chain-id`.
- `explorer_url` (default `https://explorer.citrate.ai/api`), `api_key` (sent as `apikey`; not
  required, and never included in error messages), `compiler_version` (otherwise read from the
  contract metadata), `creation_tx_hash`.
- `wait=False`: return the guid without polling.
- `poll_interval` (3 s) and `timeout` (300 s) for the status polling. A transient error while
  polling (connection reset, request timeout, HTTP 5xx or 429) does not end the wait: the poll is
  retried with a backoff that doubles from `poll_interval` up to `transient_backoff_max` (30 s),
  within `timeout`. A 4xx other than 429, or a `Fail` verdict, ends it. `poll_interval` is at
  least `MIN_POLL_INTERVAL` (5 ms), so 0 does not retry in a tight loop.
- `rate_limit_retries` (3) and `rate_limit_backoff` (5 s) for `Max rate limit reached`. The
  explorer takes one submission per 5 s per IP, so while it has not indexed a just-deployed
  contract, `deploy_and_verify` resubmits at most every `max(poll_interval, rate_limit_backoff)`
  seconds, for up to `index_timeout` (120 s).

`check_verify_status(guid)` and `wait_for_verification(guid)` poll a job you submitted earlier;
pass the same `chain_id` (or none) as the submission. `CitrateClient.deploy_contract` waits up to
`receipt_timeout` (120 s) for the receipt and raises `CitrateError` with code `DEPLOY_FAILED`
when the receipt has status 0.

Errors subclass `VerificationError` (a `CitrateError`):
- `BuildInfoError`: bad input, nothing sent. A plain `forge build` without `--build-info` gets
  this error, with the fix in the message.
- `VerificationFailedError`: `Fail - Unable to verify`.
- `VerificationRejectedError`: the explorer's refusal string.
- `VerificationRateLimitedError`: still rate limited after retries.
- `VerificationTimeoutError`: no verdict yet. The job may still finish.
- `ExplorerResponseError`: the explorer could not be reached or gave an unexpected answer.
  `transient` is true for a transport failure, a timeout, HTTP 5xx and 429.

The explorer accepts at most 64 files and 2 MiB, inline content only.

forge and hardhat can verify against the same API directly. Two details matter on chain 40204:
- **forge:** use `--verifier custom --verifier-url https://explorer.citrate.ai/api --verifier-api-key citrate`.
  With forge 1.5.1, `--verifier etherscan` stops before sending anything ("No known Etherscan API
  URL for chain `40204`"). `--verifier-api-key` must be present, and any value works.
- **hardhat-verify:** give `etherscan.apiKey` as a per-network object (`{ citrate: "citrate" }`)
  with a `customChains` entry for chainId 40204 (`apiURL: "https://explorer.citrate.ai/api"`).
  With hardhat-verify 2.1.3 a single string `apiKey` switches it to Etherscan's v2 mode, which
  ignores `customChains` and sends the request to api.etherscan.io.

## Configuration
| Env var | Default | Purpose |
|---------|---------|---------|
| `CITRATE_RPC_URL` | `http://localhost:8545` | chain JSON-RPC endpoint |
| `CITRATE_PRIVATE_KEY` | — | signer key (examples generate an ephemeral one if unset) |
| `CITRATE_GATEWAY_API_KEY` | — | `cgk_` bearer key for the inference gateway |

`CitrateClient(rpc_url, private_key=None, timeout=..., allow_insecure_http=False, chain_id=None,
expected_genesis_hash=<vendored>)`. The expected chain id (40204), genesis hash (r1006) and
gateway base URL come from the vendored federation artifact; `citrate contract` prints the full
table. The managers take the same `chain_id=` / `expected_genesis_hash=` keywords.

## Links
- Docs: <https://docs.citrate.ai>
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) · [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway) · [citrate-identity](https://github.com/CitrateNetwork/citrate-identity)
- Parity with: [citrate-sdk-js](https://github.com/CitrateNetwork/citrate-sdk-js) (canonical SDK)
- Contributing (DCO): `CONTRIBUTING.md` · Security: `SECURITY.md` · License: [`LICENSE`](LICENSE)

## License

Licensed under the Apache License, Version 2.0 (see [`LICENSE`](LICENSE)). This is the open-source infrastructure tier of Citrate's open-core model. The commercial application layer is source-available under BUSL-1.1. Licensor: Citrate Inc.
