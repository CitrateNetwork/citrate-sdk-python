# citrate-sdk-python
> The Python SDK and `citrate` CLI for the Citrate Network (chain **40204**) — connect to the chain, deploy/run models, encrypt inference inputs, and call the inference gateway.

## What it is
`citrate-labs-sdk` is the Python client for the Citrate distributed-AI network: a JSON-RPC
`CitrateClient`, managers for compute/learning/staking/treasury/farming, an AES-GCM/HKDF
crypto envelope for encrypted inference, an OpenAI-compatible `GatewayClient`, and a
`citrate` command-line tool. Chain id 40204 is bound from a vendored federation-contract
artifact and enforced at signing time (a hostile RPC cannot make you sign for another
chain). It mirrors the canonical TypeScript SDK (`@citratelabs/sdk`) and may lag it.

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
   )
   assert client.get_chain_id() == 40204
   ```
   The client refuses to sign if the RPC's `eth_chainId` does not match the expected 40204;
   pass `chain_id=` to override for a custom local chain.
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

## Configuration
| Env var | Default | Purpose |
|---------|---------|---------|
| `CITRATE_RPC_URL` | `http://localhost:8545` | chain JSON-RPC endpoint |
| `CITRATE_PRIVATE_KEY` | — | signer key (examples generate an ephemeral one if unset) |
| `CITRATE_GATEWAY_API_KEY` | — | `cgk_` bearer key for the inference gateway |

`CitrateClient(rpc_url, private_key=None, timeout=..., allow_insecure_http=False, chain_id=None)`.
The expected chain id (40204) and gateway base URL come from the vendored federation
artifact; `citrate contract` prints the full table.

## Links
- Docs: <https://docs.citrate.ai>
- Depends on: [citrate-chain](https://github.com/CitrateNetwork/citrate-chain) · [citrate-inference-gateway](https://github.com/CitrateNetwork/citrate-inference-gateway) · [citrate-identity](https://github.com/CitrateNetwork/citrate-identity)
- Parity with: [citrate-sdk-js](https://github.com/CitrateNetwork/citrate-sdk-js) (canonical SDK)
- Contributing (DCO): `CONTRIBUTING.md` · Security: `SECURITY.md` · License: [`LICENSE`](LICENSE)

## License
Apache-2.0.
