"""
ECON-2: SDK Treasury Extensions (Python)

Provides the TreasuryManager class for interacting with Citrate's treasury and
institutional compute credit system:
  - Stablecoin deposits into the StablecoinTreasury
  - Compute credit purchases via BulkComputeGateway
  - Credit balance and inference estimation queries
  - Treasury value and epoch revenue queries

All methods wire to real on-chain contracts via the SDK's RPC client.
No mock returns -- every call encodes the actual Solidity ABI and sends
via eth_call (reads) or eth_sendTransaction (writes).

Data sources:
  - StablecoinTreasury.sol: stablecoin deposits, TVL, epoch revenue, distribution
  - BulkComputeGateway.sol: compute credit purchases, balances, inference estimation
"""

from __future__ import annotations

from typing import Any, cast

from ._chain_guard import expected_chain_id, pinned_send
from .abi import AbiInterface
from .errors import ConfigurationError

# ============================================================================
# Contract ABIs (minimal -- only the methods we call)
# Identical to the JS SDK's human-readable ABI arrays.
# ============================================================================

STABLECOIN_TREASURY_ABI = [
    "function deposit(address stablecoin, uint256 amount)",
    "function totalValueLocked() view returns (uint256 tvl)",
    "function totalValueUsd() view returns (uint256)",
    "function totalDistributed() view returns (uint256)",
    "function stablecoinBalances(address token) view returns (uint256)",
    "function stablecoinCount() view returns (uint256)",
    "function getAcceptedStablecoins() view returns (address[])",
    "function currentEpoch() view returns (uint256)",
    "function getEpochRevenue(uint256 epoch) view returns (uint256 totalUsd, uint256 computeJobsCount, uint256 inferenceCalls, uint256 startBlock, uint256 endBlock)",
]

BULK_COMPUTE_GATEWAY_ABI = [
    "function purchaseComputeCredits(address stablecoin, uint256 amount) returns (uint256 creditsReceived)",
    "function getCreditBalance(address institution) view returns (uint256 credits)",
    "function estimateCallsRemaining(address institution, uint256 avgTokensPerCall) view returns (uint256 callsRemaining)",
    "function computeCredits(address institution) view returns (uint256)",
    "function totalCreditsPurchased() view returns (uint256)",
    "function totalCreditsSpent() view returns (uint256)",
    "function purchaseCount() view returns (uint256)",
    "function currentCreditPriceUsd() view returns (uint256 priceUsd6)",
]


# ============================================================================
# TreasuryManager
# ============================================================================

class TreasuryManager:
    """Wraps StablecoinTreasury and BulkComputeGateway contracts.

    Data sources:
      - StablecoinTreasury contract: deposit stablecoins, TVL, epoch revenue
      - BulkComputeGateway contract: compute credit purchases, balance queries
    """

    def __init__(
        self,
        rpc_call: Any,
        default_account: str | None = None,
        gas_limit: int = 500_000,
        gas_price: str = "0x3b9aca00",
        contract_addresses: dict[str, str] | None = None,
        *,
        chain_id: int | None = None,
    ) -> None:
        self._rpc_call = rpc_call
        # PBA-L6b-042: writes assert eth_chainId against this before sending.
        self._expected_chain_id = expected_chain_id(chain_id)
        self._chain_verified = False
        self._default_account = default_account
        self._gas_limit = gas_limit
        self._gas_price = gas_price

        addrs = contract_addresses or {}
        self._treasury_addr = addrs.get("stablecoinTreasury")
        self._gateway_addr = addrs.get("bulkComputeGateway")

        self._treasury_iface = AbiInterface(STABLECOIN_TREASURY_ABI)
        self._gateway_iface = AbiInterface(BULK_COMPUTE_GATEWAY_ABI)

    # --- Internal helpers ---

    def _require_treasury_address(self) -> str:
        if not self._treasury_addr:
            raise ConfigurationError(
                "StablecoinTreasury contract address not configured. Set it via contract_addresses."
            )
        return self._treasury_addr

    def _require_gateway_address(self) -> str:
        if not self._gateway_addr:
            raise ConfigurationError(
                "BulkComputeGateway contract address not configured. Set it via contract_addresses."
            )
        return self._gateway_addr

    def _eth_call(self, to: str, data: str) -> str:
        result = self._rpc_call("eth_call", [{"to": to, "data": data}, "latest"])
        return cast(str, result)

    def _send_transaction(self, to: str, data: str, value: str = "0x0") -> str:
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
        return pinned_send(self, tx)

    # -------------------------------------------------------------------
    # StablecoinTreasury — Deposits
    # -------------------------------------------------------------------

    def deposit_stablecoin(self, stablecoin_addr: str, amount: int) -> str:
        """Deposit stablecoin into treasury. Returns tx hash.

        Data source: StablecoinTreasury.deposit(address, uint256) via eth_sendTransaction.

        Args:
            stablecoin_addr: ERC-20 stablecoin contract address.
            amount: Amount in token's native decimals (e.g., 1_000_000 for $1 USDC).

        Returns:
            Transaction hash.
        """
        addr = self._require_treasury_address()
        data = self._treasury_iface.encode_function_data("deposit", [stablecoin_addr, amount])
        return self._send_transaction(addr, data)

    # -------------------------------------------------------------------
    # BulkComputeGateway — Credit Purchases
    # -------------------------------------------------------------------

    def purchase_compute_credits(self, stablecoin_addr: str, usd_amount: int) -> str:
        """Buy compute credits with stablecoins. Returns tx hash.

        Data source: BulkComputeGateway.purchaseComputeCredits(address, uint256) via eth_sendTransaction.

        Args:
            stablecoin_addr: ERC-20 stablecoin contract address.
            usd_amount: Amount in stablecoin native decimals (e.g., 1_000_000 for $1 USDC).

        Returns:
            Transaction hash (credits received emitted in CreditsPurchased event).
        """
        addr = self._require_gateway_address()
        data = self._gateway_iface.encode_function_data("purchaseComputeCredits", [
            stablecoin_addr, usd_amount,
        ])
        return self._send_transaction(addr, data)

    # -------------------------------------------------------------------
    # BulkComputeGateway — Credit Queries
    # -------------------------------------------------------------------

    def get_credit_balance(self, institution: str | None = None) -> int:
        """Get compute credit balance in PFLOP-hours (18 decimals).

        Data source: BulkComputeGateway.getCreditBalance(address) via eth_call.

        Args:
            institution: Address to query. Uses default_account if not provided.

        Returns:
            Credit balance in PFLOP-hours (18 decimals).
        """
        addr = self._require_gateway_address()
        target = institution or self._default_account
        if not target:
            raise ConfigurationError("No institution address provided and no defaultAccount configured.")

        data = self._gateway_iface.encode_function_data("getCreditBalance", [target])
        result = self._eth_call(addr, data)
        (credits,) = self._gateway_iface.decode_function_result("getCreditBalance", result)
        return int(credits)

    def estimate_calls_remaining(self, institution: str | None = None, avg_tokens: int = 1000) -> int:
        """Estimate inference calls remaining for institution.

        Data source: BulkComputeGateway.estimateCallsRemaining(address, uint256) via eth_call.

        Args:
            institution: Address to estimate for. Uses default_account if not provided.
            avg_tokens: Average tokens per inference call (default 1000).

        Returns:
            Approximate number of inference calls possible.
        """
        addr = self._require_gateway_address()
        target = institution or self._default_account
        if not target:
            raise ConfigurationError("No institution address provided and no defaultAccount configured.")

        data = self._gateway_iface.encode_function_data("estimateCallsRemaining", [
            target, avg_tokens,
        ])
        result = self._eth_call(addr, data)
        (calls_remaining,) = self._gateway_iface.decode_function_result("estimateCallsRemaining", result)
        return int(calls_remaining)

    # -------------------------------------------------------------------
    # StablecoinTreasury — Value Queries
    # -------------------------------------------------------------------

    def get_treasury_value(self) -> int:
        """Get total value locked in treasury (USD, 6 decimals).

        Data source: StablecoinTreasury.totalValueLocked() via eth_call.

        Returns:
            Total value in USD terms (6 decimals, e.g., 1_000_000 = $1.00).
        """
        addr = self._require_treasury_address()
        data = self._treasury_iface.encode_function_data("totalValueLocked")
        result = self._eth_call(addr, data)
        (tvl,) = self._treasury_iface.decode_function_result("totalValueLocked", result)
        return int(tvl)

    def get_epoch_revenue(self, epoch: int) -> dict:
        """Get revenue for a specific epoch.

        Data source: StablecoinTreasury.getEpochRevenue(uint256) via eth_call.

        Args:
            epoch: Epoch number to query.

        Returns:
            Dictionary with keys: total_usd, compute_jobs_count, inference_calls,
            start_block, end_block.
        """
        addr = self._require_treasury_address()
        data = self._treasury_iface.encode_function_data("getEpochRevenue", [epoch])
        result = self._eth_call(addr, data)
        decoded = self._treasury_iface.decode_function_result("getEpochRevenue", result)
        total_usd, compute_jobs_count, inference_calls, start_block, end_block = decoded

        return {
            "total_usd": int(total_usd),
            "compute_jobs_count": int(compute_jobs_count),
            "inference_calls": int(inference_calls),
            "start_block": int(start_block),
            "end_block": int(end_block),
        }

    # -------------------------------------------------------------------
    # StablecoinTreasury — Additional Queries
    # -------------------------------------------------------------------

    def get_current_epoch(self) -> int:
        """Get the current epoch number.

        Data source: StablecoinTreasury.currentEpoch() via eth_call.

        Returns:
            Current epoch number.
        """
        addr = self._require_treasury_address()
        data = self._treasury_iface.encode_function_data("currentEpoch")
        result = self._eth_call(addr, data)
        (epoch,) = self._treasury_iface.decode_function_result("currentEpoch", result)
        return int(epoch)

    def get_stablecoin_balance(self, token_addr: str) -> int:
        """Get treasury balance for a specific stablecoin.

        Data source: StablecoinTreasury.stablecoinBalances(address) via eth_call.

        Args:
            token_addr: ERC-20 stablecoin address to query.

        Returns:
            Balance in token's native decimals.
        """
        addr = self._require_treasury_address()
        data = self._treasury_iface.encode_function_data("stablecoinBalances", [token_addr])
        result = self._eth_call(addr, data)
        (balance,) = self._treasury_iface.decode_function_result("stablecoinBalances", result)
        return int(balance)

    def get_total_distributed(self) -> int:
        """Get total USD distributed across all distributions.

        Data source: StablecoinTreasury.totalDistributed() via eth_call.

        Returns:
            Total distributed in USD terms (6 decimals).
        """
        addr = self._require_treasury_address()
        data = self._treasury_iface.encode_function_data("totalDistributed")
        result = self._eth_call(addr, data)
        (total,) = self._treasury_iface.decode_function_result("totalDistributed", result)
        return int(total)

    def get_credit_price_usd(self) -> int:
        """Get current credit price in USD per PFLOP-hour (6 decimals).

        Data source: BulkComputeGateway.currentCreditPriceUsd() via eth_call.

        Returns:
            Price in 6-decimal USD (e.g., 130_000 = $0.13).
        """
        addr = self._require_gateway_address()
        data = self._gateway_iface.encode_function_data("currentCreditPriceUsd")
        result = self._eth_call(addr, data)
        (price,) = self._gateway_iface.decode_function_result("currentCreditPriceUsd", result)
        return int(price)
