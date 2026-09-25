"""
Tests for the TreasuryManager.

Verifies that each method:
  - Constructs the correct ABI-encoded calldata (matching Solidity function selectors)
  - Calls the correct contract address
  - Properly decodes return values
  - Raises ConfigurationError when contract addresses are missing
"""

from unittest.mock import MagicMock

import pytest
from eth_abi import encode as abi_encode

from citrate_sdk.abi import AbiInterface, keccak256
from citrate_sdk.errors import ConfigurationError
from citrate_sdk.treasury import (
    BULK_COMPUTE_GATEWAY_ABI,
    STABLECOIN_TREASURY_ABI,
    TreasuryManager,
)
from tests._chain_rpc import chain_rpc

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_TREASURY_ADDR = "0x" + "aa" * 20
FAKE_GATEWAY_ADDR = "0x" + "bb" * 20
DEFAULT_ACCOUNT = "0x" + "11" * 20
FAKE_STABLECOIN = "0x" + "cc" * 20

_treasury_iface = AbiInterface(STABLECOIN_TREASURY_ABI)
_gateway_iface = AbiInterface(BULK_COMPUTE_GATEWAY_ABI)


def _encode_uint256(val: int) -> str:
    return "0x" + val.to_bytes(32, "big").hex()


def _encode_abi(*types_and_vals) -> str:
    """Convenience: encode ABI types and return 0x-prefixed hex."""
    types = list(types_and_vals[0])
    vals = list(types_and_vals[1])
    return "0x" + abi_encode(types, vals).hex()


# ---------------------------------------------------------------------------
# TreasuryManager Tests
# ---------------------------------------------------------------------------

class TestTreasuryManager:
    """Tests for TreasuryManager."""

    def _make_manager(self, rpc_call=None):
        return TreasuryManager(
            rpc_call=rpc_call or MagicMock(),
            default_account=DEFAULT_ACCOUNT,
            contract_addresses={
                "stablecoinTreasury": FAKE_TREASURY_ADDR,
                "bulkComputeGateway": FAKE_GATEWAY_ADDR,
            },
        )

    # --- Configuration error tests ---

    def test_missing_treasury_address(self):
        """Raises ConfigurationError when stablecoinTreasury address not set."""
        mgr = TreasuryManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="StablecoinTreasury"):
            mgr.get_treasury_value()

    def test_missing_gateway_address(self):
        """Raises ConfigurationError when bulkComputeGateway address not set."""
        mgr = TreasuryManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="BulkComputeGateway"):
            mgr.get_credit_balance(DEFAULT_ACCOUNT)

    def test_no_default_account_write(self):
        """Write operations raise when no default account."""
        mgr = TreasuryManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={
                "stablecoinTreasury": FAKE_TREASURY_ADDR,
            },
        )
        with pytest.raises(ConfigurationError, match="defaultAccount"):
            mgr.deposit_stablecoin(FAKE_STABLECOIN, 1_000_000)

    def test_no_address_for_credit_balance(self):
        """get_credit_balance raises when no address and no default account."""
        mgr = TreasuryManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"bulkComputeGateway": FAKE_GATEWAY_ADDR},
        )
        with pytest.raises(ConfigurationError, match="No institution"):
            mgr.get_credit_balance()

    def test_no_address_for_estimate_calls(self):
        """estimate_calls_remaining raises when no address and no default account."""
        mgr = TreasuryManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"bulkComputeGateway": FAKE_GATEWAY_ADDR},
        )
        with pytest.raises(ConfigurationError, match="No institution"):
            mgr.estimate_calls_remaining()

    # --- Deposit stablecoin ---

    def test_deposit_stablecoin_calldata(self):
        """deposit_stablecoin sends correct calldata to treasury."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.deposit_stablecoin(FAKE_STABLECOIN, 100_000_000)
        tx = rpc.call_args_list[-1][0][1][0]
        assert tx["to"] == FAKE_TREASURY_ADDR
        expected = _treasury_iface.encode_function_data("deposit", [FAKE_STABLECOIN, 100_000_000])
        assert tx["data"] == expected

    def test_deposit_stablecoin_selector(self):
        """deposit calldata has correct function selector."""
        sig = b"deposit(address,uint256)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _treasury_iface.encode_function_data("deposit", [FAKE_STABLECOIN, 1000])
        assert data[2:10] == expected_selector

    # --- Purchase compute credits ---

    def test_purchase_compute_credits_calldata(self):
        """purchase_compute_credits sends correct calldata to gateway."""
        rpc = chain_rpc("0xtx")
        mgr = self._make_manager(rpc)
        mgr.purchase_compute_credits(FAKE_STABLECOIN, 50_000_000)
        tx = rpc.call_args_list[-1][0][1][0]
        assert tx["to"] == FAKE_GATEWAY_ADDR
        expected = _gateway_iface.encode_function_data("purchaseComputeCredits", [
            FAKE_STABLECOIN, 50_000_000,
        ])
        assert tx["data"] == expected

    def test_purchase_compute_credits_selector(self):
        """purchaseComputeCredits calldata has correct function selector."""
        sig = b"purchaseComputeCredits(address,uint256)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _gateway_iface.encode_function_data("purchaseComputeCredits", [FAKE_STABLECOIN, 1000])
        assert data[2:10] == expected_selector

    # --- Get credit balance ---

    def test_get_credit_balance_decode(self):
        """get_credit_balance properly decodes uint256 result."""
        expected_balance = 5_000_000_000_000_000_000  # 5 PFLOP-hours
        rpc = MagicMock(return_value=_encode_uint256(expected_balance))
        mgr = self._make_manager(rpc)
        balance = mgr.get_credit_balance(DEFAULT_ACCOUNT)
        assert balance == expected_balance

    def test_get_credit_balance_uses_default_account(self):
        """get_credit_balance uses default_account when no address provided."""
        rpc = MagicMock(return_value=_encode_uint256(100))
        mgr = self._make_manager(rpc)
        mgr.get_credit_balance()  # no address parameter
        call_args = rpc.call_args_list[-1][0]
        # Verify the call went to the correct contract
        assert call_args[1][0]["to"] == FAKE_GATEWAY_ADDR

    def test_get_credit_balance_selector(self):
        """getCreditBalance calldata has correct function selector."""
        sig = b"getCreditBalance(address)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _gateway_iface.encode_function_data("getCreditBalance", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected_selector

    # --- Estimate calls remaining ---

    def test_estimate_calls_remaining_decode(self):
        """estimate_calls_remaining properly decodes uint256 result."""
        expected_calls = 42_000
        rpc = MagicMock(return_value=_encode_uint256(expected_calls))
        mgr = self._make_manager(rpc)
        calls = mgr.estimate_calls_remaining(DEFAULT_ACCOUNT, avg_tokens=1000)
        assert calls == expected_calls

    def test_estimate_calls_remaining_default_tokens(self):
        """estimate_calls_remaining uses avg_tokens=1000 by default."""
        rpc = MagicMock(return_value=_encode_uint256(100))
        mgr = self._make_manager(rpc)
        mgr.estimate_calls_remaining(DEFAULT_ACCOUNT)
        call_args = rpc.call_args_list[-1][0]
        expected = _gateway_iface.encode_function_data("estimateCallsRemaining", [
            DEFAULT_ACCOUNT, 1000,
        ])
        assert call_args[1][0]["data"] == expected

    # --- Treasury value ---

    def test_get_treasury_value_decode(self):
        """get_treasury_value properly decodes uint256 result."""
        tvl = 500_000_000_000  # $500K in 6 decimals
        rpc = MagicMock(return_value=_encode_uint256(tvl))
        mgr = self._make_manager(rpc)
        value = mgr.get_treasury_value()
        assert value == tvl

    def test_get_treasury_value_selector(self):
        """totalValueLocked calldata has correct function selector."""
        sig = b"totalValueLocked()"
        expected_selector = keccak256(sig)[:4].hex()
        data = _treasury_iface.encode_function_data("totalValueLocked")
        assert data[2:10] == expected_selector

    # --- Epoch revenue ---

    def test_get_epoch_revenue_decode(self):
        """get_epoch_revenue properly decodes tuple result."""
        encoded = _encode_abi(
            ["uint256", "uint256", "uint256", "uint256", "uint256"],
            [100_000_000, 5, 200, 1000, 1999],
        )
        rpc = MagicMock(return_value=encoded)
        mgr = self._make_manager(rpc)
        rev = mgr.get_epoch_revenue(0)
        assert rev["total_usd"] == 100_000_000
        assert rev["compute_jobs_count"] == 5
        assert rev["inference_calls"] == 200
        assert rev["start_block"] == 1000
        assert rev["end_block"] == 1999

    def test_get_epoch_revenue_selector(self):
        """getEpochRevenue calldata has correct function selector."""
        sig = b"getEpochRevenue(uint256)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _treasury_iface.encode_function_data("getEpochRevenue", [0])
        assert data[2:10] == expected_selector

    # --- Current epoch ---

    def test_get_current_epoch_decode(self):
        """get_current_epoch properly decodes uint256 result."""
        rpc = MagicMock(return_value=_encode_uint256(7))
        mgr = self._make_manager(rpc)
        epoch = mgr.get_current_epoch()
        assert epoch == 7

    # --- Stablecoin balance ---

    def test_get_stablecoin_balance_decode(self):
        """get_stablecoin_balance properly decodes uint256 result."""
        rpc = MagicMock(return_value=_encode_uint256(250_000_000))
        mgr = self._make_manager(rpc)
        bal = mgr.get_stablecoin_balance(FAKE_STABLECOIN)
        assert bal == 250_000_000

    # --- Total distributed ---

    def test_get_total_distributed_decode(self):
        """get_total_distributed properly decodes uint256 result."""
        rpc = MagicMock(return_value=_encode_uint256(100_000_000))
        mgr = self._make_manager(rpc)
        total = mgr.get_total_distributed()
        assert total == 100_000_000

    # --- Credit price ---

    def test_get_credit_price_usd_decode(self):
        """get_credit_price_usd properly decodes uint256 result."""
        # 13 cents = 130_000 in 6 decimals
        rpc = MagicMock(return_value=_encode_uint256(130_000))
        mgr = self._make_manager(rpc)
        price = mgr.get_credit_price_usd()
        assert price == 130_000


# ---------------------------------------------------------------------------
# ABI selector verification
# ---------------------------------------------------------------------------

class TestTreasuryAbiSelectors:
    """Verify treasury function selectors match keccak256 of canonical signatures."""

    def test_deposit_selector(self):
        sig = b"deposit(address,uint256)"
        expected = keccak256(sig)[:4].hex()
        data = _treasury_iface.encode_function_data("deposit", [FAKE_STABLECOIN, 0])
        assert data[2:10] == expected

    def test_total_value_locked_selector(self):
        sig = b"totalValueLocked()"
        expected = keccak256(sig)[:4].hex()
        data = _treasury_iface.encode_function_data("totalValueLocked")
        assert data[2:10] == expected

    def test_current_epoch_selector(self):
        sig = b"currentEpoch()"
        expected = keccak256(sig)[:4].hex()
        data = _treasury_iface.encode_function_data("currentEpoch")
        assert data[2:10] == expected

    def test_purchase_credits_selector(self):
        sig = b"purchaseComputeCredits(address,uint256)"
        expected = keccak256(sig)[:4].hex()
        data = _gateway_iface.encode_function_data("purchaseComputeCredits", [FAKE_STABLECOIN, 0])
        assert data[2:10] == expected

    def test_get_credit_balance_selector(self):
        sig = b"getCreditBalance(address)"
        expected = keccak256(sig)[:4].hex()
        data = _gateway_iface.encode_function_data("getCreditBalance", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected

    def test_estimate_calls_remaining_selector(self):
        sig = b"estimateCallsRemaining(address,uint256)"
        expected = keccak256(sig)[:4].hex()
        data = _gateway_iface.encode_function_data("estimateCallsRemaining", [DEFAULT_ACCOUNT, 1000])
        assert data[2:10] == expected

    def test_current_credit_price_usd_selector(self):
        sig = b"currentCreditPriceUsd()"
        expected = keccak256(sig)[:4].hex()
        data = _gateway_iface.encode_function_data("currentCreditPriceUsd")
        assert data[2:10] == expected
