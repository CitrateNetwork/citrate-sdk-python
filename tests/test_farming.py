"""
Tests for the FarmingManager.

Verifies that each method:
  - Constructs the correct ABI-encoded calldata (matching Solidity function selectors)
  - Calls the correct contract address
  - Properly decodes return values
  - Raises ConfigurationError when contract addresses are missing
"""

import pytest
from unittest.mock import MagicMock

from eth_abi import encode as abi_encode

from citrate_sdk.abi import AbiInterface, keccak256
from citrate_sdk.errors import ConfigurationError
from citrate_sdk.farming import (
    FarmingManager,
    TESTNET_FARMING_ABI,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FAKE_FARMING_ADDR = "0x" + "aa" * 20
DEFAULT_ACCOUNT = "0x" + "11" * 20
ZERO_ADDR = "0x" + "00" * 20

_farming_iface = AbiInterface(TESTNET_FARMING_ABI)


def _encode_uint256(val: int) -> str:
    return "0x" + val.to_bytes(32, "big").hex()


def _encode_bool(val: bool) -> str:
    return _encode_uint256(1 if val else 0)


def _encode_abi(types, vals) -> str:
    return "0x" + abi_encode(types, vals).hex()


# ---------------------------------------------------------------------------
# FarmingManager Tests
# ---------------------------------------------------------------------------

class TestFarmingManager:
    """Tests for FarmingManager."""

    def _make_manager(self, rpc_call=None):
        return FarmingManager(
            rpc_call=rpc_call or MagicMock(),
            default_account=DEFAULT_ACCOUNT,
            contract_addresses={
                "testnetFarmingAccounting": FAKE_FARMING_ADDR,
            },
        )

    # --- Configuration error tests ---

    def test_missing_farming_address(self):
        """Raises ConfigurationError when testnetFarmingAccounting address not set."""
        mgr = FarmingManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="TestnetFarmingAccounting"):
            mgr.get_my_score(DEFAULT_ACCOUNT)

    def test_no_default_account_write(self):
        """Write operations raise when no default account."""
        mgr = FarmingManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"testnetFarmingAccounting": FAKE_FARMING_ADDR},
        )
        with pytest.raises(ConfigurationError, match="defaultAccount"):
            mgr.claim()

    def test_no_address_for_score(self):
        """get_my_score raises when no address and no default account."""
        mgr = FarmingManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"testnetFarmingAccounting": FAKE_FARMING_ADDR},
        )
        with pytest.raises(ConfigurationError, match="No address"):
            mgr.get_my_score()

    def test_no_address_for_share(self):
        """get_my_share raises when no address and no default account."""
        mgr = FarmingManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"testnetFarmingAccounting": FAKE_FARMING_ADDR},
        )
        with pytest.raises(ConfigurationError, match="No address"):
            mgr.get_my_share()

    # --- Score queries ---

    def test_get_my_score_decode(self):
        """get_my_score properly decodes uint256 result."""
        expected_score = 15_000
        rpc = MagicMock(return_value=_encode_uint256(expected_score))
        mgr = self._make_manager(rpc)
        score = mgr.get_my_score(DEFAULT_ACCOUNT)
        assert score == expected_score

    def test_get_my_score_uses_default_account(self):
        """get_my_score uses default_account when no address provided."""
        rpc = MagicMock(return_value=_encode_uint256(100))
        mgr = self._make_manager(rpc)
        mgr.get_my_score()  # no address parameter
        call_args = rpc.call_args_list[0][0]
        assert call_args[1][0]["to"] == FAKE_FARMING_ADDR

    def test_get_my_score_selector(self):
        """snapshotScores calldata has correct function selector."""
        sig = b"snapshotScores(address)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("snapshotScores", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected_selector

    # --- Share calculation ---

    def test_get_my_share_decode(self):
        """get_my_share properly decodes uint256 result."""
        expected_share = 50_000_000  # $50 in 6 decimals
        rpc = MagicMock(return_value=_encode_uint256(expected_share))
        mgr = self._make_manager(rpc)
        share = mgr.get_my_share(DEFAULT_ACCOUNT)
        assert share == expected_share

    def test_get_my_share_selector(self):
        """calculateShare calldata has correct function selector."""
        sig = b"calculateShare(address)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("calculateShare", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected_selector

    # --- Leaderboard ---

    def test_get_leaderboard_decode(self):
        """get_leaderboard properly decodes tuple of arrays."""
        addr1 = "0x" + "11" * 20
        addr2 = "0x" + "22" * 20
        encoded = _encode_abi(
            ["address[]", "uint256[]", "uint256[]"],
            [
                [addr1, addr2],
                [5000, 3000],
                [100_000_000, 60_000_000],
            ],
        )
        rpc = MagicMock(return_value=encoded)
        mgr = self._make_manager(rpc)
        lb = mgr.get_leaderboard(count=2)
        assert len(lb) == 2
        assert lb[0]["address"].lower() == addr1.lower()
        assert lb[0]["score"] == 5000
        assert lb[0]["share"] == 100_000_000
        assert lb[1]["address"].lower() == addr2.lower()
        assert lb[1]["score"] == 3000
        assert lb[1]["share"] == 60_000_000

    def test_get_leaderboard_selector(self):
        """getTopContributors calldata has correct function selector."""
        sig = b"getTopContributors(uint256)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("getTopContributors", [20])
        assert data[2:10] == expected_selector

    def test_get_leaderboard_default_count(self):
        """get_leaderboard uses count=20 by default."""
        encoded = _encode_abi(
            ["address[]", "uint256[]", "uint256[]"],
            [[], [], []],
        )
        rpc = MagicMock(return_value=encoded)
        mgr = self._make_manager(rpc)
        mgr.get_leaderboard()  # default count
        call_args = rpc.call_args_list[0][0]
        expected = _farming_iface.encode_function_data("getTopContributors", [20])
        assert call_args[1][0]["data"] == expected

    # --- Claim ---

    def test_claim_calldata(self):
        """claim sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.claim()
        tx = rpc.call_args_list[0][0][1][0]
        expected = _farming_iface.encode_function_data("claim")
        assert tx["data"] == expected
        assert tx["to"] == FAKE_FARMING_ADDR

    def test_claim_selector(self):
        """claim calldata has correct function selector."""
        sig = b"claim()"
        expected_selector = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("claim")
        assert data[2:10] == expected_selector

    # --- Has claimed ---

    def test_has_claimed_true(self):
        """has_claimed returns True when decoded as 1."""
        rpc = MagicMock(return_value=_encode_bool(True))
        mgr = self._make_manager(rpc)
        assert mgr.has_claimed(DEFAULT_ACCOUNT) is True

    def test_has_claimed_false(self):
        """has_claimed returns False when decoded as 0."""
        rpc = MagicMock(return_value=_encode_bool(False))
        mgr = self._make_manager(rpc)
        assert mgr.has_claimed(DEFAULT_ACCOUNT) is False

    def test_has_claimed_selector(self):
        """hasClaimed calldata has correct function selector."""
        sig = b"hasClaimed(address)"
        expected_selector = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("hasClaimed", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected_selector

    # --- Distribution info ---

    def test_get_distribution_info_calls_all_fields(self):
        """get_distribution_info makes eth_call for all 8 state fields."""
        call_count = 0
        responses = [
            _encode_bool(True),       # distributionActive
            _encode_abi(["address"], ["0x" + "cc" * 20]),  # distributionStablecoin
            _encode_uint256(1_000_000_000),  # distributionPool
            _encode_uint256(200_000_000),    # totalClaimed
            _encode_uint256(800_000_000),    # remainingDistribution
            _encode_uint256(50_000),         # totalSnapshotScore
            _encode_uint256(100),            # snapshotParticipantCount
            _encode_bool(True),              # snapshotTaken
        ]

        def mock_rpc(method, params):
            nonlocal call_count
            idx = call_count
            call_count += 1
            return responses[idx]

        mgr = self._make_manager(mock_rpc)
        info = mgr.get_distribution_info()

        assert info["distribution_active"] is True
        assert info["stablecoin"].lower() == ("0x" + "cc" * 20).lower()
        assert info["distribution_pool"] == 1_000_000_000
        assert info["total_claimed"] == 200_000_000
        assert info["remaining"] == 800_000_000
        assert info["total_snapshot_score"] == 50_000
        assert info["participant_count"] == 100
        assert info["snapshot_taken"] is True
        assert call_count == 8

    # --- Is in snapshot ---

    def test_is_in_snapshot_true(self):
        """is_in_snapshot returns True when decoded as 1."""
        rpc = MagicMock(return_value=_encode_bool(True))
        mgr = self._make_manager(rpc)
        assert mgr.is_in_snapshot(DEFAULT_ACCOUNT) is True

    def test_is_in_snapshot_false(self):
        """is_in_snapshot returns False when decoded as 0."""
        rpc = MagicMock(return_value=_encode_bool(False))
        mgr = self._make_manager(rpc)
        assert mgr.is_in_snapshot(DEFAULT_ACCOUNT) is False

    # --- Claimed amount ---

    def test_get_claimed_amount_decode(self):
        """get_claimed_amount properly decodes uint256 result."""
        rpc = MagicMock(return_value=_encode_uint256(75_000_000))
        mgr = self._make_manager(rpc)
        amount = mgr.get_claimed_amount(DEFAULT_ACCOUNT)
        assert amount == 75_000_000


# ---------------------------------------------------------------------------
# ABI selector verification
# ---------------------------------------------------------------------------

class TestFarmingAbiSelectors:
    """Verify farming function selectors match keccak256 of canonical signatures."""

    def test_snapshot_scores_selector(self):
        sig = b"snapshotScores(address)"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("snapshotScores", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected

    def test_calculate_share_selector(self):
        sig = b"calculateShare(address)"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("calculateShare", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected

    def test_get_top_contributors_selector(self):
        sig = b"getTopContributors(uint256)"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("getTopContributors", [10])
        assert data[2:10] == expected

    def test_claim_selector(self):
        sig = b"claim()"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("claim")
        assert data[2:10] == expected

    def test_has_claimed_selector(self):
        sig = b"hasClaimed(address)"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("hasClaimed", [DEFAULT_ACCOUNT])
        assert data[2:10] == expected

    def test_distribution_active_selector(self):
        sig = b"distributionActive()"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("distributionActive")
        assert data[2:10] == expected

    def test_remaining_distribution_selector(self):
        sig = b"remainingDistribution()"
        expected = keccak256(sig)[:4].hex()
        data = _farming_iface.encode_function_data("remainingDistribution")
        assert data[2:10] == expected
