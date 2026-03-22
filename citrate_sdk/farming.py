"""
ECON-2: SDK Farming Extensions (Python)

Provides the FarmingManager class for interacting with Citrate's testnet
farming distribution system:
  - Snapshot score queries for participants
  - USD share calculation from distribution pool
  - Leaderboard of top contributors
  - Claim stablecoin distribution
  - Distribution status queries

All methods wire to real on-chain contracts via the SDK's RPC client.
No mock returns -- every call encodes the actual Solidity ABI and sends
via eth_call (reads) or eth_sendTransaction (writes).

Data sources:
  - TestnetFarmingAccounting.sol: snapshot scores, share calculation,
    leaderboard, claims, distribution info
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from .abi import AbiInterface
from .errors import ConfigurationError

# ============================================================================
# Contract ABIs (minimal -- only the methods we call)
# Identical to the JS SDK's human-readable ABI arrays.
# ============================================================================

TESTNET_FARMING_ABI = [
    "function snapshotScores(address participant) view returns (uint256)",
    "function calculateShare(address participant) view returns (uint256 usdShare)",
    "function getTopContributors(uint256 count) view returns (address[] addrs, uint256[] scoresList, uint256[] shares)",
    "function claim()",
    "function hasClaimed(address participant) view returns (bool)",
    "function snapshotTaken() view returns (bool)",
    "function distributionActive() view returns (bool)",
    "function distributionStablecoin() view returns (address)",
    "function distributionPool() view returns (uint256)",
    "function totalClaimed() view returns (uint256)",
    "function totalSnapshotScore() view returns (uint256)",
    "function snapshotParticipantCount() view returns (uint256)",
    "function isSnapshotted(address participant) view returns (bool)",
    "function claimedAmount(address participant) view returns (uint256)",
    "function remainingDistribution() view returns (uint256)",
]


# ============================================================================
# FarmingManager
# ============================================================================

class FarmingManager:
    """Wraps TestnetFarmingAccounting contract for testnet-end stablecoin
    distribution to participants based on Shapley-weighted contribution scores.

    Data source: TestnetFarmingAccounting contract via eth_call / eth_sendTransaction.
    """

    def __init__(
        self,
        rpc_call: Any,
        default_account: Optional[str] = None,
        gas_limit: int = 300_000,
        gas_price: str = "0x3b9aca00",
        contract_addresses: Optional[Dict[str, str]] = None,
    ) -> None:
        self._rpc_call = rpc_call
        self._default_account = default_account
        self._gas_limit = gas_limit
        self._gas_price = gas_price

        addrs = contract_addresses or {}
        self._farming_addr = addrs.get("testnetFarmingAccounting")

        self._iface = AbiInterface(TESTNET_FARMING_ABI)

    # --- Internal helpers ---

    def _require_address(self) -> str:
        if not self._farming_addr:
            raise ConfigurationError(
                "TestnetFarmingAccounting contract address not configured. Set it via contract_addresses."
            )
        return self._farming_addr

    def _eth_call(self, to: str, data: str) -> str:
        result = self._rpc_call("eth_call", [{"to": to, "data": data}, "latest"])
        return result

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
        return self._rpc_call("eth_sendTransaction", [tx])

    def _resolve_address(self, address: Optional[str]) -> str:
        target = address or self._default_account
        if not target:
            raise ConfigurationError("No address provided and no defaultAccount configured.")
        return target

    # -------------------------------------------------------------------
    # Score Queries
    # -------------------------------------------------------------------

    def get_my_score(self, address: Optional[str] = None) -> int:
        """Get participant's contribution score from the snapshot.

        Data source: TestnetFarmingAccounting.snapshotScores(address) via eth_call.

        Args:
            address: Participant address. Uses default_account if not provided.

        Returns:
            Contribution score (raw uint256).
        """
        addr = self._require_address()
        target = self._resolve_address(address)

        data = self._iface.encode_function_data("snapshotScores", [target])
        result = self._eth_call(addr, data)
        (score,) = self._iface.decode_function_result("snapshotScores", result)
        return int(score)

    def get_my_share(self, address: Optional[str] = None) -> int:
        """Calculate participant's USD share of treasury distribution pool.

        Data source: TestnetFarmingAccounting.calculateShare(address) via eth_call.

        Args:
            address: Participant address. Uses default_account if not provided.

        Returns:
            USD share amount (stablecoin decimals, e.g., 6 for USDC).
        """
        addr = self._require_address()
        target = self._resolve_address(address)

        data = self._iface.encode_function_data("calculateShare", [target])
        result = self._eth_call(addr, data)
        (share,) = self._iface.decode_function_result("calculateShare", result)
        return int(share)

    # -------------------------------------------------------------------
    # Leaderboard
    # -------------------------------------------------------------------

    def get_leaderboard(self, count: int = 20) -> List[Dict[str, Any]]:
        """Get top N contributors with scores and shares.

        Data source: TestnetFarmingAccounting.getTopContributors(uint256) via eth_call.

        Args:
            count: Maximum number of contributors to return (default 20).

        Returns:
            List of dicts with keys: address, score, share.
        """
        addr = self._require_address()

        data = self._iface.encode_function_data("getTopContributors", [count])
        result = self._eth_call(addr, data)
        decoded = self._iface.decode_function_result("getTopContributors", result)
        addrs, scores_list, shares_list = decoded

        leaderboard: List[Dict[str, Any]] = []
        for i in range(len(addrs)):
            leaderboard.append({
                "address": addrs[i],
                "score": int(scores_list[i]),
                "share": int(shares_list[i]),
            })

        return leaderboard

    # -------------------------------------------------------------------
    # Claim
    # -------------------------------------------------------------------

    def claim(self) -> str:
        """Claim stablecoin distribution. Returns tx hash.

        Data source: TestnetFarmingAccounting.claim() via eth_sendTransaction.

        Returns:
            Transaction hash.
        """
        addr = self._require_address()
        data = self._iface.encode_function_data("claim")
        return self._send_transaction(addr, data)

    def has_claimed(self, address: Optional[str] = None) -> bool:
        """Check if participant has already claimed.

        Data source: TestnetFarmingAccounting.hasClaimed(address) via eth_call.

        Args:
            address: Participant address. Uses default_account if not provided.

        Returns:
            True if already claimed.
        """
        addr = self._require_address()
        target = self._resolve_address(address)

        data = self._iface.encode_function_data("hasClaimed", [target])
        result = self._eth_call(addr, data)
        (claimed,) = self._iface.decode_function_result("hasClaimed", result)
        return bool(claimed)

    # -------------------------------------------------------------------
    # Distribution Info
    # -------------------------------------------------------------------

    def get_distribution_info(self) -> Dict[str, Any]:
        """Get distribution pool info (stablecoin, total pool, total claimed).

        Data source: TestnetFarmingAccounting state variables via eth_call.

        Returns:
            Dictionary with keys: distribution_active, stablecoin, distribution_pool,
            total_claimed, remaining, total_snapshot_score, participant_count,
            snapshot_taken.
        """
        addr = self._require_address()

        # distributionActive
        active_data = self._iface.encode_function_data("distributionActive")
        active_result = self._eth_call(addr, active_data)
        (active,) = self._iface.decode_function_result("distributionActive", active_result)

        # distributionStablecoin
        stablecoin_data = self._iface.encode_function_data("distributionStablecoin")
        stablecoin_result = self._eth_call(addr, stablecoin_data)
        (stablecoin,) = self._iface.decode_function_result("distributionStablecoin", stablecoin_result)

        # distributionPool
        pool_data = self._iface.encode_function_data("distributionPool")
        pool_result = self._eth_call(addr, pool_data)
        (pool,) = self._iface.decode_function_result("distributionPool", pool_result)

        # totalClaimed
        claimed_data = self._iface.encode_function_data("totalClaimed")
        claimed_result = self._eth_call(addr, claimed_data)
        (total_claimed,) = self._iface.decode_function_result("totalClaimed", claimed_result)

        # remainingDistribution
        remaining_data = self._iface.encode_function_data("remainingDistribution")
        remaining_result = self._eth_call(addr, remaining_data)
        (remaining,) = self._iface.decode_function_result("remainingDistribution", remaining_result)

        # totalSnapshotScore
        score_data = self._iface.encode_function_data("totalSnapshotScore")
        score_result = self._eth_call(addr, score_data)
        (total_score,) = self._iface.decode_function_result("totalSnapshotScore", score_result)

        # snapshotParticipantCount
        count_data = self._iface.encode_function_data("snapshotParticipantCount")
        count_result = self._eth_call(addr, count_data)
        (participant_count,) = self._iface.decode_function_result("snapshotParticipantCount", count_result)

        # snapshotTaken
        snapshot_data = self._iface.encode_function_data("snapshotTaken")
        snapshot_result = self._eth_call(addr, snapshot_data)
        (snapshot_taken,) = self._iface.decode_function_result("snapshotTaken", snapshot_result)

        return {
            "distribution_active": bool(active),
            "stablecoin": stablecoin,
            "distribution_pool": int(pool),
            "total_claimed": int(total_claimed),
            "remaining": int(remaining),
            "total_snapshot_score": int(total_score),
            "participant_count": int(participant_count),
            "snapshot_taken": bool(snapshot_taken),
        }

    def is_in_snapshot(self, address: Optional[str] = None) -> bool:
        """Check if an address is included in the snapshot.

        Data source: TestnetFarmingAccounting.isSnapshotted(address) via eth_call.

        Args:
            address: Address to check. Uses default_account if not provided.

        Returns:
            True if address is in the snapshot.
        """
        addr = self._require_address()
        target = self._resolve_address(address)

        data = self._iface.encode_function_data("isSnapshotted", [target])
        result = self._eth_call(addr, data)
        (is_in,) = self._iface.decode_function_result("isSnapshotted", result)
        return bool(is_in)

    def get_claimed_amount(self, address: Optional[str] = None) -> int:
        """Get the amount a participant has already claimed.

        Data source: TestnetFarmingAccounting.claimedAmount(address) via eth_call.

        Args:
            address: Address to query. Uses default_account if not provided.

        Returns:
            Amount claimed in stablecoin native decimals.
        """
        addr = self._require_address()
        target = self._resolve_address(address)

        data = self._iface.encode_function_data("claimedAmount", [target])
        result = self._eth_call(addr, data)
        (amount,) = self._iface.decode_function_result("claimedAmount", result)
        return int(amount)
