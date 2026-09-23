"""
Tests for the learning, staking, and classroom managers.

Verifies that each method:
  - Constructs the correct ABI-encoded calldata (matching the JS SDK's function selectors)
  - Calls the correct contract address
  - Properly decodes return values
  - Raises ConfigurationError when contract addresses are missing
"""

from unittest.mock import MagicMock

import pytest

from citrate_sdk.abi import AbiInterface, from_wei, keccak256_text, to_wei
from citrate_sdk.errors import ConfigurationError
from citrate_sdk.learning import (
    CLASSROOM_REGISTRY_ABI,
    CONTRIBUTION_ABI,
    LEARNING_CYCLE_ABI,
    LEARNING_POOL_ABI,
    LIQUID_STAKING_ABI,
    ClassroomManager,
    LearningManager,
    StakingManager,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ZERO_ADDR = "0x" + "0" * 40
FAKE_POOL_ADDR = "0x" + "aa" * 20
FAKE_CYCLE_ADDR = "0x" + "bb" * 20
FAKE_CONTRIB_ADDR = "0x" + "cc" * 20
FAKE_STAKING_ADDR = "0x" + "dd" * 20
FAKE_CLASSROOM_ADDR = "0x" + "ee" * 20
DEFAULT_ACCOUNT = "0x" + "11" * 20

# Build ABI interfaces to construct expected calldata in tests
_pool_iface = AbiInterface(LEARNING_POOL_ABI)
_cycle_iface = AbiInterface(LEARNING_CYCLE_ABI)
_contrib_iface = AbiInterface(CONTRIBUTION_ABI)
_staking_iface = AbiInterface(LIQUID_STAKING_ABI)
_classroom_iface = AbiInterface(CLASSROOM_REGISTRY_ABI)


def _encode_uint256(val: int) -> str:
    """ABI-encode a single uint256 as a 0x-prefixed 64-hex-char result."""
    return "0x" + val.to_bytes(32, "big").hex()


def _encode_bool(val: bool) -> str:
    return _encode_uint256(1 if val else 0)


# ---------------------------------------------------------------------------
# LearningManager Tests
# ---------------------------------------------------------------------------

class TestLearningManager:
    """Tests for LearningManager."""

    def _make_manager(self, rpc_call=None):
        return LearningManager(
            rpc_call=rpc_call or MagicMock(),
            default_account=DEFAULT_ACCOUNT,
            contract_addresses={
                "learningPool": FAKE_POOL_ADDR,
                "learningCycleManager": FAKE_CYCLE_ADDR,
                "contributionAccounting": FAKE_CONTRIB_ADDR,
            },
        )

    def test_missing_learning_pool_address(self):
        """Raises ConfigurationError when learningPool address not set."""
        mgr = LearningManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="learningPool"):
            mgr.list_pools()

    def test_missing_cycle_address(self):
        """Raises ConfigurationError when learningCycleManager address not set."""
        mgr = LearningManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="learningCycleManager"):
            mgr.get_cycle_status()

    def test_missing_contrib_address(self):
        """Raises ConfigurationError when contributionAccounting address not set."""
        mgr = LearningManager(rpc_call=MagicMock(), contract_addresses={})
        with pytest.raises(ConfigurationError, match="contributionAccounting"):
            mgr.get_contributions("0x" + "ab" * 20)

    def test_list_pools_empty(self):
        """list_pools returns [] when nextPoolId is 0."""
        rpc = MagicMock(return_value=_encode_uint256(0))
        mgr = self._make_manager(rpc)
        pools = mgr.list_pools()
        assert pools == []
        # Verify we called eth_call with correct target
        call_args = rpc.call_args_list[0]
        assert call_args[0][0] == "eth_call"
        assert call_args[0][1][0]["to"] == FAKE_POOL_ADDR

    def test_join_pool_calldata(self):
        """join_pool sends correct calldata and value."""
        rpc = MagicMock(return_value="0xfake_tx_hash")
        mgr = self._make_manager(rpc)
        result = mgr.join_pool(pool_id=5, stake_amount="10")
        assert result == "0xfake_tx_hash"
        call_args = rpc.call_args_list[0]
        assert call_args[0][0] == "eth_sendTransaction"
        tx = call_args[0][1][0]
        assert tx["to"] == FAKE_POOL_ADDR
        expected_data = _pool_iface.encode_function_data("joinPool", [5])
        assert tx["data"] == expected_data
        assert int(tx["value"], 16) == to_wei("10")

    def test_leave_pool_calldata(self):
        """leave_pool sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.leave_pool(pool_id=3)
        tx = rpc.call_args_list[0][0][1][0]
        expected = _pool_iface.encode_function_data("leavePool", [3])
        assert tx["data"] == expected

    def test_create_pool_calldata(self):
        """create_pool sends correct ABI-encoded data with access enum."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.create_pool("My Pool", "A test pool", "InviteOnly", "5")
        tx = rpc.call_args_list[0][0][1][0]
        expected = _pool_iface.encode_function_data("createPool", [
            "My Pool", "A test pool", 1, to_wei("5"),
        ])
        assert tx["data"] == expected
        assert int(tx["value"], 16) == to_wei("5")

    def test_register_for_cycle_calldata(self):
        """register_for_cycle sends correct calldata to cycle contract."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.register_for_cycle(cycle_id=7)
        tx = rpc.call_args_list[0][0][1][0]
        expected = _cycle_iface.encode_function_data("registerParticipant", [7])
        assert tx["data"] == expected
        assert tx["to"] == FAKE_CYCLE_ADDR

    def test_claim_cycle_reward_calldata(self):
        """claim_cycle_reward sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.claim_cycle_reward(cycle_id=2)
        tx = rpc.call_args_list[0][0][1][0]
        expected = _cycle_iface.encode_function_data("claimCycleReward", [2])
        assert tx["data"] == expected

    def test_claim_contribution_rewards_calldata(self):
        """claim_contribution_rewards sends correct calldata to contrib contract."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.claim_contribution_rewards()
        tx = rpc.call_args_list[0][0][1][0]
        expected = _contrib_iface.encode_function_data("claimRewards")
        assert tx["data"] == expected
        assert tx["to"] == FAKE_CONTRIB_ADDR

    def test_get_cycle_status_zero(self):
        """get_cycle_status returns zero-state when currentCycleId is 0."""
        rpc = MagicMock(return_value=_encode_uint256(0))
        mgr = self._make_manager(rpc)
        status = mgr.get_cycle_status()
        assert status.cycle_id == 0
        assert status.state == "Open"
        assert status.participant_count == 0

    def test_no_default_account_write(self):
        """Write methods raise ConfigurationError without default_account."""
        mgr = LearningManager(
            rpc_call=MagicMock(),
            default_account=None,
            contract_addresses={"learningPool": FAKE_POOL_ADDR},
        )
        with pytest.raises(ConfigurationError, match="defaultAccount"):
            mgr.join_pool(1, "10")


# ---------------------------------------------------------------------------
# StakingManager Tests
# ---------------------------------------------------------------------------

class TestStakingManager:
    """Tests for StakingManager."""

    def _make_manager(self, rpc_call=None):
        return StakingManager(
            rpc_call=rpc_call or MagicMock(),
            default_account=DEFAULT_ACCOUNT,
            staking_address=FAKE_STAKING_ADDR,
        )

    def test_missing_staking_address(self):
        """Raises ConfigurationError when staking address not set."""
        mgr = StakingManager(rpc_call=MagicMock())
        with pytest.raises(ConfigurationError, match="LiquidStakingPool"):
            mgr.deposit("10")

    def test_deposit_calldata(self):
        """deposit sends correct calldata and value."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.deposit("50")
        tx = rpc.call_args_list[0][0][1][0]
        expected = _staking_iface.encode_function_data("deposit")
        assert tx["data"] == expected
        assert int(tx["value"], 16) == to_wei("50")
        assert tx["to"] == FAKE_STAKING_ADDR

    def test_withdraw_calldata(self):
        """withdraw encodes requestWithdrawal with share amount."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.withdraw("25")
        tx = rpc.call_args_list[0][0][1][0]
        expected = _staking_iface.encode_function_data("requestWithdrawal", [to_wei("25")])
        assert tx["data"] == expected

    def test_claim_withdrawal_calldata(self):
        """claim_withdrawal sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.claim_withdrawal(request_id=42)
        tx = rpc.call_args_list[0][0][1][0]
        expected = _staking_iface.encode_function_data("claimWithdrawal", [42])
        assert tx["data"] == expected

    def test_preview_deposit_calldata(self):
        """preview_deposit sends correct eth_call data."""
        rpc = MagicMock(return_value=_encode_uint256(to_wei("49")))
        mgr = self._make_manager(rpc)
        result = mgr.preview_deposit("50")
        call_args = rpc.call_args_list[0]
        assert call_args[0][0] == "eth_call"
        tx = call_args[0][1][0]
        expected = _staking_iface.encode_function_data("previewDeposit", [to_wei("50")])
        assert tx["data"] == expected
        # Result should be parsed from wei
        assert result == from_wei(to_wei("49"))

    def test_preview_withdraw_calldata(self):
        """preview_withdraw sends correct eth_call data."""
        rpc = MagicMock(return_value=_encode_uint256(to_wei("24")))
        mgr = self._make_manager(rpc)
        mgr.preview_withdraw("25")
        call_args = rpc.call_args_list[0]
        tx = call_args[0][1][0]
        expected = _staking_iface.encode_function_data("previewWithdraw", [to_wei("25")])
        assert tx["data"] == expected

    def test_no_default_account_write(self):
        """Write operations raise when no default account."""
        mgr = StakingManager(
            rpc_call=MagicMock(),
            default_account=None,
            staking_address=FAKE_STAKING_ADDR,
        )
        with pytest.raises(ConfigurationError, match="defaultAccount"):
            mgr.deposit("10")


# ---------------------------------------------------------------------------
# ClassroomManager Tests
# ---------------------------------------------------------------------------

class TestClassroomManager:
    """Tests for ClassroomManager."""

    def _make_manager(self, rpc_call=None):
        return ClassroomManager(
            rpc_call=rpc_call or MagicMock(),
            default_account=DEFAULT_ACCOUNT,
            classroom_address=FAKE_CLASSROOM_ADDR,
        )

    def test_missing_classroom_address(self):
        """Raises ConfigurationError when classroom address not set."""
        mgr = ClassroomManager(rpc_call=MagicMock())
        with pytest.raises(ConfigurationError, match="ClassroomRegistry"):
            mgr.unenroll()

    def test_enroll_calldata(self):
        """enroll hashes invite code and sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.enroll("secret-code-123")
        tx = rpc.call_args_list[0][0][1][0]
        expected_hash = keccak256_text("secret-code-123")
        expected = _classroom_iface.encode_function_data(
            "enrollWithCode", [bytes.fromhex(expected_hash[2:])]
        )
        assert tx["data"] == expected
        assert tx["to"] == FAKE_CLASSROOM_ADDR

    def test_unenroll_calldata(self):
        """unenroll sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.unenroll()
        tx = rpc.call_args_list[0][0][1][0]
        expected = _classroom_iface.encode_function_data("unenroll")
        assert tx["data"] == expected

    def test_deploy_model_calldata(self):
        """deploy_model sends whitelistModel with correct bytes32."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        model_hash = "0x" + "ab" * 32
        mgr.deploy_model(model_hash)
        tx = rpc.call_args_list[0][0][1][0]
        expected = _classroom_iface.encode_function_data(
            "whitelistModel", [bytes.fromhex("ab" * 32)]
        )
        assert tx["data"] == expected

    def test_remove_model_calldata(self):
        """remove_model sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        model_hash = "cd" * 32  # no 0x prefix
        mgr.remove_model(model_hash)
        tx = rpc.call_args_list[0][0][1][0]
        expected = _classroom_iface.encode_function_data(
            "removeModel", [bytes.fromhex("cd" * 32)]
        )
        assert tx["data"] == expected

    def test_rotate_invite_code_calldata(self):
        """rotate_invite_code hashes new code and sends correct calldata."""
        rpc = MagicMock(return_value="0xtx")
        mgr = self._make_manager(rpc)
        mgr.rotate_invite_code("new-secret")
        tx = rpc.call_args_list[0][0][1][0]
        expected_hash = keccak256_text("new-secret")
        expected = _classroom_iface.encode_function_data(
            "rotateInviteCode", [bytes.fromhex(expected_hash[2:])]
        )
        assert tx["data"] == expected

    def test_can_student_access_model_calldata(self):
        """can_student_access_model calls correct contract."""
        rpc = MagicMock(return_value=_encode_bool(True))
        mgr = self._make_manager(rpc)
        student = "0x" + "22" * 20
        model = "0x" + "ff" * 32
        result = mgr.can_student_access_model(student, model)
        assert result is True
        call_args = rpc.call_args_list[0]
        assert call_args[0][0] == "eth_call"
        assert call_args[0][1][0]["to"] == FAKE_CLASSROOM_ADDR

    def test_get_student_teacher_calldata(self):
        """get_student_teacher calls getStudentTeacher on classroom contract."""
        "0x" + "33" * 20
        # ABI-encode an address return: 12 zero bytes + 20 address bytes
        encoded_addr = "0x" + "00" * 12 + "33" * 20
        rpc = MagicMock(return_value=encoded_addr)
        mgr = self._make_manager(rpc)
        student = "0x" + "44" * 20
        mgr.get_student_teacher(student)
        call_args = rpc.call_args_list[0]
        assert call_args[0][0] == "eth_call"
        tx = call_args[0][1][0]
        expected = _classroom_iface.encode_function_data("getStudentTeacher", [student])
        assert tx["data"] == expected

    def test_no_default_account_write(self):
        """Write methods raise ConfigurationError without default_account."""
        mgr = ClassroomManager(
            rpc_call=MagicMock(),
            default_account=None,
            classroom_address=FAKE_CLASSROOM_ADDR,
        )
        with pytest.raises(ConfigurationError, match="defaultAccount"):
            mgr.unenroll()


# ---------------------------------------------------------------------------
# ABI interface selector tests
# ---------------------------------------------------------------------------

class TestAbiSelectors:
    """Verify function selectors match what ethers.Interface generates."""

    def test_join_pool_selector(self):
        """joinPool(uint256) selector = keccak256('joinPool(uint256)')[:4]."""
        iface = AbiInterface(LEARNING_POOL_ABI)
        data = iface.encode_function_data("joinPool", [0])
        # keccak256("joinPool(uint256)") first 4 bytes
        from citrate_sdk.abi import keccak256
        expected_selector = keccak256(b"joinPool(uint256)")[:4].hex()
        assert data[2:10] == expected_selector

    def test_deposit_selector(self):
        """deposit() selector = keccak256('deposit()')[:4]."""
        iface = AbiInterface(LIQUID_STAKING_ABI)
        data = iface.encode_function_data("deposit")
        from citrate_sdk.abi import keccak256
        expected_selector = keccak256(b"deposit()")[:4].hex()
        assert data[2:10] == expected_selector

    def test_enroll_with_code_selector(self):
        """enrollWithCode(bytes32) selector matches."""
        iface = AbiInterface(CLASSROOM_REGISTRY_ABI)
        dummy = bytes(32)
        data = iface.encode_function_data("enrollWithCode", [dummy])
        from citrate_sdk.abi import keccak256
        expected_selector = keccak256(b"enrollWithCode(bytes32)")[:4].hex()
        assert data[2:10] == expected_selector
