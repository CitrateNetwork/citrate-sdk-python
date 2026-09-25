"""ClassroomRegistry invite-key enrolment (citrate-chain d89200c2, #222).

The registry's invite is now a key pair. The teacher registers
``keccak256(abi.encodePacked(inviteKey))``, where ``inviteKey`` is the address of
the invite secret. A student enrols with
``enrollWithInvite(inviteKey, signature)``, where ``signature`` is the invite
secret's EIP-191 signature over
``enrollmentDigest(teacher, student, inviteCodeHash) =
keccak256(abi.encode(ENROLL_TAG, chainid, registry, teacher, student, inviteCodeHash))``.
The digest here is computed independently of the SDK.
"""
from __future__ import annotations

import warnings
from typing import Any

import pytest
from eth_abi import decode as abi_decode
from eth_abi import encode as abi_encode
from eth_account import Account
from eth_account.messages import encode_defunct
from eth_utils import keccak, to_checksum_address

from citrate_sdk.abi import keccak256
from citrate_sdk.learning import ClassroomManager

TEACHER = to_checksum_address("0x" + "01" * 20)
STUDENT = to_checksum_address("0x" + "0a" * 20)
REGISTRY = to_checksum_address("0x" + "02" * 20)
ENROLL_TAG = keccak(b"CitrateClassroomRegistry.Enroll.v1")


def _commitment(invite_key: str) -> bytes:
    return keccak(bytes.fromhex(invite_key[2:]))


def _mgr(account: str, code_to_teacher: dict[bytes, str] | None = None, chain: int = 40204) -> tuple[ClassroomManager, list[Any]]:
    sent: list[Any] = []

    def rpc(method: str, params: Any) -> Any:
        if method == "eth_chainId":
            return hex(chain)
        if method == "eth_sendTransaction":
            sent.append(params[0])
            return "0xhash"
        if method == "eth_call":
            data = bytes.fromhex(params[0]["data"][2:])
            assert data[:4] == keccak(b"codeToTeacher(bytes32)")[:4]
            teacher = (code_to_teacher or {}).get(data[4:36], "0x" + "00" * 20)
            return "0x" + abi_encode(["address"], [teacher]).hex()
        raise AssertionError(method)
    return ClassroomManager(rpc, default_account=account, classroom_address=REGISTRY), sent


class TestCreate:
    def test_create_generates_an_invite_key_and_registers_its_commitment(self) -> None:
        mgr, sent = _mgr(TEACHER)
        mgr.create("Grade 5", 30)
        secret = mgr.last_invite_code
        assert secret is not None and secret.startswith("0x") and len(secret) == 66
        invite_key = Account.from_key(secret).address
        data = bytes.fromhex(sent[-1]["data"][2:])
        assert data[:4] == keccak(b"createClassroom(string,uint256,bytes32)")[:4]
        name, max_students, commit = abi_decode(["string", "uint256", "bytes32"], data[4:])
        assert (name, max_students, commit) == ("Grade 5", 30, _commitment(invite_key))
        mgr.create("Grade 6", 30)
        assert mgr.last_invite_code != secret

    def test_create_accepts_a_caller_supplied_invite_secret(self) -> None:
        secret = "0x" + "5a" * 32
        mgr, sent = _mgr(TEACHER)
        mgr.create("c", 3, invite_code=secret)
        assert mgr.last_invite_code == secret
        commit = abi_decode(["string", "uint256", "bytes32"], bytes.fromhex(sent[-1]["data"][10:]))[2]
        assert commit == _commitment(Account.from_key(secret).address)

    @pytest.mark.parametrize("bad", ["teacher-chosen", "0x1234", "0x" + "zz" * 32, "0x" + "00" * 32])
    def test_create_refuses_a_non_key_invite_code(self, bad: str) -> None:
        mgr, sent = _mgr(TEACHER)
        with pytest.raises(ValueError, match="invite secret"):
            mgr.create("c", 3, invite_code=bad)
        assert sent == []

    def test_rotate_uses_the_same_key_pair_scheme(self) -> None:
        mgr, sent = _mgr(TEACHER)
        mgr.rotate_invite_code()
        secret = mgr.last_invite_code
        assert secret is not None
        data = bytes.fromhex(sent[-1]["data"][2:])
        assert data[:4] == keccak(b"rotateInviteCode(bytes32)")[:4]
        assert data[4:36] == _commitment(Account.from_key(secret).address)


class TestEnrollWithInvite:
    secret = "0x" + "7b" * 32

    def _setup(self, chain: int = 40204) -> tuple[ClassroomManager, list[Any], str]:
        invite_key = Account.from_key(self.secret).address
        mgr, sent = _mgr(STUDENT, {_commitment(invite_key): TEACHER}, chain=chain)
        return mgr, sent, invite_key

    def test_sends_invite_key_and_a_signature_bound_to_the_student(self) -> None:
        mgr, sent, invite_key = self._setup()
        mgr.enroll_with_invite(self.secret)
        data = bytes.fromhex(sent[-1]["data"][2:])
        assert data[:4] == keccak(b"enrollWithInvite(address,bytes)")[:4]
        key, sig = abi_decode(["address", "bytes"], data[4:])
        assert to_checksum_address(key) == invite_key
        digest = keccak(abi_encode(
            ["bytes32", "uint256", "address", "address", "address", "bytes32"],
            [ENROLL_TAG, 40204, REGISTRY, TEACHER, STUDENT, _commitment(invite_key)],
        ))
        assert Account.recover_message(encode_defunct(primitive=digest), signature=sig) == invite_key
        # The secret itself never appears in calldata.
        assert self.secret[2:] not in sent[-1]["data"]

    def test_signature_is_bound_to_the_chain_id(self) -> None:
        mgr, sent, invite_key = self._setup(chain=31337)
        mgr._expected_chain_id = 31337
        mgr.enroll_with_invite(self.secret)
        _, sig = abi_decode(["address", "bytes"], bytes.fromhex(sent[-1]["data"][10:]))
        d40204 = keccak(abi_encode(["bytes32", "uint256", "address", "address", "address", "bytes32"],
                                   [ENROLL_TAG, 40204, REGISTRY, TEACHER, STUDENT, _commitment(invite_key)]))
        assert Account.recover_message(encode_defunct(primitive=d40204), signature=sig) != invite_key

    def test_unknown_or_rotated_invite_is_refused_before_sending(self) -> None:
        mgr, sent = _mgr(STUDENT, {})
        with pytest.raises(ValueError, match="not an active invite"):
            mgr.enroll_with_invite(self.secret)
        assert sent == []

    def test_malformed_secret_is_refused(self) -> None:
        mgr, sent, _ = self._setup()
        with pytest.raises(ValueError, match="invite secret"):
            mgr.enroll_with_invite("classroom-code")
        assert sent == []

    def test_needs_a_student_account(self) -> None:
        invite_key = Account.from_key(self.secret).address
        mgr, _ = _mgr(STUDENT, {_commitment(invite_key): TEACHER})
        mgr._default_account = None
        with pytest.raises(Exception, match="defaultAccount"):
            mgr.enroll_with_invite(self.secret)

    def test_old_enroll_is_deprecated_and_delegates(self) -> None:
        mgr, sent, _ = self._setup()
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            mgr.enroll(self.secret)
        assert any(issubclass(x.category, DeprecationWarning) for x in w)
        assert sent[-1]["data"][2:10] == keccak(b"enrollWithInvite(address,bytes)")[:4].hex()

    def test_old_enroll_refuses_a_plain_text_code(self) -> None:
        mgr, sent, _ = self._setup()
        with pytest.raises(ValueError, match="invite secret"), warnings.catch_warnings():
            warnings.simplefilter("ignore")
            mgr.enroll("secret-code")
        assert sent == []


def test_removed_selector_is_not_encoded() -> None:
    from citrate_sdk.abi import AbiInterface
    from citrate_sdk.learning import CLASSROOM_REGISTRY_ABI
    sels = {fn.selector for fn in AbiInterface(CLASSROOM_REGISTRY_ABI)._funcs.values()}
    assert keccak256(b"enrollWithCode(bytes)")[:4] not in sels
    assert keccak256(b"enrollWithCode(bytes32)")[:4] not in sels
