"""PBA-L6b-028 and PBA-L6b-040: ClassroomManager.

L6b-028: the default invite code was ``classroom-<ms timestamp>``. keccak of it
is published on-chain at createClassroom, and the block timestamp bounds the
millisecond window, so a +/-60 s search (120k hashes, < 1 s) recovered it.
The default is now ``secrets.token_urlsafe(16)`` (128 bits) and is returned to
the caller via ``last_invite_code``.

L6b-040: the SDK encoded ``enrollWithCode(bytes32 hash)``, the pre-CHAIN-B-C009
ABI. ClassroomRegistry now takes ``enrollWithCode(bytes inviteCode)`` and hashes
it on-chain, so every SDK enroll hit a selector the contract does not have. The
parity test below pins every ClassroomRegistry selector the SDK encodes to the
contract source (citrate-chain contracts/src/ClassroomRegistry.sol @ 21726055).
It also caught ``getClassroom``: it returns a ``Classroom`` struct with a
dynamic member (ABI: one tuple, behind an offset), which the SDK decoded flat.
"""
from __future__ import annotations

import time
from typing import Any

from eth_abi import encode as abi_encode

from citrate_sdk.abi import AbiInterface, keccak256, keccak256_text
from citrate_sdk.learning import CLASSROOM_REGISTRY_ABI, ClassroomManager

# Signatures as declared in ClassroomRegistry.sol @ citrate-chain 21726055
# (external/public functions and public-mapping getters the SDK calls).
CONTRACT_SIGNATURES = {
    "createClassroom": "createClassroom(string,uint256,bytes32)",
    "enrollWithCode": "enrollWithCode(bytes)",
    "unenroll": "unenroll()",
    "removeStudent": "removeStudent(address)",
    "whitelistModel": "whitelistModel(bytes32)",
    "removeModel": "removeModel(bytes32)",
    "rotateInviteCode": "rotateInviteCode(bytes32)",
    "getClassroom": "getClassroom(address)",
    "isStudentEnrolled": "isStudentEnrolled(address,address)",
    "getStudentTeacher": "getStudentTeacher(address)",
    "isModelWhitelistedFor": "isModelWhitelistedFor(address,bytes32)",
    "canStudentAccessModel": "canStudentAccessModel(address,bytes32)",
    "classroomExists": "classroomExists(address)",
    "activeInviteCode": "activeInviteCode(address)",  # public mapping getter
}

TEACHER = "0x" + "01" * 20
REGISTRY = "0x" + "02" * 20


def _manager(sent: dict[str, Any], result: str = "0x") -> ClassroomManager:
    def rpc(method: str, params: Any) -> Any:
        if method == "eth_sendTransaction":
            sent["tx"] = params[0]
            return "0xhash"
        if method == "eth_chainId":
            return hex(40204)
        if method == "eth_call":
            return result
        raise AssertionError(method)
    return ClassroomManager(rpc, default_account=TEACHER, classroom_address=REGISTRY)


def test_every_sdk_selector_matches_the_contract() -> None:
    iface = AbiInterface(CLASSROOM_REGISTRY_ABI)
    names = {frag.split("function ")[1].split("(")[0] for frag in CLASSROOM_REGISTRY_ABI}
    assert names <= set(CONTRACT_SIGNATURES), names - set(CONTRACT_SIGNATURES)
    for name in names:
        fn = iface._funcs[name]
        assert fn.selector == keccak256(CONTRACT_SIGNATURES[name].encode())[:4], name


def test_enroll_sends_the_raw_code_as_bytes() -> None:
    sent: dict[str, Any] = {}
    _manager(sent).enroll("secret-code")
    data = sent["tx"]["data"]
    assert data[2:10] == keccak256(b"enrollWithCode(bytes)")[:4].hex()
    assert data[10:] == abi_encode(["bytes"], [b"secret-code"]).hex()


def test_default_invite_code_is_unguessable_and_returned() -> None:
    sent: dict[str, Any] = {}
    mgr = _manager(sent)
    t0 = int(time.time() * 1000)
    mgr.create("Grade 5", 30)
    code = mgr.last_invite_code
    assert code is not None and len(code) >= 22 and not code.startswith("classroom-")
    commit = bytes.fromhex(sent["tx"]["data"][2:])[4 + 64: 4 + 96]
    assert commit == bytes.fromhex(keccak256_text(code)[2:])
    # The audit's brute force (+/-2 s of millisecond timestamps) finds nothing.
    for ms in range(t0 - 2_000, t0 + 2_000):
        assert bytes.fromhex(keccak256_text(f"classroom-{ms}")[2:]) != commit
    mgr.create("Grade 6", 30)
    assert mgr.last_invite_code != code


def test_explicit_invite_code_is_used_verbatim() -> None:
    sent: dict[str, Any] = {}
    mgr = _manager(sent)
    mgr.create("Grade 5", 30, invite_code="teacher-chosen")
    assert mgr.last_invite_code == "teacher-chosen"
    commit = bytes.fromhex(sent["tx"]["data"][2:])[4 + 64: 4 + 96]
    assert commit == bytes.fromhex(keccak256_text("teacher-chosen")[2:])


def test_get_classroom_decodes_the_struct_return() -> None:
    struct = (TEACHER, "Grade 5", 30, 7, 1_700_000_000, True)
    ret = "0x" + abi_encode(["(address,string,uint256,uint256,uint256,bool)"], [struct]).hex()
    info = _manager({}, result=ret).get_classroom(TEACHER)
    assert (info.teacher.lower(), info.name, info.max_students, info.student_count, info.created_at, info.exists) == \
        (TEACHER, "Grade 5", 30, 7, 1_700_000_000, True)
