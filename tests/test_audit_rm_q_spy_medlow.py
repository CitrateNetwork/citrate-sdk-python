"""RM-Q (2026-09-07) — regression tripwires for the open MEDIUM + LOW findings in
the 2026-09-02 graded federation audit against citrate-sdk-python.

Each test is RED on the pre-fix code and GREEN after the remediation.

  * SPY-B-006  — receipt log-topic match used ASCII hex of the event NAME
                 (`ascii('ModelDep')`) instead of keccak256 of the event
                 SIGNATURE, so deploy/inference always raised after broadcast.
  * SPY-B-007  — deploy/inference sent to `0x0100..0100/0101` (wrong high byte),
                 not the canonical `0x0000..0100/0101` from the vendored table.
  * SPY-B-008  — `cryptography~=46.0` structurally excluded every fixed release.
  * SPY-B-009  — plaintext transport WARNED and proceeded (see test_url_security).
  * SPY-B-012  — the CLI accepted the gateway key as a `--api-key` value on argv.
  * SPY-B-013  — `encrypted=True` on a keyless client SILENTLY sent plaintext;
                 `get_chain_id()` returned a hex string despite `-> int`.
  * CIT-SDKPY-01 — V2 envelope was documented as forward-secret; it is not.
  * CIT-SDKPY-02 — the SDK's own inference decrypt did not pin the response sender.
  * CIT-SDKPY-03 — the IPFS manager defaulted to third-party fallbacks + no timeout.
"""
from __future__ import annotations

import inspect
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from citrate_sdk._generated import contract
from citrate_sdk.client import (
    INFERENCE_COMPLETE_EVENT_SIGNATURE,
    MODEL_DEPLOYED_EVENT_SIGNATURE,
    CitrateClient,
    _event_topic,
)

_REPO = Path(__file__).resolve().parent.parent
# valid, nonzero secp256k1 private keys for offline crypto tests
_CLIENT_KEY = "0x" + "11" * 32


def _client(**kw):
    return CitrateClient(rpc_url="http://localhost:8545", **kw)


# ── SPY-B-006 · receipt topics match keccak256 of the event signature ─────────

def test_extract_model_id_matches_keccak_topic():
    """GREEN: a real keccak topic is recognized (pre-fix it never matched)."""
    c = _client()
    topic = _event_topic(MODEL_DEPLOYED_EVENT_SIGNATURE)
    receipt = {"logs": [{"topics": [topic], "data": "0x" + "ab" * 40}]}
    model_id = c._extract_model_id_from_receipt(receipt)
    assert model_id.startswith("0x")


def test_extract_inference_output_matches_keccak_topic():
    c = _client()
    topic = _event_topic(INFERENCE_COMPLETE_EVENT_SIGNATURE)
    payload = json.dumps({"class": "cat"}).encode().hex()
    receipt = {"logs": [{"topics": [topic], "data": "0x" + payload}]}
    out = c._extract_inference_output(receipt)
    assert out == {"class": "cat"}


def test_ascii_name_topic_is_not_what_we_match():
    """RC-8: the pre-fix literal (ascii of 'ModelDep') must NOT match a topic."""
    c = _client()
    ascii_literal = "0x" + b"ModelDeployed".hex()[:16]  # 0x4d6f64656c446570
    assert ascii_literal == "0x4d6f64656c446570"
    # the correct keccak topic is not the ascii literal
    assert not _event_topic(MODEL_DEPLOYED_EVENT_SIGNATURE).startswith(ascii_literal)
    # a receipt carrying the old broken literal is not recognized
    receipt = {"logs": [{"topics": [ascii_literal], "data": "0x" + "ab" * 40}],
               "transactionHash": "0xdeadbeef"}
    with pytest.raises(Exception) as ei:
        c._extract_model_id_from_receipt(receipt)
    # the failure now names the tx so a caller can recover instead of resubmitting
    assert "0xdeadbeef" in str(ei.value)


# ── SPY-B-007 · deploy/inference dispatch to canonical precompiles ────────────

def test_precompile_helper_returns_canonical_addresses():
    c = _client()
    assert c._precompile("ModelDeploy") == contract.precompiles()["ModelDeploy"]
    assert c._precompile("ModelDeploy").lower() == "0x0000000000000000000000000000000000000100"
    assert c._precompile("ModelInference").lower() == "0x0000000000000000000000000000000000000101"


def test_precompile_unknown_name_fails_loud():
    c = _client()
    with pytest.raises(Exception):
        c._precompile("NoSuchPrecompile")


def test_inference_sends_to_canonical_precompile():
    """Behavioral: the address inference actually dispatches to is the canonical
    one from the vendored table, not a `0x0100..` literal."""
    c = _client(private_key=_CLIENT_KEY)
    captured = {}

    def fake_send(to_address, data, value=0, gas_limit=500000):
        captured["to"] = to_address
        return "0xhash"

    with patch.object(c, "_send_transaction", side_effect=fake_send), \
         patch.object(c, "_wait_for_receipt", return_value={}), \
         patch.object(c, "_extract_inference_output", return_value={"class": "x"}):
        c.inference("m", {"x": 1})

    assert captured["to"].lower() == "0x0000000000000000000000000000000000000101"
    assert not captured["to"].lower().startswith("0x01")


# ── SPY-B-008 · cryptography bound admits a non-vulnerable release ────────────

def test_cryptography_bound_admits_fixed_version():
    import sys

    if sys.version_info >= (3, 11):
        import tomllib
    else:  # Python 3.10: stdlib tomllib is 3.11+
        import tomli as tomllib
    from packaging.requirements import Requirement

    data = tomllib.loads((_REPO / "pyproject.toml").read_text())
    deps = data["project"]["dependencies"]
    crypto = next(d for d in deps if Requirement(d).name == "cryptography")
    spec = Requirement(crypto).specifier
    # lowest known fix is 48.0.1 — the range MUST admit it
    assert spec.contains("48.0.1"), crypto
    assert spec.contains("50.0.0"), crypto
    # and MUST NOT admit the known-vulnerable 46.x line
    assert not spec.contains("46.0.7"), crypto


# ── SPY-B-012 · CLI never takes the gateway key as a value on argv ────────────

def test_cli_gateway_has_no_api_key_value_flag():
    from citrate_sdk.cli import build_parser

    p = build_parser()
    # a secret-on-argv flag must not exist
    with pytest.raises(SystemExit):
        p.parse_args(["gateway", "models", "--api-key", "cgk_secret"])
    # the safe alternative (a file path, not the secret itself) does exist
    ns = p.parse_args(["gateway", "models", "--api-key-file", "/run/secrets/gw"])
    assert ns.api_key_file == "/run/secrets/gw"


# ── SPY-B-013 · encrypted=True fails closed without a KeyManager ──────────────

def test_inference_encrypted_without_keymanager_raises():
    c = _client()  # no private_key -> no key_manager
    with pytest.raises(Exception) as ei:
        c.inference("m", {"secret": 1}, encrypted=True, recipient_public_key="00" * 33)
    msg = str(ei.value).lower()
    assert "plaintext" in msg or "keymanager" in msg


# ── CIT-SDKPY-01 · V2 is honestly documented as NOT forward-secret ────────────

def test_v2_is_not_forward_secret_static_key_compromise_decrypts():
    """Documents reality: compromising the sender's static key + the public
    envelope fields re-derives the KEK and decrypts. If forward secrecy is ever
    added (ephemeral-static ECDH), this test should be revisited."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from citrate_sdk.crypto import KeyManager

    sender = KeyManager("0x" + "11" * 32)
    recipient = KeyManager("0x" + "22" * 32)
    rpub = recipient.get_public_key()
    env = sender.encrypt_data("top-secret", rpub)
    # normal decrypt by the recipient
    assert recipient.decrypt_data(env) == "top-secret"

    pkg = json.loads(env)
    # attacker who has compromised the sender's STATIC key + the public envelope
    attacker = KeyManager("0x" + "11" * 32)
    shared = attacker.derive_shared_key(
        pkg["recipient_public_key"],
        salt=bytes.fromhex(pkg["kdf_salt"]),
        info=KeyManager._kek_info(pkg["sender_public_key"], pkg["recipient_public_key"]),
    )
    key = AESGCM(shared).decrypt(bytes.fromhex(pkg["wrap_nonce"]),
                                 bytes.fromhex(pkg["wrapped_key"]), None)
    pt = AESGCM(key).decrypt(bytes.fromhex(pkg["nonce"]),
                             bytes.fromhex(pkg["ciphertext"]), None)
    assert pt == b"top-secret"


def test_docs_do_not_overclaim_forward_secrecy():
    import citrate_sdk.crypto as cm

    src = inspect.getsource(cm)
    changelog = (_REPO / "CHANGELOG.md").read_text()
    for text in (src, changelog):
        assert "confined to a single message" not in text


# ── CIT-SDKPY-02 · inference pins the response sender ─────────────────────────

def test_inference_pins_response_sender():
    from citrate_sdk.crypto import KeyManager

    c = _client(private_key=_CLIENT_KEY)
    client_pub = c.key_manager.ecdh_manager.get_public_key_uncompressed().hex()

    model = KeyManager("0x" + "33" * 32)
    model_pub = model.ecdh_manager.get_public_key_uncompressed().hex()
    good_env = model.encrypt_data(json.dumps({"ok": 1}), client_pub)

    with patch.object(c, "_send_transaction", return_value="0xh"), \
         patch.object(c, "_wait_for_receipt", return_value={}), \
         patch.object(c, "_extract_inference_output", return_value={"encrypted": good_env}):
        res = c.inference("m", {"x": 1}, encrypted=True, recipient_public_key=model_pub)
    assert res.output_data == {"ok": 1}

    # a response from a DIFFERENT keypair (not the model we sent to) is refused
    imposter = KeyManager("0x" + "44" * 32)
    bad_env = imposter.encrypt_data(json.dumps({"ok": 1}), client_pub)
    with patch.object(c, "_send_transaction", return_value="0xh"), \
         patch.object(c, "_wait_for_receipt", return_value={}), \
         patch.object(c, "_extract_inference_output", return_value={"encrypted": bad_env}):
        with pytest.raises(Exception):
            c.inference("m", {"x": 1}, encrypted=True, recipient_public_key=model_pub)


# ── CIT-SDKPY-03 · IPFS: no implicit third-party fallbacks, timeouts present ──

def test_ipfs_no_implicit_thirdparty_fallbacks():
    import citrate_sdk.ipfs as ipfs

    ipfs._ipfs_manager = None
    try:
        mgr = ipfs.get_ipfs_manager()
        # no implicit third-party fallbacks — localhost only unless opted in
        assert mgr.fallbacks == []
        assert mgr.primary.api_url == "http://localhost:5001"
        # opt-in still works
        ipfs._ipfs_manager = None
        mgr2 = ipfs.get_ipfs_manager(["http://localhost:5001", "https://my.gateway:5001"])
        assert len(mgr2.fallbacks) == 1
    finally:
        ipfs._ipfs_manager = None


def test_ipfs_client_has_request_timeout():
    from citrate_sdk.ipfs import IPFSClient

    c = IPFSClient("http://localhost:5001")
    assert isinstance(c.timeout, (int, float)) and c.timeout > 0
