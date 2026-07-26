"""DEVX-S1 / F2 — embedded wallet prediction (Python parity with JS + on-chain factory).

Pinned to the on-chain CitrateWalletFactory.predictAddress(0x4242…)=0x1615Af12… (2026-07-25),
the SAME value the JS SDK produces — cross-language byte parity (risk R-2).
"""
from __future__ import annotations

from citrate_sdk.identity import wallet

USER_ID_4242 = "0x" + "42" * 32


def _raises(exc, fn):
    try:
        fn()
        return False
    except exc:
        return True


def test_predict_matches_onchain_and_js():
    assert wallet.predict_wallet_address(USER_ID_4242) == "0x1615Af127952c4e4987D7b597bDD7cb8B49aFB89"


def test_predict_uses_artifact_factory_and_impl_by_default():
    from citrate_sdk._generated import contract
    aa = contract.aa_stack()
    explicit = wallet.predict_wallet_address(
        USER_ID_4242, factory=aa["CitrateWalletFactory"], implementation=aa["CitrateWallet"]
    )
    assert explicit == wallet.predict_wallet_address(USER_ID_4242)


def test_predict_deterministic_and_differs():
    a = wallet.predict_wallet_address("0x" + "01" * 32)
    b = wallet.predict_wallet_address("0x" + "02" * 32)
    assert a != b
    assert wallet.predict_wallet_address("0x" + "01" * 32) == a


def test_predict_rejects_bad_userid():
    assert _raises(wallet.WalletPredictionError, lambda: wallet.predict_wallet_address("0xdeadbeef"))


def test_uuid_to_user_id_case_insensitive():
    up = wallet.uuid_to_user_id("DEADBEEF-0000-4000-8000-000000000000")
    lo = wallet.uuid_to_user_id("deadbeef-0000-4000-8000-000000000000")
    assert up == lo
    assert up.startswith("0x") and len(up) == 66


def test_address_to_user_id_pads():
    uid = wallet.address_to_user_id("0x000000000000000000000000000000000000dEaD")
    assert uid == "0x000000000000000000000000000000000000000000000000000000000000dead"
