"""DEVX-S1 / F2 — embedded wallet prediction (Python parity with JS + on-chain factory).

r1006 (genesis 0xa3651a27…): factory 0x6ee3b590…, implementation CitrateWallet 0x2d742b98…
(unchanged), predictAddress(0x4242…) = 0xEFf9CC17…, computed offline with the formula that
reproduces r1005's live factory answer 0x6Ef76179… (2026-10-06, factory 0x9Ac05AD6…, genesis
0x1dcfc490…) byte-for-byte; the JS SDK pins the same values (risk R-2). Re-read the r1006 value
from the live factory after the public cutover.
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
    assert wallet.predict_wallet_address(USER_ID_4242) == "0xEFf9CC174Cdcbe60FF9D8D2b469Fb94008C8336D"


def test_formula_reproduces_the_r1005_live_factory_answer():
    assert wallet.predict_wallet_address(
        USER_ID_4242,
        factory="0x9Ac05AD65C9E8E48Fbb41dDE029512afA5346C85",
        implementation="0x2D742B98D867Fc7363F530DD6d756622e4Eb768D",
    ) == "0x6Ef7617980a1fe91D3449315E8D48f99A68Bb5eA"


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
