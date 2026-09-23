"""SPY-B-001 tripwire — purchase_model_access must fail closed.

The pre-fix code signed and broadcast a transaction sending the buyer's full
payment as ``value`` to ``0x0100000000000000000000000000000000000104`` — an
address that is NOT in the canonical precompile table this package vendors, so
the funds left the buyer's account with nothing able to credit the purchase
(destroyed funds). These tests assert the method now raises and signs/broadcasts
nothing, and that the phantom address is genuinely not a canonical precompile.
"""
from unittest.mock import patch

import pytest

from citrate_sdk import CitrateClient
from citrate_sdk._generated.contract import federation_contract
from citrate_sdk.errors import CitrateError

MOCK_RPC = "http://localhost:8545"
MOCK_KEY = "0x" + "1" * 64
PHANTOM_ACCESS_ADDR = "0x0100000000000000000000000000000000000104"


def test_purchase_model_access_raises_and_sends_nothing():
    """RED on pre-fix code: _send_transaction WAS called (funds moved). GREEN:
    the method raises CitrateError and no transaction is signed or broadcast."""
    client = CitrateClient(MOCK_RPC, MOCK_KEY)
    with patch.object(CitrateClient, "_send_transaction") as send:
        with pytest.raises(CitrateError):
            client.purchase_model_access("model-1", 10 ** 18)
        assert not send.called, (
            "purchase_model_access must not sign or broadcast any transaction "
            "(SPY-B-001) — it moved the buyer's funds to a non-precompile address"
        )


def test_phantom_access_address_is_not_a_canonical_precompile():
    """Structural guard: the address the pre-fix code sent funds to is not a
    member of the canonical precompile table, which is exactly why sending funds
    there destroys them."""
    precompiles = {v.lower() for v in federation_contract()["precompiles"].values()}
    assert PHANTOM_ACCESS_ADDR.lower() not in precompiles, (
        "0x..0104 must not appear in the canonical precompile table; if it ever "
        "does, wire purchase_model_access to it instead of failing closed"
    )
