"""DEVX-S3 / F5 — the citrate CLI (fixes the previously-missing entry point)."""
from __future__ import annotations

import contextlib
import io

from citrate_sdk.cli import main


def _run(argv):
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rc = main(argv)
    return rc, buf.getvalue()


def test_entry_point_resolves_and_help_returns():
    # A bare invocation prints help and returns non-zero (no ModuleNotFoundError).
    rc, _ = _run([])
    assert rc == 2


def test_wallet_predict_matches_onchain_vector():
    rc, out = _run(["wallet", "predict", "--user-id", "0x" + "42" * 32])
    assert rc == 0
    assert "0xfb43484CDbA25C6457C2775C1d6dfeD71cE4e720" in out


def test_entitlement_capabilities():
    rc, out = _run(["entitlement", "capabilities", "--tier", "commercial.kyc"])
    assert rc == 0
    assert '"confidential_docs": false' in out
    assert '"ecosystem_tx": true' in out


def test_contract_section():
    rc, out = _run(["contract", "--section", "chain"])
    assert rc == 0
    assert "40204" in out
