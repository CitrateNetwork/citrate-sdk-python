"""Differential property test: share guard versus share parsers.

Generates near-hex strings (hex pairs, stray hex digits, ASCII and Unicode
whitespace, junk characters, 0x/0X prefixes) from a fixed seed and checks two
properties on every input:

1. ``parse_share_y`` agrees with a reference strict grammar (optional 0x/0X,
   even-length hex, nothing else). A lenient parser fails this.
2. Any input that ANY known decoder turns into >= 16 bytes (the strict
   reference, Python's ``bytes.fromhex``, and the legacy truncating JS
   decoder) is refused by the guard. A guard that only matches canonical hex
   fails this.
"""
from __future__ import annotations

import random
import re

import pytest

from citrate_sdk import crypto
from citrate_sdk.crypto import assert_no_key_share_material
from citrate_sdk.errors import CitrateError

N = 40_000
MIN = 16
_STRICT = re.compile(r"(?:0[xX])?((?:[0-9a-fA-F]{2})*)")
_HEX = "0123456789abcdefABCDEF"
_WS = [" ", "\t", "\n", "\r", " ", " ", "　"]
_JUNK = ["z", "g", "x", "X", "-", ":", "１", "."]


def strict_ref(s: str) -> bytes | None:
    m = _STRICT.fullmatch(s)
    return bytes.fromhex(m.group(1)) if m else None


def py_fromhex(s: str) -> bytes | None:
    t = s[2:] if s[:2] in ("0x", "0X") else s
    try:
        return bytes.fromhex(t)
    except ValueError:
        return None


def js_legacy(s: str) -> bytes | None:
    """The pre-hardening JS decoder: strip a leading 0x, then read
    floor(len/2) pairs with parseInt (a trailing odd character is dropped).
    Counted only when every pair it reads is real hex."""
    t = s[2:] if s.startswith("0x") else s
    body = t[: len(t) // 2 * 2]
    if not re.fullmatch(r"[0-9a-fA-F]*", body):
        return None
    return bytes.fromhex(body)


def _gen(rng: random.Random) -> str:
    """Three regimes: canonical hex (optionally prefixed), canonical hex with
    one to three perturbations, and free-form near-hex."""
    pairs = [rng.choice(_HEX) + rng.choice(_HEX) for _ in range(rng.randint(12, 40))]
    mode = rng.random()
    if mode < 0.34:
        out = pairs
    elif mode < 0.67:
        out = list(pairs)
        for _ in range(rng.randint(1, 3)):
            tok = rng.choice(_WS + _JUNK + list(_HEX))
            out.insert(rng.randint(0, len(out)), tok)
    else:
        out = []
        for _ in range(rng.randint(10, 40)):
            r = rng.random()
            if r < 0.80:
                out.append(rng.choice(_HEX) + rng.choice(_HEX))
            elif r < 0.88:
                out.append(rng.choice(_HEX))
            elif r < 0.95:
                out.append(rng.choice(_WS))
            else:
                out.append(rng.choice(_JUNK))
    prefix = rng.choice(["0x", "0X"]) if rng.random() < 0.3 else ""
    return prefix + "".join(out)


def _inputs() -> list[str]:
    rng = random.Random(0xC17A7E)
    return [_gen(rng) for _ in range(N)]


def _guard_refuses(y: str) -> bool:
    try:
        assert_no_key_share_material({"x": 1, "y": y})
    except CitrateError:
        return True
    return False


def test_parser_matches_the_strict_reference() -> None:
    bad = []
    for s in _inputs():
        ref = strict_ref(s)
        try:
            got: bytes | None = crypto.parse_share_y(s)
        except ValueError:
            got = None
        if got != ref:
            bad.append(s)
    assert bad == [], f"{len(bad)} disagreements, e.g. {bad[:3]!r}"


@pytest.mark.parametrize("decoder", [strict_ref, py_fromhex, js_legacy], ids=["strict", "fromhex", "js-legacy"])
def test_guard_refuses_everything_any_decoder_accepts(decoder: object) -> None:
    accepted = 0
    missed = []
    for s in _inputs():
        b = decoder(s)  # type: ignore[operator]
        if b is not None and len(b) >= MIN:
            accepted += 1
            if not _guard_refuses(s):
                missed.append(s)
    assert accepted > 1000, "generator produced too few decodable inputs to be meaningful"
    assert missed == [], f"{len(missed)} decodable inputs passed the guard, e.g. {missed[:3]!r}"
