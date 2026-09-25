"""PBA-L6b-003 tripwire: does public deploy calldata reveal the model AES key?

Deliberately independent of the SDK code under test: its own GF(2^8)
arithmetic (AES polynomial 0x11b, the one ``citrate_sdk.finite_field`` uses),
its own Lagrange interpolation, no share validation. A regression in the SDK's
Shamir code can neither hide a leak nor fake a pass here.

``reveals_key(calldata, key)`` answers "can an observer who holds only the
calldata rebuild the key?" by trying:

1. the key bytes verbatim (hex or base64) anywhere in the text;
2. explicit share objects (``{"x": .., "y": ..}``) anywhere in the decoded
   JSON: every subset is interpolated at x = 0;
3. bare key-length hex strings anywhere (share values with x stripped): every
   subset of up to ``MAX_BARE_SUBSET`` of them, under every assignment of x in
   1..``MAX_BARE_X``, is interpolated at x = 0.

Nested JSON strings are parsed recursively. Used by
tests/test_pba_r2_l6b_keyshares.py (source tree) and
scripts/check_keyshare_wheel.py (built wheel).
"""
from __future__ import annotations

import base64
import itertools
import json
import re
from typing import Any

MAX_EXPLICIT_SUBSET = 8
MAX_BARE_SUBSET = 3
MAX_BARE_X = 8


def _mul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


# Test-only lookup tables (timing does not matter here; speed does).
_MUL = [[_mul(a, b) for b in range(256)] for a in range(256)]
_INV: list[int | None] = [None] + [next(b for b in range(1, 256) if _MUL[a][b] == 1) for a in range(1, 256)]


def _inv(a: int) -> int | None:
    return _INV[a]


def interpolate_at_zero(points: list[tuple[int, bytes]]) -> bytes | None:
    length = len(points[0][1])
    if any(len(y) != length for _, y in points):
        return None
    xs = [x for x, _ in points]
    if len(set(xs)) != len(xs):
        return None
    out = bytearray(length)
    for i, (xi, yi) in enumerate(points):
        num, den = 1, 1
        for j, xj in enumerate(xs):
            if i == j:
                continue
            num = _MUL[num][xj]
            den = _MUL[den][xi ^ xj]
        inv = _inv(den)
        if inv is None:
            return None
        row = _MUL[_MUL[num][inv]]
        for b in range(length):
            out[b] ^= row[yi[b]]
    return bytes(out)


def _walk(value: Any, explicit: list[tuple[int, bytes]], strings: list[str], depth: int) -> None:
    if depth > 16 or value is None:
        return
    if isinstance(value, str):
        strings.append(value)
        t = value.strip()
        if t[:1] in ("{", "[") and len(t) < 1_000_000:
            try:
                _walk(json.loads(t), explicit, strings, depth + 1)
            except ValueError:
                pass
        return
    if isinstance(value, list):
        for v in value:
            _walk(v, explicit, strings, depth + 1)
        return
    if isinstance(value, dict):
        x, y = value.get("x"), value.get("y")
        try:
            xi = int(x) if x is not None else None
        except (TypeError, ValueError):
            xi = None
        if xi is not None and isinstance(y, str):
            try:
                explicit.append((xi & 0xFF, bytes.fromhex(y[2:] if y.startswith("0x") else y)))
            except ValueError:
                pass
        for v in value.values():
            _walk(v, explicit, strings, depth + 1)


def reveals_key(calldata: bytes | str, key: bytes) -> tuple[bool, str]:
    """Return (True, how) if ``calldata`` lets an observer rebuild ``key``."""
    text = calldata.decode("utf-8", "replace") if isinstance(calldata, bytes) else calldata
    if key.hex() in text.lower() or base64.b64encode(key).decode() in text:
        return True, "key bytes appear verbatim"

    explicit: list[tuple[int, bytes]] = []
    strings: list[str] = []
    try:
        root: Any = json.loads(text)
    except ValueError:
        root = text
    _walk(root, explicit, strings, 0)

    for size in range(1, min(MAX_EXPLICIT_SUBSET, len(explicit)) + 1):
        for subset in itertools.combinations(explicit, size):
            if interpolate_at_zero(list(subset)) == key:
                return True, "explicit shares x=" + ",".join(str(x) for x, _ in subset)

    want = len(key) * 2
    pattern = re.compile(r"(?:0x)?([0-9a-fA-F]{%d})(?![0-9a-fA-F])" % want)
    seen: set[str] = set()
    bare: list[bytes] = []
    for s in strings:
        for m in pattern.finditer(s):
            h = m.group(1).lower()
            if h not in seen:
                seen.add(h)
                bare.append(bytes.fromhex(h))
    for size in range(1, min(MAX_BARE_SUBSET, len(bare)) + 1):
        for ys in itertools.combinations(bare, size):
            for xs in itertools.product(range(1, MAX_BARE_X + 1), repeat=size):
                if interpolate_at_zero(list(zip(xs, ys, strict=True))) == key:
                    return True, "bare key-length values at x=" + ",".join(map(str, xs))
    return False, ""
