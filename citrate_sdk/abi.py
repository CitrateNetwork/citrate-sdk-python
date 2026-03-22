"""
ABI encoding / decoding utilities for Citrate SDK.

Provides the same capability as ethers.Interface in the TypeScript SDK:
  - Compute function selectors (first 4 bytes of keccak256 of the signature)
  - ABI-encode arguments (uint256, address, string, bytes, bytes32, bool, uint8, string[])
  - ABI-decode return values from eth_call results

Uses the ``eth_abi`` library (bundled with the ``web3`` dependency) for canonical
ABI encoding so that calldata is byte-identical to what the JS SDK emits via
``ethers.Interface.encodeFunctionData``.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Sequence, Tuple

from eth_abi import encode as abi_encode, decode as abi_decode  # type: ignore[import-untyped]
from web3 import Web3  # type: ignore[import-untyped]


# ---------------------------------------------------------------------------
# Keccak-256 helper
# ---------------------------------------------------------------------------

def keccak256(data: bytes) -> bytes:
    """Return the Keccak-256 hash of *data*."""
    return Web3.keccak(data)


def keccak256_text(text: str) -> str:
    """Return the 0x-prefixed Keccak-256 hash of a UTF-8 string."""
    return "0x" + keccak256(text.encode("utf-8")).hex()


# ---------------------------------------------------------------------------
# Wei / Ether conversion
# ---------------------------------------------------------------------------

def to_wei(ether: str) -> int:
    """Convert an ether-denominated decimal string to wei (int)."""
    return Web3.to_wei(ether, "ether")


def from_wei(wei: int) -> str:
    """Convert a wei integer to an ether-denominated decimal string."""
    return str(Web3.from_wei(wei, "ether"))


# ---------------------------------------------------------------------------
# ABI Interface helper — lightweight mirror of ethers.Interface
# ---------------------------------------------------------------------------

# Regex for a simple human-readable ABI line.
# Examples:
#   "function nextPoolId() view returns (uint256)"
#   "function joinPool(uint256 poolId) payable"
_FUNC_RE = re.compile(
    r"function\s+(\w+)\s*"        # function name
    r"\(([^)]*)\)"                 # input params
    r"(?:\s*(?:view|pure|payable|external|public))*"  # modifiers
    r"(?:\s*returns\s*\(([^)]*)\))?"  # optional return types
)


def _parse_param_types(raw: str) -> List[str]:
    """Parse a comma-separated param string into a list of Solidity types.

    e.g. "uint256 poolId, address member" -> ["uint256", "address"]
    """
    if not raw or not raw.strip():
        return []
    parts = [p.strip() for p in raw.split(",") if p.strip()]
    types: List[str] = []
    for part in parts:
        tokens = part.split()
        # Handle "string[]" -> type is "string[]"
        types.append(tokens[0])
    return types


class AbiFunction:
    """Parsed representation of a single Solidity function signature."""

    __slots__ = ("name", "input_types", "output_types", "selector")

    def __init__(self, name: str, input_types: List[str], output_types: List[str]) -> None:
        self.name = name
        self.input_types = input_types
        self.output_types = output_types
        # canonical signature: "name(type1,type2,...)"
        sig = f"{name}({','.join(input_types)})"
        self.selector: bytes = keccak256(sig.encode("utf-8"))[:4]


class AbiInterface:
    """Minimal mirror of ``ethers.Interface`` that can encode/decode ABI calls.

    Accepts the same human-readable ABI array format used in the JS SDK.
    """

    def __init__(self, fragments: Sequence[str]) -> None:
        self._funcs: Dict[str, AbiFunction] = {}
        for frag in fragments:
            m = _FUNC_RE.search(frag)
            if not m:
                continue
            name = m.group(1)
            in_types = _parse_param_types(m.group(2))
            out_types = _parse_param_types(m.group(3) or "")
            self._funcs[name] = AbiFunction(name, in_types, out_types)

    def encode_function_data(self, name: str, args: Sequence[Any] | None = None) -> str:
        """ABI-encode a function call. Returns a 0x-prefixed hex string."""
        fn = self._funcs.get(name)
        if fn is None:
            raise ValueError(f"Unknown function: {name}")
        if not fn.input_types:
            return "0x" + fn.selector.hex()
        if args is None:
            args = []
        encoded = abi_encode(fn.input_types, list(args))
        return "0x" + fn.selector.hex() + encoded.hex()

    def decode_function_result(self, name: str, data: str) -> Tuple[Any, ...]:
        """Decode ABI-encoded return data from an eth_call result.

        Returns a tuple of decoded values.
        """
        fn = self._funcs.get(name)
        if fn is None:
            raise ValueError(f"Unknown function: {name}")
        if not fn.output_types:
            return ()
        raw = bytes.fromhex(data[2:] if data.startswith("0x") else data)
        return abi_decode(fn.output_types, raw)
