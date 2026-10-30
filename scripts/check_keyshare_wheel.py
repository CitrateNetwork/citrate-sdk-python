#!/usr/bin/env python3
"""PBA-L6b-003 tripwire against the BUILT wheel, not the source tree.

Builds the wheel exactly as a release would (``pip wheel --no-deps``), or takes
one as an argument, unpacks it, imports ``citrate_sdk`` from the unpacked wheel
only, and drives the public ``CitrateClient.deploy_model`` with a capturing RPC:

1. ``threshold_shares > 0`` without holder keys must be refused before any send;
2. with holder keys, no subset of the RLP-decoded deploy calldata may rebuild
   the model key (scripts/keyshare_leak_tripwire.py);
3. the holders must still rebuild the key from their envelopes.

The wheel's genesis guard stays on: the capturing RPC answers block 0 with the wheel's
vendored genesis, and a client on another genesis must refuse before sending.

Usage: python scripts/check_keyshare_wheel.py [path/to/citrate_labs_sdk-*.whl]
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def fail(msg: str) -> None:
    print(f"PBA-L6b-003 wheel tripwire FAILED: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    work = Path(tempfile.mkdtemp(prefix="keyshare-wheel-"))
    if len(sys.argv) > 1:
        wheel = Path(sys.argv[1]).resolve()
    else:
        subprocess.run([sys.executable, "-m", "pip", "wheel", "--no-deps", "-q", "-w", str(work), str(ROOT)], check=True)
        wheels = sorted(work.glob("citrate_labs_sdk-*.whl"))
        if not wheels:
            fail("pip wheel produced no citrate_labs_sdk wheel")
        wheel = wheels[-1]
    unpacked = work / "unpacked"
    with zipfile.ZipFile(wheel) as z:
        z.extractall(unpacked)
    sys.path.insert(0, str(unpacked))
    for mod in [m for m in sys.modules if m == "citrate_sdk" or m.startswith("citrate_sdk.")]:
        del sys.modules[mod]
    import citrate_sdk  # noqa: E402
    if not Path(citrate_sdk.__file__).resolve().is_relative_to(unpacked.resolve()):
        fail(f"imported citrate_sdk from {citrate_sdk.__file__}, not from the wheel")
    import rlp  # type: ignore[import-untyped]  # noqa: E402

    from citrate_sdk import CitrateClient, KeyManager  # noqa: E402
    from citrate_sdk.crypto import EncryptionConfig  # noqa: E402
    from citrate_sdk.errors import CitrateError  # noqa: E402
    from citrate_sdk.models import ModelConfig  # noqa: E402

    spec = importlib.util.spec_from_file_location("tw", ROOT / "scripts" / "keyshare_leak_tripwire.py")
    assert spec and spec.loader
    tw = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tw)

    from citrate_sdk._generated import contract as wheel_contract  # noqa: E402

    owner = "0x" + "11" * 32
    holders = ["0x" + "22" * 32, "0x" + "33" * 32, "0x" + "44" * 32]
    model = work / "m.onnx"
    model.write_bytes(b"SECRET-MODEL-WEIGHTS" * 100)
    # The wheel's network guard stays on: block 0 is answered with the wheel's own vendored
    # genesis, so the guard runs and passes before the key-share checks below.
    genesis = wheel_contract.genesis_hash()
    if not isinstance(genesis, str) or len(genesis) != 66:
        fail(f"wheel genesis_hash() is not a 32-byte hash: {genesis!r}")

    def capturing_client(block0_hash: str) -> tuple[Any, dict[str, Any]]:
        box: dict[str, Any] = {"block0_reads": 0}

        def rpc(method: str, params: Any = None) -> Any:
            if method == "eth_getBlockByNumber" and params and params[0] in ("0x0", 0):
                box["block0_reads"] += 1
                return {"number": "0x0", "hash": block0_hash}
            if method == "eth_getTransactionCount":
                return "0x0"
            if method == "eth_chainId":
                return hex(40204)
            if method == "eth_gasPrice":
                return "0x1"
            if method == "eth_sendRawTransaction":
                box["raw"] = params[0]
                return "0x" + "ab" * 32
            raise AssertionError(method)

        # Port 1 is never a node; every RPC below is answered by the stub.
        c = CitrateClient("http://127.0.0.1:1", private_key=owner)
        stubs: dict[str, Any] = {
            "_rpc_call": rpc,
            "_upload_to_ipfs": lambda data: "bafyFAKE",
            "_wait_for_receipt": lambda h: {"logs": []},
            "_extract_model_id_from_receipt": lambda r: "0x01",
        }
        for name, fn in stubs.items():  # offline: RPC and IPFS are stubbed
            setattr(c, name, fn)
        return c, box

    # 0. the wheel's network guard is live: another block 0 is refused before any send
    other, other_box = capturing_client("0x" + "0" * 63 + "1")
    try:
        other.deploy_model(model, ModelConfig(name="m"))
        fail("the wheel's client did not refuse an RPC on another genesis")
    except CitrateError as e:
        if getattr(e, "error_code", None) != "WRONG_NETWORK":
            fail(f"expected a WRONG_NETWORK refusal on another genesis, got {e!r}")
    if "raw" in other_box:
        fail("a transaction was sent to an RPC on another genesis")

    client, box = capturing_client(genesis)

    try:
        client.deploy_model(model, ModelConfig(name="m", encrypted=True, encryption_config=EncryptionConfig(
            threshold_shares=2, total_shares=3)))
        fail("threshold_shares > 0 without share_holder_public_keys was not refused")
    except CitrateError:
        pass
    if "raw" in box:
        fail("a transaction was sent for the refused deploy")

    pubs = [KeyManager(k).get_public_key() for k in holders]
    dep = client.deploy_model(model, ModelConfig(name="m", encrypted=True, encryption_config=EncryptionConfig(
        threshold_shares=2, total_shares=3, share_holder_public_keys=pubs)))
    if box["block0_reads"] < 1:
        fail("the deploy was sent without the block-0 network check")
    calldata = bytes(rlp.decode(bytes.fromhex(box["raw"][2:]))[5])
    meta = json.loads(calldata.decode())["encryption_metadata"]
    key = KeyManager(owner)._decrypt_key_from_owner(meta["encrypted_key"])
    reveals, how = tw.reveals_key(calldata, key)
    if reveals:
        fail(f"deploy calldata reveals the model key ({how})")

    envs = dep.key_share_envelopes or []
    if len(envs) != 3:
        fail(f"expected 3 key-share envelopes, got {len(envs)}")
    owner_pub = KeyManager(owner).get_public_key()
    s0 = KeyManager(holders[0]).unwrap_key_share(envs[0], owner_pub)
    s1 = KeyManager(holders[1]).unwrap_key_share(envs[1], owner_pub)
    if KeyManager(holders[0]).reconstruct_key_from_shares([s0, s1], threshold=2) != key:
        fail("holders could not rebuild the key")
    print(f"PBA-L6b-003 wheel tripwire PASSED for {wheel.name} (citrate_sdk {citrate_sdk.__version__})")


if __name__ == "__main__":
    main()
