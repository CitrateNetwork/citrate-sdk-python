"""citrate — the Citrate SDK command line (DEVX-S3).

Fixes the previously-declared-but-missing `citrate_sdk.cli:main` entry point. Every command
reads the vendored federation contract artifact (DEVX-S0), so addresses/endpoints are never
hand-typed.

    citrate contract [--section all|chain|aa|identity|gateway|entitlements]
    citrate wallet predict (--user-id 0x… | --uuid <uuid>) [--verify]
    citrate entitlement capabilities --tier <tier>
    citrate entitlement normalize --tier <value>
    citrate gateway (models|health|chat --model M --message TEXT) [--api-key-file PATH]
        (the gateway key comes from $CITRATE_GATEWAY_API_KEY or --api-key-file,
         never a --api-key value on argv — SPY-B-012)
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import entitlements
from ._generated import contract
from .gateway import GatewayClient, GatewayError
from .identity import wallet


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=2, default=lambda o: getattr(o, "__dict__", str(o))))


def _cmd_contract(args: argparse.Namespace) -> int:
    fc = contract.federation_contract()
    section = args.section
    if section == "all":
        _print({k: fc[k] for k in ("chain", "aaStack", "membership", "identity", "entitlements", "gateway")})
    elif section == "chain":
        _print(fc["chain"])
    elif section == "aa":
        _print({"aaStack": fc["aaStack"], "membership": fc["membership"]})
    elif section == "identity":
        _print(fc["identity"])
    elif section == "gateway":
        _print(fc["gateway"])
    elif section == "entitlements":
        _print(fc["entitlements"])
    return 0


def _cmd_wallet(args: argparse.Namespace) -> int:
    if args.action != "predict":
        return 2
    if args.uuid:
        user_id = wallet.uuid_to_user_id(args.uuid)
    elif args.user_id:
        user_id = args.user_id
    else:
        print("error: provide --user-id or --uuid", file=sys.stderr)
        return 2
    try:
        if args.verify:
            addr = wallet.verify_wallet_address_on_chain(user_id)
            _print({"userId": user_id, "address": addr, "verifiedOnChain": True})
        else:
            _print({"userId": user_id, "address": wallet.predict_wallet_address(user_id)})
    except wallet.WalletPredictionError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    return 0


def _cmd_entitlement(args: argparse.Namespace) -> int:
    if args.action == "normalize":
        _print({"input": args.tier, "normalized": entitlements.normalize_tier(args.tier)})
        return 0
    caps = entitlements.capabilities(args.tier)
    _print({"tier": entitlements.normalize_tier(args.tier), "capabilities": caps.__dict__})
    return 0


def _cmd_gateway(args: argparse.Namespace) -> int:
    # SPY-B-012: never accept the gateway key as a command-line value — it would
    # land in the process table (world-readable via `ps`) and in shell history.
    # Read it from the env var, or from a file path (whose contents are not on
    # argv). `-` reads one line from stdin.
    key = os.environ.get("CITRATE_GATEWAY_API_KEY", "")
    if not key and getattr(args, "api_key_file", None):
        if args.api_key_file == "-":
            key = sys.stdin.readline().strip()
        else:
            try:
                with open(args.api_key_file, encoding="utf-8") as fh:
                    key = fh.read().strip()
            except OSError as e:
                print(f"error: cannot read --api-key-file: {e}", file=sys.stderr)
                return 2
    try:
        client = GatewayClient(api_key=key)
        if args.action == "health":
            _print(client.health())
        elif args.action == "models":
            _print(client.list_models())
        elif args.action == "chat":
            if not (args.model and args.message):
                print("error: chat needs --model and --message", file=sys.stderr)
                return 2
            _print(client.chat_completions(args.model, [{"role": "user", "content": args.message}]))
    except GatewayError as e:
        print(f"gateway error: {e}", file=sys.stderr)
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="citrate", description="Citrate SDK command line")
    sub = p.add_subparsers(dest="cmd")

    pc = sub.add_parser("contract", help="Print the federation contract table")
    pc.add_argument("--section", default="all",
                    choices=["all", "chain", "aa", "identity", "gateway", "entitlements"])
    pc.set_defaults(func=_cmd_contract)

    pw = sub.add_parser("wallet", help="Embedded smart-account wallet helpers")
    pw.add_argument("action", choices=["predict"])
    pw.add_argument("--user-id")
    pw.add_argument("--uuid")
    pw.add_argument("--verify", action="store_true", help="verify against the on-chain factory")
    pw.set_defaults(func=_cmd_wallet)

    pe = sub.add_parser("entitlement", help="Entitlement capabilities")
    pe.add_argument("action", choices=["capabilities", "normalize"])
    pe.add_argument("--tier", required=True)
    pe.set_defaults(func=_cmd_entitlement)

    # SPY-B-012: allow_abbrev=False so a prefix like `--api-key` is NOT silently
    # accepted as an abbreviation of `--api-key-file` — the removed value flag
    # must stay removed, not resurrected by argparse prefix matching.
    pg = sub.add_parser("gateway", help="Inference gateway", allow_abbrev=False)
    pg.add_argument("action", choices=["chat", "models", "health"])
    pg.add_argument("--model")
    pg.add_argument("--message")
    # SPY-B-012: no `--api-key` value flag — a secret on argv leaks via `ps` and
    # shell history. The key comes from CITRATE_GATEWAY_API_KEY or --api-key-file
    # (path, or `-` for stdin).
    pg.add_argument("--api-key-file",
                    help="path to a file containing the cgk_ gateway key, or - for stdin")
    pg.set_defaults(func=_cmd_gateway)

    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 2
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
