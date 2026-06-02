"""RM-G.4 — transactions must be EIP-155 (chainId-bound) so a signature can't
be replayed cross-network. CI-gated (eth_account/cryptography not installable
in the read-only audit env)."""
from unittest.mock import patch
from citrate_sdk.client import CitrateClient


def test_eip155_chain_id_normalizes_and_caches():
    c = CitrateClient(rpc_url="http://example")
    with patch.object(c, "get_chain_id", return_value="0x9d0c") as m:
        assert c._eip155_chain_id() == 40204  # 0x9d0c
        assert c._eip155_chain_id() == 40204  # cached — no 2nd RPC
        assert m.call_count == 1


def test_eip155_chain_id_accepts_int():
    c = CitrateClient(rpc_url="http://example")
    with patch.object(c, "get_chain_id", return_value=40204):
        assert c._eip155_chain_id() == 40204
