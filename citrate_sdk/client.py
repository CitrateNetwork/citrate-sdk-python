"""
Citrate Client - Main SDK interface for Citrate blockchain interaction
"""

import hashlib
import json
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, cast

import requests

from ._generated import contract as _contract
from ._url_security import enforce_transport_security
from .crypto import EncryptionConfig, KeyManager, assert_no_key_share_material
from .errors import CitrateError, ModelNotFoundError
from .ipfs import upload_to_ipfs
from .models import InferenceRequest, InferenceResult, ModelConfig, ModelDeployment

# SPY-B-006: receipt log topics are keccak256 of the event signature, NOT the
# ASCII hex of the event name. Pre-fix the client matched
# ``"0x" + "ModelDeployed".encode().hex()[:16]`` == ``0x4d6f64656c446570`` (the
# bytes of "ModelDep"), which is valid hex but matches a real topic with
# probability ~2**-64, so every deploy/inference fell through to a raise AFTER
# the tx was broadcast and confirmed. The event SIGNATURES are the single source
# of truth; the tripwire builds its fixture from these same constants via
# ``Web3.keccak(text=...)`` so the matcher and the fixture cannot drift apart.
# If the node's ABI differs, change the signature here — one place.
MODEL_DEPLOYED_EVENT_SIGNATURE = "ModelDeployed(bytes32,address)"
INFERENCE_COMPLETE_EVENT_SIGNATURE = "InferenceComplete(bytes32,bytes)"


def _event_topic(signature: str) -> str:
    """keccak256 topic (0x-prefixed hex) for an event signature string."""
    from web3 import Web3

    return Web3.keccak(text=signature).hex().lower()


class CitrateClient:
    """
    Main client for interacting with Citrate blockchain.

    Provides methods for:
    - Model deployment and management
    - Inference execution
    - Encryption and access control
    - Payment and revenue sharing
    """

    def __init__(self, rpc_url: str = "http://localhost:8545", private_key: str | None = None,
                 allow_insecure_http: bool = False, timeout: float = 30.0,
                 chain_id: int | None = None):
        """
        Initialize Citrate client.

        Args:
            rpc_url: RPC endpoint URL
            private_key: Optional private key for transactions
            allow_insecure_http: SECREM-01 WEB-4 (pre-audit 2026-06-09) —
                silence the cleartext-transport warning when intentionally
                using plain http:// to a remote RPC host. Localhost http:// is
                always allowed silently. Defaults to False (warn on remote http).
            timeout: Per-request timeout in seconds for every JSON-RPC call.
                Was hardcoded to 30 with no way to change it, which meant a
                caller with a latency budget had no lever and a hung RPC held
                the caller for the full 30s. Note that `requests.Session` has no
                honoured `timeout` attribute — setting `client.session.timeout`
                does nothing, which is exactly the mistake the old timeout test
                made. It must be passed per request, as it now is.
            chain_id: SPY-B-005 — the EIP-155 chain-id bound into every signed
                transaction. Defaults to the value the package VENDORS
                (`federation_contract()["chain"]["chainId"]` = 40204), NOT the
                RPC's answer. `_eip155_chain_id` asserts the RPC's `eth_chainId`
                matches this and REFUSES TO SIGN on mismatch, so a hostile RPC
                cannot make the SDK produce a signature valid on another network
                (e.g. Ethereum mainnet). Pass an explicit value only when
                genuinely targeting a different Citrate network.
        """
        self.timeout = timeout
        # SPY-B-005: the chain-id that domain-separates every signature is PINNED to
        # the vendored artifact (or an explicit override), never adopted from the RPC.
        self._expected_chain_id = int(chain_id) if chain_id is not None else _contract.chain_id()
        # SECREM-01 WEB-4: warn when an RPC endpoint sends signed transactions /
        # private inputs to a remote host over plaintext http://.
        rpc_url = enforce_transport_security(rpc_url, allow_insecure_http=allow_insecure_http)
        self.rpc_url = rpc_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'citrate-python-sdk/0.1.0'
        })

        self.key_manager = KeyManager(private_key) if private_key else None
        self._request_id = 0
        # RM-G.4 — cached EIP-155 chain id, bound into every signed tx so a
        # signature cannot be replayed on another network.
        self._chain_id: int | None = None

    def _next_request_id(self) -> int:
        """Get next JSON-RPC request ID"""
        self._request_id += 1
        return self._request_id

    def _rpc_call(self, method: str, params: list[Any] | None = None) -> Any:
        """
        Make JSON-RPC call to Citrate node.

        Args:
            method: RPC method name
            params: Method parameters

        Returns:
            RPC response result

        Raises:
            CitrateError: If RPC call fails
        """
        payload = {
            "jsonrpc": "2.0",
            "method": method,
            "params": params or [],
            "id": self._next_request_id()
        }

        try:
            response = self.session.post(self.rpc_url, json=payload, timeout=self.timeout)
            response.raise_for_status()

            data = response.json()
            if "error" in data:
                raise CitrateError(f"RPC error: {data['error']['message']}")

            return data.get("result")

        except requests.exceptions.RequestException as e:
            raise CitrateError(f"Network error: {str(e)}")
        except json.JSONDecodeError as e:
            raise CitrateError(f"Invalid JSON response: {str(e)}")
        except Exception as e:
            raise CitrateError(f"Network error: {str(e)}")

    def get_chain_id(self) -> int:
        """Get blockchain chain ID.

        SPY-B-013: ``eth_chainId`` answers a hex string like ``"0x9d0c"``; this
        getter is annotated ``-> int`` and callers write ``get_chain_id() == 40204``,
        which silently returned ``False`` when the raw string leaked through.
        Normalize to ``int`` here so the public getter honours its annotation
        (``_eip155_chain_id`` already normalized internally; the getter did not).
        """
        raw = self._rpc_call("eth_chainId")
        if isinstance(raw, str):
            return int(raw, 16) if raw.startswith("0x") else int(raw)
        return int(raw)

    def get_balance(self, address: str) -> int:
        """Get account balance in wei"""
        result = self._rpc_call("eth_getBalance", [address, "latest"])
        return int(result, 16)

    def get_nonce(self, address: str) -> int:
        """Get account transaction nonce"""
        result = self._rpc_call("eth_getTransactionCount", [address, "pending"])
        return int(result, 16)

    def deploy_model(
        self,
        model_path: str | Path,
        config: ModelConfig
    ) -> ModelDeployment:
        """
        Deploy an AI model to Citrate blockchain.

        Args:
            model_path: Path to model file (.mlpackage, .onnx, etc.)
            config: Model configuration including encryption and access settings

        Returns:
            ModelDeployment with deployment details

        Raises:
            CitrateError: If deployment fails
        """
        if not self.key_manager:
            raise CitrateError("Private key required for model deployment")

        model_path = Path(model_path)
        if not model_path.exists():
            raise CitrateError(f"Model file not found: {model_path}")

        # Read and hash model file
        model_data = model_path.read_bytes()
        model_hash = hashlib.sha256(model_data).hexdigest()

        # Encrypt model if requested
        encrypted_data = None
        encryption_metadata = None
        key_share_envelopes: list[dict[str, Any]] | None = None

        if config.encrypted:
            if not config.encryption_config:
                config.encryption_config = EncryptionConfig()

            if config.encryption_config.threshold_shares:
                # PBA-L6b-003: shares come back wrapped to their holders and
                # separate from the public metadata; they never enter calldata.
                encrypted_data, encryption_metadata, key_share_envelopes = (
                    self.key_manager.encrypt_model_with_key_shares(model_data, config.encryption_config)
                )
            else:
                encrypted_data, encryption_metadata = self.key_manager.encrypt_model(
                    model_data, config.encryption_config
                )

        # Upload to IPFS
        ipfs_hash = self._upload_to_ipfs(encrypted_data or model_data)

        # Deploy to blockchain
        tx_data = {
            "model_hash": model_hash,
            "ipfs_hash": ipfs_hash,
            "encrypted": config.encrypted,
            "access_price": config.access_price,
            "access_list": config.access_list or [],
            "metadata": config.metadata or {}
        }

        if encryption_metadata:
            tx_data["encryption_metadata"] = encryption_metadata

        # PBA-L6b-003: this calldata is public. Serialise ONCE, run the share
        # guard on the parsed result of exactly those bytes, and send those
        # same bytes, so the guard judges what is sent rather than how the
        # live objects answer when read.
        payload = json.dumps(tx_data)
        assert_no_key_share_material(json.loads(payload))

        # Call model deployment precompile. SPY-B-007: the address is read from
        # the vendored canonical table (ModelDeploy = 0x..0100), NOT a hardcoded
        # `0x0100..0100` literal. The pre-fix literals were wrong in the high byte
        # (`0x01`-prefixed), so every deploy dispatched to an address with no
        # precompile entry and the state change never happened.
        tx_hash = self._send_transaction(self._precompile("ModelDeploy"), payload)

        # Wait for confirmation
        receipt = self._wait_for_receipt(tx_hash)

        # Extract model ID from logs
        model_id = self._extract_model_id_from_receipt(receipt)

        return ModelDeployment(
            model_id=model_id,
            tx_hash=tx_hash,
            ipfs_hash=ipfs_hash,
            encrypted=config.encrypted,
            access_price=config.access_price,
            deployment_time=int(time.time()),
            key_share_envelopes=key_share_envelopes,
        )

    def inference(
        self,
        model_id: str,
        input_data: dict[str, Any],
        encrypted: bool = False,
        max_gas: int = 1000000,
        recipient_public_key: str | None = None
    ) -> InferenceResult:
        """
        Execute inference on deployed model.

        Args:
            model_id: Deployed model identifier
            input_data: Input data for inference
            encrypted: Whether to use encrypted inference
            max_gas: Maximum gas limit for execution
            recipient_public_key: REQUIRED when ``encrypted=True`` — the
                model/recipient public key (hex) the symmetric key is
                ECDH-wrapped to. Without it the encrypted path fails closed
                (CITRATE_SDK_PYTHON-001): the SDK will not ship a key in
                cleartext on public calldata.

        Returns:
            InferenceResult with outputs and metadata

        Raises:
            ModelNotFoundError: If model doesn't exist
            InsufficientFundsError: If insufficient funds for inference
            CitrateError: For other execution errors (incl. encrypted=True
                without recipient_public_key)
        """
        # Prepare inference request
        request = InferenceRequest(
            model_id=model_id,
            input_data=input_data,
            encrypted=encrypted,
            timestamp=int(time.time())
        )

        # Encrypt input if needed. CITRATE_SDK_PYTHON-001: the symmetric key
        # is ECDH-wrapped to recipient_public_key and never shipped raw; the
        # call fails closed if no recipient key is supplied.
        # SPY-B-013: fail CLOSED when the caller asked for encryption but no
        # KeyManager is configured. The pre-fix `if encrypted and self.key_manager:`
        # had no `else`, so `encrypted=True` on a keyless client SILENTLY skipped
        # encryption and sent `input_data` as plaintext into permanent public
        # calldata. A downstream `_send_transaction` guard happened to catch it,
        # but confidentiality must not depend on an unrelated check in another
        # method — refuse here, naming encryption.
        if encrypted:
            if not self.key_manager:
                raise CitrateError(
                    "encrypted=True but no KeyManager is configured (no private_key). "
                    "Refusing to send the inference input in plaintext (SPY-B-013)."
                )
            encrypted_input = self.key_manager.encrypt_data(
                json.dumps(input_data), recipient_public_key
            )
            request.input_data = {"encrypted": encrypted_input}

        # Call inference precompile. SPY-B-007: address read from the vendored
        # canonical table (ModelInference = 0x..0101), not a hardcoded literal.
        tx_data = asdict(request)
        tx_hash = self._send_transaction(
            self._precompile("ModelInference"),
            tx_data,
            gas_limit=max_gas
        )

        # Wait for execution
        receipt = self._wait_for_receipt(tx_hash)

        # Extract results from logs
        output_data = self._extract_inference_output(receipt)

        # Decrypt output if encrypted. CIT-SDKPY-02: pin the sender to the model/
        # recipient key we wrapped the REQUEST to, so a successful decrypt also
        # authenticates that the response came from that keypair — not merely that
        # *some* holder of a valid key produced it. Static-static ECDH already
        # guarantees the envelope was minted by the claimed sender; pinning makes
        # the SDK's own consumer of `decrypt_data` actually USE that guarantee
        # instead of reading decrypt-success as authenticity.
        if encrypted and self.key_manager and "encrypted" in output_data:
            decrypted_output = self.key_manager.decrypt_data(
                output_data["encrypted"],
                expected_sender_public_key=recipient_public_key,
            )
            output_data = json.loads(decrypted_output)

        return InferenceResult(
            model_id=model_id,
            output_data=output_data,
            gas_used=int(receipt["gasUsed"], 16) if isinstance(receipt.get("gasUsed"), str) else receipt.get("gasUsed", 0),
            execution_time=receipt.get("executionTime", 0),
            tx_hash=tx_hash
        )

    def get_model_info(self, model_id: str) -> dict[str, Any]:
        """Get model deployment information"""
        params = [model_id]
        result = self._rpc_call("citrate_getModel", params)

        if not result:
            raise ModelNotFoundError(f"Model not found: {model_id}")

        return cast("dict[str, Any]", result)

    def list_models(self, owner: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        """List deployed models.

        SEC-037: the node answers `{"models": [...]}`, but this is annotated
        (and used) as a list. Returning the raw dict meant `for m in
        list_models()` iterated DICT KEYS and yielded the string "models" — no
        exception, silently wrong, and the shape integrators report as "the SDK
        returns nothing". Unwrap, and tolerate a bare list in case the node's
        shape changes back.
        """
        params = [owner, limit] if owner else [limit]
        result = self._rpc_call("citrate_listModels", params)
        if isinstance(result, dict):
            return cast("list[dict[str, Any]]", result.get("models", []))
        return result or []

    def purchase_model_access(self, model_id: str, payment_amount: int) -> str:
        """Purchase access to a paid model.

        SPY-B-001 (fail closed): this previously signed and broadcast a
        transaction sending the buyer's full ``payment_amount`` as ``value`` to
        ``0x0100000000000000000000000000000000000104`` -- an address absent from
        the canonical precompile table this package vendors
        (``federation_contract()["precompiles"]``: 0x..0100-0103, 0105+, but no
        0104), so the funds left the buyer's account with nothing able to credit
        the purchase (destroyed funds). No node-confirmed access-purchase
        precompile exists, so this path raises and moves no money until a real
        on-chain purchase route is wired.
        """
        raise CitrateError(
            "purchase_model_access is unavailable: no node-confirmed "
            "access-purchase precompile exists (SPY-B-001). Refusing to sign or "
            "broadcast a transaction that would send funds to a non-precompile "
            "address and destroy the payment."
        )

    def _upload_to_ipfs(self, data: bytes) -> str:
        """Upload data to IPFS and return the content identifier (CID)."""
        try:
            return upload_to_ipfs(data)
        except Exception as e:
            # FAIL CLOSED. Previously this fabricated a `fallback_<sha256>`
            # pseudo-CID and returned it as if the upload succeeded — a
            # non-retrievable reference that silently entered deployment
            # metadata and downstream flows. Surface the failure instead.
            # Audit: CITRATE_SDK_PYTHON-B-2026-05-31-003.
            raise CitrateError(
                f"IPFS upload failed and no verifiable fallback is permitted: {e}"
            ) from e

    def _precompile(self, name: str) -> str:
        """Canonical precompile address for ``name`` from the vendored table.

        SPY-B-007: the single source of truth is
        ``federation_contract()["precompiles"]`` (which ``cli.py`` already reads),
        never a hardcoded literal in this module. Raises if the name is unknown so
        a typo fails loudly instead of dispatching to nothing.
        """
        table = _contract.precompiles()
        addr = table.get(name)
        if not addr:
            raise CitrateError(
                "unknown precompile {!r}; vendored table has: {}".format(name, ", ".join(sorted(table)))
            )
        return addr

    def _eip155_chain_id(self) -> int:
        """Resolve + cache the chain id for EIP-155 transaction signing (RM-G.4).

        SPY-B-005: fetched once via eth_chainId, then ASSERTED against the
        configured/vendored chain-id (`self._expected_chain_id`, default 40204).
        The RPC's answer is *verified*, never *adopted* — a hostile or mistaken
        endpoint reporting any other chain-id (e.g. 1 for Ethereum mainnet) makes
        this raise and refuse to sign, so a signature cannot be domain-separated
        onto a network the SDK did not intend. This mirrors the pin
        `IdentityClient.discover()` already applies to the OIDC issuer.
        """
        if self._chain_id is None:
            # ``get_chain_id`` normalizes ``eth_chainId`` to ``int`` (SPY-B-013),
            # but keep the defensive hex-string normalization too: callers (and
            # tests) may substitute a ``get_chain_id`` that hands back the raw
            # ``"0x..."`` string. Typing the local as ``int | str`` keeps that
            # branch honest rather than trusting the ``-> int`` annotation.
            raw: int | str = self.get_chain_id()
            if isinstance(raw, str):
                reported = int(raw, 16) if raw.startswith("0x") else int(raw)
            else:
                reported = int(raw)
            if reported != self._expected_chain_id:
                raise CitrateError(
                    "RPC chain-id mismatch: endpoint reports %d but the "
                    "configured/vendored chain-id is %d. Refusing to sign a "
                    "transaction whose signature could be replayed on another "
                    "network (SPY-B-005)." % (reported, self._expected_chain_id)
                )
            self._chain_id = reported
        return self._chain_id

    def _send_transaction(
        self,
        to_address: str,
        data: dict[str, Any] | str,
        value: int = 0,
        gas_limit: int = 500000
    ) -> str:
        """Send transaction to blockchain.

        ``data`` is either a dict (serialised here) or an already-serialised
        JSON string, which is sent byte-for-byte (see ``deploy_model``).
        """
        encoded = data if isinstance(data, str) else json.dumps(data)
        if not self.key_manager:
            raise CitrateError("Private key required for transactions")

        # Get account info
        from_address = self.key_manager.get_address()
        nonce = self.get_nonce(from_address)

        # Build transaction. RM-G.4: bind chainId so the signature is
        # EIP-155 (domain-separated) and cannot be replayed on another
        # Citrate network — the pre-fix tx omitted chainId (pre-EIP-155).
        tx = {
            "from": from_address,
            "to": to_address,
            "value": hex(value),
            "gas": hex(gas_limit),
            "gasPrice": hex(20_000_000_000),  # 20 gwei
            "nonce": hex(nonce),
            "data": "0x" + encoded.encode().hex(),
            "chainId": self._eip155_chain_id(),
        }

        # Sign transaction
        signed_tx = self.key_manager.sign_transaction(tx)

        # Send raw transaction
        return cast(str, self._rpc_call("eth_sendRawTransaction", [signed_tx]))

    def _wait_for_receipt(self, tx_hash: str, timeout: int = 60) -> dict[str, Any]:
        """Wait for transaction receipt"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                receipt = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
                if receipt:
                    return cast("dict[str, Any]", receipt)
            except CitrateError:
                pass

            time.sleep(1)

        raise CitrateError(f"Transaction timeout: {tx_hash}")

    def _extract_model_id_from_receipt(self, receipt: dict[str, Any]) -> str:
        """Extract model ID from deployment receipt logs.

        SPY-B-006: match ``topics[0]`` against the keccak256 of the event
        signature, not the ASCII hex of the event name. The old check could
        never match a real topic, so this always raised AFTER the tx was
        broadcast and confirmed. On genuine not-found the error now carries the
        transactionHash so the caller can recover the already-mined deployment
        instead of blindly retrying and paying gas again.
        """
        want = _event_topic(MODEL_DEPLOYED_EVENT_SIGNATURE)
        logs = receipt.get("logs", [])
        for log in logs:
            topics = log.get("topics", [])
            if topics and str(topics[0]).lower() == want:
                # Extract model ID from log data
                return cast(str, log["data"][:66])  # First 32 bytes as hex

        raise CitrateError(
            "Model ID not found in deployment receipt (tx {}); the transaction "
            "may already be mined — do not blindly resubmit.".format(receipt.get("transactionHash", "?"))
        )

    def _extract_inference_output(self, receipt: dict[str, Any]) -> dict[str, Any]:
        """Extract inference output from execution receipt.

        SPY-B-006: match ``topics[0]`` against the keccak256 of the event
        signature rather than the ASCII hex of the event name.
        """
        want = _event_topic(INFERENCE_COMPLETE_EVENT_SIGNATURE)
        logs = receipt.get("logs", [])
        for log in logs:
            topics = log.get("topics", [])
            if topics and str(topics[0]).lower() == want:
                # Decode output data from log
                data_hex = log["data"]
                data_bytes = bytes.fromhex(data_hex[2:])
                return cast("dict[str, Any]", json.loads(data_bytes.decode()))

        raise CitrateError(
            "Inference output not found in receipt (tx {})".format(receipt.get("transactionHash", "?"))
        )
