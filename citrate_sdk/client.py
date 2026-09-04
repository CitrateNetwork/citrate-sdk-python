"""
Citrate Client - Main SDK interface for Citrate blockchain interaction
"""

import json
import requests
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, asdict
from pathlib import Path
import hashlib
import time

from .models import ModelConfig, ModelDeployment, InferenceRequest, InferenceResult
from .crypto import EncryptionConfig, KeyManager
from .errors import CitrateError, ModelNotFoundError, InsufficientFundsError
from .ipfs import upload_to_ipfs
from ._url_security import enforce_transport_security


class CitrateClient:
    """
    Main client for interacting with Citrate blockchain.

    Provides methods for:
    - Model deployment and management
    - Inference execution
    - Encryption and access control
    - Payment and revenue sharing
    """

    def __init__(self, rpc_url: str = "http://localhost:8545", private_key: Optional[str] = None,
                 allow_insecure_http: bool = False, timeout: float = 30.0):
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
        """
        self.timeout = timeout
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
        self._chain_id: Optional[int] = None

    def _next_request_id(self) -> int:
        """Get next JSON-RPC request ID"""
        self._request_id += 1
        return self._request_id

    def _rpc_call(self, method: str, params: List[Any] = None) -> Any:
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
        """Get blockchain chain ID"""
        return self._rpc_call("eth_chainId")

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
        model_path: Union[str, Path],
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

        if config.encrypted:
            if not config.encryption_config:
                config.encryption_config = EncryptionConfig()

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

        # Call model deployment precompile (0x0100)
        tx_hash = self._send_transaction("0x0100000000000000000000000000000000000100", tx_data)

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
            deployment_time=int(time.time())
        )

    def inference(
        self,
        model_id: str,
        input_data: Dict[str, Any],
        encrypted: bool = False,
        max_gas: int = 1000000,
        recipient_public_key: str = None
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
        if encrypted and self.key_manager:
            encrypted_input = self.key_manager.encrypt_data(
                json.dumps(input_data), recipient_public_key
            )
            request.input_data = {"encrypted": encrypted_input}

        # Call inference precompile (0x0101)
        tx_data = asdict(request)
        tx_hash = self._send_transaction(
            "0x0100000000000000000000000000000000000101",
            tx_data,
            gas_limit=max_gas
        )

        # Wait for execution
        receipt = self._wait_for_receipt(tx_hash)

        # Extract results from logs
        output_data = self._extract_inference_output(receipt)

        # Decrypt output if encrypted
        if encrypted and self.key_manager and "encrypted" in output_data:
            decrypted_output = self.key_manager.decrypt_data(output_data["encrypted"])
            output_data = json.loads(decrypted_output)

        return InferenceResult(
            model_id=model_id,
            output_data=output_data,
            gas_used=int(receipt["gasUsed"], 16) if isinstance(receipt.get("gasUsed"), str) else receipt.get("gasUsed", 0),
            execution_time=receipt.get("executionTime", 0),
            tx_hash=tx_hash
        )

    def get_model_info(self, model_id: str) -> Dict[str, Any]:
        """Get model deployment information"""
        params = [model_id]
        result = self._rpc_call("citrate_getModel", params)

        if not result:
            raise ModelNotFoundError(f"Model not found: {model_id}")

        return result

    def list_models(self, owner: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
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
            return result.get("models", [])
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

    def _eip155_chain_id(self) -> int:
        """Resolve + cache the chain id for EIP-155 transaction signing
        (RM-G.4). Fetched once via eth_chainId; normalized to int."""
        if self._chain_id is None:
            raw = self.get_chain_id()
            if isinstance(raw, str):
                self._chain_id = int(raw, 16) if raw.startswith("0x") else int(raw)
            else:
                self._chain_id = int(raw)
        return self._chain_id

    def _send_transaction(
        self,
        to_address: str,
        data: Dict[str, Any],
        value: int = 0,
        gas_limit: int = 500000
    ) -> str:
        """Send transaction to blockchain"""
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
            "data": "0x" + json.dumps(data).encode().hex(),
            "chainId": self._eip155_chain_id(),
        }

        # Sign transaction
        signed_tx = self.key_manager.sign_transaction(tx)

        # Send raw transaction
        return self._rpc_call("eth_sendRawTransaction", [signed_tx])

    def _wait_for_receipt(self, tx_hash: str, timeout: int = 60) -> Dict[str, Any]:
        """Wait for transaction receipt"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                receipt = self._rpc_call("eth_getTransactionReceipt", [tx_hash])
                if receipt:
                    return receipt
            except CitrateError:
                pass

            time.sleep(1)

        raise CitrateError(f"Transaction timeout: {tx_hash}")

    def _extract_model_id_from_receipt(self, receipt: Dict[str, Any]) -> str:
        """Extract model ID from deployment receipt logs"""
        logs = receipt.get("logs", [])
        for log in logs:
            # Look for ModelDeployed event
            if log.get("topics", []):
                topic = log["topics"][0]
                if topic.startswith("0x" + "ModelDeployed".encode().hex()[:16]):
                    # Extract model ID from log data
                    return log["data"][:66]  # First 32 bytes as hex

        raise CitrateError("Model ID not found in deployment receipt")

    def _extract_inference_output(self, receipt: Dict[str, Any]) -> Dict[str, Any]:
        """Extract inference output from execution receipt"""
        logs = receipt.get("logs", [])
        for log in logs:
            if log.get("topics", []):
                topic = log["topics"][0]
                if topic.startswith("0x" + "InferenceComplete".encode().hex()[:16]):
                    # Decode output data from log
                    data_hex = log["data"]
                    data_bytes = bytes.fromhex(data_hex[2:])
                    return json.loads(data_bytes.decode())

        raise CitrateError("Inference output not found in receipt")
