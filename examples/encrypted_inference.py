#!/usr/bin/env python3
"""
Encrypted inference example for Citrate Python SDK

This example demonstrates:
1. Deploying an encrypted model
2. Setting up access controls
3. Running encrypted inference
4. Key sharing and threshold schemes
"""

import json
import os
from pathlib import Path

from citrate_sdk import AccessType, CitrateClient, ModelConfig, ModelType
from citrate_sdk.crypto import EncryptionConfig, KeyManager


def main() -> None:
    """Run encrypted inference example"""

    # Configuration
    RPC_URL = os.getenv("CITRATE_RPC_URL", "http://localhost:8545")
    PRIVATE_KEY = os.getenv("CITRATE_PRIVATE_KEY")

    if not PRIVATE_KEY:
        print("Please set CITRATE_PRIVATE_KEY environment variable")
        return

    # Connect to Citrate
    print(f"Connecting to Citrate at {RPC_URL}...")
    client = CitrateClient(rpc_url=RPC_URL, private_key=PRIVATE_KEY)
    assert client.key_manager is not None  # constructed with a private key

    try:
        address = client.key_manager.get_address()
        balance = client.get_balance(address)
        print(f"Account: {address}")
        print(f"Balance: {balance / 10**18:.4f} ETH")

    except Exception as e:
        print(f"Connection failed: {e}")
        return

    # Create a sensitive AI model
    model_path = Path("sensitive_model.json")
    sensitive_model = {
        "type": "proprietary_classifier",
        "version": "2.0",
        "algorithm": "advanced_neural_network",
        "parameters": {
            "layers": [128, 64, 32, 10],
            "activation": "relu",
            "learning_rate": 0.001
        },
        "proprietary_weights": [0.123456] * 1000,  # Sensitive model weights
        "training_data_info": "confidential_dataset_v2"
    }

    with open(model_path, 'w') as f:
        json.dump(sensitive_model, f, indent=2)

    print(f"Created sensitive model: {model_path}")

    # Key-share holders (simulating three other parties). In production these
    # are the holders' own public keys; their private keys never leave them.
    alice, bob, carol = KeyManager(), KeyManager(), KeyManager()

    # Configure encryption with threshold sharing. PBA-L6b-003: every share is
    # ECDH-wrapped to one named holder and returned on the deployment result for
    # OFF-CHAIN delivery. Shares are never written to the deploy transaction
    # (its calldata is public). threshold_shares > 0 without holder keys is
    # refused.
    encryption_config = EncryptionConfig(
        algorithm="AES-256-GCM",
        key_derivation="HKDF-SHA256",
        access_control=True,
        threshold_shares=2,  # Need 2 shares to rebuild the model key
        total_shares=3,      # One share per holder
        share_holder_public_keys=[
            alice.get_public_key(),
            bob.get_public_key(),
            carol.get_public_key(),
        ],
    )

    # Configure encrypted model deployment
    config = ModelConfig(
        name="Sensitive AI Model",
        description="Proprietary model with encrypted weights",
        model_type=ModelType.CUSTOM,
        access_type=AccessType.PAID,
        access_price=500000000000000000,  # 0.5 ETH per inference
        encrypted=True,
        encryption_config=encryption_config,
        metadata={
            "sensitivity_level": "high",
            "compliance": "GDPR,CCPA",
            "encryption": "AES-256-GCM"
        }
    )

    try:
        # Deploy encrypted model
        print("\n🔒 Deploying encrypted model...")
        deployment = client.deploy_model(model_path, config)

        print("✅ Encrypted model deployed!")
        print(f"Model ID: {deployment.model_id}")
        print(f"Transaction: {deployment.tx_hash}")
        print(f"Encrypted: {deployment.encrypted}")

        # Demonstrate key sharing: deliver each wrapped share to its holder
        # off-chain (e.g. over an authenticated channel); any 2 holders can
        # then rebuild the model key. Nothing here touched the chain.
        print("\n🔑 Demonstrating key sharing...")
        envelopes = deployment.key_share_envelopes or []
        print(f"Wrapped key shares to deliver off-chain: {len(envelopes)}")
        owner_pubkey = client.key_manager.get_public_key()
        share_a = alice.unwrap_key_share(envelopes[0], owner_pubkey)
        share_b = bob.unwrap_key_share(envelopes[1], owner_pubkey)
        rebuilt = alice.reconstruct_key_from_shares([share_a, share_b], threshold=2)
        print(f"Alice + Bob rebuilt a {len(rebuilt)}-byte model key")

        print(f"Alice address: {alice.get_address()}")
        print(f"Bob address: {bob.get_address()}")

        # Get shared keys for secure communication
        client.key_manager.get_public_key()
        alice_pubkey = alice.get_public_key()
        bob_pubkey = bob.get_public_key()

        # Derive shared keys
        alice_shared = client.key_manager.derive_shared_key(alice_pubkey)
        bob_shared = client.key_manager.derive_shared_key(bob_pubkey)

        print(f"Shared key with Alice: {alice_shared[:8].hex()}...")
        print(f"Shared key with Bob: {bob_shared[:8].hex()}...")

        # Run encrypted inference
        print("\n🧠 Running encrypted inference...")

        # Prepare sensitive input data
        sensitive_input = {
            "patient_data": {
                "age": 45,
                "symptoms": ["fever", "cough"],
                "medical_history": "confidential"
            },
            "analysis_level": "detailed"
        }

        # Execute encrypted inference. SPY-B-011: `encrypted=True` REQUIRES a
        # recipient_public_key — the symmetric key is ECDH-wrapped to it and
        # never shipped in cleartext (the call fails closed otherwise). Here we
        # wrap to the model owner's own public key for the demo; in production
        # this is the model/node public key from the deployment record.
        recipient_pubkey = client.key_manager.get_public_key()
        result = client.inference(
            model_id=deployment.model_id,
            input_data=sensitive_input,
            encrypted=True,
            max_gas=1500000,
            recipient_public_key=recipient_pubkey,
        )

        print("✅ Encrypted inference completed!")
        print(f"Output (encrypted): {str(result.output_data)[:100]}...")
        print(f"Gas used: {result.gas_used}")
        print(f"Execution time: {result.execution_time}ms")

        # Demonstrate data encryption utilities
        print("\n🔐 Testing encryption utilities...")

        # Encrypt arbitrary data. SPY-B-011 / CITRATE_SDK_PYTHON-001:
        # encrypt_data REQUIRES a recipient public key (the key is ECDH-wrapped
        # to it, never shipped raw).
        test_data = "This is sensitive information that needs protection"
        recipient_pubkey = client.key_manager.get_public_key()
        encrypted_data = client.key_manager.encrypt_data(test_data, recipient_pubkey)
        decrypted_data = client.key_manager.decrypt_data(encrypted_data)

        print(f"Original: {test_data}")
        print(f"Encrypted: {encrypted_data[:50]}...")
        print(f"Decrypted: {decrypted_data}")
        print(f"Match: {test_data == decrypted_data}")

        # Test model integrity
        print("\n🛡️  Testing model integrity...")
        from citrate_sdk.crypto import hash_model_data, verify_model_integrity

        model_data = model_path.read_bytes()
        model_hash = hash_model_data(model_data)
        is_valid = verify_model_integrity(model_data, model_hash)

        print(f"Model hash: {model_hash}")
        print(f"Integrity check: {is_valid}")

    except Exception as e:
        print(f"❌ Operation failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        if model_path.exists():
            model_path.unlink()
            print(f"Cleaned up: {model_path}")

    print("\n✅ Encrypted inference demo completed!")


if __name__ == "__main__":
    main()
