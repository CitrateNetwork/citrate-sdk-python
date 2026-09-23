#!/usr/bin/env python3
"""
Marketplace demo for Citrate Python SDK

This example demonstrates:
1. Browsing model marketplace
2. Purchasing model access
3. Revenue sharing setup
4. Model rating and reviews
"""

import os
import time

from citrate_sdk import AccessType, CitrateClient, ModelConfig, ModelType
from citrate_sdk.crypto import KeyManager


def main():
    """Run marketplace demo"""

    # Configuration
    RPC_URL = os.getenv("CITRATE_RPC_URL", "http://localhost:8545")

    # SPY-B-011: source keys from the environment rather than constructing a
    # throwaway KeyManager purely to extract its private key as a string and hand
    # it to another constructor — the anti-pattern the SDK should steer users away
    # from. Real participants bring their own keys; the demo reads them from env
    # (mirrors basic_usage.py / encrypted_inference.py).
    SELLER_KEY = os.getenv("CITRATE_PRIVATE_KEY")
    BUYER_KEY = os.getenv("CITRATE_BUYER_PRIVATE_KEY")
    if not (SELLER_KEY and BUYER_KEY):
        print("Please set CITRATE_PRIVATE_KEY (seller) and "
              "CITRATE_BUYER_PRIVATE_KEY (buyer) environment variables")
        return

    # Create marketplace participants from their own keys
    print("Creating marketplace participants...")

    # Model seller
    seller = CitrateClient(rpc_url=RPC_URL, private_key=SELLER_KEY)
    print(f"Seller: {seller.key_manager.get_address()}")

    # Model buyer
    buyer = CitrateClient(rpc_url=RPC_URL, private_key=BUYER_KEY)
    print(f"Buyer: {buyer.key_manager.get_address()}")

    # Revenue partner (e.g., dataset provider) — a keypair, used as a payee
    partner = KeyManager()
    print(f"Partner: {partner.get_address()}")

    try:
        # Check balances
        seller_balance = seller.get_balance(seller.key_manager.get_address())
        buyer_balance = buyer.get_balance(buyer.key_manager.get_address())

        print("\nInitial balances:")
        print(f"Seller: {seller_balance / 10**18:.4f} ETH")
        print(f"Buyer: {buyer_balance / 10**18:.4f} ETH")

        # Seller deploys a premium model with revenue sharing
        print("\n💼 Seller: Deploying premium model with revenue sharing...")

        revenue_shares = {
            seller.key_manager.get_address(): 0.70,  # 70% to model creator
            partner.get_address(): 0.25,             # 25% to data provider
            "0x0000000000000000000000000000000000000001": 0.05  # 5% to platform
        }

        config = ModelConfig(
            name="Premium Image Classifier",
            description="High-accuracy image classification model trained on premium dataset",
            model_type=ModelType.COREML,
            access_type=AccessType.PAID,
            access_price=100000000000000000,  # 0.1 ETH per inference
            revenue_shares=revenue_shares,
            metadata={
                "accuracy": 0.98,
                "dataset_size": "1M images",
                "training_time": "100 GPU hours",
                "category": "computer_vision"
            },
            tags=["image", "classification", "premium", "high-accuracy"]
        )

        # Create dummy model file
        import json
        from pathlib import Path

        model_path = Path("premium_classifier.json")
        premium_model = {
            "type": "image_classifier",
            "architecture": "ResNet-50",
            "input_size": [224, 224, 3],
            "output_classes": 1000,
            "accuracy": 0.98,
            "model_size": "25MB"
        }

        with open(model_path, 'w') as f:
            json.dump(premium_model, f)

        deployment = seller.deploy_model(model_path, config)

        print("✅ Premium model deployed!")
        print(f"Model ID: {deployment.model_id}")
        print(f"Price: {config.access_price / 10**18} ETH per inference")

        # Browse marketplace
        print("\n🛒 Buyer: Browsing marketplace...")

        # List available models
        available_models = buyer.list_models(limit=10)
        print(f"Found {len(available_models)} models in marketplace:")

        for model in available_models:
            print(f"  📦 {model.get('name', 'Unnamed')}")
            print(f"     ID: {model.get('model_id')}")
            print(f"     Price: {model.get('access_price', 0) / 10**18} ETH")
            print(f"     Owner: {model.get('owner', 'Unknown')}")

        # Get detailed model info
        print(f"\n🔍 Examining model: {deployment.model_id}")
        model_info = buyer.get_model_info(deployment.model_id)

        print("Model details:")
        print(f"  Name: {model_info.get('name')}")
        print(f"  Description: {model_info.get('description')}")
        print(f"  Price: {model_info.get('access_price', 0) / 10**18} ETH")
        print(f"  Total inferences: {model_info.get('total_inferences', 0)}")
        print(f"  Revenue: {model_info.get('total_revenue', 0) / 10**18} ETH")

        # SPY-B-001: model-access purchase has no node-confirmed on-chain
        # precompile, so purchase_model_access() fails closed rather than
        # burning the buyer's payment to a non-precompile address. The demo
        # skips the purchase step until a real access-purchase route is wired.
        print("\n💳 Buyer: (access-purchase skipped — no on-chain purchase precompile yet; SPY-B-001)")

        # Wait for transaction confirmation
        print("Waiting for transaction confirmation...")
        time.sleep(5)

        # Use the model
        print("\n🧠 Buyer: Running inference on purchased model...")

        inference_input = {
            "image": "base64_encoded_image_data_here",
            "format": "jpg",
            "preprocessing": "resize_224x224"
        }

        result = buyer.inference(
            model_id=deployment.model_id,
            input_data=inference_input
        )

        print("✅ Inference completed!")
        print(f"Classification: {result.output_data.get('class', 'unknown')}")
        print(f"Confidence: {result.output_data.get('confidence', 0)}")
        print(f"Gas used: {result.gas_used}")

        # Simulate multiple users and usage
        print("\n📊 Simulating marketplace activity...")

        # Create more buyers. These are throwaway SIMULATION accounts (fresh
        # random keypairs), so generating them here is intentional — unlike the
        # seller/buyer above, they do not represent a real user whose key should
        # come from the environment (SPY-B-011).
        from eth_account import Account
        buyers = []
        for i in range(3):
            sim_key = Account.create().key.hex()
            buyer_client = CitrateClient(rpc_url=RPC_URL, private_key=sim_key)
            buyers.append(buyer_client)

        # Simulate purchases and usage
        total_revenue = 0
        for i, buyer_client in enumerate(buyers):
            print(f"User {i+1}: Purchasing and using model...")

            try:
                # SPY-B-001: purchase step skipped — purchase_model_access
                # fails closed (no on-chain access-purchase precompile yet;
                # it previously burned the payment to a non-precompile address).

                # Run inference
                result = buyer_client.inference(
                    model_id=deployment.model_id,
                    input_data={"image": f"test_image_{i+1}"}
                )

                total_revenue += config.access_price
                print(f"  ✅ User {i+1} completed inference")

            except Exception as e:
                print(f"  ❌ User {i+1} failed: {e}")

        # Check final marketplace stats
        print("\n📈 Final marketplace statistics:")

        updated_model_info = seller.get_model_info(deployment.model_id)
        print(f"Total inferences: {updated_model_info.get('total_inferences', 0)}")
        print(f"Total revenue: {updated_model_info.get('total_revenue', 0) / 10**18} ETH")

        # Check seller revenue
        final_seller_balance = seller.get_balance(seller.key_manager.get_address())
        revenue_earned = (final_seller_balance - seller_balance) / 10**18

        print(f"Seller revenue earned: {revenue_earned:.4f} ETH")

        print("\n💡 Revenue sharing breakdown (per inference):")
        for address, percentage in revenue_shares.items():
            amount = (config.access_price * percentage) / 10**18
            print(f"  {address[:10]}...: {percentage*100}% = {amount:.4f} ETH")

    except Exception as e:
        print(f"❌ Marketplace demo failed: {e}")
        import traceback
        traceback.print_exc()

    finally:
        # Cleanup
        if 'model_path' in locals() and model_path.exists():
            model_path.unlink()

    print("\n✅ Marketplace demo completed!")


if __name__ == "__main__":
    main()
