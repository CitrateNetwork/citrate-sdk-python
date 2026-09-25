"""
Data models for Citrate SDK
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# The canonical, publicly-exported encryption config lives in ``crypto``; it is
# the type actually constructed and consumed by ``KeyManager.encrypt_model``.
# Re-export it here so ``ModelConfig.encryption_config`` is annotated with the
# same class that is assigned to it at runtime (previously a separate, stale
# duplicate dataclass lived here and never matched the value stored in it).
from .crypto import EncryptionConfig


class ModelType(Enum):
    """Supported model types"""
    COREML = "coreml"
    ONNX = "onnx"
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    CUSTOM = "custom"


class AccessType(Enum):
    """Model access types"""
    PUBLIC = "public"
    PRIVATE = "private"
    PAID = "paid"
    WHITELIST = "whitelist"


@dataclass
class ModelConfig:
    """Configuration for model deployment"""
    # Basic settings
    name: str = ""
    description: str = ""
    model_type: ModelType = ModelType.COREML
    version: str = "1.0.0"

    # Access control
    access_type: AccessType = AccessType.PUBLIC
    access_price: int = 0  # Price in wei per inference
    access_list: list[str] | None = None  # Whitelist addresses

    # Encryption
    encrypted: bool = False
    encryption_config: EncryptionConfig | None = None

    # Metadata
    metadata: dict[str, Any] | None = None
    tags: list[str] = field(default_factory=list)

    # Performance
    max_batch_size: int = 1
    timeout_seconds: int = 30
    memory_limit_mb: int = 1024

    # Revenue sharing
    revenue_shares: dict[str, float] | None = None  # address -> percentage


@dataclass
class ModelDeployment:
    """Result of model deployment"""
    model_id: str
    tx_hash: str
    ipfs_hash: str
    encrypted: bool
    access_price: int
    deployment_time: int
    gas_used: int | None = None
    deployment_cost: int | None = None
    #: PBA-L6b-003: holder-wrapped key shares when threshold sharing was
    #: requested. Deliver each to its holder off-chain; none of it is on-chain.
    key_share_envelopes: list[dict[str, Any]] | None = None


@dataclass
class InferenceRequest:
    """Request for model inference"""
    model_id: str
    input_data: dict[str, Any]
    encrypted: bool = False
    batch_size: int = 1
    timeout: int = 30
    timestamp: int | None = None


@dataclass
class InferenceResult:
    """Result of model inference"""
    model_id: str
    output_data: dict[str, Any]
    gas_used: int
    execution_time: float  # milliseconds
    tx_hash: str
    confidence: float | None = None
    metadata: dict[str, Any] | None = None


@dataclass
class ModelInfo:
    """Detailed model information"""
    model_id: str
    name: str
    description: str
    owner: str
    model_type: ModelType
    access_type: AccessType
    access_price: int
    encrypted: bool
    ipfs_hash: str
    deployment_time: int
    total_inferences: int
    total_revenue: int
    metadata: dict[str, Any]
    tags: list[str]


@dataclass
class ModelStats:
    """Model usage statistics"""
    model_id: str
    total_inferences: int
    total_revenue: int
    average_execution_time: float
    average_gas_cost: int
    unique_users: int
    last_inference_time: int


@dataclass
class PaymentInfo:
    """Payment information for model access"""
    model_id: str
    price_per_inference: int
    payment_token: str = "ETH"
    payment_address: str = ""
    revenue_sharing: dict[str, float] | None = None


@dataclass
class AccessControlEntry:
    """Access control entry for a model"""
    address: str
    access_level: str  # "read", "write", "admin"
    granted_by: str
    granted_at: int
    expires_at: int | None = None


@dataclass
class ModelVersion:
    """Model version information"""
    model_id: str
    version: str
    ipfs_hash: str
    deployment_time: int
    changes: str
    deprecated: bool = False
