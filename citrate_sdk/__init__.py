"""
Citrate Python SDK

A comprehensive Python SDK for interacting with the Citrate AI blockchain platform.
Provides easy-to-use interfaces for model deployment, inference execution,
encryption, access control, payment systems, learning pools, liquid staking,
classrooms, compute marketplace, treasury, and farming operations.
"""

from .client import CitrateClient

# COMPUTE-4: Compute marketplace manager
from .compute import ComputeManager
from .crypto import EncryptionConfig, KeyManager
from .errors import CitrateError, InsufficientFundsError, ModelNotFoundError
from .farming import FarmingManager

# LC.5.3: Learning / Staking / Classroom managers
from .learning import ClassroomManager, LearningManager, StakingManager

# Memory — typed client for a citrate-memories gateway ("git for agents"):
# OIDC REST (recall/search/neighbors/verify/review/assert/layout) + BYOM MCP.
from .memory import ByomMemoryClient, MemoryClient, MemoryError
from .models import (
    AccessType,
    InferenceRequest,
    InferenceResult,
    ModelConfig,
    ModelDeployment,
    ModelType,
)

# ECON-2: Treasury and farming managers
from .treasury import TreasuryManager

# Shared data types for learning / staking / classroom / compute
from .types import (
    ClassroomInfo,
    ComputeJob,
    ComputePool,
    ContributionDetail,
    Contributions,
    CycleStatus,
    Dispute,
    LearningPool,
    PendingWithdrawal,
    ProviderInfo,
    StakingInfo,
)

__version__ = "0.6.3"
__author__ = "Citrate Team"

__all__ = [
    # Core client
    "CitrateClient",
    # Model types
    "ModelConfig",
    "ModelDeployment",
    "InferenceRequest",
    "InferenceResult",
    "ModelType",
    "AccessType",
    # Crypto
    "EncryptionConfig",
    "KeyManager",
    # Errors
    "CitrateError",
    "ModelNotFoundError",
    "InsufficientFundsError",
    # LC.5.3: Learning managers
    "LearningManager",
    "StakingManager",
    "ClassroomManager",
    # COMPUTE-4: Compute manager
    "ComputeManager",
    # ECON-2: Treasury and farming managers
    "TreasuryManager",
    "FarmingManager",
    # Memory clients
    "MemoryClient",
    "ByomMemoryClient",
    "MemoryError",
    # Data types
    "LearningPool",
    "CycleStatus",
    "Contributions",
    "ContributionDetail",
    "StakingInfo",
    "PendingWithdrawal",
    "ClassroomInfo",
    "ComputeJob",
    "ProviderInfo",
    "ComputePool",
    "Dispute",
]
