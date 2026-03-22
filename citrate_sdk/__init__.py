"""
Citrate Python SDK

A comprehensive Python SDK for interacting with the Citrate AI blockchain platform.
Provides easy-to-use interfaces for model deployment, inference execution,
encryption, access control, payment systems, learning pools, liquid staking,
classrooms, compute marketplace, treasury, and farming operations.
"""

from .client import CitrateClient
from .models import ModelConfig, ModelDeployment, InferenceRequest, InferenceResult, ModelType, AccessType
from .crypto import EncryptionConfig, KeyManager
from .errors import CitrateError, ModelNotFoundError, InsufficientFundsError

# LC.5.3: Learning / Staking / Classroom managers
from .learning import LearningManager, StakingManager, ClassroomManager

# COMPUTE-4: Compute marketplace manager
from .compute import ComputeManager

# ECON-2: Treasury and farming managers
from .treasury import TreasuryManager
from .farming import FarmingManager

# Shared data types for learning / staking / classroom / compute
from .types import (
    LearningPool,
    CycleStatus,
    Contributions,
    ContributionDetail,
    StakingInfo,
    PendingWithdrawal,
    ClassroomInfo,
    ComputeJob,
    ProviderInfo,
    ComputePool,
    Dispute,
)

__version__ = "0.4.0"
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
