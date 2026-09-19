"""Pupyteer Evasion Testing Subsystem — Phase 10.

Provides detection-resilience testing capability:
- Controlled test configurations (reproducible builds)
- Artifact hash recording
- Test result tracking per defensive-control
- Litterbox integration (sandbox submission & polling)
- Explicit laboratory/testing mode gating
"""
from __future__ import annotations

__version__ = "1.0.0"

from pupyteer.server.evasion.manager import EvasionTestManager
from pupyteer.server.evasion.models import (
    EvasionTestConfig,
    EvasionTestResult,
    DetectionResult,
    ExecutionResult,
    TestEnvironment,
)
from pupyteer.server.evasion.profiles import TestConfigurationProfile, BUILTIN_PROFILES, get_profile, list_profiles, create_custom_profile
from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig

__all__ = [
    "EvasionTestManager",
    "EvasionTestRunner",
    "RunnerConfig",
    "EvasionTestConfig",
    "EvasionTestResult",
    "DetectionResult",
    "ExecutionResult",
    "TestEnvironment",
    "TestConfigurationProfile",
    "BUILTIN_PROFILES",
    "get_profile",
    "list_profiles",
    "create_custom_profile",
]
