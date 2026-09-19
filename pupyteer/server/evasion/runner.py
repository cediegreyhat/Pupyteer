"""Evasion Test Runner — orchestrates obfuscation + Litterbox analysis + result recording.

High-level flow:
1. Select a test configuration profile (which obfuscation techniques to apply)
2. Optionally obfuscate the payload using the profile's ObfuscationConfig
3. Compute artifact hash for reproducibility verification
4. Submit to Litterbox or run local checks
5. Record results with all evaluation metrics
6. Persist to history

The runner is the primary entry point for running detection-resilience
experiments. It wraps EvasionTestManager with obfuscation orchestration.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import shutil
import tempfile
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.evasion.litterbox_client import LitterboxClient, LitterboxError
from pupyteer.server.evasion.manager import EvasionTestManager
from pupyteer.server.evasion.models import (
    ControlResult,
    DetectionResult,
    EvasionTestConfig,
    EvasionTestResult,
    ExecutionResult,
    TestEnvironment,
    compute_file_hash,
    verify_artifact_hash,
)
from pupyteer.server.evasion.obfuscator import ObfuscationConfig, ObfuscationEngine
from pupyteer.server.evasion.profiles import TestConfigurationProfile, get_profile

logger = logging.getLogger("pupyteer.evasion.runner")


@dataclass
class RunnerConfig:
    """Configuration for the EvasionTestRunner."""
    auto_obfuscate: bool = True  # automatically obfuscate before testing
    obfuscated_output_dir: str = "./payloads/evasion_artifacts"
    cleanup_obfuscated: bool = False  # keep artifacts after test for analysis
    default_environment: str = TestEnvironment.LOCAL.value
    default_controls: List[str] = field(default_factory=list)


class EvasionTestRunner:
    """
    High-level orchestrator for evasion detection-resilience testing.

    Combines obfuscation, artifact hashing, Litterbox submission, and
    result recording into a single workflow.

    Usage:
        runner = EvasionTestRunner(config, audit)
        await runner.initialize()

        # Run with a named profile
        result = await runner.run_with_profile("full_chain", "/path/to/payload.exe")

        # Run with a custom profile
        profile = create_custom_profile("my_test", scheme="xor")
        result = await runner.run_with_profile_obj(profile, "/path/to/payload.exe")

        await runner.shutdown()
    """

    def __init__(
        self,
        config: ConfigManager,
        audit: AuditLogger,
        runner_config: Optional[RunnerConfig] = None,
    ):
        self._config = config
        self._audit = audit
        self._runner_config = runner_config or RunnerConfig()
        self._test_manager: Optional[EvasionTestManager] = None
        self._obfuscator: Optional[ObfuscationEngine] = None
        self._litterbox: Optional[LitterboxClient] = None
        self._initialized = False
        self._lock = asyncio.Lock()
        self._run_count = 0

    @property
    def test_mode(self) -> bool:
        """Whether lab/testing mode is enabled."""
        return self._config.get("evasion.test_mode", False)

    @property
    def run_count(self) -> int:
        """Number of tests run by this runner instance."""
        return self._run_count

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def initialize(self) -> None:
        """Initialize the runner and all subsystems."""
        if self._initialized:
            return

        # Initialize test manager
        self._test_manager = EvasionTestManager(self._config, self._audit)
        await self._test_manager.initialize()

        # Initialize obfuscator
        self._obfuscator = ObfuscationEngine(self._config, self._audit)
        await self._obfuscator.initialize()

        # Create output dir for obfuscated artifacts
        output_dir = Path(self._runner_config.obfuscated_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        # Initialize Litterbox client if configured
        self._init_litterbox()

        self._initialized = True
        self._audit.log_event("evasion_runner_initialized", {
            "test_mode": self.test_mode,
            "litterbox_configured": self._litterbox is not None,
        })
        logger.info(
            "EvasionTestRunner initialized (test_mode=%s, litterbox=%s)",
            self.test_mode,
            self._litterbox is not None,
        )

    async def shutdown(self) -> None:
        """Shutdown the runner and persist all results."""
        if self._test_manager:
            await self._test_manager.shutdown()
        if self._obfuscator:
            await self._obfuscator.shutdown()

        self._audit.log_event("evasion_runner_shutdown", {"tests_run": self._run_count})
        logger.info("EvasionTestRunner shutdown (total runs: %d)", self._run_count)
        self._initialized = False

    def _init_litterbox(self) -> None:
        """Initialize Litterbox client from config."""
        lb_url = self._config.get("evasion.litterbox_url")
        lb_token = self._config.get("evasion.litterbox_token", "")
        if lb_url:
            self._litterbox = LitterboxClient(
                base_url=lb_url,
                token=lb_token,
                timeout=float(self._config.get("evasion.litterbox_timeout", 120)),
            )
            logger.info("Litterbox integration enabled: %s", lb_url)

    # ------------------------------------------------------------------ #
    #  Test execution                                                     #
    # ------------------------------------------------------------------ #

    async def run_with_profile(
        self,
        profile_name: str,
        artifact_path: str,
        environment: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> EvasionTestResult:
        """
        Run an evasion test using a named built-in profile.

        Args:
            profile_name: One of "basic_xor", "full_chain", "pe_manipulation",
                          "anti_analysis", "anti_injection", "stealth_full"
            artifact_path: Path to the payload to test
            environment: Override default environment
            tags: Additional tags to attach

        Returns:
            EvasionTestResult with all evaluation metrics
        """
        profile = get_profile(profile_name)
        if profile is None:
            raise ValueError(
                f"Unknown profile: {profile_name}. "
                f"Available: {list(self.list_profiles().keys())}"
            )
        return await self.run_with_profile_obj(profile, artifact_path, environment, tags)

    async def run_with_profile_obj(
        self,
        profile: TestConfigurationProfile,
        artifact_path: str,
        environment: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> EvasionTestResult:
        """
        Run an evasion test using a TestConfigurationProfile object.

        This is the core execution path:
        1. Verify lab mode
        2. Optionally obfuscate the payload
        3. Compute hash for reproducibility
        4. Build test config from profile
        5. Submit to test manager
        6. Record and return results
        """
        self._ensure_initialized()
        self._require_lab_mode()

        env = environment or profile.environment or self._runner_config.default_environment
        all_tags = list(profile.tags) + (tags or [])

        # Step 1: Optionally obfuscate the payload
        actual_artifact = artifact_path
        obfuscated_path: Optional[str] = None

        if self._runner_config.auto_obfuscate and self._obfuscator:
            logger.info("Applying obfuscation profile '%s' to %s", profile.name, artifact_path)
            obfuscated_path = await self._obfuscate_payload(artifact_path, profile.obfuscation)
            actual_artifact = obfuscated_path
            all_tags.append(f"obfuscated:{profile.obfuscation.scheme.value}")

        # Step 2: Compute hash for reproducibility
        artifact_hash = compute_file_hash(actual_artifact)

        # Step 3: Build test configuration
        test_config = EvasionTestConfig(
            name=f"{profile.name}-{uuid.uuid4().hex[:8]}",
            artifact_path=actual_artifact,
            artifact_hash_sha256=artifact_hash,
            environment=env,
            controls=profile.controls or self._runner_config.default_controls,
            test_mode=True,
            description=profile.description,
            tags=all_tags,
            metadata={
                "profile_name": profile.name,
                "original_artifact": artifact_path,
                "obfuscated_artifact": obfuscated_path,
                "obfuscation_scheme": profile.obfuscation.scheme.value,
                "profile_config": profile.to_dict(),
            },
        )

        # Step 4: Run the test
        start_time = time.time()
        result = await self._test_manager.run_test(test_config)
        duration = time.time() - start_time

        # Step 5: Enrich result with runner-level telemetry
        result.duration_seconds = duration
        result.metadata["runner"] = {
            "run_id": self._run_count + 1,
            "runner_timestamp": datetime.now(timezone.utc).isoformat(),
            "original_artifact": artifact_path,
            "original_artifact_hash": compute_file_hash(artifact_path),
            "obfuscated_artifact": obfuscated_path,
            "obfuscated_artifact_hash": artifact_hash if obfuscated_path else None,
        }

        async with self._lock:
            self._run_count += 1

        # Step 6: Optionally clean up obfuscated artifact
        if self._runner_config.cleanup_obfuscated and obfuscated_path:
            try:
                os.unlink(obfuscated_path)
            except OSError:
                pass

        return result

    async def run_custom(
        self,
        artifact_path: str,
        environment: Optional[str] = None,
        controls: Optional[List[str]] = None,
        obfuscation_config: Optional[ObfuscationConfig] = None,
        tags: Optional[List[str]] = None,
    ) -> EvasionTestResult:
        """
        Run a custom evasion test with inline configuration.

        This allows ad-hoc testing without a named profile. The config
        is still recorded for reproducibility.
        """
        self._ensure_initialized()
        self._require_lab_mode()

        env = environment or self._runner_config.default_environment
        actual_artifact = artifact_path

        # Optionally apply inline obfuscation
        if obfuscation_config and self._runner_config.auto_obfuscate and self._obfuscator:
            actual_artifact = await self._obfuscate_payload(artifact_path, obfuscation_config)

        artifact_hash = compute_file_hash(actual_artifact)

        test_config = EvasionTestConfig(
            name=f"custom-{uuid.uuid4().hex[:8]}",
            artifact_path=actual_artifact,
            artifact_hash_sha256=artifact_hash,
            environment=env,
            controls=controls or self._runner_config.default_controls,
            test_mode=True,
            tags=tags or ["custom"],
            metadata={
                "custom": True,
                "original_artifact": artifact_path,
                "obfuscated_artifact": actual_artifact if actual_artifact != artifact_path else None,
            },
        )

        result = await self._test_manager.run_test(test_config)
        async with self._lock:
            self._run_count += 1

        return result

    async def _obfuscate_payload(
        self, input_path: str, config: ObfuscationConfig
    ) -> str:
        """Run obfuscation engine on a payload, return path to obfuscated file."""
        output_dir = Path(self._runner_config.obfuscated_output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        if self._obfuscator is None:
            raise RuntimeError("Obfuscation engine not initialized")
        return await self._obfuscator.obfuscate(input_path, config)

    # ------------------------------------------------------------------ #
    #  Direct Litterbox submission                                        #
    # ------------------------------------------------------------------ #

    async def submit_to_litterbox(
        self,
        artifact_path: str,
        analysis_type: str = "static_edr_dynamic",
        edr_profiles: Optional[List[str]] = None,
        wait_for_result: bool = True,
    ) -> Dict[str, Any]:
        """
        Submit an artifact directly to Litterbox without obfuscation.

        Returns the raw Litterbox report dict.
        """
        self._ensure_initialized()

        if not self._litterbox:
            raise RuntimeError("Litterbox not configured. Set evasion.litterbox_url.")

        if not Path(artifact_path).exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        result = await self._litterbox.analyze(
            artifact_path,
            analysis_type=analysis_type,
            edr_profiles=edr_profiles,
        )

        self._audit.log_event("litterbox_submission", {
            "artifact": artifact_path,
            "analysis_type": analysis_type,
            "sha256": result.get("file_info", {}).get("sha256", "")[:16],
        })

        return result

    # ------------------------------------------------------------------ #
    #  Lab mode enforcement                                               #
    # ------------------------------------------------------------------ #

    def _require_lab_mode(self) -> None:
        """Block execution unless lab/testing mode is explicitly enabled.

        This is a safety gate to prevent accidental production deployment
        of detection-resilience testing capabilities.
        """
        if not self.test_mode:
            raise RuntimeError(
                "EVASION TESTING REQUIRES EXPLICIT LAB MODE. "
                "Set evasion.test_mode = true in configuration to proceed. "
                "This capability is for authorized laboratory environments only."
            )

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError("EvasionTestRunner not initialized. Call initialize() first.")

    # ------------------------------------------------------------------ #
    #  History & stats                                                    #
    # ------------------------------------------------------------------ #

    def get_history(self, limit: int = 100) -> List[EvasionTestResult]:
        """Return test result history."""
        if self._test_manager:
            return self._test_manager.get_history(limit)
        return []

    def get_stats(self) -> Dict[str, Any]:
        """Return aggregate test statistics."""
        stats: Dict[str, Any] = {
            "runner_runs": self._run_count,
            "test_mode": self.test_mode,
            "litterbox_configured": self._litterbox is not None,
        }
        if self._test_manager:
            stats.update(self._test_manager.get_stats())
        return stats

    @staticmethod
    def list_profiles() -> Dict[str, Dict[str, Any]]:
        """List all available test configuration profiles."""
        from pupyteer.server.evasion.profiles import BUILTIN_PROFILES
        return {name: p.to_dict() for name, p in BUILTIN_PROFILES.items()}
