"""Unified Payload-to-Evasion Pipeline — the 'MSF with FUD' differentiator.

Connects payload building with FUD testing in a single orchestrated flow:

    Build → Obfuscate → Test → Report

Stages:
    1. BUILD:    Compile payload artifact via PayloadManager
    2. OBFUSCATE: Apply encryption/PE manipulation via ObfuscationEngine
    3. TEST:     Submit to Litterbox / VirusTotal via EvasionTestManager
    4. REPORT:   Aggregate results with verdict + recommendations

All methods are async and thread-safe.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from pupyteer.payloads.manager import PayloadConfig, PayloadMetadata
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.evasion.models import (
    DetectionResult,
    EvasionTestConfig,
    EvasionTestResult,
    TestEnvironment,
    compute_file_hash,
)
from pupyteer.server.evasion.obfuscator import ObfuscationConfig, ObfuscationEngine
from pupyteer.server.evasion.profiles import TestConfigurationProfile, get_profile

if TYPE_CHECKING:
    from pupyteer.server.core.engine import PupyteerEngine

logger = logging.getLogger("pupyteer.pipeline")


# ─── Pipeline Stage Tracking ──────────────────────────────────────────────


class PipelineStage(str, Enum):
    """Stages in the unified pipeline."""
    BUILD = "build"
    OBFUSCATE = "obfuscate"
    TEST = "test"
    REPORT = "report"


class Verdict(str, Enum):
    """Final verdict for a pipeline run."""
    PASS = "pass"           # Fully FUD
    PARTIAL = "partial"     # Some detections
    FAIL = "fail"           # Detected
    ERROR = "error"         # Pipeline error
    INCOMPLETE = "incomplete"  # Did not complete all stages


@dataclass
class StageResult:
    """Result from a single pipeline stage."""
    stage: str
    success: bool
    duration_seconds: float = 0.0
    message: str = ""
    data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage": self.stage,
            "success": self.success,
            "duration_seconds": round(self.duration_seconds, 3),
            "message": self.message,
            "data": self.data,
        }


@dataclass
class PipelineResult:
    """Complete result of a pipeline run across all stages."""
    pipeline_id: str = ""
    name: str = ""
    timestamp: str = ""
    verdict: str = Verdict.INCOMPLETE.value
    stages: List[StageResult] = field(default_factory=list)
    payload_metadata: Optional[PayloadMetadata] = None
    evasion_result: Optional[EvasionTestResult] = None
    obfuscated_artifact_path: str = ""
    obfuscated_artifact_hash: str = ""
    detection_overall: str = DetectionResult.UNDETECTED.value
    detected_count: int = 0
    undetected_count: int = 0
    total_duration_seconds: float = 0.0
    recommendations: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pipeline_id": self.pipeline_id,
            "name": self.name,
            "timestamp": self.timestamp,
            "verdict": self.verdict,
            "stages": [s.to_dict() for s in self.stages],
            "payload": self.payload_metadata.to_dict() if self.payload_metadata else None,
            "evasion": self.evasion_result.to_dict() if self.evasion_result else None,
            "obfuscated_artifact_path": self.obfuscated_artifact_path,
            "obfuscated_artifact_hash": self.obfuscated_artifact_hash,
            "detection_overall": self.detection_overall,
            "detected_count": self.detected_count,
            "undetected_count": self.undetected_count,
            "total_duration_seconds": round(self.total_duration_seconds, 3),
            "recommendations": self.recommendations,
            "tags": self.tags,
        }


# ─── Recommendation Engine ────────────────────────────────────────────────


def generate_recommendations(result: PipelineResult) -> List[str]:
    """Generate actionable recommendations based on pipeline results."""
    recs: List[str] = []

    if result.detection_overall == DetectionResult.DETECTED.value:
        recs.append("CRITICAL: Payload detected. Try stronger obfuscation (CHAIN scheme).")
        recs.append("Consider adding anti-sandbox/anti-debug checks to the agent stub.")
        recs.append("Enable string encryption and import obfuscation.")
        recs.append("Try PE manipulation: section rename, timestamp randomization, debug strip.")
    elif result.detection_overall == DetectionResult.PARTIAL.value:
        recs.append("PARTIAL: Some controls detected the payload.")
        if result.detected_count > 0:
            recs.append(f"Review {result.detected_count} triggered control(s) and adjust evasion.")
        recs.append("Consider increasing XOR key size or using full CHAIN encryption.")
    elif result.detection_overall == DetectionResult.UNDETECTED.value:
        recs.append("PASS: Payload is fully FUD. Ready for authorized operations.")

    # Check for high entropy (may trigger heuristic detection)
    if result.payload_metadata and result.payload_metadata.size_bytes > 0:
        if result.obfuscated_artifact_path and Path(result.obfuscated_artifact_path).exists():
            obf_size = Path(result.obfuscated_artifact_path).stat().st_size
            orig_size = result.payload_metadata.size_bytes
            if orig_size > 0 and obf_size / orig_size > 3.0:
                recs.append("WARNING: Obfuscated artifact is >3x original size. Consider reducing entropy.")

    # Check for specific control failures
    if result.evasion_result:
        for cr in result.evasion_result.control_results:
            if cr.detection == DetectionResult.DETECTED.value:
                if "virustotal" in cr.control.lower():
                    recs.append(f"VirusTotal detection: {cr.notes}. Consider re-obfuscating with different keys.")
                elif "yara" in cr.control.lower():
                    recs.append(f"YARA rule triggered: {cr.notes}. Review signature patterns.")
                elif "amsi" in cr.control.lower():
                    recs.append("AMSI detection: Consider runtime string decryption and AMSI bypass techniques.")
                elif "defender" in cr.control.lower():
                    recs.append("Windows Defender detection: Try process injection or living-off-the-land techniques.")

    if not recs:
        recs.append("No specific recommendations. Continue monitoring detection landscape.")

    return recs


# ─── Pipeline Manager ─────────────────────────────────────────────────────


class PipelineManager:
    """
    Unified payload-to-evasion pipeline.

    Orchestrates the full Build → Obfuscate → Test → Report flow
    using the existing PayloadManager, ObfuscationEngine, and
    EvasionTestManager subsystems.

    Usage:
        engine = PupyteerEngine()
        pipeline = PipelineManager(engine)
        await pipeline.initialize()

        # Build + Test
        result = await pipeline.build_and_test(payload_config, evasion_config)

        # Build + Obfuscate + Test
        result = await pipeline.build_obfuscate_test(payload_config, obf_config, evasion_config)

        # Auto (one-shot with profile)
        result = await pipeline.auto("my_payload", profile_name="stealth_full")
    """

    def __init__(self, engine: PupyteerEngine):
        self._engine = engine
        self._config = engine.config
        self._audit = engine.audit
        self._obfuscator: Optional[ObfuscationEngine] = None
        self._initialized = False
        self._lock = asyncio.Lock()
        self._run_count = 0
        self._history: List[PipelineResult] = []

    @property
    def run_count(self) -> int:
        return self._run_count

    @property
    def history(self) -> List[PipelineResult]:
        return list(self._history)

    async def initialize(self) -> None:
        """Initialize the pipeline and its subsystems."""
        if self._initialized:
            return

        # Initialize obfuscation engine
        self._obfuscator = ObfuscationEngine(self._config, self._audit)
        await self._obfuscator.initialize()

        self._initialized = True
        self._audit.log_event("pipeline_manager_initialized", {})
        logger.info("PipelineManager initialized")

    async def shutdown(self) -> None:
        """Shutdown the pipeline."""
        if self._obfuscator:
            await self._obfuscator.shutdown()
        self._audit.log_event("pipeline_manager_shutdown", {"runs": self._run_count})
        logger.info("PipelineManager shutdown (total runs: %d)", self._run_count)
        self._initialized = False

    def _ensure_initialized(self) -> None:
        if not self._initialized:
            raise RuntimeError("PipelineManager not initialized. Call initialize() first.")

    # ── Core Pipeline Flows ─────────────────────────────────────────────

    async def build_and_test(
        self,
        payload_config: PayloadConfig,
        evasion_config: EvasionTestConfig,
    ) -> PipelineResult:
        """
        Build a payload and run evasion test on the artifact.

        Flow: BUILD → TEST → REPORT
        """
        self._ensure_initialized()
        pipeline_id = f"pipe-{uuid.uuid4().hex[:12]}"
        start_time = time.time()
        result = PipelineResult(
            pipeline_id=pipeline_id,
            name=payload_config.name,
            tags=["build", "test"],
        )

        try:
            # Stage 1: BUILD
            build_result = await self._run_build_stage(payload_config)
            result.stages.append(build_result)
            if not build_result.success:
                result.verdict = Verdict.ERROR.value
                result.total_duration_seconds = time.time() - start_time
                result.recommendations = ["Build failed. Check payload configuration."]
                return result

            result.payload_metadata = build_result.data.get("metadata")
            artifact_path = build_result.data.get("artifact_path", "")

            # Stage 2: TEST
            evasion_config.artifact_path = artifact_path
            if not evasion_config.artifact_hash_sha256 and result.payload_metadata:
                evasion_config.artifact_hash_sha256 = result.payload_metadata.hash_sha256
            if not evasion_config.name:
                evasion_config.name = payload_config.name

            test_result = await self._run_test_stage(evasion_config)
            result.stages.append(test_result)
            if not test_result.success:
                result.verdict = Verdict.ERROR.value
                result.total_duration_seconds = time.time() - start_time
                result.recommendations = ["Evasion test failed. Check test configuration."]
                return result

            result.evasion_result = test_result.data.get("evasion_result")
            result.detection_overall = result.evasion_result.detection_overall if result.evasion_result else DetectionResult.ERROR.value
            result.detected_count = result.evasion_result.detected_count if result.evasion_result else 0
            result.undetected_count = result.evasion_result.undetected_count if result.evasion_result else 0

            # Stage 3: REPORT
            report_result = self._run_report_stage(result)
            result.stages.append(report_result)

            # Determine verdict
            result.verdict = self._determine_verdict(result)
            result.recommendations = generate_recommendations(result)

        except Exception as e:
            logger.error("Pipeline error: %s", e)
            result.verdict = Verdict.ERROR.value
            result.stages.append(StageResult(
                stage=PipelineStage.REPORT.value,
                success=False,
                message=f"Pipeline error: {e}",
            ))
            result.recommendations = [f"Pipeline error: {e}"]

        result.total_duration_seconds = time.time() - start_time
        async with self._lock:
            self._run_count += 1
            self._history.append(result)

        return result

    async def build_only(self, payload_config: PayloadConfig) -> PayloadMetadata:
        """
        Build a payload without testing.

        Returns the PayloadMetadata from the build.
        """
        self._ensure_initialized()
        metadata = await self._engine.payloads.build(payload_config)
        return metadata

    async def test_only(
        self,
        artifact_path: str,
        evasion_config: Optional[EvasionTestConfig] = None,
    ) -> EvasionTestResult:
        """
        Test an existing artifact without building.

        If evasion_config is None, a default config is created.
        """
        self._ensure_initialized()

        if evasion_config is None:
            artifact_hash = compute_file_hash(artifact_path)
            evasion_config = EvasionTestConfig(
                name=f"test-{uuid.uuid4().hex[:8]}",
                artifact_path=artifact_path,
                artifact_hash_sha256=artifact_hash,
                environment=TestEnvironment.LOCAL.value,
                test_mode=True,
            )
        else:
            evasion_config.artifact_path = artifact_path
            if not evasion_config.artifact_hash_sha256:
                evasion_config.artifact_hash_sha256 = compute_file_hash(artifact_path)

        return await self._engine.evasion.run_test(evasion_config)

    async def build_obfuscate_test(
        self,
        payload_config: PayloadConfig,
        obfuscation_config: ObfuscationConfig,
        evasion_config: EvasionTestConfig,
    ) -> PipelineResult:
        """
        Full pipeline: Build → Obfuscate → Test → Report.

        This is the primary 'MSF with FUD' flow.
        """
        self._ensure_initialized()
        pipeline_id = f"pipe-{uuid.uuid4().hex[:12]}"
        start_time = time.time()
        result = PipelineResult(
            pipeline_id=pipeline_id,
            name=payload_config.name,
            tags=["build", "obfuscate", "test"],
        )

        try:
            # Stage 1: BUILD
            build_result = await self._run_build_stage(payload_config)
            result.stages.append(build_result)
            if not build_result.success:
                result.verdict = Verdict.ERROR.value
                result.total_duration_seconds = time.time() - start_time
                result.recommendations = ["Build failed. Check payload configuration."]
                return result

            result.payload_metadata = build_result.data.get("metadata")
            artifact_path = build_result.data.get("artifact_path", "")

            # Stage 2: OBFUSCATE
            obf_result = await self._run_obfuscate_stage(artifact_path, obfuscation_config)
            result.stages.append(obf_result)
            if not obf_result.success:
                result.verdict = Verdict.ERROR.value
                result.total_duration_seconds = time.time() - start_time
                result.recommendations = ["Obfuscation failed. Check obfuscation config."]
                return result

            obfuscated_path = obf_result.data.get("obfuscated_path", "")
            result.obfuscated_artifact_path = obfuscated_path
            result.obfuscated_artifact_hash = obf_result.data.get("obfuscated_hash", "")

            # Stage 3: TEST
            evasion_config.artifact_path = obfuscated_path
            evasion_config.artifact_hash_sha256 = result.obfuscated_artifact_hash
            if not evasion_config.name:
                evasion_config.name = payload_config.name

            test_result = await self._run_test_stage(evasion_config)
            result.stages.append(test_result)
            if not test_result.success:
                result.verdict = Verdict.ERROR.value
                result.total_duration_seconds = time.time() - start_time
                result.recommendations = ["Evasion test failed. Check test configuration."]
                return result

            result.evasion_result = test_result.data.get("evasion_result")
            result.detection_overall = result.evasion_result.detection_overall if result.evasion_result else DetectionResult.ERROR.value
            result.detected_count = result.evasion_result.detected_count if result.evasion_result else 0
            result.undetected_count = result.evasion_result.undetected_count if result.evasion_result else 0

            # Stage 4: REPORT
            report_result = self._run_report_stage(result)
            result.stages.append(report_result)

            # Determine verdict
            result.verdict = self._determine_verdict(result)
            result.recommendations = generate_recommendations(result)

        except Exception as e:
            logger.error("Pipeline error: %s", e)
            result.verdict = Verdict.ERROR.value
            result.stages.append(StageResult(
                stage=PipelineStage.REPORT.value,
                success=False,
                message=f"Pipeline error: {e}",
            ))
            result.recommendations = [f"Pipeline error: {e}"]

        result.total_duration_seconds = time.time() - start_time
        async with self._lock:
            self._run_count += 1
            self._history.append(result)

        return result

    async def auto(
        self,
        name: str,
        platform: str = "windows",
        arch: str = "x64",
        payload_type: str = "executable",
        transport: str = "tcp",
        host: str = "127.0.0.1",
        port: int = 8443,
        profile_name: str = "full_chain",
        environment: str = "local",
    ) -> PipelineResult:
        """
        One-shot: Build + Obfuscate + Test with a named profile.

        This is the simplest entry point for the full pipeline.
        """
        self._ensure_initialized()

        # Build payload config
        from pupyteer.payloads.manager import PayloadPlatform, PayloadArch, PayloadType
        payload_config = PayloadConfig(
            name=name,
            platform=PayloadPlatform(platform),
            arch=PayloadArch(arch),
            payload_type=PayloadType(payload_type),
            transport=transport,
            host=host,
            port=port,
        )

        # Get obfuscation profile
        profile = get_profile(profile_name)
        if profile is None:
            raise ValueError(
                f"Unknown profile: {profile_name}. "
                f"Available: basic_xor, full_chain, pe_manipulation, anti_analysis, anti_injection, stealth_full"
            )

        # Build evasion config
        evasion_config = EvasionTestConfig(
            name=name,
            environment=environment,
            controls=profile.controls,
            test_mode=True,
            tags=["auto", f"profile:{profile_name}"],
        )

        return await self.build_obfuscate_test(
            payload_config,
            profile.obfuscation,
            evasion_config,
        )

    # ── Stage Implementations ───────────────────────────────────────────

    async def _run_build_stage(self, payload_config: PayloadConfig) -> StageResult:
        """Execute the BUILD stage."""
        start = time.time()
        try:
            metadata = await self._engine.payloads.build(payload_config)
            return StageResult(
                stage=PipelineStage.BUILD.value,
                success=True,
                duration_seconds=time.time() - start,
                message=f"Built {metadata.name} v{metadata.version} ({metadata.hash_sha256[:16]}...)",
                data={
                    "metadata": metadata,
                    "artifact_path": metadata.artifact_path,
                    "hash_sha256": metadata.hash_sha256,
                    "size_bytes": metadata.size_bytes,
                },
            )
        except Exception as e:
            return StageResult(
                stage=PipelineStage.BUILD.value,
                success=False,
                duration_seconds=time.time() - start,
                message=f"Build failed: {e}",
            )

    async def _run_obfuscate_stage(
        self,
        artifact_path: str,
        obfuscation_config: ObfuscationConfig,
    ) -> StageResult:
        """Execute the OBFUSCATE stage."""
        start = time.time()
        try:
            if not self._obfuscator:
                raise RuntimeError("Obfuscation engine not initialized")

            obfuscated_path = await self._obfuscator.obfuscate(artifact_path, obfuscation_config)
            obfuscated_hash = compute_file_hash(obfuscated_path)

            return StageResult(
                stage=PipelineStage.OBFUSCATE.value,
                success=True,
                duration_seconds=time.time() - start,
                message=f"Obfuscated with {obfuscation_config.scheme.value} → {obfuscated_path}",
                data={
                    "obfuscated_path": obfuscated_path,
                    "obfuscated_hash": obfuscated_hash,
                    "scheme": obfuscation_config.scheme.value,
                },
            )
        except Exception as e:
            return StageResult(
                stage=PipelineStage.OBFUSCATE.value,
                success=False,
                duration_seconds=time.time() - start,
                message=f"Obfuscation failed: {e}",
            )

    async def _run_test_stage(self, evasion_config: EvasionTestConfig) -> StageResult:
        """Execute the TEST stage."""
        start = time.time()
        try:
            evasion_result = await self._engine.evasion.run_test(evasion_config)
            return StageResult(
                stage=PipelineStage.TEST.value,
                success=True,
                duration_seconds=time.time() - start,
                message=f"Test {evasion_result.test_id}: {evasion_result.detection_overall}",
                data={
                    "evasion_result": evasion_result,
                    "test_id": evasion_result.test_id,
                    "detection_overall": evasion_result.detection_overall,
                },
            )
        except Exception as e:
            return StageResult(
                stage=PipelineStage.TEST.value,
                success=False,
                duration_seconds=time.time() - start,
                message=f"Test failed: {e}",
            )

    def _run_report_stage(self, result: PipelineResult) -> StageResult:
        """Execute the REPORT stage (synchronous aggregation)."""
        start = time.time()
        try:
            # Aggregate detection details
            detection_details = {}
            if result.evasion_result:
                for cr in result.evasion_result.control_results:
                    detection_details[cr.control] = {
                        "detection": cr.detection,
                        "notes": cr.notes,
                        "signatures": cr.signatures_triggered,
                    }

            return StageResult(
                stage=PipelineStage.REPORT.value,
                success=True,
                duration_seconds=time.time() - start,
                message=f"Report generated: {result.verdict}",
                data={
                    "detection_details": detection_details,
                    "verdict": result.verdict,
                },
            )
        except Exception as e:
            return StageResult(
                stage=PipelineStage.REPORT.value,
                success=False,
                duration_seconds=time.time() - start,
                message=f"Report generation failed: {e}",
            )

    # ── Verdict Logic ───────────────────────────────────────────────────

    def _determine_verdict(self, result: PipelineResult) -> str:
        """Determine the final verdict from pipeline results."""
        if result.detection_overall == DetectionResult.UNDETECTED.value:
            return Verdict.PASS.value
        elif result.detection_overall == DetectionResult.PARTIAL.value:
            return Verdict.PARTIAL.value
        elif result.detection_overall == DetectionResult.DETECTED.value:
            return Verdict.FAIL.value
        elif result.detection_overall == DetectionResult.ERROR.value:
            return Verdict.ERROR.value
        return Verdict.INCOMPLETE.value

    # ── History & Stats ────────────────────────────────────────────────

    def get_history(self, limit: int = 50) -> List[PipelineResult]:
        """Return recent pipeline results."""
        return self._history[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics across all pipeline runs."""
        total = len(self._history)
        by_verdict: Dict[str, int] = {}
        by_detection: Dict[str, int] = {}
        total_duration = 0.0

        for r in self._history:
            by_verdict[r.verdict] = by_verdict.get(r.verdict, 0) + 1
            by_detection[r.detection_overall] = by_detection.get(r.detection_overall, 0) + 1
            total_duration += r.total_duration_seconds

        return {
            "total_runs": total,
            "by_verdict": by_verdict,
            "by_detection": by_detection,
            "avg_duration_seconds": round(total_duration / total, 2) if total > 0 else 0,
        }
