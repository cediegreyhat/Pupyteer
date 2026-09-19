"""Evasion Test Manager — core orchestrator for detection-resilience testing.

Manages the full test lifecycle:
1. Load / validate test configuration
2. Verify artifact reproducibility (hash check)
3. Submit to Litterbox (optional), VirusTotal (Composio), or run locally
4. Record results per defensive control
5. Persist test history

Thread-safe: uses an asyncio.Lock for concurrent test tracking.
"""
from __future__ import annotations

import asyncio
import json
import logging
import shutil
import subprocess
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.evasion.litterbox_client import LitterboxClient, LitterboxError
from pupyteer.server.evasion.models import (
    DetectionResult,
    EvasionTestConfig,
    EvasionTestResult,
    ControlResult,
    TestEnvironment,
    compute_file_hash,
    verify_artifact_hash,
)

logger = logging.getLogger("pupyteer.evasion")


class VirusTotalComposioClient:
    """VirusTotal via Composio CLI (authenticated, no API key management).

    Uses `composio execute VIRUSTOTAL_GET_FILE_REPORT -d '{"id": "<hash>"}'`
    to fetch the latest VT report for a file hash. Requires the Composio
    CLI to be installed and the virustotal toolkit connected.
    """

    def __init__(self, max_positives: int = 5):
        self._max_positives = max_positives
        self._composio_path = shutil.which("composio")

    @property
    def available(self) -> bool:
        return self._composio_path is not None

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """Fetch VT file report by hash. Returns flat summary dict."""
        if not self._composio_path:
            raise RuntimeError("composio CLI not found in PATH")

        proc = subprocess.run(
            [
                self._composio_path, "execute", "VIRUSTOTAL_GET_FILE_REPORT",
                "-d", json.dumps({"id": file_hash}),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if proc.returncode != 0:
            raise RuntimeError(f"composio execute failed: {proc.stderr[:300]}")

        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError as e:
            raise RuntimeError(f"composio output not JSON: {e}") from e

        # Composio wraps VT response — find the attributes dict
        vt_data = data
        if isinstance(data, dict):
            # composio structure: {"data": {"data": {"attributes": {...}}}}
            for key in ("data", "data", "attributes"):
                if isinstance(vt_data, dict) and key in vt_data:
                    vt_data = vt_data[key]

        attrs = vt_data if isinstance(vt_data, dict) else {}
        stats = attrs.get("last_analysis_stats", {})
        results = attrs.get("last_analysis_results", {})

        positives = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total = sum(
            stats.get(k, 0)
            for k in ("malicious", "suspicious", "undetected", "harmless", "timeout")
        )

        scanners = {}
        for engine, res in results.items():
            scanners[engine] = {
                "detected": res.get("category") in ("malicious", "suspicious"),
                "result": res.get("result", ""),
            }

        return {
            "sha256": attrs.get("sha256", file_hash),
            "md5": attrs.get("md5", ""),
            "positives": positives,
            "total": total,
            "scanners": scanners,
            "permalink": f"https://www.virustotal.com/gui/file/{attrs.get('sha256', file_hash)}",
            "not_found": total == 0 and not results,
        }


class EvasionTestManager:
    """
    Central facade for all evasion-test operations.

    Requires explicit laboratory mode (config.evasion.test_mode = true)
    to run any tests — accidental production use is blocked.

    Environments:
    - local: placeholder checks
    - litterbox: submit to Litterbox sandbox
    - virustotal: hash lookup via Composio
    - full_pipeline: Litterbox + VirusTotal combined (pass = FUD on both)
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._lock = asyncio.Lock()
        self._active_tests: Dict[str, EvasionTestResult] = {}
        self._history: List[EvasionTestResult] = []
        self._test_mode: bool = config.get("evasion.test_mode", False)
        self._litterbox: Optional[LitterboxClient] = None
        self._vt_client: Optional[VirusTotalComposioClient] = None

        # Load persisted history
        self._history_file = Path(config.get("evasion.history_path", "./logs/evasion_history.json"))
        if self._history_file.exists():
            self._load_history()

        # Initialize integrations if configured
        self._init_litterbox()
        self._init_virustotal()

    @property
    def test_mode(self) -> bool:
        """Live read of test_mode from config."""
        return self._config.get("evasion.test_mode", False)

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                          #
    # ------------------------------------------------------------------ #

    async def initialize(self) -> None:
        """Start background housekeeping."""
        self._audit.log_event("evasion_manager_initialized", {
            "test_mode": self.test_mode,
            "litterbox": self._litterbox is not None,
            "virustotal": self._vt_client is not None,
        })
        logger.info(
            "EvasionTestManager initialized (test_mode=%s, litterbox=%s, vt=%s)",
            self.test_mode,
            self._litterbox is not None,
            self._vt_client is not None,
        )

    async def shutdown(self) -> None:
        """Persist history and clean up."""
        self._save_history()
        self._audit.log_event("evasion_manager_shutdown", {"tests_run": len(self._history)})
        logger.info("EvasionTestManager shutdown (total tests: %d)", len(self._history))

    def _init_litterbox(self) -> None:
        """Initialize the Litterbox client from config."""
        lb_url = self._config.get("evasion.litterbox_url")
        lb_token = self._config.get("evasion.litterbox_token", "")
        if lb_url:
            lb_timeout = float(self._config.get("evasion.litterbox_timeout", 120))
            self._litterbox = LitterboxClient(
                base_url=lb_url,
                token=lb_token,
                timeout=lb_timeout,
            )
            logger.info("Litterbox integration enabled: %s (timeout=%ds)", lb_url, lb_timeout)

    def _init_virustotal(self) -> None:
        """Initialize VirusTotal client (Composio-backed) from config."""
        if not self._config.get("evasion.virustotal_enabled", False):
            return
        max_pos = int(self._config.get("evasion.virustotal_max_positives", 5))
        client = VirusTotalComposioClient(max_positives=max_pos)
        if client.available:
            self._vt_client = client
            logger.info("VirusTotal (Composio) integration enabled (max_positives=%d)", max_pos)
        else:
            logger.warning("VirusTotal enabled but composio CLI not found")

    # ------------------------------------------------------------------ #
    #  Test execution                                                     #
    # ------------------------------------------------------------------ #

    async def run_test(self, test_config: EvasionTestConfig) -> EvasionTestResult:
        """
        Execute a full evasion test run.

        Flow:
        1. Validate config (lab mode, artifact present)
        2. Verify hash reproducibility
        3. Submit to Litterbox / VirusTotal / local checks
        4. Parse detection results per control
        5. Record and persist
        """
        errors = test_config.validate()
        if errors:
            raise ValueError(f"Invalid evasion test config: {errors}")

        if not self.test_mode:
            raise RuntimeError(
                "Evasion tests require test_mode=true. "
                "This capability is for authorized laboratory environments only."
            )

        test_id = f"evt-{uuid.uuid4().hex[:12]}"
        logger.info("Starting evasion test: %s (%s)", test_id, test_config.name)

        start_time = time.time()
        result = EvasionTestResult(
            test_id=test_id,
            config=test_config.to_dict(),
            environment=test_config.environment,
            operator=self._config.get("operator.name", "unknown"),
        )

        # Verify artifact reproducibility
        if test_config.artifact_path:
            result.artifact_hash_verified = verify_artifact_hash(
                test_config.artifact_path, test_config.artifact_hash_sha256
            )
            if not result.artifact_hash_verified:
                logger.warning(
                    "Artifact hash mismatch for %s — reproducibility check failed",
                    test_config.artifact_path,
                )
                result.notes = "Artifact hash verification failed"
                result.build_reproducible = False
            else:
                result.build_reproducible = True

        # Route by environment
        env = test_config.environment
        if env == TestEnvironment.LITTERBOX.value and self._litterbox:
            result = await self._run_litterbox_test(test_config, result)
        elif env == TestEnvironment.VIRUSTOTAL.value:
            result = await self._run_virustotal_test(test_config, result)
        elif env == TestEnvironment.FULL_PIPELINE.value:
            result = await self._run_full_pipeline_test(test_config, result)
        else:
            result = await self._run_local_test(test_config, result)

        result.duration_seconds = time.time() - start_time

        # Persist
        async with self._lock:
            self._history.append(result)
        self._save_history()

        self._audit.log_event(
            "evasion_test_completed",
            {
                "test_id": test_id,
                "name": test_config.name,
                "detection_overall": result.detection_overall,
                "detected_count": result.detected_count,
                "undetected_count": result.undetected_count,
            },
            result="success",
        )

        logger.info(
            "Evasion test %s completed: %s (%d/%d undetected)",
            test_id,
            result.detection_overall,
            result.undetected_count,
            len(result.control_results),
        )
        return result

    async def _run_litterbox_test(
        self,
        config: EvasionTestConfig,
        result: EvasionTestResult,
    ) -> EvasionTestResult:
        """Submit artifact to Litterbox and parse results."""
        if not self._litterbox:
            raise RuntimeError("Litterbox client not initialized")

        if not Path(config.artifact_path).exists():
            raise FileNotFoundError(f"Artifact not found: {config.artifact_path}")

        try:
            report = await self._litterbox.analyze(
                config.artifact_path,
                analysis_type="static_edr_dynamic",
            )

            result.litterbox_job_id = report.get("file_info", {}).get("sha256", "")[:16]
            result = self._map_litterbox_report(report, result)

        except LitterboxError as e:
            logger.error("Litterbox test failed: %s", e)
            result.detection_overall = DetectionResult.ERROR.value
            result.execution_result = "error"
            result.notes = f"Litterbox error: {e}"

        return result

    async def _run_virustotal_test(
        self,
        config: EvasionTestConfig,
        result: EvasionTestResult,
    ) -> EvasionTestResult:
        """Look up artifact hash on VirusTotal via Composio."""
        if not self._vt_client:
            result.detection_overall = DetectionResult.ERROR.value
            result.execution_result = "error"
            result.notes = "VirusTotal client not available (composio not connected?)"
            return result

        file_hash = config.artifact_hash_sha256 or compute_file_hash(config.artifact_path)

        try:
            # Run blocking composio subprocess in executor
            loop = asyncio.get_event_loop()
            vt_report = await loop.run_in_executor(
                None, self._vt_client.get_file_report, file_hash
            )

            positives = vt_report.get("positives", 0)
            total = vt_report.get("total", 0)
            max_pos = self._vt_client._max_positives

            if vt_report.get("not_found"):
                result.detection_overall = DetectionResult.UNDETECTED.value
                result.execution_result = "success"
                result.notes = "Hash not in VirusTotal database (never uploaded)"
                result.metadata["virustotal"] = {
                    "positives": 0, "total": 0, "not_found": True,
                    "permalink": vt_report.get("permalink", ""),
                }
            else:
                passed = positives <= max_pos
                result.detection_overall = (
                    DetectionResult.UNDETECTED.value if passed else DetectionResult.DETECTED.value
                )
                result.execution_result = "success"
                result.notes = f"VirusTotal: {positives}/{total} engines detected (threshold: {max_pos})"

                result.control_results.append(
                    ControlResult(
                        control="virustotal",
                        detection=DetectionResult.UNDETECTED.value if passed else DetectionResult.DETECTED.value,
                        notes=f"{positives}/{total} detected",
                        signatures_triggered=[
                            f"{eng}: {r['result']}"
                            for eng, r in vt_report.get("scanners", {}).items()
                            if r.get("detected")
                        ],
                    )
                )
                result.metadata["virustotal"] = {
                    "positives": positives,
                    "total": total,
                    "permalink": vt_report.get("permalink", ""),
                }

        except Exception as e:
            logger.error("VirusTotal test failed: %s", e)
            result.detection_overall = DetectionResult.ERROR.value
            result.execution_result = "error"
            result.notes = f"VirusTotal error: {e}"

        return result

    async def _run_full_pipeline_test(
        self,
        config: EvasionTestConfig,
        result: EvasionTestResult,
    ) -> EvasionTestResult:
        """
        Full pipeline: Litterbox + VirusTotal.

        PASS criteria (per operator spec):
        - Litterbox: FUD (no detections)
        - VirusTotal: <= max_positives (default 5) engines detecting
        """
        # Litterbox leg
        if self._litterbox and Path(config.artifact_path).exists():
            lb_result = EvasionTestResult(
                test_id=result.test_id,
                config=result.config,
                environment=TestEnvironment.LITTERBOX.value,
                operator=result.operator,
            )
            lb_result = await self._run_litterbox_test(config, lb_result)
            result.control_results.extend(lb_result.control_results)
            result.litterbox_job_id = lb_result.litterbox_job_id
            result.litterbox_report_url = lb_result.litterbox_report_url
            result.metadata["litterbox"] = {
                "detection_overall": lb_result.detection_overall,
                "notes": lb_result.notes,
            }

        # VirusTotal leg
        vt_result = EvasionTestResult(
            test_id=result.test_id,
            config=result.config,
            environment=TestEnvironment.VIRUSTOTAL.value,
            operator=result.operator,
        )
        vt_result = await self._run_virustotal_test(config, vt_result)
        result.control_results.extend(vt_result.control_results)
        result.metadata["virustotal"] = vt_result.metadata.get("virustotal", {})

        # Overall verdict: both must pass
        lb_pass = result.metadata.get("litterbox", {}).get("detection_overall") == "undetected"
        vt_positives = result.metadata.get("virustotal", {}).get("positives", 0)
        vt_pass = vt_positives <= (self._vt_client._max_positives if self._vt_client else 5)

        if lb_pass and vt_pass:
            result.detection_overall = DetectionResult.UNDETECTED.value
            result.notes = "PASS: FUD on Litterbox + VT within threshold"
        elif lb_pass:
            result.detection_overall = DetectionResult.PARTIAL.value
            result.notes = f"PARTIAL: Litterbox FUD but VT detections={vt_positives} (>{self._vt_client._max_positives if self._vt_client else 5})"
        elif vt_pass:
            result.detection_overall = DetectionResult.PARTIAL.value
            result.notes = "PARTIAL: VT within threshold but Litterbox detected"
        else:
            result.detection_overall = DetectionResult.DETECTED.value
            result.notes = "FAIL: detected on both Litterbox and VT"

        result.execution_result = "success"
        return result

    async def _run_local_test(
        self,
        config: EvasionTestConfig,
        result: EvasionTestResult,
    ) -> EvasionTestResult:
        """
        Run local detection checks (hash-only, static scan placeholders).

        In a full deployment this would invoke local YARA rules,
        AMSI providers, etc. Here we record what *would* be checked.
        """
        for control in config.controls:
            control_result = ControlResult(
                control=control,
                detection=DetectionResult.UNDETECTED.value,
                notes="Local scan placeholder — no actual AV engine integrated",
            )
            result.control_results.append(control_result)

        result.detection_overall = DetectionResult.UNDETECTED.value
        result.execution_result = "success"
        result.notes = "Local test completed (no AV engines — placeholder results)"

        return result

    # ------------------------------------------------------------------ #
    #  Result mapping                                                     #
    # ------------------------------------------------------------------ #

    def _map_litterbox_report(
        self,
        report: Dict[str, Any],
        result: EvasionTestResult,
    ) -> EvasionTestResult:
        """Map a Litterbox report to our internal result format."""
        detections = report.get("detections", report.get("results", []))
        overall = report.get("overall_detection", report.get("verdict", "undetected"))

        if isinstance(overall, str):
            result.detection_overall = overall.lower()
        elif isinstance(overall, (int, float)):
            result.detection_overall = DetectionResult.UNDETECTED.value if overall == 0 else DetectionResult.DETECTED.value

        for det in detections:
            if not isinstance(det, dict):
                continue
            control_name = det.get("engine", det.get("control", "unknown"))
            detected = det.get("detected", False)
            result.control_results.append(
                ControlResult(
                    control=control_name,
                    detection=DetectionResult.DETECTED.value if detected else DetectionResult.UNDETECTED.value,
                    notes=det.get("signature", det.get("details", "")),
                    signatures_triggered=det.get("signatures", []),
                )
            )

        telemetry = report.get("telemetry", [])
        if isinstance(telemetry, list):
            result.telemetry_generated = [str(t) for t in telemetry]

        return result

    # ------------------------------------------------------------------ #
    #  History & persistence                                              #
    # ------------------------------------------------------------------ #

    def _save_history(self) -> None:
        """Persist test history to disk."""
        try:
            self._history_file.parent.mkdir(parents=True, exist_ok=True)
            with open(self._history_file, "w") as f:
                json.dump(
                    [r.to_dict() for r in self._history],
                    f,
                    indent=2,
                    default=str,
                )
        except Exception as e:
            logger.warning("Failed to save evasion history: %s", e)

    def _load_history(self) -> None:
        """Load persisted test history from disk."""
        try:
            with open(self._history_file) as f:
                data = json.load(f)
            for entry in data:
                results = entry.pop("control_results", [])
                result = EvasionTestResult(**entry)
                result.control_results = [ControlResult(**c) for c in results]
                self._history.append(result)
            logger.info("Loaded %d evasion test history entries", len(self._history))
        except Exception as e:
            logger.warning("Failed to load evasion history: %s", e)

    def get_history(self, limit: int = 100) -> List[EvasionTestResult]:
        """Return recent test results."""
        return self._history[-limit:]

    def get_test(self, test_id: str) -> Optional[EvasionTestResult]:
        """Look up a specific test by ID."""
        for r in self._history:
            if r.test_id == test_id:
                return r
        return None

    def list_all(self) -> List[EvasionTestResult]:
        """Return all test results."""
        return list(self._history)

    def get_stats(self) -> Dict[str, Any]:
        """Aggregate statistics across all tests."""
        total = len(self._history)
        by_detection: Dict[str, int] = {}
        by_execution: Dict[str, int] = {}
        for r in self._history:
            by_detection[r.detection_overall] = by_detection.get(r.detection_overall, 0) + 1
            by_execution[r.execution_result] = by_execution.get(r.execution_result, 0) + 1
        return {
            "total": total,
            "by_detection": by_detection,
            "by_execution": by_execution,
            "litterbox_linked": sum(1 for r in self._history if r.litterbox_job_id),
            "reproducible_builds": sum(1 for r in self._history if r.build_reproducible),
        }
