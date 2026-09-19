"""Data models for the Pupyteer evasion testing subsystem.

Covers:
- Test configuration (what to test, with which controls)
- Test results (detection, execution, telemetry, defensive triggers)
- Reproducible build tracking via artifact hashes
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class TestEnvironment(str, Enum):
    """Where the test runs."""
    LOCAL = "local"
    LAB = "lab"
    LITTERBOX = "litterbox"
    VIRUSTOTAL = "virustotal"
    FULL_PIPELINE = "full_pipeline"  # runs Litterbox + VT + local


class DetectionResult(str, Enum):
    """Outcome of a detection test."""
    UNDETECTED = "undetected"
    DETECTED = "detected"
    PARTIAL = "partial"
    ERROR = "error"


class ExecutionResult(str, Enum):
    """Whether the payload actually ran."""
    SUCCESS = "success"
    BLOCKED = "blocked"
    PARTIAL = "partial"
    ERROR = "error"


class DefensiveControl(str, Enum):
    """Known defensive controls that may be encountered."""
    WINDOWS_DEFENDER = "windows_defender"
    CROWDSTRIKE = "crowdstrike"
    SENTINELONE = "sentinelone"
    CARBON_BLACK = "carbon_black"
    ELASTIC_SIEM = "elastic_siem"
    SPLUNK = "splunk"
    YARA = "yara"
    SIGMA = "sigma"
    AMSI = "amsi"
    ETW = "etw"
    CUSTOM = "custom"


@dataclass
class EvasionTestConfig:
    """Configuration for a single evasion test run."""
    name: str
    payload_id: str = ""
    artifact_path: str = ""
    artifact_hash_sha256: str = ""
    environment: str = TestEnvironment.LAB.value
    controls: List[str] = field(default_factory=list)
    test_mode: bool = True  # must be True to run — explicit lab mode
    description: str = ""
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["environment"] = self.environment
        return d

    def validate(self) -> List[str]:
        errors = []
        if not self.name:
            errors.append("Test name is required")
        if not self.test_mode:
            errors.append("test_mode must be True (explicit laboratory mode)")
        if not self.artifact_path and not self.payload_id:
            errors.append("Either artifact_path or payload_id must be provided")
        return errors


@dataclass
class ControlResult:
    """Result against a specific defensive control."""
    control: str
    detection: str = DetectionResult.UNDETECTED.value
    notes: str = ""
    telemetry_generated: bool = False
    signatures_triggered: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvasionTestResult:
    """Complete result record for an evasion test run."""
    test_id: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""
    environment: str = ""
    detection_overall: str = DetectionResult.UNDETECTED.value
    execution_result: str = ExecutionResult.BLOCKED.value
    false_positive_risk: str = "low"
    control_results: List[ControlResult] = field(default_factory=list)
    telemetry_generated: List[str] = field(default_factory=list)
    litterbox_job_id: str = ""
    litterbox_report_url: str = ""
    build_reproducible: bool = False
    artifact_hash_verified: bool = False
    operator: str = ""
    notes: str = ""
    duration_seconds: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["control_results"] = [c.to_dict() for c in self.control_results]
        return d

    @property
    def detected_count(self) -> int:
        return sum(
            1 for c in self.control_results
            if c.detection in (DetectionResult.DETECTED.value, DetectionResult.PARTIAL.value)
        )

    @property
    def undetected_count(self) -> int:
        return sum(
            1 for c in self.control_results
            if c.detection == DetectionResult.UNDETECTED.value
        )


def compute_file_hash(path: str, algorithm: str = "sha256") -> str:
    """Compute hash of a local artifact."""
    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def verify_artifact_hash(path: str, expected_hash: str) -> bool:
    """Verify an artifact matches its expected SHA256 hash."""
    if not expected_hash:
        return False
    actual = compute_file_hash(path)
    return actual == expected_hash
