"""Standalone test script for the Pupyteer evasion subsystem.

Run: python -m pupyteer.tests.unit.test_evasion
"""
from __future__ import annotations

import os
import sys
import tempfile
import asyncio
from pathlib import Path

import pytest

# Add project root
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from pupyteer.server.evasion.models import (
    EvasionTestConfig,
    EvasionTestResult,
    ControlResult,
    DetectionResult,
    TestEnvironment,
    compute_file_hash,
    verify_artifact_hash,
)
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.evasion.manager import EvasionTestManager


def test_compute_hash_deterministic():
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"test data" * 100)
    tf.close()
    h1 = compute_file_hash(tf.name)
    h2 = compute_file_hash(tf.name)
    os.unlink(tf.name)
    assert h1 == h2, f"Hash mismatch: {h1} != {h2}"
    assert len(h1) == 64, f"SHA256 hex digest should be 64 chars, got {len(h1)}"
    print("PASS: test_compute_hash_deterministic")


def test_verify_artifact_hash_correct():
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"test data")
    tf.close()
    h = compute_file_hash(tf.name)
    assert verify_artifact_hash(tf.name, h) is True
    os.unlink(tf.name)
    print("PASS: test_verify_artifact_hash_correct")


def test_verify_artifact_hash_incorrect():
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"test data")
    tf.close()
    assert verify_artifact_hash(tf.name, "wronghash") is False
    os.unlink(tf.name)
    print("PASS: test_verify_artifact_hash_incorrect")


def test_verify_artifact_hash_empty():
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"test data")
    tf.close()
    assert verify_artifact_hash(tf.name, "") is False
    os.unlink(tf.name)
    print("PASS: test_verify_artifact_hash_empty")


def test_config_validate_valid():
    cfg = EvasionTestConfig(
        name="test",
        artifact_path="/tmp/test.bin",
        test_mode=True,
    )
    errors = cfg.validate()
    assert errors == [], f"Expected no errors, got {errors}"
    print("PASS: test_config_validate_valid")


def test_config_validate_missing_name():
    cfg = EvasionTestConfig(name="", test_mode=True)
    errors = cfg.validate()
    assert any("name" in e.lower() for e in errors)
    print("PASS: test_config_validate_missing_name")


def test_config_validate_not_lab_mode():
    cfg = EvasionTestConfig(name="test", test_mode=False)
    errors = cfg.validate()
    assert any("test_mode" in e for e in errors)
    print("PASS: test_config_validate_not_lab_mode")


def test_config_validate_missing_artifact():
    cfg = EvasionTestConfig(name="test", test_mode=True)
    errors = cfg.validate()
    assert any("artifact" in e.lower() or "payload_id" in e for e in errors)
    print("PASS: test_config_validate_missing_artifact")


def test_result_detected_count():
    result = EvasionTestResult()
    result.control_results.append(
        ControlResult(control="yara", detection=DetectionResult.DETECTED.value)
    )
    result.control_results.append(
        ControlResult(control="amsi", detection=DetectionResult.UNDETECTED.value)
    )
    result.control_results.append(
        ControlResult(control="defender", detection=DetectionResult.PARTIAL.value)
    )
    assert result.detected_count == 2, f"Expected 2 detected, got {result.detected_count}"
    assert result.undetected_count == 1, f"Expected 1 undetected, got {result.undetected_count}"
    print("PASS: test_result_detected_count")


def test_result_to_dict():
    result = EvasionTestResult(
        test_id="evt-001",
        detection_overall=DetectionResult.UNDETECTED.value,
    )
    result.control_results.append(
        ControlResult(control="test", detection=DetectionResult.UNDETECTED.value)
    )
    d = result.to_dict()
    assert d["test_id"] == "evt-001"
    assert d["detection_overall"] == "undetected"
    assert len(d["control_results"]) == 1
    print("PASS: test_result_to_dict")


def test_result_serialization_roundtrip():
    """EvasionTestResult -> dict -> JSON -> dict preserves data."""
    import json

    result = EvasionTestResult(
        test_id="evt-abc",
        config={"name": "test"},
        detection_overall=DetectionResult.DETECTED.value,
        execution_result="blocked",
        notes="test notes",
    )
    result.control_results.append(ControlResult(control="yara", notes="sig1"))

    d = result.to_dict()
    s = json.dumps(d)
    d2 = json.loads(s)
    assert d2["test_id"] == "evt-abc"
    assert d2["detection_overall"] == "detected"
    assert d2["control_results"][0]["control"] == "yara"
    print("PASS: test_result_serialization_roundtrip")


@pytest.mark.asyncio
async def test_manager_local_test():
    """EvasionTestManager runs a local test end-to-end."""
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    config.set("operator.name", "test-operator")

    audit = AuditLogger(config)
    manager = EvasionTestManager(config, audit)
    await manager.initialize()

    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    tf.write(b"FAKE_PAYLOAD_TEST")
    tf.close()
    h = compute_file_hash(tf.name)

    cfg = EvasionTestConfig(
        name="local-test",
        artifact_path=tf.name,
        artifact_hash_sha256=h,
        environment=TestEnvironment.LOCAL.value,
        controls=["yara", "amsi"],
        test_mode=True,
    )

    result = await manager.run_test(cfg)
    os.unlink(tf.name)

    assert result.test_id.startswith("evt-")
    assert result.artifact_hash_verified is True
    assert result.build_reproducible is True
    assert result.duration_seconds > 0
    assert result.detection_overall in ("undetected", "detected", "error")

    await manager.shutdown()

    # Cleanup
    hist = Path(config.get("evasion.history_path"))
    if hist.exists():
        hist.unlink()

    print("PASS: test_manager_local_test")


@pytest.mark.asyncio
async def test_manager_rejects_non_lab_mode():
    """Tests are rejected when test_mode is False."""
    config = ConfigManager()
    config.set("evasion.test_mode", False)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))

    audit = AuditLogger(config)
    manager = EvasionTestManager(config, audit)
    await manager.initialize()

    # Provide artifact_path so config validation passes
    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"DATA")
    tf.close()

    cfg = EvasionTestConfig(name="test", test_mode=True, artifact_path=tf.name)

    try:
        await manager.run_test(cfg)
        assert False, "Expected RuntimeError"
    except RuntimeError as e:
        assert "test_mode" in str(e)

    os.unlink(tf.name)
    await manager.shutdown()

    hist = Path(config.get("evasion.history_path"))
    if hist.exists():
        hist.unlink()

    print("PASS: test_manager_rejects_non_lab_mode")


@pytest.mark.asyncio
async def test_manager_history_persistence():
    """History is saved and reloaded."""
    hist_path = tempfile.mktemp(suffix=".json")

    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", hist_path)
    config.set("operator.name", "test")

    audit = AuditLogger(config)
    manager = EvasionTestManager(config, audit)
    await manager.initialize()

    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"DATA")
    tf.close()
    h = compute_file_hash(tf.name)

    cfg = EvasionTestConfig(
        name="persist",
        artifact_path=tf.name,
        artifact_hash_sha256=h,
        environment=TestEnvironment.LOCAL.value,
        test_mode=True,
    )
    result = await manager.run_test(cfg)
    os.unlink(tf.name)
    await manager.shutdown()

    # Verify file exists
    assert Path(hist_path).exists(), "History file not created"

    # New manager should load history
    audit2 = AuditLogger(config)
    manager2 = EvasionTestManager(config, audit2)
    history = manager2.get_history()
    assert len(history) >= 1, f"Expected at least 1 entry, got {len(history)}"
    assert any(r.test_id == result.test_id for r in history)

    # Cleanup
    Path(hist_path).unlink(missing_ok=True)

    print("PASS: test_manager_history_persistence")


def main():
    print("=== Pupyteer Evasion Subsystem Tests ===\n")

    # Sync tests
    test_compute_hash_deterministic()
    test_verify_artifact_hash_correct()
    test_verify_artifact_hash_incorrect()
    test_verify_artifact_hash_empty()
    test_config_validate_valid()
    test_config_validate_missing_name()
    test_config_validate_not_lab_mode()
    test_config_validate_missing_artifact()
    test_result_detected_count()
    test_result_to_dict()
    test_result_serialization_roundtrip()

    # Async tests
    asyncio.run(test_manager_local_test())
    asyncio.run(test_manager_rejects_non_lab_mode())
    asyncio.run(test_manager_history_persistence())

    print("\n=== All tests passed ===")


if __name__ == "__main__":
    main()
