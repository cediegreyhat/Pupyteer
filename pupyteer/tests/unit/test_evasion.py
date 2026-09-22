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
from pupyteer.server.evasion.manager import (
    EvasionTestManager,
    LITTERBOX_DETECTION_UNAVAILABLE,
)


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


# ─── Litterbox response-shape reconciliation ───────────────────────────────
#
# The Litterbox HTTP API returns file metadata (and a risk score) only; it
# does NOT expose per-engine scanner verdicts over the API. The manager must
# therefore (a) read file_info from the correct place in the response envelope
# and (b) report detection status honestly as *unavailable* rather than
# implying a clean "0 detections" result. These tests cover the actual
# metadata-only shape, the honest-empty case, and a hypothetical
# detections-present shape (so the fix must not weaken real detection handling).

def _litterbox_manager() -> EvasionTestManager:
    """Manager used only to exercise the pure result-mapping method."""
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    return EvasionTestManager(config, AuditLogger(config))


def test_litterbox_map_metadata_only_is_honest_not_clean():
    """Metadata-only response => detection status is 'unavailable', NOT the
    historical always-'undetected' lie, and it does not inflate the
    undetected count."""
    mgr = _litterbox_manager()
    result = EvasionTestResult(test_id="lb-meta")
    # Envelope exactly as returned by LitterboxClient.upload(): file_info only.
    report = {
        "file_info": {
            "sha256": "a" * 64,
            "md5": "b" * 32,
            "size": 4096,
            "detection_risk": "high",
        },
        "detections_available": False,
    }
    out = mgr._map_litterbox_report(report, result)

    assert out.detection_overall == LITTERBOX_DETECTION_UNAVAILABLE
    assert out.detection_overall != DetectionResult.UNDETECTED.value, (
        "metadata-only result must not be reported as clean/undetected"
    )
    # The fake "0 detections" success path must be gone: nothing counts as
    # undetected when the source never reported per-engine results.
    assert out.undetected_count == 0
    assert out.detected_count == 0
    # Honest audit trail: the record says detection data was not available.
    assert out.metadata["litterbox"]["detections_available"] is False
    assert out.metadata["litterbox"]["sha256"] == "a" * 64
    assert "unavailable" in out.notes.lower()
    print("PASS: test_litterbox_map_metadata_only_is_honest_not_clean")


def test_litterbox_map_reads_file_info_from_envelope_not_double_nested():
    """Regression: the manager used to read report['file_info'] while the
    client returned the already-unwrapped file_info, so the job id came back
    empty. The client now returns the envelope; the job id must be populated."""
    mgr = _litterbox_manager()
    result = EvasionTestResult(test_id="lb-env")
    report = {"file_info": {"sha256": "deadbeef" * 8, "detection_risk": "low"}}
    out = mgr._map_litterbox_report(report, result)
    assert out.metadata["litterbox"]["sha256"].startswith("deadbeef")
    print("PASS: test_litterbox_map_reads_file_info_from_envelope_not_double_nested")


def test_litterbox_map_with_real_detections_is_not_weakened():
    """If a Litterbox deployment does return per-engine results, we must still
    map them (detected/undetected) instead of reporting 'unavailable'."""
    mgr = _litterbox_manager()
    result = EvasionTestResult(test_id="lb-det")
    report = {
        "file_info": {"sha256": "c" * 64},
        "detections": [
            {"engine": "yara", "detected": True, "signature": "Win.Trojan.Test"},
            {"engine": "amsi", "detected": False},
        ],
        "detections_available": True,
    }
    out = mgr._map_litterbox_report(report, result)
    assert out.detection_overall == DetectionResult.DETECTED.value
    assert out.detected_count == 1
    assert out.undetected_count == 1
    controls = {c.control for c in out.control_results}
    assert {"yara", "amsi"} <= controls
    print("PASS: test_litterbox_map_with_real_detections_is_not_weakened")


class _FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code
        self.text = ""

    def json(self):
        return self._payload


class _FakeAsyncClient:
    """Minimal stand-in for httpx.AsyncClient used by LitterboxClient.upload."""

    last_post_response = None

    def __init__(self, *args, **kwargs):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def post(self, url, **kwargs):
        return _FakeResponse(type(self).last_post_response)

    async def get(self, url, **kwargs):  # pragma: no cover - unused here
        return _FakeResponse({})


@pytest.mark.asyncio
async def test_litterbox_client_returns_envelope_and_flags_no_detections(tmp_path):
    """The real upload path must return the raw envelope (so callers can read
    report['file_info']) and honestly flag that no detections are available."""
    from pupyteer.server.evasion import litterbox_client as lc

    artifact = tmp_path / "payload.bin"
    artifact.write_bytes(b"MZ" + b"\x00" * 32)

    # Metadata-only response — mirrors the documented Litterbox API shape.
    _FakeAsyncClient.last_post_response = {
        "file_info": {
            "md5": "1" * 32,
            "sha256": "2" * 64,
            "size": 34,
            "detection_risk": "medium",
        }
    }
    original = lc.httpx.AsyncClient
    lc.httpx.AsyncClient = _FakeAsyncClient
    try:
        client = lc.LitterboxClient("http://localhost:1337")
        report = await client.upload(str(artifact))
    finally:
        lc.httpx.AsyncClient = original

    assert isinstance(report, dict)
    assert report.get("file_info", {}).get("sha256") == "2" * 64
    # Honest flag: metadata-only provider => no detections available.
    assert report["detections_available"] is False
    print("PASS: test_litterbox_client_returns_envelope_and_flags_no_detections")


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
