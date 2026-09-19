"""Integration test for evasion testing subsystem."""
from __future__ import annotations

import asyncio
import tempfile
import os
from pathlib import Path

import pytest

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.evasion.manager import EvasionTestManager
from pupyteer.server.evasion.models import (
    EvasionTestConfig, TestEnvironment, compute_file_hash
)


@pytest.mark.asyncio
async def test_full_litterbox_flow():
    """Test complete flow: configure → run → verify history → stats."""
    hist_path = tempfile.mktemp(suffix=".json")

    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", hist_path)
    config.set("operator.name", "integration-test")

    audit = AuditLogger(config)
    manager = EvasionTestManager(config, audit)
    await manager.initialize()

    # Create artifact
    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    tf.write(b"MZ" + b"\x00" * 100 + b"PAYLOAD_EXECUTABLE_STUB")
    tf.close()
    h = compute_file_hash(tf.name)

    # Run test
    cfg = EvasionTestConfig(
        name="integration-full-flow",
        artifact_path=tf.name,
        artifact_hash_sha256=h,
        environment=TestEnvironment.LOCAL.value,
        controls=["windows_defender", "yara", "amsi", "sigma"],
        test_mode=True,
        tags=["integration", "phase10"],
    )

    result = await manager.run_test(cfg)
    os.unlink(tf.name)

    # Verify result
    assert result.test_id
    assert result.artifact_hash_verified
    assert result.build_reproducible
    assert result.detection_overall in ("undetected", "detected", "error")
    assert result.execution_result == "success"
    assert len(result.control_results) == 4

    # Verify history
    history = manager.get_history()
    assert len(history) == 1
    assert history[0].test_id == result.test_id

    # Verify stats
    stats = manager.get_stats()
    assert stats["total"] == 1
    assert stats["reproducible_builds"] == 1
    assert stats["by_detection"][result.detection_overall] == 1

    await manager.shutdown()

    # Verify persistence across restart
    audit2 = AuditLogger(config)
    manager2 = EvasionTestManager(config, audit2)
    history2 = manager2.get_history()
    assert len(history2) == 1
    assert history2[0].test_id == result.test_id

    # Cleanup
    Path(hist_path).unlink(missing_ok=True)
    print("PASS: test_full_litterbox_flow")


@pytest.mark.asyncio
async def test_multiple_tests_accumulate():
    """Multiple tests accumulate in history."""
    hist_path = tempfile.mktemp(suffix=".json")

    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", hist_path)
    config.set("operator.name", "test")

    audit = AuditLogger(config)
    manager = EvasionTestManager(config, audit)
    await manager.initialize()

    for i in range(3):
        tf = tempfile.NamedTemporaryFile(delete=False)
        tf.write(f"PAYLOAD_V{i}".encode())
        tf.close()
        h = compute_file_hash(tf.name)

        cfg = EvasionTestConfig(
            name=f"test-{i}",
            artifact_path=tf.name,
            artifact_hash_sha256=h,
            environment=TestEnvironment.LOCAL.value,
            test_mode=True,
        )
        await manager.run_test(cfg)
        os.unlink(tf.name)

    history = manager.get_history()
    assert len(history) == 3

    stats = manager.get_stats()
    assert stats["total"] == 3

    await manager.shutdown()
    Path(hist_path).unlink(missing_ok=True)
    print("PASS: test_multiple_tests_accumulate")


def main():
    print("=== Pupyteer Evasion Integration Tests ===\n")
    asyncio.run(test_full_litterbox_flow())
    asyncio.run(test_multiple_tests_accumulate())
    print("\n=== All integration tests passed ===")


if __name__ == "__main__":
    main()
