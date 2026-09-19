"""Tests for the EvasionTestRunner and TestConfigurationProfiles."""
from __future__ import annotations

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.evasion.models import (
    EvasionTestConfig,
    EvasionTestResult,
    TestEnvironment,
    compute_file_hash,
)
from pupyteer.server.evasion.profiles import (
    BUILTIN_PROFILES,
    TestConfigurationProfile,
    create_custom_profile,
    get_profile,
    list_profiles,
)
from pupyteer.server.evasion.runner import EvasionTestRunner, RunnerConfig


# ─── Profile Tests ──────────────────────────────────────────────────


def test_profile_count():
    assert len(BUILTIN_PROFILES) >= 4, "Should have at least 4 built-in profiles"


def test_profile_to_dict():
    p = get_profile("basic_xor")
    assert p is not None
    d = p.to_dict()
    assert d["name"] == "basic_xor"
    assert "description" in d
    assert "obfuscation_scheme" in d


def test_profile_list():
    profiles = list_profiles()
    assert isinstance(profiles, list)
    names = [p["name"] for p in profiles]
    assert "basic_xor" in names
    assert "stealth_full" in names


def test_profile_get_unknown():
    assert get_profile("nonexistent") is None


def test_profile_controls_populated():
    """All profiles should have at least one control defined."""
    for name, profile in BUILTIN_PROFILES.items():
        assert len(profile.controls) > 0, f"Profile {name} has no controls"


def test_create_custom_profile():
    p = create_custom_profile(
        name="custom_test",
        description="test",
        scheme="xor",
        controls=["yara"],
        anti_sandbox=True,
    )
    assert p.name == "custom_test"
    assert p.obfuscation.scheme.value == "xor"
    assert p.controls == ["yara"]
    assert p.obfuscation.anti_sandbox is True


# ─── Runner Tests ───────────────────────────────────────────────────


def test_runner_init():
    config = ConfigManager()
    audit = AuditLogger(config)
    runner = EvasionTestRunner(config, audit)
    assert runner is not None
    assert runner.run_count == 0


@pytest.mark.asyncio
async def test_runner_lab_mode_gate():
    """Runner must reject tests when lab mode is disabled."""
    config = ConfigManager()
    config.set("evasion.test_mode", False)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    audit = AuditLogger(config)

    runner = EvasionTestRunner(config, audit)
    await runner.initialize()

    try:
        await runner.run_with_profile("basic_xor", "/tmp/nonexistent")
        assert False, "Expected RuntimeError"
    except RuntimeError as e:
        assert "lab mode" in str(e).lower() or "test_mode" in str(e).lower()

    await runner.shutdown()


@pytest.mark.asyncio
async def test_runner_list_profiles():
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    audit = AuditLogger(config)

    runner = EvasionTestRunner(config, audit)
    profiles = runner.list_profiles()
    assert isinstance(profiles, dict)
    assert "basic_xor" in profiles
    assert "stealth_full" in profiles


@pytest.mark.asyncio
async def test_runner_with_profile():
    """Run a full test using a built-in profile."""
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    config.set("operator.name", "test")
    audit = AuditLogger(config)

    runner = EvasionTestRunner(
        config, audit,
        RunnerConfig(auto_obfuscate=False),
    )
    await runner.initialize()

    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".bin")
    tf.write(b"MZ" + b"\x00" * 100 + b"PAYLOAD_EXECUTABLE_STUB")
    tf.close()

    try:
        result = await runner.run_with_profile("basic_xor", tf.name)
        assert result.test_id.startswith("evt-")
        assert result.artifact_hash_verified is True
        assert result.build_reproducible is True
        assert result.detection_overall in ("undetected", "detected", "error")
    finally:
        os.unlink(tf.name)

    await runner.shutdown()


@pytest.mark.asyncio
async def test_runner_with_profile_obj():
    """Run a test with a TestConfigurationProfile object."""
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    config.set("operator.name", "test")
    audit = AuditLogger(config)

    runner = EvasionTestRunner(
        config, audit,
        RunnerConfig(auto_obfuscate=False),
    )
    await runner.initialize()

    profile = get_profile("pe_manipulation")
    assert profile is not None

    tf = tempfile.NamedTemporaryFile(delete=False, suffix=".exe")
    tf.write(b"MZ" + b"\x00" * 100 + b"PE_STUB")
    tf.close()
    h = compute_file_hash(tf.name)

    try:
        result = await runner.run_with_profile_obj(profile, tf.name)
        assert result.test_id
        assert result.artifact_hash_verified is True
        assert result.build_reproducible is True
        assert "pe_manipulation" in result.config.get("metadata", {}).get("profile_name", "")
    finally:
        os.unlink(tf.name)

    await runner.shutdown()


@pytest.mark.asyncio
async def test_runner_custom():
    """Run a custom test without a named profile."""
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    config.set("operator.name", "test")
    audit = AuditLogger(config)

    runner = EvasionTestRunner(
        config, audit,
        RunnerConfig(auto_obfuscate=False),
    )
    await runner.initialize()

    tf = tempfile.NamedTemporaryFile(delete=False)
    tf.write(b"CUSTOM_PAYLOAD")
    tf.close()

    try:
        result = await runner.run_custom(
            tf.name,
            controls=["yara", "sigma"],
            tags=["custom-test"],
        )
        assert result.test_id.startswith("evt-")
        assert result.detection_overall in ("undetected", "detected", "error")
    finally:
        os.unlink(tf.name)

    await runner.shutdown()


@pytest.mark.asyncio
async def test_runner_stats():
    """Stats should accumulate across multiple test runs."""
    config = ConfigManager()
    config.set("evasion.test_mode", True)
    config.set("evasion.history_path", tempfile.mktemp(suffix=".json"))
    config.set("operator.name", "test")
    audit = AuditLogger(config)

    runner = EvasionTestRunner(
        config, audit,
        RunnerConfig(auto_obfuscate=False),
    )
    await runner.initialize()

    for i in range(2):
        tf = tempfile.NamedTemporaryFile(delete=False)
        tf.write(f"PAYLOAD_{i}".encode() * 10)
        tf.close()
        try:
            await runner.run_custom(tf.name)
        finally:
            os.unlink(tf.name)

    stats = runner.get_stats()
    assert stats["runner_runs"] == 2
    assert stats["test_mode"] is True

    await runner.shutdown()


def main():
    """Run all tests synchronously."""
    print("=== Evasion Runner & Profile Tests ===\n")

    # Sync tests
    test_profile_count()
    print("PASS: test_profile_count")
    test_profile_to_dict()
    print("PASS: test_profile_to_dict")
    test_profile_list()
    print("PASS: test_profile_list")
    test_profile_get_unknown()
    print("PASS: test_profile_get_unknown")
    test_profile_controls_populated()
    print("PASS: test_profile_controls_populated")
    test_create_custom_profile()
    print("PASS: test_create_custom_profile")
    test_runner_init()
    print("PASS: test_runner_init")
    test_runner_list_profiles()
    print("PASS: test_runner_list_profiles")

    # Async tests
    asyncio.run(test_runner_lab_mode_gate())
    print("PASS: test_runner_lab_mode_gate")
    asyncio.run(test_runner_with_profile())
    print("PASS: test_runner_with_profile")
    asyncio.run(test_runner_with_profile_obj())
    print("PASS: test_runner_with_profile_obj")
    asyncio.run(test_runner_custom())
    print("PASS: test_runner_custom")
    asyncio.run(test_runner_stats())
    print("PASS: test_runner_stats")

    print("\n=== All tests passed ===")


if __name__ == "__main__":
    main()
