"""Tests for full payload lifecycle management per spec section 3."""
import asyncio
import os
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.payloads.manager import (
    PayloadConfig,
    PayloadPlatform,
    PayloadArch,
    PayloadType,
    PayloadStatus,
    PayloadBuilder,
    PayloadStore,
    PayloadManager,
    PayloadSigner,
    PayloadMetadata,
    VALID_PLATFORM_ARCH,
)


@pytest.fixture
def config(tmp_path):
    cfg = ConfigManager()
    cfg.set("paths.payload_artifacts", str(tmp_path))
    return cfg


@pytest.fixture
def audit(config):
    return AuditLogger(config)


# ─── Spec Field Coverage ─────────────────────────────────────────


class TestSpecFields:
    """Verify all 10 spec metadata fields exist and are populated."""

    def test_all_spec_fields_present(self):
        meta = PayloadMetadata(payload_id="pl-test", name="test")
        assert hasattr(meta, "payload_id")       # Payload ID
        assert hasattr(meta, "version")          # Version
        assert hasattr(meta, "platform")         # Platform
        assert hasattr(meta, "arch")             # Architecture
        assert hasattr(meta, "build_timestamp")  # Build Timestamp
        assert hasattr(meta, "profile")          # Configuration Profile
        assert hasattr(meta, "status")           # Build Status
        assert hasattr(meta, "hash_sha256")      # Hash
        assert hasattr(meta, "operator")         # Operator
        assert hasattr(meta, "expiration")       # Expiration/Validity

    @pytest.mark.asyncio
    async def test_fields_populated_after_build(self, config, audit):
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="spec-test")
        pid = builder.generate_payload_id()
        meta = await builder.build(cfg, pid, version="2.1.0")
        assert meta.payload_id == pid
        assert meta.version == "2.1.0"
        assert meta.platform == "windows"
        assert meta.arch == "x64"
        assert meta.profile == "HTTPS-Standard"
        assert meta.hash_sha256 != ""
        assert meta.operator != ""
        assert meta.status in (PayloadStatus.BUILT.value, PayloadStatus.VERIFIED.value)


# ─── Lifecycle Tests ─────────────────────────────────────────────


class TestLifecycle:
    """Configuration → Validation → Build → Verification → Artifact Management → Deployment"""

    @pytest.mark.asyncio
    async def test_validation_catches_invalid_config(self, config, audit):
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="", port=99999, host="")
        errors = builder.validate_config(cfg)
        assert len(errors) > 0
        assert any("name" in e.lower() for e in errors)

    @pytest.mark.asyncio
    async def test_validation_catches_invalid_platform_arch(self, config, audit):
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", platform=PayloadPlatform.MACOS, arch=PayloadArch.X86)
        errors = builder.validate_config(cfg)
        assert any("arch" in e.lower() for e in errors)

    @pytest.mark.asyncio
    async def test_validation_catches_invalid_transport(self, config, audit):
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", transport="invalid_proto")
        errors = builder.validate_config(cfg)
        assert any("transport" in e.lower() for e in errors)

    @pytest.mark.asyncio
    async def test_build_transitions_through_statuses(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="lifecycle-test", platform=PayloadPlatform.LINUX, arch=PayloadArch.X64)
        meta = await pm.build(cfg)
        # After successful build, status should be BUILT or VERIFIED
        assert meta.status in (PayloadStatus.BUILT.value, PayloadStatus.VERIFIED.value)
        assert meta.artifact_path != ""
        assert Path(meta.artifact_path).exists()

    @pytest.mark.asyncio
    async def test_build_failure_tracking(self, config, audit):
        builder = PayloadBuilder(config, audit)
        # Create config that will trigger fallback path (will still succeed as built)
        cfg = PayloadConfig(name="fail-test", transport="tcp", host="0.0.0.0", port=1)
        pid = builder.generate_payload_id()
        meta = await builder.build(cfg, pid)
        # Should succeed (with stub fallback) or fail gracefully
        assert meta.status in (PayloadStatus.BUILT.value, PayloadStatus.VERIFIED.value, PayloadStatus.FAILED.value)


# ─── Versioning Tests ────────────────────────────────────────────


class TestVersioning:
    @pytest.mark.asyncio
    async def test_auto_increment_version(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="versioned")

        meta1 = await pm.build(cfg)
        assert meta1.version == "1.0.0"

        meta2 = await pm.build(cfg)
        assert meta2.version == "1.0.1"

        meta3 = await pm.build(cfg)
        assert meta3.version == "1.0.2"

    @pytest.mark.asyncio
    async def test_explicit_version(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="explicit-ver")
        meta = await pm.build(cfg, version="3.2.1")
        assert meta.version == "3.2.1"

    @pytest.mark.asyncio
    async def test_version_history(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="history-test")
        await pm.build(cfg)
        await pm.build(cfg)
        history = pm.get_version_history("history-test")
        assert len(history) == 2
        assert history[0]["version"] == "1.0.0"
        assert history[1]["version"] == "1.0.1"


# ─── Artifact Management Tests ───────────────────────────────────


class TestArtifactManagement:
    @pytest.mark.asyncio
    async def test_list_all(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="list-test")
        await pm.build(cfg)
        all_payloads = pm.list_all()
        assert len(all_payloads) >= 1

    @pytest.mark.asyncio
    async def test_list_by_name(self, config, audit):
        pm = PayloadManager(config, audit)
        await pm.build(PayloadConfig(name="by-name"))
        await pm.build(PayloadConfig(name="by-name"))
        await pm.build(PayloadConfig(name="other"))
        results = pm.list_by_name("by-name")
        assert len(results) == 2

    @pytest.mark.asyncio
    async def test_remove_payload(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="removable")
        meta = await pm.build(cfg)
        assert pm.remove(meta.payload_id) is True
        assert pm.get(meta.payload_id) is None

    @pytest.mark.asyncio
    async def test_cleanup_old_versions(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="cleanup-versions")
        for _ in range(5):
            await pm.build(cfg)
        removed = pm.cleanup_old_versions("cleanup-versions", keep=2)
        assert removed == 3
        assert len(pm.list_by_name("cleanup-versions")) == 2

    @pytest.mark.asyncio
    async def test_cleanup_expired_by_age(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="aged")
        meta = await pm.build(cfg)
        # Manually set created_at to old date
        meta.created_at = "2020-01-01T00:00:00+00:00"
        pm._store._save_index()
        removed = pm.cleanup(max_age_days=1)
        assert removed >= 1

    @pytest.mark.asyncio
    async def test_mark_expired(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="expiring")
        meta = await pm.build(cfg, expiration_days=1)
        # Set expiration to the past
        from datetime import datetime, timezone, timedelta
        meta.expiration = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        pm._store._save_index()
        count = pm.mark_expired()
        assert count >= 1
        updated = pm.get(meta.payload_id)
        assert updated is not None
        assert updated.status == PayloadStatus.EXPIRED.value



# ─── Generation Logs Tests ───────────────────────────────────────


class TestGenerationLogs:
    @pytest.mark.asyncio
    async def test_generation_log_created(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="log-test")
        meta = await pm.build(cfg)
        log = pm.get_generation_log(meta.payload_id)
        assert log != ""
        assert "Build" in log

    @pytest.mark.asyncio
    async def test_generation_log_persists(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="persist-log")
        meta = await pm.build(cfg)
        log_path = pm._builder._log_dir / f"{meta.payload_id}.log"
        assert log_path.exists()


# ─── Signing Tests ───────────────────────────────────────────────


class TestSigning:
    def test_signer_disabled_by_default(self, config, audit):
        signer = PayloadSigner(config, audit)
        assert signer.enabled is False

    def test_signer_no_op_when_disabled(self, config, audit, tmp_path):
        signer = PayloadSigner(config, audit)
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test data")
        ok, result = signer.sign(str(test_file), "pl-test")
        assert ok is True
        assert result == ""

    def test_signer_with_missing_key(self, config, audit, tmp_path):
        config.set("payloads.signing.enabled", True)
        config.set("payloads.signing.key_path", "")
        signer = PayloadSigner(config, audit)
        test_file = tmp_path / "test.bin"
        test_file.write_bytes(b"test data")
        ok, result = signer.sign(str(test_file), "pl-test")
        assert ok is False
        assert "key_path" in result


# ─── Verification Tests ──────────────────────────────────────────


class TestVerification:
    @pytest.mark.asyncio
    async def test_verify_valid_payload(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="verify-test")
        meta = await pm.build(cfg)
        ok, msg = pm.verify(meta.payload_id)
        assert ok is True
        assert msg == "OK"

    @pytest.mark.asyncio
    async def test_verify_missing_payload(self, config, audit):
        pm = PayloadManager(config, audit)
        ok, msg = pm.verify("pl-nonexistent")
        assert ok is False
        assert "not found" in msg.lower()

    @pytest.mark.asyncio
    async def test_verify_corrupted_artifact(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="corrupt-test")
        meta = await pm.build(cfg)
        # Corrupt the artifact
        Path(meta.artifact_path).write_bytes(b"CORRUPTED")
        ok, msg = pm.verify(meta.payload_id)
        assert ok is False
        assert "mismatch" in msg.lower()


# ─── Stats Tests ─────────────────────────────────────────────────


class TestStats:
    @pytest.mark.asyncio
    async def test_stats_breakdown(self, config, audit):
        pm = PayloadManager(config, audit)
        await pm.build(PayloadConfig(name="stats1", platform=PayloadPlatform.WINDOWS))
        await pm.build(PayloadConfig(name="stats2", platform=PayloadPlatform.LINUX))
        stats = pm.get_stats()
        assert stats["total"] >= 2
        assert "windows" in stats["by_platform"]
        assert "linux" in stats["by_platform"]
        assert stats["total_size_bytes"] > 0


# ─── Platform/Arch Validation Tests ──────────────────────────────


class TestPlatformArchValidation:
    def test_all_platforms_have_valid_archs(self):
        for platform in PayloadPlatform:
            assert platform in VALID_PLATFORM_ARCH
            assert len(VALID_PLATFORM_ARCH[platform]) > 0

    def test_macos_x86_rejected(self, config, audit):
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", platform=PayloadPlatform.MACOS, arch=PayloadArch.X86)
        errors = builder.validate_config(cfg)
        assert any("arch" in e.lower() for e in errors)

    def test_windows_arm64_accepted(self, config, audit):
        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(name="test", platform=PayloadPlatform.WINDOWS, arch=PayloadArch.ARM64)
        errors = builder.validate_config(cfg)
        assert not any("arch" in e.lower() for e in errors)


# ─── Expiration Tests ────────────────────────────────────────────


class TestExpiration:
    @pytest.mark.asyncio
    async def test_expiration_set(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="expire-test")
        meta = await pm.build(cfg, expiration_days=30)
        assert meta.expiration != ""
        assert meta.is_expired is False

    @pytest.mark.asyncio
    async def test_no_expiration_by_default(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(name="no-expire")
        meta = await pm.build(cfg)
        assert meta.expiration == ""
        assert meta.is_expired is False

    def test_is_expired_property(self):
        from datetime import datetime, timezone, timedelta
        meta = PayloadMetadata(payload_id="pl-test", name="test")
        meta.expiration = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert meta.is_expired is True

    def test_is_valid_property(self):
        meta = PayloadMetadata(payload_id="pl-test", name="test")
        meta.status = PayloadStatus.VERIFIED.value
        assert meta.is_valid is True

    def test_is_valid_expired(self):
        from datetime import datetime, timezone, timedelta
        meta = PayloadMetadata(payload_id="pl-test", name="test")
        meta.status = PayloadStatus.VERIFIED.value
        meta.expiration = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        assert meta.is_valid is False
