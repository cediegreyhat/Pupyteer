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
    PayloadDelivery,
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
    # A build derives the enrollment secret from config, so point that file into
    # tmp_path: a test run must not generate a real team secret into the checkout.
    cfg.set("server.agent_auth_file", str(tmp_path / "enrollment.key"))
    # The builds below are the plaintext path on purpose. TLS is the shipped
    # default now, so a test that asserts an agent carries no pin has to turn it
    # off and mean it, rather than inherit a default that used to be false.
    cfg.set("server.tls", False)
    return cfg


@pytest.fixture
def audit(config):
    return AuditLogger(config)


def _load_agent(agent_path: Path):
    """Import a generated agent without running it (the __main__ guard holds)."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(agent_path.stem, str(agent_path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _pinned_cert(agent_path: Path) -> str:
    """The certificate PEM compiled into a generated agent.

    Read from the imported module rather than the source text, so the escaping
    the template applies cannot hide a mismatch between build and listener.
    """
    return _load_agent(agent_path).TLS_CERT_PEM


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
        cfg = PayloadConfig(name="spec-test", payload_type=PayloadType.SCRIPT)
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
        cfg = PayloadConfig(name="lifecycle-test", payload_type=PayloadType.SCRIPT, platform=PayloadPlatform.LINUX, arch=PayloadArch.X64)
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


class TestBuildSettingsReachTheStub:
    """What the operator asks for must be compiled into the artifact."""

    @pytest.mark.asyncio
    async def test_beacon_timing_is_baked_in(self, config, audit):
        pm = PayloadManager(config, audit)
        cfg = PayloadConfig(
            name="timed", payload_type=PayloadType.SCRIPT,
            sleep=37, jitter=5, profile="TCP-Raw",
        )
        meta = await pm.build(cfg)
        code = Path(meta.artifact_path).read_text(encoding="utf-8")
        assert "base_sleep = 37" in code, "payload ignored the requested sleep"
        assert "jitter_pct = 5" in code, "payload ignored the requested jitter"

    @pytest.mark.asyncio
    async def test_persistence_is_absent_unless_requested(self, config, audit):
        pm = PayloadManager(config, audit)
        default = await pm.build(PayloadConfig(
            name="quiet", payload_type=PayloadType.SCRIPT, profile="TCP-Raw"))
        assert "install_persistence" not in Path(default.artifact_path).read_text(encoding="utf-8")

        opted = await pm.build(PayloadConfig(
            name="sticky", payload_type=PayloadType.SCRIPT, profile="TCP-Raw",
            persistence=True))
        assert "def install_persistence" in Path(opted.artifact_path).read_text(encoding="utf-8")

    @pytest.mark.asyncio
    async def test_nonsense_beacon_values_are_rejected(self, config, audit):
        builder = PayloadBuilder(config, audit)
        assert any("sleep" in e.lower() for e in builder.validate_config(
            PayloadConfig(name="x", sleep=0)))
        assert any("jitter" in e.lower() for e in builder.validate_config(
            PayloadConfig(name="x", jitter=140)))

    @pytest.mark.asyncio
    async def test_screenshot_toggle_reaches_the_artifact(self, config, audit):
        """The build accepted --screenshot; the artifact has to act like it."""
        pm = PayloadManager(config, audit)
        default = await pm.build(PayloadConfig(
            name="flat", payload_type=PayloadType.SCRIPT, profile="TCP-Raw"))
        assert "def mod_screenshot" not in Path(default.artifact_path).read_text(encoding="utf-8")

        armed = await pm.build(PayloadConfig(
            name="shotted", payload_type=PayloadType.SCRIPT, profile="TCP-Raw",
            screenshot=True))
        code = Path(armed.artifact_path).read_text(encoding="utf-8")
        assert "def mod_screenshot" in code
        assert 'action == "screenshot"' in code, (
            "capture code is present but no action reaches it"
        )

    @pytest.mark.asyncio
    async def test_migration_toggle_reaches_the_artifact(self, config, audit):
        """Migration is compiled in by default, but an operator can turn it off."""
        pm = PayloadManager(config, audit)
        default = await pm.build(PayloadConfig(
            name="migratory", payload_type=PayloadType.SCRIPT, profile="TCP-Raw"))
        code = Path(default.artifact_path).read_text(encoding="utf-8")
        assert "def migrate(" in code, "default payload lost its migration handler"
        assert 'action == "migrate"' in code, (
            "handler is present but no action reaches it"
        )

        off = await pm.build(PayloadConfig(
            name="rooted", payload_type=PayloadType.SCRIPT, profile="TCP-Raw",
            migration=False))
        code = Path(off.artifact_path).read_text(encoding="utf-8")
        assert "def migrate(" not in code, (
            "migration=False still compiled in the process-migration handler"
        )
        assert 'action == "migrate"' not in code, (
            "a migrate tasking would still be routed to a missing handler"
        )


class TestCompilationIsReal:
    """An artifact that only has an executable's extension is not one.

    These pin the fail-closed behaviour: the build must report failure rather
    than hand back a file the operator finds unrunnable on the target.
    """

    @pytest.mark.asyncio
    async def test_executable_build_fails_without_the_compiler(
        self, config, audit, monkeypatch
    ):
        import shutil as _shutil
        monkeypatch.setattr(_shutil, "which", lambda name: None)

        pm = PayloadManager(config, audit)
        meta = await pm.build(PayloadConfig(
            name="noexe", platform=PayloadPlatform.WINDOWS,
            compiler="pyinstaller"))

        assert meta.status == PayloadStatus.FAILED.value, (
            "a build with no compiler must not report a usable payload"
        )
        assert meta.artifact_path == ""
        assert meta.hash_sha256 == ""
        joined = " ".join(meta.build_log)
        assert "--type script" in joined, "the failure must say what to do instead"

    @pytest.mark.asyncio
    async def test_compiler_cannot_cross_compile(self, config, audit, monkeypatch):
        """PyInstaller freezes for the host it runs on; asking for another
        platform has to be an error, not a host binary named for the target."""
        import shutil as _shutil
        import sys as _sys
        if _sys.platform.startswith("win"):
            foreign = PayloadPlatform.LINUX
        else:
            foreign = PayloadPlatform.WINDOWS

        monkeypatch.setattr(_shutil, "which", lambda name: "/usr/bin/pyinstaller")
        pm = PayloadManager(config, audit)
        meta = await pm.build(PayloadConfig(
            name="foreign", platform=foreign, compiler="pyinstaller"))

        assert meta.status == PayloadStatus.FAILED.value
        joined = " ".join(meta.build_log)
        assert foreign.value in joined
        assert "host" in joined.lower(), "must name the build host as the constraint"
        assert "--type script" in joined

    @pytest.mark.asyncio
    async def test_compiler_script_is_honoured_for_an_executable_request(
        self, config, audit
    ):
        """--compiler script is the documented way to get the standalone agent."""
        pm = PayloadManager(config, audit)
        meta = await pm.build(PayloadConfig(
            name="portable", platform=PayloadPlatform.WINDOWS,
            payload_type=PayloadType.EXECUTABLE, compiler="script"))
        assert meta.status == PayloadStatus.VERIFIED.value
        assert meta.artifact_path.endswith(".py")

    @pytest.mark.asyncio
    async def test_unknown_compiler_and_stage_delivery_are_rejected(self, config, audit):
        builder = PayloadBuilder(config, audit)
        assert any("compiler" in e.lower() for e in builder.validate_config(
            PayloadConfig(name="x", compiler="gcc")))
        assert any("stage" in e.lower() for e in builder.validate_config(
            PayloadConfig(name="x", delivery=PayloadDelivery.STAGE)))
        assert any("mingw" in e.lower() for e in builder.validate_config(
            PayloadConfig(name="x", platform=PayloadPlatform.LINUX, compiler="mingw")))


class TestMinGWPeBuildReachesBuilder:
    """compiler=mingw used to raise `name 'StubConfig' is not defined` before it
    ever reached the PE builder, because StubConfig was only imported in the
    sibling stageless branch. That came back as a generic "MinGW PE build error"
    with the real cause buried — a build that never started looking like a build
    that failed. These pin that the mingw path now constructs its StubConfig and
    calls PEBuilder for real."""

    @pytest.mark.asyncio
    async def test_mingw_branch_reaches_pe_builder(self, config, audit, monkeypatch):
        from pupyteer.agent.core.stub import StubConfig
        from pupyteer.payloads import pe_builder as pe_mod
        from pupyteer.payloads.pe_builder import PEBuildResult

        received: dict = {}

        class _FakePEBuilder:
            def __init__(self, config, audit):
                pass

            async def build(self, stub_cfg, output_path):
                # Reaching this line at all means StubConfig resolved in the
                # mingw branch; a real toolchain is not needed to prove that.
                received["stub_cfg"] = stub_cfg
                output_path.write_bytes(b"MZfakepe")
                return PEBuildResult(
                    artifact_path=str(output_path), status="built",
                    hash_sha256="0" * 64, size_bytes=output_path.stat().st_size,
                )

        monkeypatch.setattr(pe_mod, "PEBuilder", _FakePEBuilder)

        builder = PayloadBuilder(config, audit)
        cfg = PayloadConfig(
            name="mingw-pe", platform=PayloadPlatform.WINDOWS,
            payload_type=PayloadType.EXECUTABLE, compiler="mingw",
            host="10.0.0.5", port=4444, sleep=11, jitter=3,
        )
        meta = await builder.build(cfg, builder.generate_payload_id())

        assert isinstance(received.get("stub_cfg"), StubConfig), (
            "mingw branch never reached PEBuilder with a StubConfig"
        )
        # Build settings must arrive at the PE builder, not just any StubConfig.
        assert received["stub_cfg"].host == "10.0.0.5"
        assert received["stub_cfg"].port == 4444
        assert received["stub_cfg"].sleep == 11
        assert received["stub_cfg"].jitter == 3
        assert meta.status == PayloadStatus.VERIFIED.value, " ".join(meta.build_log)
        assert meta.artifact_path.endswith(".exe")
        assert any("PE built via MinGW" in line for line in meta.build_log)


class TestUnimplementedPayloadTypesRejected:
    """library/apk/oneliner have no code path that produces them. A library build
    with pyinstaller froze an exe and returned it named as a DLL — an artifact
    that lies about what it is. Refusing them at validation is the honest outcome
    (the same posture as the delivery=stage refusal)."""

    @pytest.mark.parametrize("ptype", [
        PayloadType.LIBRARY, PayloadType.APK, PayloadType.ONELINER,
    ])
    def test_validate_rejects_unimplemented_types(self, config, audit, ptype):
        builder = PayloadBuilder(config, audit)
        errors = builder.validate_config(PayloadConfig(name="x", payload_type=ptype))
        assert any("not implemented" in e.lower() for e in errors), errors

    @pytest.mark.parametrize("ptype", [
        PayloadType.EXECUTABLE, PayloadType.SCRIPT,
    ])
    def test_validate_accepts_supported_types(self, config, audit, ptype):
        builder = PayloadBuilder(config, audit)
        errors = builder.validate_config(
            PayloadConfig(name="x", payload_type=ptype, compiler="script"))
        assert not any("payload_type" in e.lower() for e in errors), errors

    @pytest.mark.asyncio
    async def test_manager_raises_instead_of_emitting_mislabeled_artifact(
        self, config, audit
    ):
        pm = PayloadManager(config, audit)
        with pytest.raises(ValueError) as exc:
            await pm.build(
                PayloadConfig(name="dll-lie", payload_type=PayloadType.LIBRARY))
        assert "not implemented" in str(exc.value).lower()
        # Nothing was stored: no mislabelled artifact ever reached the index.
        assert pm.list_all() == []


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
        cfg = PayloadConfig(name="verify-test", payload_type=PayloadType.SCRIPT)
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
        cfg = PayloadConfig(name="corrupt-test", payload_type=PayloadType.SCRIPT)
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
        await pm.build(PayloadConfig(name="stats1", platform=PayloadPlatform.WINDOWS, payload_type=PayloadType.SCRIPT))
        await pm.build(PayloadConfig(name="stats2", platform=PayloadPlatform.LINUX, payload_type=PayloadType.SCRIPT))
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


# ─── Listener TLS Tests ──────────────────────────────────────────


class TestListenerTlsIsBakedIn:
    """An agent pins the listener's certificate at build time, so a build has to
    produce exactly the certificate the server will present. Getting this wrong
    is invisible until a payload cannot call home.
    """

    @pytest.fixture
    def tls_config(self, config, tmp_path):
        config.set("server.tls", True)
        config.set("server.tls_cert", str(tmp_path / "listener.crt"))
        config.set("server.tls_key", str(tmp_path / "listener.key"))
        config.set("server.tls_hostnames", ["127.0.0.1", "team-server"])
        return config

    @pytest.mark.asyncio
    async def test_build_produces_and_pins_the_listener_certificate(
        self, tls_config, audit, tmp_path
    ):
        from pupyteer.server.core.tls import certificate_fingerprint

        builder = PayloadBuilder(tls_config, audit)
        cfg = PayloadConfig(name="tls-baked", payload_type=PayloadType.SCRIPT)
        meta = await builder.build(cfg, builder.generate_payload_id())
        artifact = Path(meta.artifact_path)
        assert artifact.exists()
        code = artifact.read_text(encoding="utf-8")

        assert "TLS_ON = True" in code
        assert "BEGIN CERTIFICATE" in code
        # The pair is generated on demand, and what got compiled in is the very
        # certificate the listener will serve from the same config.
        assert _pinned_cert(artifact) == (tmp_path / "listener.crt").read_text(encoding="ascii")
        assert certificate_fingerprint(str(tmp_path / "listener.crt"))

    @pytest.mark.asyncio
    async def test_a_second_build_reuses_the_certificate(
        self, tls_config, audit, tmp_path
    ):
        """Regenerating it on the next build would strand every earlier payload."""
        from pupyteer.server.core.tls import certificate_fingerprint

        builder = PayloadBuilder(tls_config, audit)
        first = Path(str(tmp_path / "listener.crt"))
        await builder.build(
            PayloadConfig(name="reuse-a", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        stamp = first.stat().st_mtime_ns
        fingerprint = certificate_fingerprint(str(first))

        await builder.build(
            PayloadConfig(name="reuse-b", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        assert first.stat().st_mtime_ns == stamp
        assert certificate_fingerprint(str(first)) == fingerprint

    @pytest.mark.asyncio
    async def test_tls_off_leaves_the_agent_plaintext(self, config, audit):
        builder = PayloadBuilder(config, audit)
        meta = await builder.build(
            PayloadConfig(name="no-tls", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        code = Path(meta.artifact_path).read_text(encoding="utf-8")
        assert "TLS_ON = False" in code
        assert "BEGIN CERTIFICATE" not in code
        # Opting out is allowed; doing it quietly is not. This line is what the
        # operator sees in the build log.
        assert any("plaintext" in line.lower() for line in meta.build_log)

    @pytest.mark.asyncio
    async def test_a_build_that_says_nothing_about_tls_is_encrypted(
        self, tmp_path, audit
    ):
        """The default has to be the secure one, not merely documented as such.

        A config that never mentions TLS is what a fresh install runs, so this is
        the one case where an operator cannot be blamed for not reading anything.
        """
        cfg = ConfigManager()
        cfg.set("paths.payload_artifacts", str(tmp_path))
        cfg.set("server.agent_auth_file", str(tmp_path / "enrollment.key"))
        cfg.set("server.tls_cert", str(tmp_path / "default.crt"))
        cfg.set("server.tls_key", str(tmp_path / "default.key"))

        builder = PayloadBuilder(cfg, audit)
        meta = await builder.build(
            PayloadConfig(name="by-default", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        code = Path(meta.artifact_path).read_text(encoding="utf-8")
        assert "TLS_ON = True" in code
        assert "BEGIN CERTIFICATE" in code
        assert (tmp_path / "default.crt").exists()


# ─── Enrollment Secret Tests ─────────────────────────────────────


class TestEnrollmentSecretIsBakedIn:
    """A payload is admitted to the listener only if it carries this server's
    secret, so the builder and the transport manager have to read one value. If
    they each invent their own, every payload is refused and nothing says so.
    """

    @pytest.fixture
    def auth_config(self, config, tmp_path):
        config.set("server.agent_auth_file", str(tmp_path / "team.key"))
        return config

    @pytest.mark.asyncio
    async def test_build_compiles_in_the_secret_the_listener_checks(
        self, auth_config, audit, tmp_path
    ):
        from pupyteer.server.core.enrollment import listener_secret

        builder = PayloadBuilder(auth_config, audit)
        meta = await builder.build(
            PayloadConfig(name="auth-baked", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())

        # The file is the listener's view, created by this build.
        assert (tmp_path / "team.key").exists()
        expected = listener_secret(auth_config.get)
        assert _load_agent(Path(meta.artifact_path)).AUTH_SECRET == expected

    @pytest.mark.asyncio
    async def test_a_second_build_reuses_the_secret(self, auth_config, audit, tmp_path):
        """A new secret strands every payload built before it, quietly."""
        from pupyteer.server.core.enrollment import listener_secret

        builder = PayloadBuilder(auth_config, audit)
        first = tmp_path / "team.key"
        await builder.build(
            PayloadConfig(name="reuse-c", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        stamp, secret = first.stat().st_mtime_ns, listener_secret(auth_config.get)

        await builder.build(
            PayloadConfig(name="reuse-d", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        assert first.stat().st_mtime_ns == stamp
        assert listener_secret(auth_config.get) == secret

    @pytest.mark.asyncio
    async def test_auth_off_builds_an_agent_with_nothing_to_present(
        self, auth_config, audit
    ):
        auth_config.set("server.agent_auth", False)
        builder = PayloadBuilder(auth_config, audit)
        meta = await builder.build(
            PayloadConfig(name="open-build", payload_type=PayloadType.SCRIPT),
            builder.generate_payload_id())
        assert _load_agent(Path(meta.artifact_path)).AUTH_SECRET == ""
