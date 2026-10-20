"""Tests for the anti-forensics modules (lab-only, safeguarded).

These modules destroy evidence on a host (clear logs, timestomp, wipe
artifacts, delete prefetch, empty recycle bin). They are shipped disabled
by default and require an explicit opt-in, mirroring the TriGlyph 'unsafe
writes' guard.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.modules.registry import ModuleCategory, ModuleRegistry


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


class FakeSession:
    session_id = "sess-af"
    os = "linux"


class TestAntiForensicsCategory:
    def test_category_exists(self):
        assert ModuleCategory.ANTI_FORENSICS.value == "anti_forensics"

    def test_all_five_modules_discoverable(self, config, audit):
        reg = ModuleRegistry(config, audit)
        reg.discover()
        for name in ("log_clear", "timestamp_match", "artifact_wipe",
                     "prefetch_delete", "recycle_clear"):
            assert name in reg._modules, f"{name} not discovered"


class TestAntiForensicsSafeguard:
    """Disabled by default; must refuse to run unless explicitly armed."""

    @pytest.mark.asyncio
    async def test_log_clear_refuses_when_disabled(self, config, audit):
        reg = ModuleRegistry(config, audit)
        reg.discover()
        mod = reg.create("log_clear")
        mod._session_manager = None
        result = await mod.execute(FakeSession(), {})
        assert result["status"] == "error"
        msg = (result.get("error") or "").lower()
        assert "disabled" in msg or "lab" in msg or "unsafe" in msg

    @pytest.mark.asyncio
    async def test_timestamp_match_refuses_when_disabled(self, config, audit):
        reg = ModuleRegistry(config, audit)
        reg.discover()
        mod = reg.create("timestamp_match")
        mod._session_manager = None
        result = await mod.execute(FakeSession(), {
            "target_file": "/tmp/a", "reference_file": "/tmp/b",
        })
        assert result["status"] == "error"
        msg = (result.get("error") or "").lower()
        assert "disabled" in msg or "lab" in msg or "unsafe" in msg

    @pytest.mark.asyncio
    async def test_log_clear_runs_when_armed(self, config, audit):
        config.set("anti_forensics.enabled", True)
        reg = ModuleRegistry(config, audit)
        reg.discover()
        mod = reg.create("log_clear")
        mod._session_manager = None
        result = await mod.execute(FakeSession(), {})
        # offline mode (no session manager) returns the command it would run
        assert result["status"] == "ok"
        assert "command" in result

    @pytest.mark.asyncio
    async def test_artifact_wipe_runs_when_armed(self, config, audit):
        config.set("anti_forensics.enabled", True)
        reg = ModuleRegistry(config, audit)
        reg.discover()
        mod = reg.create("artifact_wipe")
        mod._session_manager = None
        result = await mod.execute(FakeSession(), {"file_path": "/tmp/x"})
        assert result["status"] == "ok"
        assert "command" in result
