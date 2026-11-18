"""`payload_id` on the wire: what makes the capability claim check real.

The listener has held a registration to its build manifest since the manifest
existed, but no agent ever sent the `payload_id` it needed to look the build up,
so the branch was unreachable and every claim was taken on faith. These tests
cover the id reaching the wire from both agents and the gate it unlocks.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig
from pupyteer.payloads.manager import (
    PayloadBuilder, PayloadConfig, PayloadMetadata, PayloadStore,
)
from pupyteer.payloads.manager import PayloadArch, PayloadPlatform, PayloadType
from pupyteer.payloads.pe_builder import PEBuilder
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.transports.listener import AgentListener


class _Audit:
    def __init__(self):
        self.events = []

    def log_event(self, *args, **kwargs):
        self.events.append((args, kwargs))


@pytest.fixture
def audit():
    return _Audit()


@pytest.fixture
def store(tmp_path):
    config = ConfigManager()
    config._config["paths"]["payload_artifacts"] = str(tmp_path / "artifacts")
    return PayloadStore(config, _Audit())


def _manifest(payload_id, capabilities):
    return PayloadMetadata(payload_id=payload_id, name="m",
                           capabilities=list(capabilities))


class TestTheIdReachesTheWire:
    def test_a_script_payload_compiles_its_id_in(self, tmp_path):
        code = AgentStubGenerator().generate(StubConfig(
            name="pid", transport="tcp", host="127.0.0.1", port=8443,
            sleep=1, jitter=0, payload_id="pl-abc123"))
        assert '_PAYLOAD_ID = "pl-abc123"' in code
        # Both register paths have to name it: the beacon loop and the signed
        # listener client are separate implementations of the same handshake.
        assert code.count('"payload_id": _PAYLOAD_ID') == 2

    def test_a_payload_without_an_id_still_builds(self):
        """Built before the field existed, or by a caller that never set it."""
        code = AgentStubGenerator().generate(StubConfig(
            name="pid", transport="tcp", host="127.0.0.1", port=8443,
            sleep=1, jitter=0))
        assert '_PAYLOAD_ID = ""' in code

    def test_the_pe_template_carries_the_id(self, tmp_path):
        config = ConfigManager()
        config._config["paths"]["payload_artifacts"] = str(tmp_path / "artifacts")
        builder = PEBuilder(config, _Audit())
        source = builder._render(builder._load_template(), StubConfig(
            name="pid", transport="tcp", host="127.0.0.1", port=8443,
            sleep=1, jitter=0, payload_id="pl-abc123"))
        assert '#define AGENT_PAYLOAD_ID "pl-abc123"' in source
        assert '\\"payload_id\\":\\"%s\\"' in source

    def test_an_id_that_cannot_sit_in_a_c_string_refuses(self):
        builder = PEBuilder(ConfigManager(), _Audit())
        with pytest.raises(ValueError, match="cannot be compiled"):
            builder._render(builder._load_template(), StubConfig(
                name="pid", transport="tcp", host="127.0.0.1", port=8443,
                sleep=1, jitter=0, payload_id='pl-has"quote'))

    def test_build_passes_the_id_to_both_agents(self, tmp_path):
        """The builder is the only place that knows the id, so it has to hand it on."""
        config = ConfigManager()
        config._config["paths"]["payload_artifacts"] = str(tmp_path / "artifacts")
        builder = PayloadBuilder(config, _Audit())
        pcfg = PayloadConfig(name="pid", platform=PayloadPlatform.LINUX,
                             arch=PayloadArch.X64, payload_type=PayloadType.SCRIPT,
                             transport="tcp", host="127.0.0.1", port=8443,
                             sleep=1, jitter=0)

        import asyncio
        meta = asyncio.run(builder.build(pcfg, payload_id="pl-builds00001"))
        assert meta.status != "failed", meta.build_log
        source = Path(meta.artifact_path).read_text(encoding="utf-8")
        assert '_PAYLOAD_ID = "pl-builds00001"' in source

    def test_the_register_message_actually_carries_it(self, tmp_path):
        """The wire is the contract, so read the message rather than the source.

        A generated agent that renders the id into a constant but forgets it in
        the register would pass a source-level check and still leave the gate
        unreachable — which is exactly how this feature shipped broken.
        """
        import importlib.util

        if sys.platform.startswith("win"):
            platform = "windows"
        elif sys.platform == "darwin":
            platform = "macos"
        else:
            platform = "linux"

        path = tmp_path / "pid_wire.py"
        path.write_text(AgentStubGenerator().generate(StubConfig(
            name="pid", transport="tcp", host="127.0.0.1", port=8443,
            sleep=1, jitter=0, auth_secret="0" * 32, platform=platform,
            payload_id="pl-wire0000001")), encoding="utf-8")

        spec = importlib.util.spec_from_file_location("pid_wire", str(path))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        captured = {}

        class _Recorder:
            def request(self, msg):
                captured.update(msg)
                return {"type": "registered", "session_id": "s-1",
                        "beacon_token": "beacon-1"}

        assert module._register(_Recorder()) == ("s-1", "beacon-1")
        assert captured["payload_id"] == "pl-wire0000001"


class TestTheClaimGateItUnlocks:
    @pytest.fixture
    def listener(self, store, audit):
        return AgentListener({"host": "127.0.0.1", "port": 0}, None, audit,
                             payload_store=store)

    @pytest.mark.asyncio
    async def test_an_overclaim_is_downgraded_to_the_manifest(self, store, listener, audit):
        """The whole point: a payload cannot grant itself a permission.

        A refused command never leaves the server, so an over-claim that is
        trusted produces output an operator reads as the target's answer. The
        manifest is the only account of what the binary actually carries.
        """
        store.add(_manifest("pl-shipped0001", ["exec", "ping"]))
        captured = {}

        class _SM:
            async def register(self, info):
                captured["info"] = info
                return info.session_id
        listener._session_manager = _SM()

        await listener._handle_register({
            "type": "register", "hostname": "h", "os": "linux",
            "capabilities": ["exec", "ping", "screenshot"],
            "payload_id": "pl-shipped0001",
        }, "127.0.0.1:1", None)

        assert captured["info"].payload_id == "pl-shipped0001"
        assert captured["info"].capabilities == ["exec", "ping"]
        mismatches = [e for e in audit.events
                      if e[0] and e[0][0] == "session_capability_mismatch"]
        assert mismatches, "an over-claim has to be audited, not applied silently"

    @pytest.mark.asyncio
    async def test_a_claim_within_the_manifest_is_left_alone(self, store, listener):
        store.add(_manifest("pl-shipped0002", ["exec", "ping", "screenshot"]))
        captured = {}

        class _SM:
            async def register(self, info):
                captured["info"] = info
                return info.session_id
        listener._session_manager = _SM()
        await listener._handle_register({
            "type": "register", "hostname": "h", "os": "linux",
            "capabilities": ["exec", "ping", "screenshot"], "payload_id": "pl-shipped0002",
        }, "127.0.0.1:1", None)
        assert captured["info"].capabilities == ["exec", "ping", "screenshot"]

    @pytest.mark.asyncio
    async def test_an_unknown_id_is_not_downgraded(self, store, listener, audit):
        """No manifest for it: nothing to check the claim against, so the claim
        stands exactly as it did before the field existed."""
        captured = {}

        class _SM:
            async def register(self, info):
                captured["info"] = info
                return info.session_id
        listener._session_manager = _SM()
        await listener._handle_register({
            "type": "register", "hostname": "h", "os": "linux",
            "capabilities": ["exec", "screenshot"], "payload_id": "pl-never-built",
        }, "127.0.0.1:1", None)
        assert captured["info"].capabilities == ["exec", "screenshot"]

    @pytest.mark.asyncio
    async def test_a_payload_with_no_id_is_not_downgraded(self, store, listener):
        captured = {}

        class _SM:
            async def register(self, info):
                captured["info"] = info
                return info.session_id
        listener._session_manager = _SM()
        await listener._handle_register({
            "type": "register", "hostname": "h", "os": "linux",
            "capabilities": ["exec", "screenshot"],
        }, "127.0.0.1:1", None)
        assert captured["info"].capabilities == ["exec", "screenshot"]
        assert captured["info"].payload_id == ""
