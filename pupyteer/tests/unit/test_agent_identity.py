"""Per-agent identity: minted at build, verified at registration, revocable.

The machinery for this existed and was dead on the build path — `_mint_agent_identity`
had no callers and the CLI built with no registry, so every payload enrolled with
the shared secret and the Ed25519 handshake was never exercised by anything an
operator could run. These tests hold the whole chain: build -> registry ->
registration -> revocation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.payloads.manager import PayloadBuilder, PayloadConfig, PayloadType
from pupyteer.payloads.manager import PayloadArch, PayloadPlatform
from pupyteer.server.core.agent_keys import AgentKeyRegistry, sign_payload
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.transports.listener import AgentListener


class _Audit:
    def __init__(self):
        self.events = []

    def log_event(self, *args, **kwargs):
        self.args = args
        self.kwargs = kwargs
        self.events.append((args, kwargs))


@pytest.fixture
def registry():
    return AgentKeyRegistry()


@pytest.fixture
def audit():
    return _Audit()


def _build(config, audit, registry=None, name="ident-agent"):
    builder = PayloadBuilder(config, audit, agent_keys=registry)
    pcfg = PayloadConfig(
        name=name,
        platform=PayloadPlatform.LINUX,
        arch=PayloadArch.X64,
        payload_type=PayloadType.SCRIPT,
        transport="tcp",
        host="127.0.0.1",
        port=8443,
        sleep=1,
        jitter=0,
    )
    return builder, pcfg


class TestBuildMintsAnIdentity:
    def test_a_build_with_a_registry_embeds_one_identity(self, registry, audit, tmp_path):
        """The private half goes into the payload, the public half stays here."""
        config = ConfigManager()
        config._config["paths"]["payload_artifacts"] = str(tmp_path / "artifacts")
        builder, pcfg = _build(config, audit, registry)

        import asyncio
        meta = asyncio.run(builder.build(pcfg, payload_id="pid-identity-1"))

        assert meta.status != "failed", meta.build_log
        agent = (tmp_path / "artifacts" / "pid-identity-1" / f"{pcfg.name}_linux_x64.py")
        assert agent.exists(), meta.build_log
        source = agent.read_text(encoding="utf-8")
        assert "_AGENT_ID" in source
        # The id is rendered in, and so is a PEM private key — the payload can
        # sign without the server ever holding the private half.
        import re
        rendered = re.search(r'_AGENT_ID = "([^"]*)"', source)
        assert rendered and rendered.group(1), "no agent id compiled in"
        assert "BEGIN PRIVATE KEY" in source
        assert registry.is_known(rendered.group(1))

    def test_a_build_without_a_registry_is_unchanged(self, audit, tmp_path):
        """No registry means the legacy shared-secret path, exactly as before."""
        config = ConfigManager()
        config._config["paths"]["payload_artifacts"] = str(tmp_path / "artifacts")
        builder, pcfg = _build(config, audit, None)

        import asyncio
        meta = asyncio.run(builder.build(pcfg, payload_id="pid-legacy-1"))
        assert meta.status != "failed", meta.build_log
        agent = (tmp_path / "artifacts" / "pid-legacy-1" / f"{pcfg.name}_linux_x64.py")
        source = agent.read_text(encoding="utf-8")
        import re
        assert re.search(r'_AGENT_ID = ""', source)

    def test_the_identity_is_recorded_against_the_build(self, registry, audit, tmp_path):
        config = ConfigManager()
        config._config["paths"]["payload_artifacts"] = str(tmp_path / "artifacts")
        builder, pcfg = _build(config, audit, registry)
        import asyncio
        meta = asyncio.run(builder.build(pcfg, payload_id="pid-record-1"))
        assert meta.config.get("agent_id")
        assert registry.is_known(meta.config["agent_id"])


class TestRegistrationUsesIt:
    @pytest.fixture
    def listener(self, registry, audit):
        return AgentListener({"host": "127.0.0.1", "port": 0}, None, audit,
                             agent_keys=registry)

    @pytest.mark.asyncio
    async def test_a_minted_payload_registers_and_is_attributed(self, registry, listener):
        """The signed handshake, end to end, and the session names the agent."""
        pair = registry.generate()
        base = {"type": "register", "agent_id": pair.agent_id,
                "hostname": "host", "os": "linux", "arch": "x64",
                "username": "user", "capabilities": ["exec", "ping"]}

        first = await listener._handle_register(dict(base), "127.0.0.1:1", None)
        assert first["type"] == "challenge", first

        second = dict(base)
        second["nonce"] = first["nonce"]
        second["signature"] = sign_payload(pair.priv_pem, first["nonce"])
        # _handle_register builds a SessionInfo; stand in a manager that keeps it.
        class _SM:
            def __init__(self):
                self.seen = None

            async def register(self, info):
                self.seen = info
                return info.session_id
        listener._session_manager = _SM()
        done = await listener._handle_register(second, "127.0.0.1:1", None)
        assert done["type"] == "registered", done
        assert listener._session_manager.seen.agent_id == pair.agent_id

    @pytest.mark.asyncio
    async def test_a_revoked_identity_is_refused(self, registry, listener):
        pair = registry.generate()
        assert registry.revoke(pair.agent_id) is True
        base = {"type": "register", "agent_id": pair.agent_id,
                "hostname": "host", "os": "linux", "capabilities": ["exec"]}
        # Unknown to the registry, so there is no challenge to answer: the
        # registration is turned away rather than silently downgraded.
        refused = await listener._handle_register(dict(base), "127.0.0.1:1", None)
        assert refused.get("message") == "auth_failed", refused

    @pytest.mark.asyncio
    async def test_a_forged_signature_is_refused(self, registry, listener):
        pair = registry.generate()
        base = {"type": "register", "agent_id": pair.agent_id,
                "hostname": "host", "os": "linux", "capabilities": ["exec"]}
        first = await listener._handle_register(dict(base), "127.0.0.1:1", None)
        forged = dict(base)
        forged["nonce"] = first["nonce"]
        forged["signature"] = "00" * 64
        refused = await listener._handle_register(forged, "127.0.0.1:1", None)
        assert refused.get("message") == "auth_failed", refused


class TestTheRegistrySurvivesARestart:
    def test_what_a_build_minted_the_next_engine_trusts(self, tmp_path):
        """An identity that lives only in memory strands the payload it was issued to.

        The payload still presents its agent_id after a restart; if the registry
        has forgotten the public key, that registration cannot be verified and
        is refused — a payload bricked by a reboot, with nothing at build time
        saying so. The builder cannot write the registry itself, so the caller
        hands it a store to invoke once a key is minted.
        """
        import asyncio
        import json

        path = tmp_path / "agent_keys.json"
        registry = AgentKeyRegistry()
        saved = {}

        def store():
            path.write_text(json.dumps(registry.to_dict()), encoding="utf-8")
            saved["count"] = len(registry.agents())

        class _Cfg:
            def get(self, key, default=None):
                if key == "security.agent_keys_file":
                    return str(path)
                if key == "paths.payload_artifacts":
                    return str(tmp_path / "artifacts")
                return default

        builder = PayloadBuilder(_Cfg(), _Audit(), agent_keys=registry,
                                 identity_store=store)
        pcfg = PayloadConfig(name="persist", platform=PayloadPlatform.LINUX,
                             arch=PayloadArch.X64, payload_type=PayloadType.SCRIPT,
                             transport="tcp", host="127.0.0.1", port=8443,
                             sleep=1, jitter=0)
        meta = asyncio.run(builder.build(pcfg, payload_id="pid-persist"))
        assert meta.status != "failed", meta.build_log

        assert saved.get("count") == 1, "the minted key was never handed to the store"
        reloaded = AgentKeyRegistry()
        reloaded.load_from_dict(json.loads(path.read_text(encoding="utf-8")))
        assert reloaded.agents() == registry.agents()
        assert reloaded.is_known(meta.config["agent_id"])

    def test_engine_save_agent_keys_round_trips(self, tmp_path):
        import asyncio

        class _Cfg:
            def __init__(self, path):
                self._p = path

            def get(self, key, default=None):
                if key == "security.agent_keys_file":
                    return str(self._p)
                return default

        path = tmp_path / "keys.json"
        engine = PupyteerEngine()
        engine._config._config["security"]["agent_keys_file"] = str(path)
        pair = engine.agent_keys.generate()
        engine.save_agent_keys()
        assert path.exists()

        other = PupyteerEngine()
        other._config._config["security"]["agent_keys_file"] = str(path)
        other._load_agent_keys(str(path))
        assert other.agent_keys.is_known(pair.agent_id)


class TestHttpListenerIsNotTheWeakDoor:
    def test_the_http_listener_gets_the_registry_and_the_acl(self, registry):
        """An HTTP registration is the same registration.

        The HTTP listener used to be built without the registry or the payload
        store, so it admitted payloads the TCP listener would have refused and
        skipped manifest verification entirely.
        """
        from pupyteer.server.transports.http_listener import HTTPListener

        http = HTTPListener({"host": "127.0.0.1", "port": 0, "uri": "/",
                             "allowed_cidrs": ["10.0.0.0/8"]},
                            None, _Audit(), agent_keys=registry, payload_store=object())
        assert http._agent_keys is registry
        assert http._payload_store is not None
        assert http._allowed_cidrs == ["10.0.0.0/8"]
