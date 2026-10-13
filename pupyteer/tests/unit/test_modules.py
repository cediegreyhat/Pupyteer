"""Unit tests for Pupyteer module system — registry, discovery, lifecycle, validation."""
import asyncio
import base64
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.modules.registry import (
    PupyModule,
    ModuleRegistry,
    ModuleCategory,
    ModuleRequirement,
    ModuleState,
    ModuleHealth,
)
from pupyteer.server.sessions import capabilities, transfer


# ─── Fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def config():
    return ConfigManager()


@pytest.fixture
def audit(config):
    return AuditLogger(config)


@pytest.fixture
def registry(config, audit):
    return ModuleRegistry(config, audit)


# ─── ModuleCategory Tests ────────────────────────────────────────────


class TestModuleCategory:
    def test_core_value(self):
        assert ModuleCategory.CORE.value == "core"

    def test_recon_value(self):
        assert ModuleCategory.RECON.value == "recon"

    def test_execution_value(self):
        assert ModuleCategory.EXECUTION.value == "execution"

    def test_file_ops_value(self):
        assert ModuleCategory.FILE_OPS.value == "file_ops"

    def test_red_team_value(self):
        assert ModuleCategory.RED_TEAM.value == "red_team"

    def test_evasion_value(self):
        assert ModuleCategory.EVASION.value == "evasion"

    def test_all_spec_categories_present(self):
        values = {c.value for c in ModuleCategory}
        expected = {"core", "recon", "execution", "file_ops", "red_team", "evasion"}
        assert values == expected


# ─── ModuleRequirement Tests ─────────────────────────────────────────


class TestModuleRequirement:
    def test_basic_creation(self):
        req = ModuleRequirement("os")
        assert req.name == "os"
        assert req.version == ""
        assert req.optional is False

    def test_satisfied_by_present(self):
        req = ModuleRequirement("os")
        assert req.satisfied_by({"os": "1.0"}) is True

    def test_satisfied_by_missing_required(self):
        req = ModuleRequirement("os")
        assert req.satisfied_by({}) is False

    def test_satisfied_by_missing_optional(self):
        req = ModuleRequirement("os", optional=True)
        assert req.satisfied_by({}) is True

    def test_satisfied_by_version_match(self):
        req = ModuleRequirement("os", version="1.0")
        assert req.satisfied_by({"os": "1.0"}) is True

    def test_satisfied_by_version_mismatch(self):
        req = ModuleRequirement("os", version="1.0")
        assert req.satisfied_by({"os": "2.0"}) is False


# ─── PupyModule ABC Tests ────────────────────────────────────────────


class TestPupyModuleInterface:
    def test_cannot_instantiate_abstract(self):
        with pytest.raises(TypeError):
            PupyModule(ConfigManager(), AuditLogger(ConfigManager()))

    def test_concrete_subclass_can_be_instantiated(self):
        class MyModule(PupyModule):
            name = "test"
            version = "0.1"
            description = "test module"
            author = "tester"
            category = ModuleCategory.CORE

            async def execute(self, session, args):
                return {"status": "ok"}

        m = MyModule(ConfigManager(), AuditLogger(ConfigManager()))
        assert m.name == "test"
        assert m.version == "0.1"

    def test_get_info_returns_expected_keys(self):
        class InfoModule(PupyModule):
            name = "info_test"
            version = "2.0"
            description = "info test"
            author = "tester"
            category = ModuleCategory.RECON
            requirements = [ModuleRequirement("os")]

            async def execute(self, session, args):
                return {"status": "ok"}

        m = InfoModule(ConfigManager(), AuditLogger(ConfigManager()))
        info = m.get_info()
        assert info["name"] == "info_test"
        assert info["version"] == "2.0"
        assert info["description"] == "info test"
        assert info["author"] == "tester"
        assert info["category"] == "recon"
        assert "os" in info["requirements"]

    def test_is_compatible_with_all_platforms(self):
        class AllModule(PupyModule):
            name = "all_compat"
            compatible_systems = []

            async def execute(self, session, args):
                return {"status": "ok"}

        m = AllModule(ConfigManager(), AuditLogger(ConfigManager()))
        assert m.is_compatible_with("windows") is True
        assert m.is_compatible_with("linux") is True
        assert m.is_compatible_with("darwin") is True

    def test_is_compatible_with_specific_platform(self):
        class WinModule(PupyModule):
            name = "win_only"
            compatible_systems = ["windows"]

            async def execute(self, session, args):
                return {"status": "ok"}

        m = WinModule(ConfigManager(), AuditLogger(ConfigManager()))
        assert m.is_compatible_with("windows") is True
        assert m.is_compatible_with("linux") is False

    def test_is_compatible_with_arch(self):
        class ArchModule(PupyModule):
            name = "arch_specific"
            compatible_systems = ["linux_x64"]

            async def execute(self, session, args):
                return {"status": "ok"}

        m = ArchModule(ConfigManager(), AuditLogger(ConfigManager()))
        assert m.is_compatible_with("linux", "x64") is True
        assert m.is_compatible_with("linux", "x86") is False

    def test_validate_args_default_returns_empty(self):
        class NoArgsModule(PupyModule):
            name = "no_args"

            async def execute(self, session, args):
                return {"status": "ok"}

        m = NoArgsModule(ConfigManager(), AuditLogger(ConfigManager()))
        assert m.validate_args({}) == []

    def test_cleanup_default_does_nothing(self):
        class CleanupModule(PupyModule):
            name = "cleanup_test"

            async def execute(self, session, args):
                return {"status": "ok"}

        m = CleanupModule(ConfigManager(), AuditLogger(ConfigManager()))
        # Should not raise
        asyncio.run(m.cleanup())

    def test_health_returns_snapshot(self):
        class HealthModule(PupyModule):
            name = "health_test"

            async def execute(self, session, args):
                return {"status": "ok"}

        m = HealthModule(ConfigManager(), AuditLogger(ConfigManager()))
        h = m.health()
        assert h.name == "health_test"
        assert h.state == ModuleState.REGISTERED

    def test_subclasses_get_own_requirements_list(self):
        """Ensure __init_subclass__ properly isolates requirements lists."""
        class ModA(PupyModule):
            name = "mod_a"
            requirements = [ModuleRequirement("os")]

            async def execute(self, session, args):
                return {"status": "ok"}

        class ModB(PupyModule):
            name = "mod_b"
            requirements = []

            async def execute(self, session, args):
                return {"status": "ok"}

        assert ModA.requirements is not ModB.requirements
        assert len(ModA.requirements) == 1
        assert len(ModB.requirements) == 0


# ─── ModuleRegistry Discovery Tests ──────────────────────────────────


class TestModuleRegistry:
    def test_discover_returns_positive_count(self, registry):
        count = registry.discover()
        assert count > 0

    def test_discover_registers_sysinfo(self, registry):
        registry.discover()
        assert "sysinfo" in registry

    def test_discover_registers_exec(self, registry):
        registry.discover()
        assert "exec" in registry

    def test_discover_registers_upload(self, registry):
        registry.discover()
        assert "upload" in registry

    def test_discover_registers_download(self, registry):
        registry.discover()
        assert "download" in registry

    def test_discover_registers_file_list(self, registry):
        registry.discover()
        assert "file_list" in registry

    def test_discover_registers_discovery(self, registry):
        registry.discover()
        assert "discovery" in registry

    def test_discover_registers_credential_collect(self, registry):
        registry.discover()
        assert "credential_collect" in registry

    def test_discover_registers_lateral_sim(self, registry):
        registry.discover()
        assert "lateral_sim" in registry

    def test_discover_registers_assess(self, registry):
        registry.discover()
        assert "assess" in registry

    def test_discover_registers_evasion_test(self, registry):
        registry.discover()
        assert "evasion_test" in registry

    def test_count_matches_discover(self, registry):
        count = registry.discover()
        assert registry.count() == count

    def test_list_all_returns_list_of_dicts(self, registry):
        registry.discover()
        all_modules = registry.list_all()
        assert isinstance(all_modules, list)
        assert len(all_modules) > 0
        for m in all_modules:
            assert "name" in m
            assert "category" in m

    def test_list_by_category_recon(self, registry):
        registry.discover()
        recon = registry.list_by_category(ModuleCategory.RECON)
        assert len(recon) > 0
        for m in recon:
            assert m["category"] == "recon"

    def test_list_by_category_execution(self, registry):
        registry.discover()
        execution = registry.list_by_category(ModuleCategory.EXECUTION)
        assert len(execution) > 0
        for m in execution:
            assert m["category"] == "execution"

    def test_list_by_category_file_ops(self, registry):
        registry.discover()
        file_ops = registry.list_by_category(ModuleCategory.FILE_OPS)
        assert len(file_ops) > 0
        for m in file_ops:
            assert m["category"] == "file_ops"

    def test_list_by_category_red_team(self, registry):
        registry.discover()
        red_team = registry.list_by_category(ModuleCategory.RED_TEAM)
        assert len(red_team) > 0
        for m in red_team:
            assert m["category"] == "red_team"

    def test_list_compatible_all_platforms(self, registry):
        registry.discover()
        compatible = registry.list_compatible("windows")
        assert len(compatible) > 0

    def test_list_compatible_linux(self, registry):
        registry.discover()
        compatible = registry.list_compatible("linux")
        assert len(compatible) > 0

    def test_list_categories_returns_sorted_unique(self, registry):
        registry.discover()
        cats = registry.list_categories()
        assert "core" in cats or "recon" in cats
        assert cats == sorted(cats)

    def test_get_returns_class(self, registry):
        registry.discover()
        cls = registry.get("sysinfo")
        assert cls is not None
        assert issubclass(cls, PupyModule)

    def test_get_nonexistent_returns_none(self, registry):
        registry.discover()
        assert registry.get("nonexistent_module_xyz") is None

    def test_create_returns_instance(self, registry):
        registry.discover()
        instance = registry.create("sysinfo")
        assert instance is not None
        assert isinstance(instance, PupyModule)

    def test_create_nonexistent_returns_none(self, registry):
        registry.discover()
        assert registry.create("nonexistent") is None

    def test_len_matches_count(self, registry):
        registry.discover()
        assert len(registry) == registry.count()


# ─── ModuleRegistry Execution Tests ──────────────────────────────────


class TestModuleExecution:
    """What a module answers, and whether it actually asked the agent.

    A module that returns a well-shaped empty result for work it never did is the
    failure mode these tests exist to catch: the operator sees "ok" and believes a
    file landed. So every dispatching module is checked twice — once with no way to
    reach the agent, which must be an error, and once against a session manager
    that records what was queued.
    """

    @staticmethod
    def _session(session_id: str = "sess-1") -> Any:
        return type(
            "Session", (),
            {"session_id": session_id, "hostname": "test-host", "os": "linux",
             "arch": "x64", "username": "root", "remote_address": "127.0.0.1:1",
             "connected_at": 0, "last_checkin": 0},
        )()

    @staticmethod
    def _agent(answers: Dict[str, Any]) -> Any:
        """A session manager that completes every command with `answers`.

        `answers` maps a queued command line to the result string, falling back to
        ``answers["*"]``, so a test can assert on the exact task a module built.
        """
        queued: list = []

        class _Stub:
            async def get(self, session_id: str):
                # A real session answers this, and the transfer loop asks it how
                # long a line the agent reads before sizing a chunk. 0 is the
                # undeclared answer, which is the conservative one.
                return type("Session", (), {"session_id": session_id,
                                            "max_line": 0})()

            async def interact(self, session_id: str, command: str) -> str:
                command_id = f"cmd-{len(queued)}"
                queued.append({"command_id": command_id, "command": command,
                               "status": "queued", "result": None})
                return command_id

            async def get_pending_commands(self, session_id: str) -> list:
                for entry in queued:
                    if entry["status"] == "queued":
                        answer = answers.get(entry["command"], answers.get("*", ""))
                        entry["status"] = "completed"
                        entry["result"] = answer if isinstance(answer, str) \
                            else json.dumps(answer)
                return queued

        stub = _Stub()
        stub.queued = queued
        return stub

    @pytest.mark.asyncio
    async def test_execute_sysinfo(self, registry):
        registry.discover()
        session = self._session()
        result = await registry.execute(
            "sysinfo", session, {}, session_manager=self._agent({}))
        assert result["status"] == "ok"
        assert result["data"]["hostname"] == "test-host"

    @pytest.mark.asyncio
    async def test_execute_exec_dispatches_to_the_agent(self, registry):
        registry.discover()
        agent = self._agent({"whoami": "root"})
        result = await registry.execute(
            "exec", self._session(), {"command": "whoami"}, session_manager=agent)
        assert result["status"] == "ok"
        assert result["output"] == "root"
        assert agent.queued[0]["command"] == "whoami"

    @pytest.mark.asyncio
    async def test_execute_exec_without_an_agent_is_an_error(self, registry):
        """The command is not dispatched without a session manager, and must not
        come back looking like it ran.
        """
        registry.discover()
        result = await registry.execute("exec", self._session(), {"command": "whoami"})
        assert result["status"] == "error"
        assert "nothing was sent" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_exec_missing_command(self, registry):
        registry.discover()
        result = await registry.execute("exec", None, {})
        assert result["status"] == "error"
        assert "command" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_a_dead_session_is_not_reported_as_a_slow_agent(self, registry):
        """`interact` refuses to queue for a session that is gone. Spending the
        whole timeout before saying "timed out" sends the operator chasing a
        beaconing problem that does not exist.
        """
        class _Closed:
            async def interact(self, session_id: str, command: str):
                return None

            async def get_pending_commands(self, session_id: str) -> list:
                raise AssertionError("nothing was queued, so nothing may be polled")

        registry.discover()
        started = time.monotonic()
        result = await registry.execute(
            "exec", self._session(), {"command": "whoami", "timeout": 30},
            session_manager=_Closed())
        assert result["status"] == "error"
        assert "would not accept a command" in result["error"]
        assert "timed out" not in result["error"]
        assert time.monotonic() - started < 1.0, "the module waited out a dead session"

    @pytest.mark.asyncio
    async def test_a_silent_agent_says_so_with_the_command_it_asked_about(self, registry):
        class _NeverAnswers:
            async def interact(self, session_id: str, command: str) -> str:
                return "cmd-dead"

            async def get_pending_commands(self, session_id: str) -> list:
                return []

        registry.discover()
        result = await registry.execute(
            "exec", self._session(), {"command": "whoami", "timeout": 0.2},
            session_manager=_NeverAnswers())
        assert result["status"] == "error"
        assert "timed out" in result["error"]
        assert result["command_id"] == "cmd-dead"

    @pytest.mark.asyncio
    async def test_execute_upload_streams_the_file(self, registry, tmp_path):
        registry.discover()
        source = tmp_path / "source.txt"
        source.write_bytes(b"x" * 1024)
        target = tmp_path / "landed" / "on-target.txt"
        agent = self._agent({"*": {"ok": True, "written": 1024}})
        result = await registry.execute(
            "upload", self._session(),
            {"local_path": str(source), "remote_path": str(target)},
            session_manager=agent)
        assert result["status"] == "ok"
        assert result["bytes_transferred"] == 1024
        task = json.loads(agent.queued[0]["command"])
        assert task["action"] == "fs_put"
        assert task["path"] == str(target)
        assert base64.b64decode(task["data"]) == b"x" * 1024

    @pytest.mark.asyncio
    async def test_execute_upload_reports_what_never_arrived(self, registry, tmp_path):
        """A refusal mid-way keeps the partial byte count: most of a file is a
        corrupt file, and an operator needs to know it is one.
        """
        registry.discover()
        source = tmp_path / "source.bin"
        source.write_bytes(b"y" * (transfer.DEFAULT_CHUNK_SIZE + 7))

        class _DiskFull:
            def __init__(self) -> None:
                self.calls = 0

            async def get(self, session_id: str):
                # The stub that declares a line this long is the Python agent, and
                # it is what lets the module keep its own chunk size, so the
                # transfer spans two chunks and the second one fails.
                return type("Session", (), {"session_id": session_id,
                                            "max_line": capabilities.MAX_LINE_CAP})()

            async def interact(self, session_id: str, command: str) -> str:
                self.calls += 1
                return f"cmd-{self.calls}"

            async def get_pending_commands(self, session_id: str) -> list:
                if self.calls < 2:
                    return [{"command_id": "cmd-1", "status": "completed",
                             "result": json.dumps({"ok": True})}]
                return [{"command_id": "cmd-2", "status": "completed",
                         "result": json.dumps({"ok": False, "error": "disk full"})}]

        result = await registry.execute(
            "upload", self._session(),
            {"local_path": str(source), "remote_path": "/tmp/x.bin"},
            session_manager=_DiskFull())
        assert result["status"] == "error"
        assert result["bytes_transferred"] == transfer.DEFAULT_CHUNK_SIZE
        assert "disk full" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_upload_missing_args(self, registry):
        registry.discover()
        result = await registry.execute("upload", None, {})
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_execute_download_reassembles_chunks(self, registry, tmp_path):
        registry.discover()
        payload = base64.b64encode(b"hello target").decode()
        agent = self._agent({"*": {"size": 12, "offset": 0, "length": 12,
                                   "eof": True, "data": payload}})
        local = tmp_path / "pulled.txt"
        result = await registry.execute(
            "download", self._session(),
            {"remote_path": "/etc/hosts", "local_path": str(local)},
            session_manager=agent)
        assert result["status"] == "ok"
        assert result["bytes_transferred"] == 12
        assert local.read_bytes() == b"hello target"
        assert json.loads(agent.queued[0]["command"])["action"] == "fs_get"

    @pytest.mark.asyncio
    async def test_execute_download_names_the_file_it_pulled(
        self, registry, tmp_path
    ):
        """No local_path is not no file: the basename comes off the target."""
        registry.discover()
        cwd = os.getcwd()
        os.chdir(tmp_path)
        try:
            result = await registry.execute(
                "download", self._session(), {"remote_path": "/var/log/app.log"},
                session_manager=self._agent(
                    {"*": {"size": 2, "eof": True,
                           "data": base64.b64encode(b"hi").decode()}}))
            assert result["status"] == "ok"
            assert Path(result["local_path"]).name == "app.log"
            assert (tmp_path / "app.log").read_bytes() == b"hi"
        finally:
            os.chdir(cwd)

    @pytest.mark.asyncio
    async def test_execute_download_of_a_missing_file_fails(
        self, registry, tmp_path
    ):
        registry.discover()
        result = await registry.execute(
            "download", self._session(),
            {"remote_path": "/nope/nope", "local_path": str(tmp_path / "out")},
            session_manager=self._agent({"*": {"error": "[Errno 2] no such file"}}))
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_execute_download_missing_args(self, registry):
        registry.discover()
        result = await registry.execute("download", None, {})
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_execute_file_list_reads_the_target(self, registry):
        registry.discover()
        entries = [{"name": "passwd", "is_file": True, "is_dir": False,
                    "size": 1200, "mtime": 1.0}]
        agent = self._agent({"*": {"path": "/etc", "entries": entries}})
        result = await registry.execute(
            "file_list", self._session(), {"path": "/etc"},
            session_manager=agent)
        assert result["status"] == "ok"
        assert result["entries"] == entries
        assert json.loads(agent.queued[0]["command"])["action"] == "fs_list"

    @pytest.mark.asyncio
    async def test_an_empty_directory_is_not_an_error(self, registry):
        registry.discover()
        result = await registry.execute(
            "file_list", self._session(), {"path": "/empty"},
            session_manager=self._agent({"*": {"path": "/empty", "entries": []}}))
        assert result["status"] == "ok"
        assert result["entries"] == []

    @pytest.mark.asyncio
    async def test_a_directory_the_agent_cannot_open_is_not_empty(
        self, registry
    ):
        """The old shape reported a failure as a listing of one entry named
        `error`, which a caller reading `entries` cannot tell from content.
        """
        registry.discover()
        result = await registry.execute(
            "file_list", self._session(), {"path": "/denied"},
            session_manager=self._agent({"*": {"error": "Permission denied"}}))
        assert result["status"] == "error"
        assert "Permission denied" in result["error"]

    @pytest.mark.asyncio
    async def test_execute_file_list_without_an_agent_is_an_error(self, registry):
        registry.discover()
        result = await registry.execute("file_list", self._session(), {"path": "/tmp"})
        assert result["status"] == "error"
        assert "entries" not in result

    @pytest.mark.asyncio
    async def test_execute_discovery_asks_the_agent(self, registry):
        registry.discover()
        # The agent renders an exec answer as stripped text, not a JSON object,
        # so this is the shape a real session returns.
        agent = self._agent({"*": "root"})
        result = await registry.execute(
            "discovery", self._session(), {"target": "whoami"},
            session_manager=agent)
        assert result["status"] == "ok"
        assert result["output"] == "root"
        dispatched = json.loads(agent.queued[0]["command"])
        assert dispatched["action"] == "exec"
        assert dispatched["command"] == "whoami"

    @pytest.mark.asyncio
    async def test_execute_discovery_without_an_agent_is_an_error(self, registry):
        registry.discover()
        result = await registry.execute(
            "discovery", self._session(), {"target": "whoami"})
        assert result["status"] == "error"

    @pytest.mark.asyncio
    async def test_execute_credential_collect(self, registry):
        registry.discover()
        result = await registry.execute("credential_collect", None, {})
        assert result["status"] == "ok"
        assert result["simulation"] is True

    @pytest.mark.asyncio
    async def test_execute_lateral_sim(self, registry):
        registry.discover()
        result = await registry.execute("lateral_sim", None, {"technique": "smb"})
        assert result["status"] == "ok"
        assert result["simulation"] is True

    @pytest.mark.asyncio
    async def test_execute_assess(self, registry):
        registry.discover()
        result = await registry.execute("assess", None, {"check": "firewall"})
        assert result["status"] == "ok"
        assert result["check"] == "firewall"

    @pytest.mark.asyncio
    async def test_execute_nonexistent_module(self, registry):
        registry.discover()
        result = await registry.execute("nonexistent", None, {})
        assert result["status"] == "error"
        assert "not found" in result["error"].lower()


class TestRegistryInjectsTheSessionManager:
    """`ModuleRegistry.execute` is the console's path into a module.

    `ModuleExecutor` injects the session manager that lets a module queue work on
    the agent; without the same on this path every module quietly answers from
    session metadata and reports success.
    """

    @pytest.mark.asyncio
    async def test_the_session_manager_reaches_the_module(self, registry):
        seen = {}

        class _Probe(PupyModule):
            name = "probe"
            version = "1.0.0"
            description = "records what it was given"
            author = "test"
            category = ModuleCategory.RECON

            async def execute(self, session, args):
                seen["manager"] = getattr(self, "_session_manager", None)
                return {"status": "ok"}

        registry._modules["probe"] = _Probe
        manager = object()
        result = await registry.execute("probe", None, {}, session_manager=manager)
        assert result["status"] == "ok"
        assert seen["manager"] is manager

    @pytest.mark.asyncio
    async def test_a_module_left_without_one_sees_nothing(self, registry):
        seen = {}

        class _Probe(PupyModule):
            name = "quiet"
            version = "1.0.0"
            description = "records what it was given"
            author = "test"
            category = ModuleCategory.RECON

            async def execute(self, session, args):
                seen["manager"] = getattr(self, "_session_manager", None)
                return {"status": "ok"}

        registry._modules["quiet"] = _Probe
        await registry.execute("quiet", None, {})
        assert seen["manager"] is None


# ─── ModuleRegistry Health Tests ─────────────────────────────────────


class TestModuleHealth:
    def test_health_recorded_on_discover(self, registry):
        registry.discover()
        health = registry.list_health()
        assert len(health) > 0
        for h in health:
            assert "name" in h
            assert "state" in h

    def test_get_health_by_name(self, registry):
        registry.discover()
        h = registry.get_health("sysinfo")
        assert h is not None
        assert h.name == "sysinfo"

    def test_get_health_nonexistent(self, registry):
        registry.discover()
        assert registry.get_health("nonexistent") is None


# ─── ModuleRegistry Load/Unload Tests ────────────────────────────────


class TestModuleLoadUnload:
    def test_unload_removes_module(self, registry):
        registry.discover()
        assert "sysinfo" in registry
        ok = registry.unload("sysinfo")
        assert ok is True
        assert "sysinfo" not in registry

    def test_unload_nonexistent_returns_false(self, registry):
        registry.discover()
        assert registry.unload("nonexistent") is False

    def test_load_external_from_file(self, registry, tmp_path):
        # Create a temporary module file
        module_code = '''
from pupyteer.server.modules.registry import PupyModule, ModuleCategory

class TempModule(PupyModule):
    name = "temp_module"
    version = "0.1"
    description = "temporary test module"
    author = "test"
    category = ModuleCategory.CORE

    async def execute(self, session, args):
        return {"status": "ok", "temp": True}
'''
        mod_file = tmp_path / "temp_module.py"
        mod_file.write_text(module_code)

        name = registry.load_external(str(mod_file))
        assert name == "temp_module"
        assert "temp_module" in registry

    def test_load_external_invalid_path(self, registry):
        assert registry.load_external("/nonexistent/path.py") is None

    def test_load_external_non_python_file(self, registry, tmp_path):
        txt_file = tmp_path / "not_a_module.txt"
        txt_file.write_text("not python")
        assert registry.load_external(str(txt_file)) is None

    def test_reload_module(self, registry):
        registry.discover()
        ok = registry.reload("sysinfo")
        assert ok is True
        assert "sysinfo" in registry


# ─── ModuleRegistry Validation Tests ─────────────────────────────────


class TestModuleValidation:
    def test_module_without_name_skipped(self, registry, tmp_path):
        module_code = '''
from pupyteer.server.modules.registry import PupyModule, ModuleCategory

class NoNameModule(PupyModule):
    # No name attribute
    description = "missing name"
    category = ModuleCategory.CORE

    async def execute(self, session, args):
        return {"status": "ok"}
'''
        mod_file = tmp_path / "noname.py"
        mod_file.write_text(module_code)

        name = registry.load_external(str(mod_file))
        assert name is None

    def test_module_without_execute_skipped(self, registry, tmp_path):
        module_code = '''
from pupyteer.server.modules.registry import PupyModule, ModuleCategory

class NoExecModule(PupyModule):
    name = "no_exec"
    description = "missing execute"
    category = ModuleCategory.CORE
    # No execute method
'''
        mod_file = tmp_path / "noexec.py"
        mod_file.write_text(module_code)

        name = registry.load_external(str(mod_file))
        assert name is None


# ─── ModuleState Tests ───────────────────────────────────────────────


class TestModuleState:
    def test_registered_state(self):
        assert ModuleState.REGISTERED.value == "registered"

    def test_loaded_state(self):
        assert ModuleState.LOADED.value == "loaded"

    def test_failed_state(self):
        assert ModuleState.FAILED.value == "failed"

    def test_unloaded_state(self):
        assert ModuleState.UNLOADED.value == "unloaded"


# ─── ModuleHealth Dataclass Tests ────────────────────────────────────


class TestModuleHealthDataclass:
    def test_basic_creation(self):
        h = ModuleHealth(
            name="test",
            state=ModuleState.REGISTERED,
            registered_at="2024-01-01T00:00:00Z",
        )
        assert h.name == "test"
        assert h.state == ModuleState.REGISTERED
        assert h.last_error is None
        assert h.load_attempts == 0
        assert h.last_executed is None

    def test_with_error(self):
        h = ModuleHealth(
            name="failing",
            state=ModuleState.FAILED,
            registered_at="2024-01-01T00:00:00Z",
            last_error="ImportError: foo",
        )
        assert h.last_error == "ImportError: foo"


class TestDiscoveryFailures:
    """A module file that cannot import must still be visible to the operator."""

    def _registry_over(self, config, audit, paths):
        reg = ModuleRegistry(config, audit)
        reg._paths = paths
        return reg

    def test_unloadable_file_recorded_as_failed(self, config, audit, tmp_path):
        (tmp_path / "broken.py").write_text(
            "raise RuntimeError('boom during import')\n", encoding="utf-8"
        )
        reg = self._registry_over(config, audit, [tmp_path])
        assert reg.discover() == 0
        health = [h for h in reg.list_health() if h["state"] == "failed"]
        assert [h["name"] for h in health] == ["file:broken"]
        assert "boom during import" in health[0]["last_error"]

    def test_valid_and_broken_files_mixed(self, config, audit, tmp_path):
        (tmp_path / "good.py").write_text(
            "from pupyteer.server.modules.registry import PupyModule, ModuleCategory\n"
            "class Good(PupyModule):\n"
            "    name = 'good'\n"
            "    version = '1.0.0'\n"
            "    description = 'ok'\n"
            "    author = 't'\n"
            "    category = ModuleCategory.CORE\n"
            "    async def execute(self, session, args):\n"
            "        return {'status': 'ok'}\n",
            encoding="utf-8",
        )
        (tmp_path / "bad.py").write_text("raise ValueError('nope')\n", encoding="utf-8")
        reg = self._registry_over(config, audit, [tmp_path])
        assert reg.discover() == 1
        assert reg.get("good") is not None
        failed = [h for h in reg.list_health() if h["state"] == "failed"]
        assert [h["name"] for h in failed] == ["file:bad"]

    def test_underscore_files_are_skipped_quietly(self, config, audit, tmp_path):
        (tmp_path / "_helper.py").write_text("raise ValueError('nope')\n", encoding="utf-8")
        reg = self._registry_over(config, audit, [tmp_path])
        reg.discover()
        assert reg.list_health() == []


# ─── Anti-Forensics Gate Tests ───────────────────────────────────────

# Spec 17 "Controlled": these five modules destroy evidence on a host (event
# logs, prefetch entries, file timestamps) and have no test coverage. They are
# unreachable only because ModuleCategory has no ANTI_FORENSICS member, which
# makes builtin/antiforensics.py fail to import. Adding that one enum value
# would activate all five with no other change, so the decision is pinned here
# as a reviewed invariant rather than an accident an import fix would undo.
ANTI_FORENSICS_MODULES = [
    "log_clear",
    "timestamp_match",
    "artifact_wipe",
    "prefetch_delete",
    "recycle_clear",
]


class TestAntiForensicsDisabled:
    def test_category_member_is_absent(self):
        assert not hasattr(ModuleCategory, "ANTI_FORENSICS")

    def test_modules_are_not_registered(self, registry):
        registry.discover()
        names = {m["name"] for m in registry.list_all()}
        assert names.isdisjoint(ANTI_FORENSICS_MODULES)

    def test_source_file_is_reported_as_failed(self, registry):
        """Unreachable must not mean invisible — the console warns on this."""
        registry.discover()
        failed = {h["name"] for h in registry.list_health() if h["state"] == "failed"}
        assert "file:antiforensics" in failed


# ─── Implant Action Modules (ping / privesc / screenshot / migrate) ───


class TestImplantActionModules:
    """Modules that wrap structured agent actions already implemented in the stub.

    These use a fake session manager that answers by the action the module
    dispatched, so a test can assert both the task sent and how the reply is
    parsed. As with the file modules, a refusal or a malformed reply must surface
    as an error, never as an empty success.
    """

    @staticmethod
    def _session(session_id: str = "sess-1") -> Any:
        return type(
            "Session", (),
            {"session_id": session_id, "hostname": "test-host", "os": "linux",
             "arch": "x64", "username": "root", "remote_address": "127.0.0.1:1",
             "connected_at": 0, "last_checkin": 0},
        )()

    @staticmethod
    def _agent(replies: Dict[str, Any]) -> Any:
        """Answer each dispatched structured task by its ``action``.

        ``replies`` maps an action name to the object the agent returns; the
        queued raw commands are recorded so a test can check what was sent.
        """
        queued: list = []

        class _Stub:
            async def get(self, session_id: str):
                return type("Session", (), {"session_id": session_id,
                                            "max_line": 0})()

            async def interact(self, session_id: str, command: str) -> str:
                command_id = f"cmd-{len(queued)}"
                queued.append({"command_id": command_id, "command": command,
                               "status": "queued", "result": None})
                return command_id

            async def get_pending_commands(self, session_id: str) -> list:
                for entry in queued:
                    if entry["status"] != "queued":
                        continue
                    task = json.loads(entry["command"])
                    reply = replies.get(task.get("action"), {"error": "unhandled"})
                    entry["status"] = "completed"
                    entry["result"] = json.dumps(reply)
                return queued

        stub = _Stub()
        stub.queued = queued
        return stub

    @staticmethod
    def _sent_task(agent: Any) -> Dict[str, Any]:
        return json.loads(agent.queued[0]["command"])

    # -- ping --

    @pytest.mark.asyncio
    async def test_ping_reports_the_agent_id(self, registry):
        registry.discover()
        agent = self._agent({"ping": {"pong": True, "id": "abc123"}})
        result = await registry.execute(
            "ping", self._session(), {}, session_manager=agent)
        assert result["status"] == "ok"
        assert result["agent_id"] == "abc123"
        assert result["responsive"] is True
        assert self._sent_task(agent)["action"] == "ping"

    @pytest.mark.asyncio
    async def test_ping_without_an_agent_is_an_error(self, registry):
        registry.discover()
        result = await registry.execute("ping", self._session(), {})
        assert result["status"] == "error"
        assert "nothing was sent" in result["error"]

    @pytest.mark.asyncio
    async def test_ping_rejects_a_reply_that_is_not_a_pong(self, registry):
        registry.discover()
        agent = self._agent({"ping": {"id": "abc"}})
        result = await registry.execute(
            "ping", self._session(), {}, session_manager=agent)
        assert result["status"] == "error"

    # -- privesc --

    @pytest.mark.asyncio
    async def test_privesc_suggest_returns_structured_findings(self, registry):
        registry.discover()
        payload = {"check": {"euid": 1000, "suid_binaries": ["/usr/bin/find"]},
                   "suggestions": ["GTFOBin: /usr/bin/find"]}
        agent = self._agent({"privesc_suggest": payload})
        result = await registry.execute(
            "privesc", self._session(), {}, session_manager=agent)
        assert result["status"] == "ok"
        assert result["suggestions"] == ["GTFOBin: /usr/bin/find"]
        assert self._sent_task(agent)["action"] == "privesc_suggest"

    @pytest.mark.asyncio
    async def test_privesc_check_mode_dispatches_the_check(self, registry):
        registry.discover()
        agent = self._agent({"privesc_check": {"euid": 0, "is_admin": True}})
        result = await registry.execute(
            "privesc", self._session(), {"mode": "check"}, session_manager=agent)
        assert result["status"] == "ok"
        assert result["check"]["is_admin"] is True
        assert self._sent_task(agent)["action"] == "privesc_check"

    @pytest.mark.asyncio
    async def test_privesc_rejects_an_unknown_mode(self, registry):
        registry.discover()
        result = await registry.execute(
            "privesc", self._session(), {"mode": "exploit"})
        assert result["status"] == "error"
        assert "mode" in result["error"].lower()

    # -- screenshot --

    @pytest.mark.asyncio
    async def test_screenshot_writes_the_image_to_disk(self, registry, tmp_path):
        registry.discover()
        raw = b"\x89PNG fake image bytes"
        payload = {"format": "png", "bytes": len(raw),
                   "data": base64.b64encode(raw).decode()}
        agent = self._agent({"screenshot": payload})
        dest = tmp_path / "shot.png"
        result = await registry.execute(
            "screenshot", self._session(), {"local_path": str(dest)},
            session_manager=agent)
        assert result["status"] == "ok"
        assert result["bytes_written"] == len(raw)
        assert dest.read_bytes() == raw
        assert self._sent_task(agent)["action"] == "screenshot"

    @pytest.mark.asyncio
    async def test_screenshot_surfaces_an_agent_error(self, registry):
        registry.discover()
        agent = self._agent({"screenshot": {"error": "no working screenshot tool"}})
        result = await registry.execute(
            "screenshot", self._session(), {}, session_manager=agent)
        assert result["status"] == "error"
        assert "screenshot tool" in result["error"]

    @pytest.mark.asyncio
    async def test_screenshot_rejects_data_that_is_not_base64(self, registry, tmp_path):
        registry.discover()
        agent = self._agent({"screenshot": {"format": "png", "data": "!!!notb64!!!"}})
        result = await registry.execute(
            "screenshot", self._session(),
            {"local_path": str(tmp_path / "x.png")}, session_manager=agent)
        assert result["status"] == "error"
        assert "base64" in result["error"]

    # -- migrate --

    @pytest.mark.asyncio
    async def test_migrate_dispatches_target_and_technique(self, registry):
        registry.discover()
        agent = self._agent({"migrate": {"ok": True, "pid": 4321}})
        result = await registry.execute(
            "migrate", self._session(),
            {"target": "4321", "technique": "reflective"}, session_manager=agent)
        assert result["status"] == "ok"
        task = self._sent_task(agent)
        assert task["action"] == "migrate"
        assert task["target"] == "4321"
        assert task["technique"] == "reflective"

    @pytest.mark.asyncio
    async def test_migrate_requires_a_target(self, registry):
        registry.discover()
        result = await registry.execute("migrate", self._session(), {})
        assert result["status"] == "error"
        assert "target" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_migrate_reports_a_refused_migration(self, registry):
        registry.discover()
        agent = self._agent({"migrate": {"ok": False, "error": "OpenProcess failed"}})
        result = await registry.execute(
            "migrate", self._session(), {"target": "1"}, session_manager=agent)
        assert result["status"] == "error"
        assert "OpenProcess" in result["error"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
