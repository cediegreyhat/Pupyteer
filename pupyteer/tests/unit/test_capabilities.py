"""Commands are gated on what the implant said it can do.

The shape under test is small and easy to get wrong in a way that costs an
operator a false line in a report: a session answers a tasking its payload
cannot perform, and the answer is whatever a shell says about a word it has
never seen. So these tests hold two things — that the queue refuses on the
implant's behalf, and that a refusal never leaves the server.
"""
import base64
import io
import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.sessions import capabilities as caps
from pupyteer.server.sessions.manager import SessionInfo, SessionManager, SessionState
from pupyteer.server.sessions.transfer import (
    DEFAULT_CHUNK_SIZE, LINE_FRAMING_ALLOWANCE, chunk_budget, pull, push,
)
from pupyteer.server.transports.listener import AgentListener

REPO_ROOT = Path(__file__).resolve().parents[3]


class MockTransports:
    async def list_transports(self):
        return []


@pytest.fixture
def sessions(tmp_path):
    config = ConfigManager()
    config._config["audit"]["log_file"] = str(tmp_path / "audit.json")
    audit = AuditLogger(config)
    return SessionManager(config, MockTransports(), audit), audit


async def _connect(sm, session_id="s1", capabilities=None, max_line=0):
    await sm.register(SessionInfo(
        session_id=session_id,
        hostname="host",
        os="windows",
        state=SessionState.CONNECTED,
        capabilities=list(capabilities or []),
        max_line=max_line,
        # A session with no token cannot be beaconed for at all, which is the
        # listener's rule rather than this test's subject.
        beacon_token="test-beacon",
    ))
    return session_id


def _entry(sm, session_id, command_id):
    for entry in sm._command_queue.get(session_id, []):
        if entry["command_id"] == command_id:
            return entry
    raise AssertionError("command never reached the queue")


# ─── reading a command line ──────────────────────────────────────────


class TestRequiredCapability:
    def test_plain_text_is_the_shells_problem(self):
        assert caps.required_capability("whoami") == caps.SHELL
        assert caps.required_capability("dir /b C:\\Users") == caps.SHELL
        assert caps.required_capability("") == caps.SHELL

    def test_a_typed_verb_needs_what_the_verb_does(self):
        assert caps.required_capability("screenshot out.png") == "screenshot"
        assert caps.required_capability("PS") == "processes"
        assert caps.required_capability("exit") == "shutdown"

    def test_a_structured_task_needs_its_action(self):
        task = json.dumps({"action": "fs_get", "path": "a", "offset": 0})
        assert caps.required_capability(task) == "fs_get"

    def test_a_brace_that_is_not_json_goes_to_the_shell(self):
        # An operator typing `echo {hello}` means the shell to print it. The
        # shell's own complaint is the honest answer; a refusal would be the
        # server claiming to know what a brace means.
        assert caps.required_capability("echo {hello") == caps.SHELL
        assert caps.required_capability('{"action": ') == caps.SHELL

    def test_a_json_object_without_an_action_is_text(self):
        assert caps.required_capability('{"foo": 1}') == caps.SHELL


class TestDeclaredCapabilities:
    def test_only_the_known_vocabulary_is_kept(self):
        got = caps.declared_capabilities(["exec", "godmode", "fs_get"])
        assert got == ["exec", "fs_get"]

    def test_order_is_the_payloads_and_duplicates_are_one_claim(self):
        assert caps.declared_capabilities(["ping", "exec", "ping"]) == ["ping", "exec"]

    def test_a_string_is_not_a_list_of_one_capability(self):
        # "exec" is a Sequence of characters, none of which is a capability name.
        # Reading it as a claim would silently declare nothing while looking like
        # a declaration, which is the worst of both.
        assert caps.declared_capabilities("exec") == []
        assert caps.declared_capabilities(None) == []
        assert caps.declared_capabilities([1, None, "exec"]) == ["exec"]

    def test_the_refusal_names_both_sides(self):
        text = caps.refusal("screenshot", ["exec", "fs_get"])
        assert "screenshot" in text
        assert "exec, fs_get" in text
        assert "Nothing ran on the target" in text

    def test_an_implant_that_declared_nothing_says_so(self):
        assert "nothing beyond a shell" in caps.refusal("fs_get", [])


class TestDeclaredMaxLine:
    def test_nonsense_falls_back_to_the_assumed_buffer(self):
        assert caps.declared_max_line(None) == caps.DEFAULT_MAX_LINE
        assert caps.declared_max_line(0) == caps.DEFAULT_MAX_LINE
        assert caps.declared_max_line(-5) == caps.DEFAULT_MAX_LINE
        assert caps.declared_max_line("wide") == caps.DEFAULT_MAX_LINE

    def test_a_json_infinity_or_nan_does_not_kill_the_registration(self):
        # json.loads accepts Infinity and NaN by default, so an agent can put
        # them on the wire in a max_line field. int() of those is an
        # OverflowError, which used to escape and drop the connection the
        # implant was mid-registration on, with no reply and no audit entry.
        # A non-finite claim is not a buffer the agent announced; it is the
        # same as saying nothing.
        assert caps.declared_max_line(float("inf")) == caps.DEFAULT_MAX_LINE
        assert caps.declared_max_line(float("-inf")) == caps.DEFAULT_MAX_LINE
        assert caps.declared_max_line(float("nan")) == caps.DEFAULT_MAX_LINE

    def test_a_claim_bigger_than_the_listener_is_clamped_not_believed(self):
        assert caps.declared_max_line(1024 * 1024 * 1024) == caps.MAX_LINE_CAP

    def test_a_real_number_is_kept(self):
        assert caps.declared_max_line(65536) == 65536


class TestRequiredCapabilityReadsAnyShape:
    """required_capability is the gate the queue calls on every interact.

    It is typed as ``str`` but the queue feeds it whatever the operator typed
    and whatever a module put in a task envelope, so a non-string can reach it.
    An unguarded ``.strip()`` raised AttributeError there, which is not a
    refused command the operator can read — it is a crash inside the session
    layer. A command that is not even a string is neither a typed verb nor a
    structured task, so it reads as shell: the same answer an empty command
    gets, and the one an implant is always trusted with.
    """

    def test_a_non_string_command_reads_as_shell(self):
        for value in (123, [None], [1, 2], {"a": 1}, True, ("x",)):
            assert caps.required_capability(value) == caps.SHELL

    def test_a_string_command_still_reads_its_verb(self):
        assert caps.required_capability("ping") == "ping"
        assert caps.required_capability("  fs_get  ") == "fs_get"
        assert caps.required_capability("ps") == "processes"
        assert caps.required_capability("") == caps.SHELL
        assert caps.required_capability('{"action": "screenshot"}') == "screenshot"


# ─── the queue enforces it ───────────────────────────────────────────


class TestQueueGating:
    @pytest.mark.asyncio
    async def test_a_tasking_the_implant_cannot_do_is_refused_before_it_is_sent(
            self, sessions):
        sm, audit = sessions
        await _connect(sm, capabilities=["exec", "ping"])
        cid = await sm.interact("s1", json.dumps({"action": "screenshot"}))
        entry = _entry(sm, "s1", cid)
        assert entry["status"] == "completed"
        assert "refused" in entry["result"]
        assert entry["refused"] == "screenshot"
        recorded = audit.query(event="session_command_unsupported")
        details = recorded[-1]["details"]
        assert details["capability"] == "screenshot"
        assert details["declared"] == ["exec", "ping"]

    @pytest.mark.asyncio
    async def test_a_refusal_does_not_make_the_session_look_busy(self, sessions):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec"])
        await sm.interact("s1", "screenshot")
        session = await sm.get("s1")
        assert session.task_status == "idle"

    @pytest.mark.asyncio
    async def test_shell_text_still_passes_for_a_session_that_declared_nothing(
            self, sessions):
        # Payloads built before registration carried a claim cannot announce
        # themselves. Refusing their shell would strand every handler already in
        # the field over a field nobody deployed it with.
        sm, _ = sessions
        await _connect(sm)
        cid = await sm.interact("s1", "whoami")
        assert _entry(sm, "s1", cid)["status"] == "queued"

    @pytest.mark.asyncio
    async def test_structured_tasking_needs_the_claim_even_from_an_old_payload(
            self, sessions):
        sm, _ = sessions
        await _connect(sm)
        cid = await sm.interact("s1", json.dumps({"action": "fs_get", "path": "a"}))
        assert _entry(sm, "s1", cid)["status"] == "completed"

    @pytest.mark.asyncio
    async def test_a_declared_capability_is_queued(self, sessions):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec", "fs_get"])
        cid = await sm.interact("s1", json.dumps({"action": "fs_get", "path": "a"}))
        assert _entry(sm, "s1", cid)["status"] == "queued"

    @pytest.mark.asyncio
    async def test_a_typed_verb_and_the_task_it_stands_for_are_the_same_claim(
            self, sessions):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec"])
        typed = await sm.interact("s1", "screenshot")
        structured = await sm.interact(
            "s1", json.dumps({"action": "screenshot"}))
        assert _entry(sm, "s1", typed)["result"] == _entry(
            sm, "s1", structured)["result"]

    @pytest.mark.asyncio
    async def test_a_session_that_declared_shutdown_can_be_told_to_exit(
            self, sessions):
        # `exit` is not a shell line: the verb stands for the action that ends
        # the implant, so an implant that never said it can stop itself is not
        # handed a word it would answer with whatever `exit` means to a cmd.exe.
        sm, _ = sessions
        await _connect(sm, capabilities=["exec", "shutdown"])
        cid = await sm.interact("s1", "exit")
        assert _entry(sm, "s1", cid)["status"] == "queued"

    @pytest.mark.asyncio
    async def test_exit_still_needs_the_claim(self, sessions):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec"])
        cid = await sm.interact("s1", "exit")
        assert _entry(sm, "s1", cid)["refused"] == "shutdown"


class TestDispatchKeepsRefusalsOnTheServer:
    @pytest.mark.asyncio
    async def test_a_refused_command_is_never_handed_to_the_agent(self, sessions):
        sm, audit = sessions
        await _connect(sm, capabilities=["exec"])
        refused = await sm.interact("s1", "screenshot")
        queued = await sm.interact("s1", "whoami")

        listener = AgentListener({}, sm, audit)
        reply = await listener._handle_checkin(
            {"session_id": "s1", "beacon": await _token(sm, "s1")}, "1.2.3.4:1", None)

        sent = [c["command_id"] for c in reply["commands"]]
        assert sent == [queued]
        assert refused not in sent
        # The refusal is still answered, and still answers itself.
        assert _entry(sm, "s1", refused)["status"] == "completed"
        assert _entry(sm, "s1", queued)["status"] == "delivered"


async def _token(sm, session_id):
    session = await sm.get(session_id)
    return session.beacon_token


class TestTheVocabularyCoversBothAgents:
    """The claim vocabulary has to contain every action the agents implement.

    It did not. The recon verbs (`netstat`, `pwd`, `env`, `date`, `kill`) and
    the module dispatches (`pyexec`, `load_package`) were absent from
    `KNOWN_CAPABILITIES`, so `declared_capabilities` dropped them from every
    real payload's claim and the queue refused exactly the commands those
    payloads were built to run — a refusal that reads as a dead implant.
    """

    def test_every_operator_verb_resolves_to_a_known_capability(self):
        missing = {v: c for v, c in caps.TYPED_VERBS.items()
                   if c not in caps.KNOWN_CAPABILITIES}
        assert missing == {}, missing

    def test_every_action_the_python_agent_dispatches_is_known(self):
        source = (REPO_ROOT / "pupyteer" / "agent" / "core" / "stub.py").read_text(
            encoding="utf-8")
        body = source.split("def _dispatch(")[1].split("def _render_result")[0]
        actions = set(re.findall(r'action == "([a-z_]+)"', body))
        assert actions, "the parse found nothing — the test is not testing"
        assert actions <= set(caps.KNOWN_CAPABILITIES), actions

    def test_every_verb_the_python_agent_parses_is_known(self):
        source = (REPO_ROOT / "pupyteer" / "agent" / "core" / "stub.py").read_text(
            encoding="utf-8")
        body = source.split("def _parse_command")[1].split("# ---")[0]
        verbs = set(re.findall(r'v == "([a-z_]+)"', body))
        for tup in re.findall(r"v in \(([^)]*)\)", body):
            verbs |= set(re.findall(r'"([a-z_]+)"', tup))
        assert verbs, "the parse found nothing — the test is not testing"
        # `ps`, `kill` and `exit` are operator spellings, not capability names;
        # what matters is that the gate they resolve to is a real word.
        resolved = {caps.required_capability(v) for v in verbs}
        assert resolved <= set(caps.KNOWN_CAPABILITIES), resolved

    def test_the_pe_capability_constant_matches_the_c_register(self):
        """The manifest records what the .exe declares, so tie the two together.

        A constant that drifts from `handle_register` is a manifest that lies
        about the artifact, which is the one thing it exists not to do.
        """
        source = (REPO_ROOT / "pupyteer" / "agent" / "core" / "pe_template.c").read_text(
            encoding="utf-8")
        match = re.search(r'capabilities\\":\[([^\]]*)\]', source)
        assert match, "the C register no longer carries a capability list"
        declared = set(re.findall(r'\\"([a-z_]+)\\"', match.group(1)))
        assert declared == set(caps.PE_CAPABILITIES)
        assert declared <= set(caps.KNOWN_CAPABILITIES)

    def test_script_capabilities_follow_the_build_switches(self):
        default = caps.script_capabilities()
        assert "screenshot" not in default
        assert "screenshot" in caps.script_capabilities(screenshot=True)
        assert "migrate" in default
        assert "migrate" not in caps.script_capabilities(migration=False)
        assert set(default) <= set(caps.KNOWN_CAPABILITIES)

    @pytest.mark.asyncio
    async def test_a_real_payloads_claim_survives_the_gate(self, sessions):
        """End to end: what the stub declares is what the queue accepts."""
        sm, _ = sessions
        declared = caps.declared_capabilities(caps.script_capabilities())
        for name in ("netstat", "pwd", "env", "date", "process_kill",
                     "load_package", "pyexec"):
            assert name in declared, name
        await _connect(sm, capabilities=declared)

        for command in ("netstat", "pwd", "env", "date", "kill 4"):
            cid = await sm.interact("s1", command)
            assert _entry(sm, "s1", cid)["status"] == "queued", command

        for task in ('{"action": "load_package", "name": "x"}',
                     '{"action": "pyexec", "code": "1"}'):
            cid = await sm.interact("s1", task)
            assert _entry(sm, "s1", cid)["status"] == "queued", task


# ─── transfer sizes itself to the implant ────────────────────────────


class TestChunkBudget:
    @pytest.mark.asyncio
    async def test_a_small_read_buffer_caps_the_chunk_to_what_fits_in_one_line(
            self, sessions):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec", "fs_put"], max_line=65536)
        budget = await chunk_budget(sm, "s1")
        assert budget == (65536 - LINE_FRAMING_ALLOWANCE) * 3 // 4
        assert budget < 65536

    @pytest.mark.asyncio
    async def test_a_session_that_declared_nothing_is_assumed_the_smallest_agent(
            self, sessions):
        # The payloads in the field that cannot announce themselves are the old
        # ones, and the old Windows implant reads 64 KB lines. Assuming the
        # generous reading is the one that writes a short file and calls it done.
        sm, _ = sessions
        await _connect(sm)
        assert await chunk_budget(sm, "s1") == (
            (caps.DEFAULT_MAX_LINE - LINE_FRAMING_ALLOWANCE) * 3 // 4)

    @pytest.mark.asyncio
    async def test_a_large_buffer_does_not_raise_the_ceilings_own_preference(
            self, sessions):
        sm, _ = sessions
        await _connect(sm, max_line=caps.MAX_LINE_CAP)
        assert await chunk_budget(sm, "s1") == DEFAULT_CHUNK_SIZE

    @pytest.mark.asyncio
    async def test_an_implant_that_cannot_hold_a_request_says_so_instead_of_stalling(
            self, sessions, tmp_path):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec", "fs_get", "fs_put"], max_line=700)
        local = tmp_path / "f.bin"
        local.write_bytes(b"x" * 10)

        class NeverAsked:
            async def get(self, session_id):
                return await sm.get(session_id)

            async def interact(self, session_id, command):
                raise AssertionError("a chunk that cannot fit must not be queued")

        sink = io.BytesIO()
        assert "too small" in (await pull(
            NeverAsked(), "s1", "remote.bin", sink, timeout=1))["error"]
        assert "too small" in (await push(
            NeverAsked(), "s1", str(local), "remote.bin", timeout=1))["error"]


class TestTransfersRespectTheBudget:
    @pytest.mark.asyncio
    async def test_push_sends_chunks_the_agent_can_read(self, sessions, tmp_path):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec", "fs_put"], max_line=65536)
        local = tmp_path / "f.bin"
        local.write_bytes(b"z" * (128 * 1024))
        asked = []

        class Queue:
            async def get(self, session_id):
                return await sm.get(session_id)

            async def interact(self, session_id, command):
                task = json.loads(command)
                asked.append(len(base64.b64decode(task["data"])))
                return "cid"

            async def get_pending_commands(self, session_id):
                return [{"command_id": "cid", "status": "completed",
                         "result": json.dumps({"ok": True})}]

        outcome = await push(Queue(), "s1", str(local), "remote.bin", timeout=1)
        assert outcome["status"] == "ok"
        assert max(asked) <= (65536 - LINE_FRAMING_ALLOWANCE) * 3 // 4
        assert sum(asked) == 128 * 1024

    @pytest.mark.asyncio
    async def test_pull_asks_for_no_more_than_the_agent_can_answer_in_one_line(
            self, sessions):
        sm, _ = sessions
        await _connect(sm, capabilities=["exec", "fs_get"], max_line=65536)
        asked = []

        class Queue:
            async def get(self, session_id):
                return await sm.get(session_id)

            async def interact(self, session_id, command):
                task = json.loads(command)
                asked.append(task["length"])
                return "cid"

            async def get_pending_commands(self, session_id):
                return [{"command_id": "cid", "status": "completed",
                         "result": json.dumps({"data": "", "size": 0, "eof": True})}]

        outcome = await pull(Queue(), "s1", "remote.bin", io.BytesIO(), timeout=1)
        assert outcome["status"] == "ok"
        assert asked == [
            (65536 - LINE_FRAMING_ALLOWANCE) * 3 // 4]
