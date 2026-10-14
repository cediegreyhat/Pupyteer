"""The merged PE template, compiled and run for real, against a real listener.

The unit tests (test_pe_render.py) prove the template renders with no leftover
placeholders and cross-compiles. test_rc4_transport.py proves the RC4 wire
framing interops with a Python peer that mimics the agent. This closes the
last gap: the actual MinGW .exe the builder produces — RC4-inside-the-plaintext
channel — launched under Wine, registering and running a command on the same
asyncio listener the RC4 interop test uses.

Skipped where the toolchain or Wine is absent, because a cross-compiled .exe
cannot run on the build host without it.
"""
from __future__ import annotations

import asyncio
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from pupyteer.server.core.engine import PupyteerEngine

WINE = shutil.which("wine") or shutil.which("wine64")
MINGW = shutil.which("x86_64-w64-mingw32-gcc")
RC4_KEY_HEX = "deadbeefdeadbeefdeadbeefdeadbeef"


def _wine_can_network() -> bool:
    """Wine is installed but its winsock is not always usable (sandboxes with no
    loopback for Wine, or a wedged wineserver). Probe once: a trivial Wine exe
    must complete a TCP connect to a loopback listener. If it cannot, the live
    .exe test is skipped rather than failing for an environment reason."""
    if not WINE:
        return False
    probe_src = Path("/tmp/_pup_wine_netprobe.c")
    probe_src.write_text(
        '#include <winsock2.h>\n'
        'int main(){WSADATA w; if(WSAStartup(MAKEWORD(2,2),&w)) return 2;\n'
        ' SOCKET s=socket(AF_INET,SOCK_STREAM,0); if(s==INVALID_SOCKET) return 3;\n'
        ' struct sockaddr_in a; a.sin_family=AF_INET; a.sin_port=htons(%d);\n'
        ' a.sin_addr.s_addr=inet_addr("127.0.0.1");\n'
        ' return connect(s,(struct sockaddr*)&a,sizeof(a))==0 ? 0 : 4;}\n' % _PROBE_PORT)
    exe = Path("/tmp/_pup_wine_netprobe.exe")
    if not MINGW:
        return False
    subprocess.run([MINGW, "-o", str(exe), str(probe_src), "-lws2_32"],
                   capture_output=True)
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        srv.bind(("127.0.0.1", _PROBE_PORT))
    except OSError:
        return False
    srv.listen(1)
    srv.settimeout(8)
    import threading
    acc = {}
    def _acc():
        try:
            c, _ = srv.accept(); acc["ok"] = True; c.close()
        except Exception:
            acc["ok"] = False
    threading.Thread(target=_acc, daemon=True).start()
    time.sleep(0.3)
    subprocess.run(["pkill", "-9", "wineserver"], capture_output=True)
    time.sleep(0.5)
    env = dict(os.environ, WINEDEBUG="-all",
               WINEDLLOVERRIDES="mscoree,mshtml=")
    try:
        subprocess.run([WINE, str(exe)], capture_output=True, timeout=25, env=env)
    except (subprocess.TimeoutExpired, OSError):
        srv.close()
        return False
    time.sleep(0.5)
    srv.close()
    return bool(acc.get("ok"))


_PROBE_PORT = 33991
_WINE_OK = None


def wine_ok() -> bool:
    global _WINE_OK
    if _WINE_OK is None:
        _WINE_OK = _wine_can_network()
    return _WINE_OK


pytestmark = pytest.mark.skipif(
    not (WINE and MINGW),
    reason="needs Wine and a MinGW cross-compiler to run a real Windows PE",
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_port(host: str, port: int, timeout: float = 10.0) -> None:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with socket.create_connection((host, port), timeout=1):
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError(f"port {port} not ready")


class _EngineThread:
    """The same engine-on-a-thread harness test_rc4_transport.py proves works."""

    def __init__(self, port: int):
        self.port = port
        self.engine = None
        self.loop = None
        self.thread = None
        self.ready = threading.Event()
        self.error = None

    def start(self, timeout: float = 15.0) -> None:
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()
        if not self.ready.wait(timeout=timeout):
            raise TimeoutError("engine not ready")
        if self.error:
            raise self.error

    def _run(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.engine = PupyteerEngine()
            c = self.engine.config
            c.set("server.host", "127.0.0.1")
            c.set("server.port", self.port)
            c.set("server.tls", False)
            c.set("transports.rc4_key", RC4_KEY_HEX)
            c.set("security.require_agent_auth", False)
            self.loop.run_until_complete(self.engine.start())
            self.ready.set()
            self.loop.run_forever()
        except Exception as exc:  # noqa: BLE001
            self.error = exc
            self.ready.set()

    def stop(self, timeout: float = 15.0) -> None:
        if self.engine and self.loop:
            fut = asyncio.run_coroutine_threadsafe(self.engine.stop(), self.loop)
            try:
                fut.result(timeout=timeout)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread:
            self.thread.join(timeout=timeout)

    def submit(self, coro, timeout: float = 5.0):
        fut = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return fut.result(timeout=timeout)


class _Cfg:
    def get(self, key, default=None):
        if key == "payloads.mingw_path":
            return MINGW
        return default


class _NoAudit:
    def log_event(self, *args, **kwargs):
        pass


def _build_pe(tmp_path: Path, port: int) -> Path:
    from pupyteer.agent.core.stub import StubConfig
    from pupyteer.payloads.pe_builder import PEBuilder

    cfg = StubConfig(name="peagent", host="127.0.0.1", port=port, sleep=1,
                     jitter=0, auth_secret="", tls=False, anti_analysis=False)
    builder = PEBuilder(_Cfg(), _NoAudit())
    src = builder._render(builder._load_template(), cfg)
    cpath = tmp_path / "agent.c"
    cpath.write_text(src)
    exe = tmp_path / "agent.exe"
    r = subprocess.run([MINGW, "-o", str(exe), str(cpath), "-DSECURITY_WIN32",
                        "-lws2_32", "-lsecur32", "-lcrypt32", "-O2",
                        "-mwindows", "-s"], capture_output=True, text=True)
    assert r.returncode == 0, f"build failed: {r.stderr}"
    return exe


@pytest.fixture()
def live(tmp_path):
    port = _free_port()
    thread = _EngineThread(port)
    thread.start()
    _wait_port("127.0.0.1", port)
    time.sleep(0.5)
    exe = _build_pe(tmp_path, port)
    yield thread, exe
    thread.stop()


def test_merged_pe_registers_and_runs_a_command_under_wine(live):
    if not wine_ok():
        pytest.skip("Wine winsock cannot reach loopback in this environment")
    thread, exe = live
    proc = subprocess.Popen([WINE, str(exe)], cwd=str(exe.parent),
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        # Wait for registration.
        sid = None
        end = time.time() + 30
        while time.time() < end:
            sessions = thread.submit(thread.engine.sessions.list_all())
            if sessions:
                sid = sessions[0].session_id
                break
            time.sleep(0.5)
        assert sid, "the real compiled PE never registered with the listener"

        # Queue a command and wait for the agent to return its result.
        cid = thread.submit(
            thread.engine.sessions.interact(sid, "echo pupyteer_pe_e2e_ok"),
            timeout=10)
        out = None
        end = time.time() + 20
        while time.time() < end:
            for entry in thread.submit(
                    thread.engine.sessions.get_command_history(sid), timeout=5):
                if entry.get("command_id") == cid and entry.get("result"):
                    out = entry["result"]
                    break
            if out:
                break
            time.sleep(0.5)
        assert out is not None and "pupyteer_pe_e2e_ok" in out, \
            f"command result missing/wrong: {out!r}"
    finally:
        proc.kill()
        proc.wait(timeout=5)
