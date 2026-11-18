"""A test run must not open console windows.

The suite compiles payloads with MinGW, freezes agents with PyInstaller, and
launches generated agents as real subprocesses. On Windows each console child
gets a window of its own unless told otherwise, which flashes a cmd box over
whatever the operator is doing. These tests are the guard on that promise: the
flag is applied, and applying it does not break stdio.
"""
from __future__ import annotations

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer import _proc


@pytest.mark.skipif(sys.platform != "win32", reason="console windows are a Windows behaviour")
def test_the_flag_is_the_windows_no_window_flag():
    assert _proc.creationflags() == subprocess.CREATE_NO_WINDOW


@pytest.mark.skipif(sys.platform != "win32", reason="console windows are a Windows behaviour")
def test_the_suite_routes_every_spawn_through_it():
    """A spawn added later, or inside a library, is covered too."""
    assert getattr(subprocess.Popen, "_pupyteer_no_window", False)
    for name in ("run", "call", "check_call", "check_output"):
        assert getattr(getattr(subprocess, name), "_pupyteer_no_window", False), name


@pytest.mark.skipif(sys.platform != "win32", reason="console windows are a Windows behaviour")
def test_the_flag_does_not_break_captured_output():
    """The flag says whether a child gets a console, not what it can write."""
    proc = _proc.run([sys.executable, "-c", "print('from-child')"],
                     capture_output=True, text=True, timeout=30)
    assert proc.returncode == 0
    assert "from-child" in proc.stdout


@pytest.mark.skipif(sys.platform != "win32", reason="console windows are a Windows behaviour")
def test_a_popen_still_behaves_like_a_popen():
    proc = _proc.popen([sys.executable, "-c", "pass"])
    try:
        assert proc.wait(timeout=30) == 0
    finally:
        if proc.poll() is None:
            proc.kill()
