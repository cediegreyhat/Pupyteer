"""Subprocess helpers that do not strobe a console window on Windows.

A build or a test run shells out to console applications: the MinGW compiler,
PyInstaller, a generated Python agent, a package manager. On Windows each one
gets a console of its own unless it is told otherwise, so a quiet test run
flashes a cmd window every time it compiles a payload or launches an agent.
`CREATE_NO_WINDOW` says the child inherits nothing and shows nothing; it does
not touch stdio, so captured output is unchanged and the flag is a no-op
everywhere else.

Usage: `subprocess.run([...], creationflags=creationflags())`, or `run()` /
`popen()` here for the common case.
"""
from __future__ import annotations

import subprocess
import sys
from typing import Any

#: `subprocess.CREATE_NO_WINDOW` exists on Windows only; 0 means "no flag".
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def creationflags() -> int:
    """The flag to pass so a child console application opens no window."""
    return CREATE_NO_WINDOW if sys.platform == "win32" else 0


def run(*args: Any, **kwargs: Any):
    """`subprocess.run` with the no-console flag applied on Windows."""
    kwargs.setdefault("creationflags", creationflags())
    return subprocess.run(*args, **kwargs)


def popen(*args: Any, **kwargs: Any):
    """`subprocess.Popen` with the no-console flag applied on Windows."""
    kwargs.setdefault("creationflags", creationflags())
    return subprocess.Popen(*args, **kwargs)
