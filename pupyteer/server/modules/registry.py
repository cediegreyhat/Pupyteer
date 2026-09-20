"""Module discovery, loading, and lifecycle management.

Supports loading from:
- Built-in modules (pupyteer/server/modules/builtin/)
- External modules (configurable paths)
- Plugin directories

Category layout per spec section 9:
    Core
    ├── Session Management
    ├── Task Management
    ├── Configuration
    └── Logging

    Recon
    ├── System Information
    ├── Network Information
    └── Process Information

    Execution
    ├── Command Execution
    └── Controlled Module Execution

    File Operations
    ├── Upload
    ├── Download
    └── File Management

    Red-Team Modules
    ├── Discovery
    ├── Collection
    ├── Simulation
    └── Assessment Utilities
"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.modules")


class ModuleState(str, Enum):
    """Lifecycle state of a registered module."""
    REGISTERED = "registered"
    LOADED = "loaded"
    FAILED = "failed"
    UNLOADED = "unloaded"


class ModuleCategory(str, Enum):
    """Spec section 9 — module categories."""
    CORE = "core"
    RECON = "recon"
    EXECUTION = "execution"
    FILE_OPS = "file_ops"
    RED_TEAM = "red_team"
    EVASION = "evasion"


@dataclass
class ModuleRequirement:
    """Represents a module dependency or capability requirement."""
    name: str
    version: str = ""
    optional: bool = False

    def satisfied_by(self, available: Dict[str, str]) -> bool:
        """Check whether this requirement is met by the available capabilities."""
        if self.name not in available:
            return self.optional
        if self.version and available[self.name] != self.version:
            return self.optional
        return True


@dataclass
class ModuleHealth:
    """Runtime health snapshot for a module."""
    name: str
    state: ModuleState
    registered_at: str
    last_error: Optional[str] = None
    load_attempts: int = 0
    last_executed: Optional[str] = None


class PupyModule(ABC):
    """
    Standardized module interface for Pupyteer.

    All modules MUST implement:
        - name, version, description, author
        - category
        - requirements (list of ModuleRequirement)
        - execute(session, args)

    Modules MAY override:
        - cleanup() — post-execution teardown
        - validate_args(args) — argument validation
        - is_compatible_with(os_name, arch) — platform gating
        - initialize() — async setup before first execution
    """

    # ── Module metadata (override in subclasses) ──────────────────────
    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""
    category: ModuleCategory = ModuleCategory.CORE
    requirements: List[ModuleRequirement] = field(default_factory=list)

    # Platform compatibility — empty list means "all platforms".
    compatible_systems: List[str] = []

    def __init_subclass__(cls, **kwargs):
        """Ensure each subclass gets its own requirements list (not shared Field object)."""
        super().__init_subclass__(**kwargs)
        if 'requirements' in cls.__dict__:
            val = cls.__dict__['requirements']
            if hasattr(val, 'default_factory'):
                cls.requirements = val.default_factory()
            elif not isinstance(val, list):
                cls.requirements = []
        else:
            # Inherit safely — create a new list
            cls.requirements = []

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self.config = config
        self.audit = audit
        self._state: Dict[str, Any] = {}
        self._initialized = False

    # ── Async lifecycle hooks ─────────────────────────────────────────

    async def initialize(self) -> None:
        """Optional async setup called once before the first execute()."""
        self._initialized = True

    @abstractmethod
    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the module against a target session.

        Args:
            session: Target session info or client connection.
            args:   Module-specific arguments.

        Returns:
            Dict with at least a ``status`` key (``"ok"`` or ``"error"``).
        """
        ...

    async def cleanup(self) -> None:
        """Optional cleanup after execution. Override if needed."""
        pass

    # ── Validation helpers ────────────────────────────────────────────

    def validate_args(self, args: Dict[str, Any]) -> List[str]:
        """Validate module arguments. Return list of error strings."""
        return []

    def is_compatible_with(self, os_name: str, arch: str = "") -> bool:
        """Check whether the module is compatible with the target platform."""
        if not self.compatible_systems:
            return True
        target = f"{os_name}".lower()
        if arch:
            target = f"{os_name}_{arch}".lower()
        return any(
            target == cs.lower() or os_name.lower() == cs.lower() or cs.lower() == "all"
            for cs in self.compatible_systems
        )

    def get_info(self) -> Dict[str, Any]:
        """Return a JSON-serialisable metadata dict."""
        reqs = self.requirements if isinstance(self.requirements, list) else []
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "category": self.category.value,
            "requirements": [r.name for r in reqs],
            "compatible_systems": self.compatible_systems,
        }

    def health(self) -> ModuleHealth:
        """Return current health snapshot."""
        return ModuleHealth(
            name=self.name or self.__class__.__name__,
            state=ModuleState.LOADED if self._initialized else ModuleState.REGISTERED,
            registered_at=datetime.now(timezone.utc).isoformat(),
        )


class ModuleRegistry:
    """
    Module discovery, loading, and lifecycle management.

    Supports loading from:
    - Built-in modules (pupyteer/server/modules/builtin/)
    - External modules (configurable paths)
    - Plugin directories

    Usage::

        registry = ModuleRegistry(config, audit)
        count = registry.discover()          # scan & validate paths
        mod = registry.create("sysinfo")     # instantiate by name
        result = await mod.execute(session, args)
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._modules: Dict[str, Type[PupyModule]] = {}
        self._health: Dict[str, ModuleHealth] = {}
        self._paths: List[Path] = []

        # Default paths
        builtin = Path(__file__).parent / "builtin"
        self._paths.append(builtin)

        external_paths = config.get("modules.paths", [])
        for p in external_paths:
            self._paths.append(Path(p))

    # ── Discovery ─────────────────────────────────────────────────────

    def discover(self) -> int:
        """Scan all configured paths and register discovered modules.

        Returns the number of successfully registered modules.
        """
        count = 0
        for path in self._paths:
            if not path.exists():
                path.mkdir(parents=True, exist_ok=True)
                continue
            for f in sorted(path.glob("*.py")):
                if f.name.startswith("_"):
                    continue
                try:
                    classes = self._load_from_file(f)
                    for cls in classes:
                        if self._validate_class(cls):
                            self._register_class(cls)
                            count += 1
                        else:
                            name = cls.name or cls.__name__
                            logger.warning(
                                "Module %s failed validation — skipped", name
                            )
                            self._health[name] = ModuleHealth(
                                name=name,
                                state=ModuleState.FAILED,
                                registered_at=datetime.now(timezone.utc).isoformat(),
                                last_error="Failed validation",
                            )
                except Exception as exc:
                    logger.warning("Failed to load module file %s: %s", f, exc)
                    # Record it so the operator can see a file silently contributed
                    # nothing to the registry.
                    self._health[f"file:{f.stem}"] = ModuleHealth(
                        name=f"file:{f.stem}",
                        state=ModuleState.FAILED,
                        registered_at=datetime.now(timezone.utc).isoformat(),
                        last_error=str(exc),
                    )
        logger.info("Discovered %d modules", count)
        return count

    def _load_from_file(self, path: Path) -> List[Type[PupyModule]]:
        """Load all PupyModule subclasses from a Python file."""
        spec = importlib.util.spec_from_file_location(
            f"pupyteer.modules.{path.stem}",
            path,
        )
        if not spec or not spec.loader:
            return []
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        classes = []
        for attr_name in dir(module):
            obj = getattr(module, attr_name)
            if isinstance(obj, type) and issubclass(obj, PupyModule) and obj is not PupyModule:
                classes.append(obj)
        return classes

    def _validate_class(self, cls: Type[PupyModule]) -> bool:
        """Run validation checks on a module class before registration."""
        # Must have a non-empty name.
        if not cls.name:
            logger.warning(
                "Module class %s has no name — skipped", cls.__name__
            )
            return False
        # Must implement execute (not the abstract stub).
        if getattr(cls.execute, "__isabstractmethod__", False):
            logger.warning(
                "Module %s does not implement execute() — skipped", cls.name
            )
            return False
        # requirements must be a list of ModuleRequirement.
        if not isinstance(cls.requirements, list):
            logger.warning(
                "Module %s has invalid requirements attribute — skipped", cls.name
            )
            return False
        return True

    def _register_class(self, cls: Type[PupyModule]) -> None:
        """Register a validated module class."""
        name = cls.name
        self._modules[name] = cls
        self._health[name] = ModuleHealth(
            name=name,
            state=ModuleState.REGISTERED,
            registered_at=datetime.now(timezone.utc).isoformat(),
        )
        logger.debug("Registered module: %s (category=%s)", name, cls.category.value)

    # ── Instantiation & execution ─────────────────────────────────────

    def create(self, name: str) -> Optional[PupyModule]:
        """Instantiate a module by name.

        Returns None if the module is not registered.
        """
        cls = self._modules.get(name)
        if not cls:
            return None
        return cls(self._config, self._audit)

    def create_and_init(self, name: str) -> Optional[PupyModule]:
        """Instantiate, call initialize(), and return the module."""
        instance = self.create(name)
        if instance is None:
            return None
        # initialize() is sync-or-async friendly via call schedule
        import asyncio
        coro = instance.initialize()
        if asyncio.iscoroutine(coro):
            try:
                loop = asyncio.get_running_loop()
                # We're inside an event loop — schedule it.
                task = asyncio.ensure_future(coro)
                # We can't block-wait here; callers in async context await directly.
                # Store the task so it runs.
                instance._init_task = task  # type: ignore[attr-defined]
            except RuntimeError:
                # No running loop — run synchronously.
                asyncio.run(coro)
        return instance

    async def execute(
        self,
        name: str,
        session: Any,
        args: Dict[str, Any],
        session_manager: Any = None,
    ) -> Dict[str, Any]:
        """Convenience: instantiate, validate, execute, cleanup in one call.

        ``session_manager`` is what lets a module queue a command on the agent and
        wait for its answer. Without it a module can only read the fields the
        listener already collected at registration, and it will do that quietly and
        return a green status — so callers that mean to work *on* the session pass
        it. ``ModuleExecutor`` injects the same thing on its path.
        """
        instance = self.create(name)
        if instance is None:
            return {"status": "error", "error": f"Module not found: {name}"}

        # Validate args
        errors = instance.validate_args(args)
        if errors:
            return {"status": "error", "error": "; ".join(errors)}

        if session_manager is not None:
            instance._session_manager = session_manager  # type: ignore[attr-defined]

        # Ensure initialized
        if not instance._initialized:
            await instance.initialize()

        try:
            result = await instance.execute(session, args)
            # Update health
            if name in self._health:
                self._health[name].last_executed = datetime.now(timezone.utc).isoformat()
                self._health[name].state = ModuleState.LOADED
            # Emit module_executed audit event (spec section 11)
            try:
                self._audit.emit_spec(
                    "module_executed",
                    result=result.get("status", "unknown"),
                    module=name,
                )
            except Exception:
                pass  # Never let audit failure break module execution
            return result
        except Exception as exc:
            logger.exception("Module %s raised during execute()", name)
            if name in self._health:
                self._health[name].last_error = str(exc)
                self._health[name].state = ModuleState.FAILED
            return {"status": "error", "error": str(exc)}
        finally:
            try:
                await instance.cleanup()
            except Exception:
                logger.warning("Module %s cleanup raised", name, exc_info=True)

    # ── Introspection ─────────────────────────────────────────────────

    def get(self, name: str) -> Optional[Type[PupyModule]]:
        """Return the class for a registered module, or None."""
        return self._modules.get(name)

    def list_all(self) -> List[Dict[str, Any]]:
        """List all registered modules with their metadata."""
        result = []
        for name, cls in sorted(self._modules.items()):
            instance = cls(self._config, self._audit)
            info = instance.get_info()
            # Attach health
            health = self._health.get(name)
            if health:
                info["state"] = health.state.value
            result.append(info)
        return result

    def list_by_category(self, category: ModuleCategory) -> List[Dict[str, Any]]:
        """List modules filtered by category."""
        return [m for m in self.list_all() if m["category"] == category.value]

    def list_compatible(self, os_name: str, arch: str = "") -> List[Dict[str, Any]]:
        """List modules compatible with the given platform."""
        result = []
        for name, cls in self._modules.items():
            instance = cls(self._config, self._audit)
            if instance.is_compatible_with(os_name, arch):
                info = instance.get_info()
                health = self._health.get(name)
                if health:
                    info["state"] = health.state.value
                result.append(info)
        return result

    def list_categories(self) -> List[str]:
        """Return the distinct categories present among registered modules."""
        return sorted({cls.category.value for cls in self._modules.values()})

    # ── Health / status ───────────────────────────────────────────────

    def get_health(self, name: str) -> Optional[ModuleHealth]:
        """Return the health record for a module."""
        return self._health.get(name)

    def list_health(self) -> List[Dict[str, Any]]:
        """Return health info for every registered module."""
        return [
            {
                "name": h.name,
                "state": h.state.value,
                "last_error": h.last_error,
                "load_attempts": h.load_attempts,
                "last_executed": h.last_executed,
                "registered_at": h.registered_at,
            }
            for h in self._health.values()
        ]

    # ── Runtime load / unload ─────────────────────────────────────────

    def load_external(self, file_path: str) -> Optional[str]:
        """Dynamically load a module from a file path at runtime.

        Returns the module name on success, or None on failure.
        """
        path = Path(file_path)
        if not path.exists() or not path.suffix == ".py":
            logger.error("External module path invalid: %s", file_path)
            return None
        try:
            classes = self._load_from_file(path)
            for cls in classes:
                if self._validate_class(cls):
                    self._register_class(cls)
                    logger.info("Externally loaded module: %s", cls.name)
                    return cls.name
                else:
                    logger.warning("External module failed validation: %s", cls.name)
            return None
        except Exception as exc:
            logger.error("Failed to load external module %s: %s", file_path, exc)
            return None

    def unload(self, name: str) -> bool:
        """Remove a module from the registry. Returns True if it existed."""
        if name in self._modules:
            del self._modules[name]
            if name in self._health:
                self._health[name].state = ModuleState.UNLOADED
            logger.info("Unloaded module: %s", name)
            return True
        return False

    def reload(self, name: str) -> bool:
        """Unload and re-discover a module by name.

        Only works for modules that can be traced back to their source file.
        Returns True if successful.
        """
        cls = self._modules.get(name)
        if cls is None:
            return False

        # Determine the source file from the class module
        module_path = getattr(cls, "__module__", "")
        if not module_path.startswith("pupyteer.modules."):
            return False

        # Remove and re-discover from all paths
        self.unload(name)
        for path in self._paths:
            file_path = path / f"{module_path.split('.')[-1]}.py"
            if file_path.exists():
                try:
                    classes = self._load_from_file(file_path)
                    for c in classes:
                        if c.name == name and self._validate_class(c):
                            self._register_class(c)
                            return True
                except Exception:
                    pass
        return False

    # ── Misc ──────────────────────────────────────────────────────────

    def count(self) -> int:
        """Return the number of registered modules."""
        return len(self._modules)

    def __contains__(self, name: str) -> bool:
        return name in self._modules

    def __len__(self) -> int:
        return len(self._modules)
