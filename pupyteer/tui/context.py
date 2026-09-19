"""Module context — tracks active module and options (MSF-style).

Provides the core UX layer for module interaction:
- Tracks the active module (PupyModule instance)
- Manages module options with type coercion
- Validates required options before execution
- Builds effective args dict for module dispatch
"""
from __future__ import annotations

import copy
import logging
from typing import Any, Dict, List, Optional

from pupyteer.server.modules.registry import PupyModule, ModuleRegistry

logger = logging.getLogger("pupyteer.tui.context")


class ModuleContext:
    """Tracks active module and its options, providing MSF-style module interaction.

    Usage::

        ctx = ModuleContext(registry)
        ctx.use("sysinfo")
        ctx.set_option("SESSION", "abc123")
        missing = ctx.validate_required()
        args = ctx.get_effective_args()
    """

    def __init__(self, registry: ModuleRegistry):
        self._registry = registry
        self._active_module: Optional[PupyModule] = None
        self._active_module_class: Optional[type] = None
        self._options: Dict[str, Dict[str, Any]] = {}

    # ── Properties ──────────────────────────────────────────────────

    @property
    def has_active_module(self) -> bool:
        """Whether a module is currently active."""
        return self._active_module is not None

    @property
    def module_name(self) -> Optional[str]:
        """Name of the active module, or None."""
        if self._active_module:
            return self._active_module.name
        return None

    @property
    def module(self) -> Optional[PupyModule]:
        """The active module instance, or None."""
        return self._active_module

    @property
    def module_class(self) -> Optional[type]:
        """The active module class, or None."""
        return self._active_module_class

    @property
    def registry(self) -> ModuleRegistry:
        """The module registry used by this context."""
        return self._registry

    # ── Module selection ────────────────────────────────────────────

    def use(self, module_name: str) -> Dict[str, Any]:
        """Set the active module by name.

        Args:
            module_name: Name of the module to activate.

        Returns:
            Dict with 'status' and either 'module' info or 'error'.
        """
        cls = self._registry.get(module_name)
        if cls is None:
            return {"status": "error", "error": f"Module not found: {module_name}"}

        instance = self._registry.create(module_name)
        if instance is None:
            return {"status": "error", "error": f"Failed to instantiate module: {module_name}"}

        self._active_module = instance
        self._active_module_class = cls

        # Initialize options from module's options definition
        self._options = {}
        module_options = getattr(cls, 'options', [])
        if isinstance(module_options, list):
            for opt_def in module_options:
                if not isinstance(opt_def, dict):
                    continue
                name = opt_def.get('name', '')
                if name:
                    self._options[name] = {
                        'value': opt_def.get('default', ''),
                        'required': opt_def.get('required', False),
                        'description': opt_def.get('description', ''),
                        'type': opt_def.get('type', 'str'),
                    }

        info = instance.get_info()
        logger.info("Module context set to: %s (category=%s)", module_name, info.get('category'))
        return {"status": "ok", "module": info}

    # ── Option management ───────────────────────────────────────────

    def set_option(self, name: str, value: str) -> Dict[str, Any]:
        """Set a module option value.

        Args:
            name: Option name.
            value: Value to set (as string, will be coerced on get_effective_args).

        Returns:
            Dict with 'status' and either 'option'/'value' or 'error'.
        """
        if not self.has_active_module:
            return {"status": "error", "error": "No active module. Use 'use <module>' first."}

        if name not in self._options:
            # Allow setting unknown options (MSF behavior — ad-hoc options)
            self._options[name] = {
                'value': value,
                'required': False,
                'description': '',
                'type': 'str',
            }
        else:
            self._options[name]['value'] = value

        return {"status": "ok", "option": name, "value": value}

    def unset_option(self, name: str) -> Dict[str, Any]:
        """Unset a module option (clears its value).

        Args:
            name: Option name to clear.

        Returns:
            Dict with 'status' and either 'option' or 'error'.
        """
        if not self.has_active_module:
            return {"status": "error", "error": "No active module. Use 'use <module>' first."}

        if name in self._options:
            self._options[name]['value'] = ''
            return {"status": "ok", "option": name}

        return {"status": "error", "error": f"Unknown option: {name}"}

    def get_option(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a single option's details.

        Args:
            name: Option name.

        Returns:
            Dict with 'value', 'required', 'description', 'type' or None.
        """
        opt = self._options.get(name)
        return copy.deepcopy(opt) if opt else None

    def get_all_options(self) -> Dict[str, Dict[str, Any]]:
        """Get all options as a deep copy."""
        return copy.deepcopy(self._options)

    # ── Validation & args building ──────────────────────────────────

    def validate_required(self) -> List[str]:
        """Return list of missing required option names.

        Returns:
            List of option names that are required but have empty values.
        """
        missing = []
        for name, opt in self._options.items():
            if opt.get('required', False) and not opt.get('value'):
                missing.append(name)
        return missing

    def get_effective_args(self) -> Dict[str, Any]:
        """Build args dict from current option values (excluding empty).

        Performs type coercion based on option type:
        - 'int', 'port' -> int
        - 'bool' -> bool
        - 'str' (default) -> str

        Returns:
            Dict of option name -> coerced value.
        """
        args: Dict[str, Any] = {}
        for name, opt in self._options.items():
            val = opt.get('value', '')
            if val == '' or val is None:
                continue
            opt_type = opt.get('type', 'str')
            if opt_type in ('int', 'port'):
                try:
                    val = int(val)
                except (ValueError, TypeError):
                    pass
            elif opt_type == 'bool':
                val = val.lower() in ('true', 'yes', '1', 'on')
            args[name] = val
        return args

    # ── Lifecycle ───────────────────────────────────────────────────

    def clear(self) -> None:
        """Clear active module and all options, returning to main context."""
        self._active_module = None
        self._active_module_class = None
        self._options = {}
        logger.debug("Module context cleared")

    def __repr__(self) -> str:
        if self.has_active_module:
            return f"ModuleContext(module={self.module_name}, options={len(self._options)})"
        return "ModuleContext(inactive)"
