# Pupyteer Module Development Guide

**Version:** 1.0.0 (Nightfall)
**Last Updated:** 2026-09-19

---

## Table of Contents

1. [Overview](#overview)
2. [Module Structure](#module-structure)
3. [PupyModule API](#pupymodule-api)
4. [Creating Your First Module](#creating-your-first-module)
5. [Module Categories](#module-categories)
6. [Platform Compatibility](#platform-compatibility)
7. [Argument Validation](#argument-validation)
8. [Using Audit and Config](#using-audit-and-config)
9. [Error Handling](#error-handling)
10. [Module Discovery](#module-discovery)
11. [Testing Modules](#testing-modules)
12. [Examples](#examples)
13. [Best Practices](#best-practices)

---

## Overview

Pupyteer modules are the primary mechanism for extending framework functionality. Each module encapsulates a single capability — gathering system info, executing commands, exfiltrating files, or performing red-team actions.

### Module System Benefits

- **Standardized Interface** — All modules follow the same contract, making them interchangeable.
- **Auto-Discovery** — Drop a `.py` file in the modules directory; the registry finds it automatically.
- **Category Organization** — Modules are grouped by function for easy browsing.
- **Platform Awareness** — Modules declare compatible OS/architectures; the registry filters accordingly.
- **Lifecycle Management** — Modules have `execute()` and optional `cleanup()` for setup/teardown.

---

## Structure

A module is a Python file containing one or more classes that inherit from `PupyModule`:

```python
"""My custom module — does something useful."""

from __future__ import annotations
from pupyteer.server.modules.registry import PupyModule, ModuleCategory


class MyModule(PupyModule):
    """Short description of what this module does."""

    name = "my_module"
    version = "1.0.0"
    description = "Does something useful on the target"
    author = "Your Name"
    category = ModuleCategory.EXECUTION
    compatible_systems = []  # [] = all platforms

    async def execute(self, session, args: dict) -> dict:
        # Your logic here
        return {"status": "ok", "result": "..."}
```

### File Layout

```
pupyteer/server/modules/builtin/
├── __init__.py          # Package marker
├── recon.py             # Recon modules (sysinfo, ps, netinfo)
└── your_module.py       # Your custom module file
```

---

## PupyModule API

### Class Attributes (Required Overrides)

| Attribute | Type | Description |
|-----------|------|-------------|
| `name` | `str` | Unique module identifier (used in commands and listings) |
| `version` | `str` | Semantic version (e.g., "1.0.0") |
| `description` | `str` | One-line description shown in listings |
| `author` | `str` | Module author name or handle |
| `category` | `ModuleCategory` | Functional category (see below) |
| `requirements` | `List[ModuleRequired]` | Dependencies (optional) |
| `compatible_systems` | `List[str]` | Platform identifiers (empty = all) |

### Methods

#### `execute(session, args) → dict` (Async, Required)

The core module logic. Called by the task system when the module runs.

**Parameters:**
- `session` — The target session object (or session info dict)
- `args` — Module-specific arguments provided by the operator

**Returns:** A dictionary with at minimum a `"status"` key. Common conventions:
- `{"status": "ok", "data": {...}}` — Success with results
- `{"status": "ok", "message": "..."}` — Success with message
- `{"status": "error", "error": "..."}` — Failure with reason

#### `cleanup() → None` (Async, Optional)

Called after `execute()` completes (success or failure). Use for:
- Closing file handles
- Releasing resources
- Removing temporary files

Default implementation is a no-op.

#### `validate_args(args) → List[str]` (Override, Optional)

Validate module arguments before execution. Returns a list of error strings (empty = valid).

```python
def validate_args(self, args: dict) -> list:
    errors = []
    if not args.get("command"):
        errors.append("Missing required argument: command")
    return errors
```

#### `is_compatible_with(os_name, arch) → bool` (Override, Optional)

Check platform compatibility. Default checks `compatible_systems`.

```python
def is_compatible_with(self, os_name: str, arch: str = "") -> bool:
    if not self.compatible_systems:
        return True
    target = os_name.lower()
    if arch:
        target = f"{os_name}_{arch}".lower()
    return any(
        target == cs.lower() or os_name.lower() == cs.lower() or cs.lower() == "all"
        for cs in self.compatible_systems
    )
```

#### `get_info() → dict`

Returns module metadata as a dictionary. Used by the registry for listings.

---

## Creating Your First Module

### Step 1: Create the Module File

Create `pupyteer/server/modules/builtin/hello.py`:

```python
"""Hello World module — demonstrates the Pupyteer module API."""

from __future__ import annotations
from pupyteer.server.modules.registry import PupyModule, ModuleCategory


class HelloModule(PupyModule):
    """Simple greeting module."""

    name = "hello"
    version = "1.0.0"
    description = "Returns a greeting to verify agent connectivity"
    author = "Pupyteer Developer"
    category = ModuleCategory.CORE
    compatible_systems = []  # Works on all platforms

    async def execute(self, session, args: dict) -> dict:
        target = getattr(session, "hostname", "unknown")
        return {
            "status": "ok",
            "message": f"Hello from {target}!",
            "module_version": self.version,
        }
```

### Step 2: Test Discovery

```python
from pupyteer.server.modules.registry import ModuleRegistry

registry = ModuleRegistry(config, audit)
count = registry.discover()
print(f"Discovered {count} modules")

# Check if your module loaded
module_cls = registry.get("hello")
print(module_cls)  # <class 'HelloModule'>
```

Or via TUI:

```
pupyteer > help
  hello    Returns a greeting to verify agent connectivity
```

### Step 3: Execute the Module

```python
module = registry.create("hello")
result = await module.execute(session, {})
print(result)  # {"status": "ok", "message": "Hello from win10-pro!", ...}
```

---

## Categories

Modules are organized into categories. Choose the most specific category that fits:

| Category | Use For | Examples |
|----------|---------|----------|
| `CORE` | Infrastructure, session management, logging | Session health check, config viewer |
| `RECON` | Enumeration and discovery | System info, process list, network scan |
| `EXECUTION` | Running code or commands | Shell exec, PowerShell, shellcode |
| `FILE_OPS` | File system operations | Upload, download, file search |
| `RED_TTEAM` | Post-exploitation and lateral movement | Credential dump, persistence, pivoting |
| `EVASION` | Anti-detection and sandbox evasion | AMSI bypass, ETW patching, sleep obfuscation |

**Category Values (enum):**
```python
from pupyteer.server.modules.registry import ModuleCategory

ModuleCategory.CORE        # "core"
ModuleCategory.RECON       # "recon"
ModuleCategory.EXECUTION   # "execution"
ModuleCategory.FILE_OPS    # "file_ops"
ModuleCategory.RED_TEAM    # "red_team"
ModuleCategory.EVASION     # "evasion"
```

---

## Platform Compatibility

### Declaring Compatibility

```python
class WindowsOnlyModule(PupyModule):
    compatible_systems = ["windows"]          # Windows all arch
    # or
    compatible_systems = ["windows_x64"]       # Windows x64 only
    # or
    compatible_systems = ["windows", "linux"]  # Multiple platforms
    # or
    compatible_systems = []                    # All platforms
    # or
    compatible_systems = ["all"]               # Explicit all
```

### How It Works

The `is_compatible_with()` method compares the target OS/arch against `compatible_systems`:

```python
# Target: Windows x64
module.is_compatible_with("windows", "x64")
# compatible_systems = ["windows"] → True (OS match)
# compatible_systems = ["windows_x64"] → True (exact match)
# compatible_systems = ["linux"] → False
# compatible_systems = [] → True (no restriction)
```

### Platform Strings

| String | Meaning |
|--------|---------|
| `"windows"` | All Windows architectures |
| `"windows_x64"` | Windows 64-bit specifically |
| `"windows_x86"` | Windows 32-bit specifically |
| `"linux"` | All Linux architectures |
| `"linux_x64"` | Linux 64-bit specifically |
| `"darwin"` | macOS |
| `"android"` | Android |
| `"all"` | Every platform |

---

## Argument Validation

### Why Validate?

Argument validation catches configuration errors before the module runs on the agent, providing immediate feedback to the operator.

### How to Validate

```python
class PortScanModule(PupyModule):
    name = "portscan"
    category = ModuleCategory.RECON

    def validate_args(self, args: dict) -> list:
        errors = []

        target = args.get("target", "")
        if not target:
            errors.append("Missing required argument: target")
        elif not self._is_valid_target(target):
            errors.append(f"Invalid target format: {target}")

        ports = args.get("ports", "")
        if ports:
            try:
                self._parse_ports(ports)
            except ValueError as e:
                errors.append(f"Invalid ports: {e}")

        return errors

    def _is_valid_target(self, target: str) -> bool:
        # Simple validation — extend as needed
        return len(target) > 0 and " " not in target

    def _parse_ports(self, ports: str) -> list:
        # Parse "80,443,8080" or "1-1024"
        result = []
        for part in ports.split(","):
            if "-" in part:
                start, end = part.split("-", 1)
                result.extend(range(int(start), int(end) + 1))
            else:
                result.append(int(part))
        return result
```

### When Validation Runs

The task system calls `validate_args()` before queuing the task. If errors are returned:
- The task is NOT created
- Errors are displayed to the operator
- An audit event `task_validation_failed` is emitted

---

## Using Audit and Config

### Audit Logger

Every module instance has access to `self.audit`:

```python
class MyModule(PupyModule):
    async def execute(self, session, args: dict) -> dict:
        # Log module start
        self.audit.log_event(
            "module_executing",
            {"module": self.name, "version": self.version},
            session=getattr(session, "session_id", None),
        )

        try:
            result = await self._do_work(session, args)
            self.audit.log_event(
                "module_completed",
                {"module": self.name, "status": "success"},
                session=getattr(session, "session_id", None),
                result="success",
            )
            return result
        except Exception as e:
            self.audit.log_event(
                "module_failed",
                {"module": self.name, "error": str(e)},
                session=getattr(session, "session_id", None),
                result="error",
            )
            raise
```

### Configuration Access

Modules can access the global configuration:

```python
class MyModule(PupyModule):
    async def execute(self, session, args: dict) -> dict:
        timeout = self.config.get("timeouts.response", 60)
        log_level = self.config.get("logging.level", "INFO")

        # Use timeout for network operations
        response = await asyncio.wait_for(
            self._send_command(session, args),
            timeout=timeout,
        )
        return {"status": "ok", "response": response}
```

---

## Error Handling

### Guidelines

1. **Catch Specific Exceptions** — Never use bare `except:`.
2. **Return Structured Errors** — Use `{"status": "error", "error": "reason"}` for recoverable errors.
3. **Raise for Critical Failures** — Raise exceptions for unrecoverable errors (the task manager logs them).
4. **Clean Up in `finally`** — Release resources even on failure.

```python
class SafeModule(PupyModule):
    async def execute(self, session, args: dict) -> dict:
        handle = None
        try:
            handle = await self._open_resource(session)
            result = await self._process(handle, args)
            return {"status": "ok", "data": result}
        except ConnectionError as e:
            return {"status": "error", "error": f"Connection failed: {e}"}
        except PermissionError as e:
            return {"status": "error", "error": f"Access denied: {e}"}
        except asyncio.TimeoutError:
            return {"status": "error", "error": "Operation timed out"}
        except Exception as e:
            # Unexpected error — log and re-raise
            logger.exception("Unexpected error in %s", self.name)
            raise
        finally:
            if handle:
                await self._close_resource(handle)
```

---

## Discovery

### Automatic Discovery

The registry scans directories for Python files:

```python
registry = ModuleRegistry(config, audit)
registry.discover()  # Returns count of newly discovered modules
```

**Scan Order:**
1. `pupyteer/server/modules/builtin/` (always scanned)
2. Paths from `config["modules.paths"]` (external modules)

**Loading Process:**
1. Each `.py` file (not starting with `_`) is loaded via `importlib`
2. The registry finds the first `PupyModule` subclass
3. The class is registered under its `name` attribute (or class name)

### External Modules

Install modules from external sources by adding paths to config:

```yaml
modules:
  paths:
    - "/opt/pupyteer-modules/custom"
    - "/home/operator/my-modules"
```

Or place files in the built-in directory for automatic inclusion.

### Manual Registration

For programmatic registration:

```python
registry._register_class(MyCustomModule)
```

---

## Testing Modules

### Unit Testing

```python
import pytest
from pupyteer.server.modules.builtin.hello import HelloModule
from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger


@pytest.fixture
def module():
    config = ConfigManager()
    audit = AuditLogger(config)
    return HelloModule(config, audit)


@pytest.mark.asyncio
async def test_hello_module(module):
    # Mock session
    class MockSession:
        hostname = "test-machine"

    result = await module.execute(MockSession(), {})
    assert result["status"] == "ok"
    assert "test-machine" in result["message"]


@pytest.mark.asyncio
async def test_hello_module_info(module):
    info = module.get_info()
    assert info["name"] == "hello"
    assert info["version"] == "1.0.0"
    assert info["category"] == "core"
```

### Integration Testing

```python
@pytest.mark.asyncio
async def test_module_via_registry():
    config = ConfigManager()
    audit = AuditLogger(config)
    registry = ModuleRegistry(config, audit)
    registry.discover()

    module = registry.create("hello")
    assert module is not None

    class MockSession:
        hostname = "integration-test"

    result = await module.execute(MockSession(), {})
    assert result["status"] == "ok"
```

---

## Examples

### Recon Module — System Info

```python
class SystemInfoModule(PupyModule):
    name = "sysinfo"
    version = "1.0.0"
    description = "Collect system information (OS, hostname, architecture, user)"
    author = "Pupyteer Team"
    category = ModuleCategory.RECON
    compatible_systems = []  # All platforms

    async def execute(self, session, args: dict) -> dict:
        return {
            "status": "ok",
            "data": {
                "hostname": getattr(session, "hostname", "unknown"),
                "os": getattr(session, "os", "unknown"),
                "arch": getattr(session, "arch", "unknown"),
                "username": getattr(session, "username", "unknown"),
            },
        }
```

### Execution Module — Shell Command

```python
class ShellExecModule(PupyModule):
    name = "exec"
    version = "1.0.0"
    description = "Execute shell commands on target session"
    author = "Pupyteer Team"
    category = ModuleCategory.EXECUTION

    def validate_args(self, args: dict) -> list:
        errors = []
        if not args.get("command"):
            errors.append("Missing required argument: command")
        return errors

    async def execute(self, session, args: dict) -> dict:
        command = args["command"]
        # Placeholder — actual implementation dispatches to agent
        return {"status": "ok", "command": command, "output": ""}
```

### File Ops Module — Download

```python
class DownloadModule(PupyModule):
    name = "download"
    version = "1.0.0"
    description = "Download a file from the target"
    author = "Pupyteer Team"
    category = ModuleCategory.FILE_OPS

    def validate_args(self, args: dict) -> list:
        errors = []
        if not args.get("remote_path"):
            errors.append("Missing required argument: remote_path")
        return errors

    async def execute(self, session, args: dict) -> dict:
        remote_path = args["remote_path"]
        local_path = args.get("local_path", f"./loot/{remote_path}")
        # Implementation dispatches to agent for file transfer
        return {"status": "ok", "local_path": local_path, "size_bytes": 0}

    async def cleanup(self) -> None:
        # Ensure partial files are removed on failure
        pass
```

### Evasion Module — AMSI Bypass

```python
class AmsiBypassModule(PupyModule):
    name = "amsi_bypass"
    version = "1.0.0"
    description = "Patch AMSI to disable script scanning (Windows)"
    author = "Pupyteer Team"
    category = ModuleCategory.EVASION
    compatible_systems = ["windows"]

    async def execute(self, session, args: dict) -> dict:
        # Implementation patches AMSI.dll in-memory
        return {"status": "ok", "technique": "amsi_context_patch"}
```

---

## Best Practices

### Do

- **Keep Modules Single-Purpose** — Each module should do one thing well. Combine modules via tasks for complex workflows.
- **Validate Early** — Use `validate_args()` to catch errors before execution.
- **Use Structured Returns** — Always include `"status"` in return dicts. Use `"data"` for results.
- **Handle Platform Differences** — Use `compatible_systems` to declare platform restrictions.
- **Log Everything** — Use `self.audit` for all state changes and significant events.
- **Clean Up** — Override `cleanup()` to release resources, close handles, remove temp files.
- **Document Assumptions** — If a module requires specific privileges or conditions, document them in the description.
- **Version Your Modules** — Bump version on any behavior change.

### Don't

- **Don't Block the Event Loop** — Use `await` for all I/O. Offload CPU-bound work to executors.
- **Don't Hardcode Secrets** — Use `self.config` or environment variables for any credentials.
- **Don't Swallow Exceptions** — Always log or return errors; never silently fail.
- **Don't Assume Session Shape** — Use `getattr(session, "attr", "default")` for safety.
- **Don't Write to Disk Without Cleanup** — Any files created must be removed in `cleanup()`.
- **Don't Import Heavy Dependencies at Module Level** — Import inside `execute()` for optional dependencies.

### Module Checklist

Before submitting a module, verify:

- [ ] Class inherits from `PupyModule`
- [ ] `name`, `version`, `description`, `author`, `category` are set
- [ ] `compatible_systems` correctly declares platform support
- [ ] `validate_args()` implemented (if arguments are required)
- [ ] `execute()` is async and returns a dict with `"status"`
- [ ] `cleanup()` implemented (if resources are allocated)
- [ ] All exceptions are handled or logged
- [ ] Audit events emitted for significant actions
- [ ] Unit tests pass
- [ ] No hardcoded secrets or paths
