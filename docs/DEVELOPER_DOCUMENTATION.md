# Pupyteer Developer Documentation

**Version:** 1.0.0 (Nightfall)
**Last Updated:** 2026-09-19

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [Source Layout](#source-layout)
4. [Core Components](#core-components)
   - [ConfigManager](#configmanager)
   - [PupyteerEngine](#pupyteerengine)
   - [AuditLogger](#auditlogger)
   - [AuthLayer](#authlayer)
5. [Subsystem Managers](#subsystem-managers)
   - [SessionManager](#sessionmanager)
   - [TaskManager](#taskmanager)
   - [ProfileManager](#profilemanager)
   - [TransportManager](#transportmanager)
6. [Module System](#module-system)
7. [Protocol Interfaces](#protocol-interfaces)
8. [Async Architecture](#async-architecture)
9. [Error Handling](#error-handling)
10. [Adding New Features](#adding-new-features)
11. [Coding Standards](#coding-standards)
12. [Running Tests](#running-tests)

---

## Project Overview

Pupyteer is a from-scratch modernization of the Pupy C2 framework. It preserves the cross-platform agent ecosystem and modular post-exploitation capabilities while replacing the monolithic server with a clean, async, protocol-oriented architecture.

### Design Goals

- **Modularity** — Every subsystem is replaceable without rewriting others.
- **Testability** — Clear Protocol interfaces enable mock-based unit testing.
- **Auditability** — Every action emits structured, non-repudiable logs.
- **Operator Focus** — Common operations require minimal commands.
- **Extensibility** — New transports, profiles, and modules are first-class additions.

### Technology Stack

| Layer | Technology |
|-------|------------|
| Runtime | Python 3.8+ (asyncio) |
| Config | YAML with env-var overrides |
| CLI | `readline` + ANSI colors |
| Interfaces | `typing.Protocol` (runtime checkable) |
| Logging | stdlib `logging` + structured JSON audit |
| Crypto | `hashlib`, `hmac`, `secrets` (stdlib) |

---

## Architecture

### Engine as Orchestrator

The `PupyteerEngine` is the central coordinator. It owns all subsystems and manages their lifecycle:

```
PupyteerEngine
├── ConfigManager          (configuration access)
├── AuditLogger            (structured event logging)
├── AuthLayer              (operator auth)
├── ProfileManager         (C2 profiles)
├── TransportManager       (network listeners)
├── SessionManager         (agent sessions)
└── TaskManager            (async task queue)
```

Subsystem managers never reference each other directly — they communicate through the engine or via Protocol interfaces. This keeps coupling low and makes each subsystem independently testable.

### Data Flow

```
Operator → TUI → Engine → TaskManager → ModuleRegistry → Agent
                                ↑
                        SessionManager (lookup)
                                ↑
                        TransportManager (send/receive)
```

1. Operator enters command in TUI
2. TUI dispatches to engine method
3. Engine validates, audits, delegates
4. TaskManager queues task, workers execute
5. ModuleRegistry loads module, dispatches to agent
6. TransportManager sends payload, receives response
7. Results propagate back through TaskManager → TUI

---

## Source Layout

```
pupyteer/
├── __init__.py              # Package marker
├── main.py                  # CLI entry point, argparse
├── config/
│   ├── defaults/
│   │   └── pupyteer.yaml    # Default configuration
│   └── profiles/
│       └── https_standard.yaml  # Built-in C2 profile
├── server/
│   ├── __init__.py
│   ├── interfaces.py        # Protocol definitions (IConfig, ISessions, etc.)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py        # ConfigManager
│   │   ├── engine.py        # PupyteerEngine
│   │   ├── logging.py      # AuditLogger
│   │   └── auth.py          # AuthLayer
│   ├── sessions/
│   │   ├── __init__.py
│   │   └── manager.py       # SessionManager + SessionInfo
│   ├── tasks/
│   │   ├── __init__.py
│   │   └── manager.py       # TaskManager + TaskInfo
│   ├── profiles/
│   │   ├── __init__.py
│   │   └── manager.py       # ProfileManager
│   ├── transports/
│   │   ├── __init__.py
│   │   └── manager.py       # TransportManager
│   └── modules/
│       ├── __init__.py
│       ├── registry.py      # PupyModule ABC + ModuleRegistry
│       └── builtin/
│           ├── __init__.py
│           └── recon.py     # SystemInfoModule, ProcessListModule, etc.
├── tui/
│   ├── __init__.py
│   ├── app.py               # PupyteerTUI + CommandRegistry + Color
│   ├── commands/
│   ├── screens/
│   └── widgets/
├── payloads/
│   └── __init__.py
└── agent/
    └── __init__.py
```

---

## Core Components

### ConfigManager

**Location:** `pupyteer/server/core/config.py`

Hierarchical configuration with multiple override layers.

```python
from pupyteer.server.core.config import ConfigManager

config = ConfigManager("/path/to/config.yaml")
config.get("server.port")                    # → 8443
config.get("logging.level")                  # → "INFO"
config.set("operator.name", "new-operator")
config.all()                                 # → full dict
await config.validate()                      # → bool
```

**Override Priority (low to high):**
1. Built-in defaults
2. Explicit file path (`ConfigManager(path)`)
3. `./pupyteer.yaml`
4. `~/.config/pupyteer/config.yaml`
5. `/etc/pupyteer/config.yaml`
6. `PUPYTEER_*` environment variables

**Environment Variable Format:**
```
PUPYTEER_SERVER__PORT=9443  →  config["server"]["port"] = 9443
PUPYTEER_LOGGING__LEVEL=DEBUG  →  config["logging"]["level"] = "DEBUG"
```

Boolean coercion: `true/yes/on` → `True`, `false/no/off` → `False`. Numeric strings are coerced to `int` then `float`.

### PupyteerEngine

**Location:** `pupyteer/server/core/engine.py`

Central orchestrator. All subsystems are exposed as public attributes.

```python
from pupyteer.server.core.engine import PupyteerEngine

engine = PupyteerEngine("/path/to/config.yaml")

# Lifecycle
await engine.start()               # Initializes all subsystems
await engine.wait_for_shutdown()   # Blocks until shutdown signal
await engine.stop()                # Graceful shutdown

# Status snapshot
status = engine.get_status()
# {
#   "state": {"started": True, "active_sessions": 4, ...},
#   "config": {"server_host": "0.0.0.0", "server_port": 8443, ...},
#   "profiles": [...],
#   "transports": [...]
# }

# Subsystem access
engine.sessions    # SessionManager
engine.tasks       # TaskManager
engine.profiles    # ProfileManager
engine.transports  # TransportManager
engine.config      # ConfigManager
engine.audit       # AuditLogger
engine.auth        # AuthLayer
```

**Startup Order:**
1. ConfigManager validation
2. TransportManager initialization (bind listeners)
3. SessionManager initialization (start monitor)
4. TaskManager initialization (start workers)
5. ProfileManager initialization (load profiles)

**Shutdown Order:**
1. TaskManager (cancel workers and running tasks)
2. SessionManager (kill all sessions, stop monitor)
3. TransportManager (unbind listeners)
4. ProfileManager (unload profiles)

### AuditLogger

**Location:** `pupyteer/server/core/logging.py`

Structured JSON event emitter. Never stores secrets.

```python
from pupyteer.server.core.logging import AuditLogger

audit = AuditLogger(config)
entry = audit.log_event(
    event="task_created",
    data={"task_id": "abc123", "module": "sysinfo"},
    session="session-id",
    result="success",
)
```

**Redaction:** Fields matching `password`, `secret`, `token`, `key`, `credential` are automatically replaced with `***REDACTED***`.

**Output Destinations:**
- `pupyteer.audit` logger (stdout/stderr via stdlib logging)
- File at `config["logging.file"]` (if configured)

### AuthLayer

**Location:** `pupyteer/server/core/auth.py`

Operator authentication with file-backed credentials and rate limiting.

```python
from pupyteer.server.core.auth import AuthLayer

auth = AuthLayer(config, audit)

# Authenticate (returns token on success, None on failure)
token = auth.authenticate("admin", "changeme")

# Authorize (check token validity and permission)
if auth.authorize(token, "execute"):
    # Operator can run modules
    pass

# Get operator from token
operator = auth.get_operator(token)

# Revoke token
auth.revoke(token)

# Add new operator
auth.add_operator("alice", "secure-pass", {"read", "execute"})
```

**Rate Limiting:** After `security.max_failed_logins` (default: 5) consecutive failures, the account is locked until process restart.

**Token Format:** 64-character hex string (`secrets.token_hex(32)`). Tokens expire after `security.token_ttl` seconds (default: 3600).

---

## Subsystem Managers

### SessionManager

**Location:** `pupyteer/server/sessions/manager.py`

Manages agent session lifecycle: registration, lookup, search, tagging, and termination.

```python
from pupyteer.server.sessions.manager import SessionManager, SessionInfo, SessionState

session_mgr = SessionManager(config, transports, audit)
await session_mgr.initialize()

# Register new session
info = SessionInfo(
    session_id="",
    hostname="win10-pro",
    os="Windows",
    arch="x64",
    username="admin",
)
sid = await session_mgr.register(info)  # Returns UUID[:12]

# Lookup
session = await session_mgr.get(sid)
all_sessions = await session_mgr.list_all()

# Search
results = await session_mgr.search("linux")

# Tag
await session_mgr.tag(sid, ["production", "dc"])

# Kill
await session_mgr.kill(sid, reason="operator")

# Stats
count = session_mgr.count()
active = await session_mgr.count_active()
summary = await session_mgr.summary()
# {"total": 2, "by_os": {"Windows": 1, "Linux": 1}, "by_state": {"connected": 2}, "active": 2}
```

**SessionInfo Fields:** `session_id`, `hostname`, `os`, `arch`, `username`, `state`, `connected_at`, `last_checkin`, `profile`, `agent_version`, `tags`, `task_status`, `remote_address`, `capabilities`, `max_line`, `metadata`.

**Session States:** `CONNECTED`, `DISCONNECTED`, `TIMEOUT`, `ERROR`, `KILLED`.

**Capability gate.** `capabilities` and `max_line` come from the agent's `register` message, not from the server's build records — a session carries no payload id, so the payload's own claim is the only account of what is on the target. `interact()` resolves each command line to the one capability it needs (`sessions/capabilities.py`: a structured task needs its `action`, a recognised verb needs that verb's capability, anything else needs `exec`) and refuses what the session did not claim. A refusal completes in the queue with the refusal text as its result and is never handed out on a check-in, so the operator reads a refusal that names the implant's claim instead of cmd.exe's complaint about a word it had never seen. Shell text is not gated: both agents execute it. `max_line` sizes transfer chunks — see `sessions/transfer.py:chunk_budget()`, which caps a chunk at what fits one line of that agent's own reading buffer after base64 and framing.

A claim is only worth enforcing if the payload that made it answers the word, so three tables have to agree: `TYPED_VERBS`, the generated stub's `_parse_command`, and `bare_verb_action()` in `pe_template.c`. `test_every_typed_verb_is_a_word_the_agent_understands` checks the first two by parsing every verb in the server's table; the C side is checked against a live implant in `test_pe_payload_declares_the_tasks_it_answers`. The C payload routes a line that holds *nothing but* a recognised verb — `ping`, `sysinfo`, `network`, `ps`/`processes`, `fs_list`, `exit`/`shutdown` — to its own handler; anything with an argument after it is the shell's, because `ping host.example` is the host's ping program and the operator means that one. That is also what makes `sessions kill` work on a Windows implant: the order is a queued `exit`, and a payload that handed the word to cmd.exe exited its own child process and kept beaming at a session the server had already written off.

**Background Monitor:** Runs every 30 seconds. Sessions exceeding `session.timeout_seconds` since last check-in are marked `TIMEOUT`.

### TaskManager

**Location:** `pupyteer/server/tasks/manager.py`

Asynchronous task queue with concurrent worker pool.

```python
from pupyteer.server.tasks.manager import TaskManager, TaskState

task_mgr = TaskManager(config, sessions, audit)
await task_mgr.initialize()

# Create task
task_id = await task_mgr.create(
    name="sysinfo-001",
    module="sysinfo",
    session_id="a1b2c3d4e5f6",
    args={},
)

# Get status
task = await task_mgr.get(task_id)

# Cancel
await task_mgr.cancel(task_id)

# List/filter
all_tasks = await task_mgr.list_all()
running = await task_mgr.list_by_state(TaskState.RUNNING)
session_tasks = await task_mgr.list_by_session("a1b2c3d4e5f6")
count = task_mgr.count()
```

**Worker Model:** `tasks.max_concurrent` asyncio coroutines pull from a shared `asyncio.Queue`. Each worker runs tasks sequentially; concurrency comes from multiple workers.

**Task Lifecycle:** `QUEUED` → `RUNNING` → `COMPLETED` | `FAILED` | `CANCELLED`.

### ProfileManager

**Location:** `pupyteer/server/profiles/manager.py`

Manages C2 malleable profiles.

```python
from pupyteer.server.profiles.manager import ProfileManager

profile_mgr = ProfileManager(config, audit)
await profile_mgr.initialize()

# Access
active = profile_mgr.active_name()
all_profiles = profile_mgr.list()
profile = profile_mgr.get("HTTPS-Standard")

# Control
profile_mgr.load("HTTPS-Standard")
profile_mgr.validate("HTTPS-Standard")
```

### TransportManager

**Location:** `pupyteer/server/transports/manager.py`

Manages network transport listeners.

```python
from pupyteer.server.transports.manager import TransportManager

transport_mgr = TransportManager(config, profiles, audit)
await transport_mgr.initialize()

transports = transport_mgr.list()
# [{"type": "https", "host": "0.0.0.0", "port": 8443, "status": "listening"}]
```

---

## Module System

### PupyModule Abstract Base

All modules inherit from `PupyModule`:

```python
from pupyteer.server.modules.registry import PupyModule, ModuleCategory, ModuleRequirement

class MyModule(PupyModule):
    name = "my_module"
    version = "1.0.0"
    description = "Does something useful"
    author = "Your Name"
    category = ModuleCategory.EXECUTION
    requirements = [ModuleRequirement("paramiko", optional=True)]
    compatible_systems = ["windows", "linux"]  # [] = all

    async def execute(self, session, args: dict) -> dict:
        # Core logic here
        return {"status": "ok", "result": "..."}

    def validate_args(self, args: dict) -> list:
        errors = []
        if not args.get("target"):
            errors.append("Missing required argument: target")
        return errors
```

### Module Categories

| Category | Purpose |
|----------|---------|
| `CORE` | Session/task/config/logging infrastructure |
| `RECON` | System, network, process enumeration |
| `EXECUTION` | Command and shellcode execution |
| `FILE_OPS` | Upload, download, file management |
| `RED_TEAM` | Discovery, collection, simulation, assessment |
| `EVASION` | Anti-detection, sandbox evasion |

### Module Registry

```python
from pupyteer.server.modules.registry import ModuleRegistry

registry = ModuleRegistry(config, audit)

# Discovery
count = registry.discover()  # Scans builtin/ and configured paths

# Lookup
module_cls = registry.get("sysinfo")
module = registry.create("sysinfo")  # Instantiated with config + audit

# Listing
all_modules = registry.list_all()
recon = registry.list_by_category(ModuleCategory.RECON)
compatible = registry.list_compatible("windows", "x64")
```

**Discovery Scans:**
1. `pupyteer/server/modules/builtin/`
2. Paths from `config["modules.paths"]`

Each `.py` is loaded via `importlib.util.spec_from_file_location`. The registry
registers **every** `PupyModule` subclass it finds in the file, not just the
first, so one file can contribute several modules. A file that raises on import
is skipped and recorded as a failed module so the console can warn about it.

### Built-in Modules

Modules in `pupyteer/server/modules/builtin/`:

| Module | Category | File | Description |
|--------|----------|------|-------------|
| `sysinfo` | RECON | `recon.py` | Collect system info (hostname, OS, arch, user) |
| `ps` | RECON | `recon.py` | Enumerate running processes |
| `netinfo` | RECON | `recon.py` | Collect network interfaces, routes, connections |
| `discovery` | RED_TEAM | `recon.py` | Run discovery commands (whoami, ipconfig, ...) |
| `credential_collect` | RED_TEAM | `recon.py` | Report credential locations (**simulation only**) |
| `lateral_sim` | RED_TEAM | `recon.py` | Enumerate lateral paths (**simulation only**) |
| `assess` | RED_TEAM | `recon.py` | Run security-assessment checks |
| `exec` | EXECUTION | `recon.py` | Execute shell commands on target |
| `upload` | FILE_OPS | `recon.py` | Upload a file to the target (chunked) |
| `download` | FILE_OPS | `recon.py` | Download a file from the target (chunked) |
| `file_list` | FILE_OPS | `recon.py` | List files and directories on the target |
| `ping` | RECON | `implant_actions.py` | Liveness check — confirm the agent replies |
| `screenshot` | RECON | `implant_actions.py` | Capture the target screen to a local PNG |
| `privesc` | RED_TEAM | `implant_actions.py` | Enumerate privilege-escalation posture |
| `migrate` | RED_TEAM | `implant_actions.py` | Migrate the agent into another process |
| `evasion_test` | EVASION | `evasion.py` | Run detection/evasion test checks |
| `evasion_config` | EVASION | `evasion.py` | Inspect evasion configuration |

`implant_actions.py` modules wrap structured agent actions the Python stub
already implements and that `sessions.capabilities` gates by declared capability.
A payload built without the matching feature (e.g. `modules.screenshot`) gets a
clear refusal rather than a fabricated result.

The five anti-forensics modules in `antiforensics.py` (`log_clear`,
`timestamp_match`, `artifact_wipe`, `prefetch_delete`, `recycle_clear`) are
**intentionally not registered**: they destroy evidence on a host, carry no test
coverage, and reference a `ModuleCategory` member that is deliberately left
undefined. See `tests/unit/test_modules.py` — the disabled state is pinned as a
reviewed invariant, not an import bug.

---

## Protocol Interfaces

**Location:** `pupyteer/server/interfaces.py`

All subsystem contracts are defined as `typing.Protocol` classes. Any object implementing these methods can be substituted for the built-in manager:

| Protocol | Methods | Description |
|----------|---------|-------------|
| `IConfig` | `get`, `set`, `validate`, `all` | Configuration access |
| `IAudit` | `log_event` | Structured audit logging |
| `IAuth` | `authenticate`, `authorize`, `get_operator`, `revoke` | Operator auth |
| `ISessions` | `initialize`, `shutdown`, `register`, `get`, `list_all`, `remove`, `kill`, `search`, `tag`, `update_checkin`, `count`, `count_active`, `summary` | Session lifecycle |
| `ITasks` | `initialize`, `shutdown`, `create`, `get`, `cancel`, `list_all`, `list_by_state`, `list_by_session`, `count` | Task queue |
| `ITransports` | `initialize`, `shutdown`, `create`, `register`, `unregister`, `get`, `list`, `available_types` | Transport management |
| `IProfiles` | `initialize`, `shutdown`, `load`, `validate`, `active_name`, `list`, `get_active` | Profile management |
| `IEngine` | `start`, `stop`, `wait_for_shutdown`, `get_status` | Top-level orchestrator |

Using Protocols enables:
- **Mocking** in tests without real infrastructure
- **Swapping** implementations (e.g., Redis-backed sessions)
- **Type checking** via `runtime_checkable` and static analysis

---

## Async Architecture

Pupyteer is built on Python's `asyncio`. All I/O operations and subsystem lifecycle methods are `async`.

### Event Loop

The TUI runs its own event loop and dispatches commands asynchronously:

```python
async def run(self):
    await self._engine.start()
    while self._running:
        line = await loop.run_in_executor(None, lambda: input(self._prompt))
        # ... parse and dispatch
        await cmd["handler"](cmd_args)
```

### Concurrency Model

- **Task Workers:** `tasks.max_concurrent` coroutines pull from a shared queue
- **Session Monitor:** Background coroutine polling every 30 seconds
- **TUI Input:** Blocking `input()` offloaded to `run_in_executor`
- **Engine Shutdown:** `asyncio.Event` signals termination

### Locking

- `SessionManager._lock` — protects session dictionary mutations
- `TaskManager._lock` — protects task dictionary mutations

Both use `asyncio.Lock` for coroutine-safe access.

---

## Error Handling

Pupyteer uses a layered error-handling strategy:

1. **Command Layer (TUI):** Catches exceptions from handlers, prints red error message, logs full traceback.
2. **Manager Layer:** Catches operational errors, emits audit events with `result="error"`, re-raises critical failures.
3. **Engine Layer:** Catches subsystem initialization failures, triggers rollback (calls `stop()`), emits `engine_start_failed` audit event.
4. **Main Entry:** Catches `KeyboardInterrupt`, returns exit code 0.

**Best Practices:**
- Never silently swallow exceptions in modules
- Always emit an audit event on failure
- Use `logger.exception()` for tracebacks in logs
- User-facing messages go to stdout (red); debug info goes to logs

---

## Adding New Features

### Adding a New Subsystem Manager

1. Create the manager class in `pupyteer/server/<name>/manager.py`
2. Add a Protocol interface in `pupyteer/server/interfaces.py`
3. Wire it into `PupyteerEngine.__init__()` in `engine.py`
4. Add lifecycle calls in `engine.py` `start()` and `stop()`
5. Add TUI commands in `tui/app.py` `_register_commands()`
6. Write tests in `tests/unit/`

### Adding a New Transport

1. Create a transport class with the standard interface methods
2. Register it in `TransportManager._transports`
3. Add configuration schema to `config/profiles/`
4. Update `available_types()` return value

### Adding a New Module

1. Create a `.py` file in `pupyteer/server/modules/builtin/` (or external path)
2. Subclass `PupyModule`
3. Implement `execute()` and optionally `cleanup()` and `validate_args()`
4. Run `registry.discover()` to auto-load

---

## Coding Standards

- **Python Version:** 3.8+ (uses `from __future__ import annotations`, `typing.Protocol`)
- **Async First:** All I/O and lifecycle methods must be `async`
- **Type Hints:** All public methods must have type annotations
- **Docstrings:** Google-style docstrings on all public classes and methods
- **Imports:** Absolute imports within the `pupyteer` package
- **Naming:** `snake_case` for functions/variables, `PascalCase` for classes, `UPPER_SNAKE` for constants
- **Logging:** Use `logging.getLogger("pupyteer.<subsystem>")` — never the root logger
- **Audit Events:** All state-changing operations must emit an audit event via `self._audit.log_event()`

---

## Running Tests

```bash
# From project root
python -m pytest tests/ -v

# Specific test category
python -m pytest tests/unit/ -v
python -m pytest tests/integration/ -v

# With coverage
python -m pytest tests/ --cov=pupyteer --cov-report=term-missing
```

Test structure mirrors source layout:

```
tests/
├── unit/
│   ├── test_config.py
│   ├── test_engine.py
│   ├── test_sessions.py
│   ├── test_tasks.py
│   ├── test_profiles.py
│   ├── test_transports.py
│   ├── test_auth.py
│   └── test_modules.py
├── integration/
│   └── test_tui_engine.py
└── regression/
    └── test_full_lifecycle.py
```
