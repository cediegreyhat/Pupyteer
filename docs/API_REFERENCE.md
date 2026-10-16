# Pupyteer API Reference

> **Version:** 1.0.0 ("Nightfall")  
> **Description:** Modular Red-Team Operations Framework  
> **Generated from source code analysis**

---

## Table of Contents

1. [Overview & Architecture](#1-overview--architecture)
2. [Core Engine (`pupyteer.server.core.engine`)](#2-core-engine-pupyteercoreengine)
3. [Configuration (`pupyteer.server.core.config`)](#3-configuration-pupyteercoreconfig)
4. [Session Management (`pupyteer.server.sessions`)](#4-session-management-pupyteersessions)
5. [Task Management (`pupyteer.server.tasks`)](#5-task-management-pupyteertasks)
6. [Module System (`pupyteer.server.modules`)](#6-module-system-pupyteermodules)
7. [Transports & Listener (`pupyteer.server.transports`)](#7-transports--listener-pupyteertransports)
8. [Profiles (`pupyteer.server.profiles`)](#8-profiles-pupyteerprofiles)
9. [Payload System (`pupyteer.payloads`)](#9-payload-system-pupyteerpayloads)
10. [Evasion System (`pupyteer.server.evasion`)](#10-evasion-system-pupyteerevasion)
11. [CLI & Entry Points (`pupyteer.cli`, `pupyteer.main`)](#11-cli--entry-points-pupyteercli-pupytermain)
12. [TUI System (`pupyteer.tui`)](#12-tui-system-pupyteertui)
13. [Authentication & RBAC](#13-authentication--rbac)
14. [Utilities & Tools](#14-utilities--tools)

---

## 1. Overview & Architecture

Pupyteer is an asynchronous Python C2 (Command & Control) framework built on `asyncio`. It follows a modular plugin architecture with a central orchestrator (`PupyteerEngine`) that manages all subsystems.

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    PupyteerEngine                        │
│  (Central Orchestrator — server/core/engine.py)          │
├─────────┬─────────┬─────────┬─────────┬─────────────────┤
│ Sessions│  Tasks  │ Modules │Transports│  Payloads      │
│ Manager │ Manager │Registry │ Manager │  Manager        │
├─────────┴─────────┴─────────┴─────────┴─────────────────┤
│  ConfigManager  │  AuthLayer  │  RBAC  │  AuditLogger   │
├─────────────────┼─────────────┼────────┼────────────────┤
│  ProfileManager │  Pipeline   │ Evasion│  AgentKeys     │
└─────────────────┴─────────────┴────────┴────────────────┘
         │                                    │
    ┌────▼────┐                        ┌──────▼──────┐
    │   TUI   │                        │   CLI       │
    │(tui/)   │                        │(cli.py)     │
    └─────────┘                        └─────────────┘
```

### Package Structure

```
pupyteer/
├── __init__.py              # Package exports
├── main.py                  # Entry point
├── cli.py                   # Non-interactive CLI
├── agent/
│   └── core/
│       ├── sleep_mask.py    # Memory obfuscation
│       └── stub.py          # Agent stub generator
├── payloads/
│   ├── manager.py           # Payload lifecycle
│   └── pe_builder.py        # Windows PE builder
├── server/
│   ├── core/
│   │   ├── engine.py        # Primary orchestrator
│   │   ├── c2.py            # Legacy engine
│   │   ├── config.py        # Configuration
│   │   ├── auth.py          # Authentication
│   │   ├── rbac.py          # Role-based access control
│   │   ├── session_auth.py  # Session authorization
│   │   ├── agent_keys.py    # Agent key registry
│   │   ├── audit.py         # Audit logging
│   │   ├── errors.py        # Error hierarchy
│   │   ├── queue.py         # Task queue
│   │   ├── pipeline.py      # Build→Test pipeline
│   │   ├── enrollment.py    # Enrollment secrets
│   │   ├── tls.py           # TLS certificate management
│   │   ├── validation.py    # Config validation
│   │   └── logging.py       # Logging setup
│   ├── sessions/
│   │   ├── manager.py       # Session lifecycle
│   │   ├── capabilities.py  # Capability system
│   │   └── transfer.py      # File transfer
│   ├── tasks/
│   │   └── manager.py       # Task dispatch & results
│   ├── modules/
│   │   ├── registry.py      # Module discovery
│   │   ├── executor.py      # Module execution
│   │   └── builtin/         # Built-in modules
│   │       ├── recon.py
│   │       ├── exploitation.py
│   │       ├── implant_actions.py
│   │       ├── antiforensics.py
│   │       └── evasion.py
│   ├── transports/
│   │   ├── manager.py       # Transport management
│   │   ├── listener.py      # TCP listener
│   │   ├── http_listener.py # HTTP listener
│   │   ├── tcp_transport.py # TCP transport
│   │   └── http_transports.py # HTTP/HTTPS transports
│   ├── profiles/
│   │   ├── manager.py       # Profile CRUD
│   │   ├── parser.py        # Profile parsing
│   │   └── validator.py     # Profile validation
│   └── evasion/
│       ├── manager.py       # Evasion test manager
│       ├── obfuscator.py    # Obfuscation engine
│       └── runner.py        # Evasion test runner
├── tui/
│   ├── app.py               # TUI application
│   ├── context.py           # Module context
│   ├── themes.py            # Theme system
│   └── commands/            # TUI command modules
└── tools/
    └── callback_test.py     # Callback testing
```

### Key Design Patterns

- **Async-first:** All I/O operations use `async`/`await`
- **Subsystem isolation:** Each subsystem has its own manager with `initialize()`/`shutdown()` lifecycle
- **Plugin architecture:** Modules are discovered and loaded dynamically via `ModuleRegistry`
- **Profile-driven:** C2 behavior is configured through profiles (URI patterns, headers, etc.)
- **RBAC:** Four-role permission system (VIEWER, OPERATOR, ADMIN, SYSTEM)

---

## 2. Core Engine (`pupyteer.server.core.engine`)

### `EnginePhase` (Enum)

```python
class EnginePhase(str, Enum):
    INITIALIZED = "initialized"
    STARTING    = "starting"
    RUNNING     = "running"
    STOPPING    = "stopping"
    STOPPED     = "stopped"
    ERROR       = "error"
```

### `EngineState` (Dataclass)

```python
@dataclass
class EngineState:
    started: bool = False
    shutting_down: bool = False
    active_sessions: int = 0
    queued_tasks: int = 0
    loaded_profile: Optional[str] = None
    uptime_seconds: float = 0.0
    phase: str = EnginePhase.INITIALIZED.value
```

### `PupyteerEngine` (Class)

Central C2 orchestrator. Manages lifecycle of all subsystems.

#### Constructor

```python
def __init__(self, config_path: Optional[str] = None)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `phase` | `EnginePhase` | Current engine lifecycle phase |
| `is_running` | `bool` | True if engine is fully started |
| `config` | `ConfigManager` | Configuration manager |
| `audit` | `AuditLogger` | Audit logger |
| `auth` | `AuthLayer` | Authentication layer |
| `agent_keys` | `AgentKeyRegistry` | Registry of trusted per-agent public keys |
| `authz` | `SessionAuthorization` | Session authorization |
| `rbac` | `PermissionChecker` | Permission checker |
| `sessions` | `SessionManager` | Session manager |
| `tasks` | `TaskManager` | Task manager |
| `profiles` | `ProfileManager` | Profile manager |
| `transports` | `TransportManager` | Transport manager |
| `evasion` | `EvasionTestManager` | Evasion test manager |
| `payloads` | `PayloadManager` | Payload manager |
| `pipeline` | `PipelineManager` | Pipeline manager |
| `modules` | `ModuleExecutor` | Module execution engine |
| `module_registry` | `ModuleRegistry` | Module registry |
| `queue` | `TaskQueue` | Priority task queue |
| `error` | `Optional[C2EngineError]` | Last error that caused ERROR phase |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `start` | `async start() -> None` | Initialize and start all subsystems in dependency order |
| `stop` | `async stop(timeout: float = 30.0) -> None` | Gracefully shut down all subsystems in reverse order |
| `wait_for_shutdown` | `async wait_for_shutdown() -> None` | Block until shutdown is complete |
| `get_status` | `get_status() -> Dict[str, Any]` | Return current engine status snapshot |
| `health_check` | `async health_check() -> Dict[str, Any]` | Perform health check on all subsystems |
| `submit_task` | `async submit_task(name: str, module: str = "", session_id: Optional[str] = None, args: Optional[Dict[str, Any]] = None, priority: TaskPriority = TaskPriority.NORMAL) -> str` | Submit a task to the priority queue |
| `attach_signal_handlers` | `attach_signal_handlers(loop: Optional[asyncio.AbstractEventLoop] = None) -> None` | Attach SIGINT/SIGTERM handlers for graceful shutdown |

#### Usage Example

```python
import asyncio
from pupyteer import PupyteerEngine

async def run():
    engine = PupyteerEngine(config_path="/path/to/config.yaml")
    await engine.start()
    
    # Submit a task
    task_id = await engine.submit_task(
        name="recon.system_info",
        module="recon",
        session_id="sess_001",
        args={"target": "all"}
    )
    
    # Check status
    status = engine.get_status()
    print(f"Active sessions: {status['active_sessions']}")
    
    await engine.stop()

asyncio.run(run())
```

---

## 3. Configuration (`pupyteer.server.core.config`)

### Constants

| Name | Type | Value | Description |
|------|------|-------|-------------|
| `DEFAULT_OPERATORS_FILE` | `str` | `"./data/keys/operators.json"` | Operator credentials location |
| `DEFAULT_AUDIT_LOG_FILE` | `str` | `"./logs/audit.json"` | Default audit trail path |
| `DEFAULT_CONFIG` | `Dict[str, Any]` | *(see below)* | Default configuration tree |

### `DEFAULT_CONFIG` Structure

```python
{
    "server": {
        "host": "0.0.0.0",
        "port": 8443,
        "backlog": 10,
        "http_port": 0,           # 0 = disabled
        "http_uri": "/index.html",
        "tls": True,
        "tls_cert": "",
        "tls_key": "",
        "tls_hostnames": [],
        "agent_auth": True,
        "agent_auth_file": ""
    },
    "logging": {
        "level": "INFO",
        "format": "json"
    },
    "audit": {
        "log_file": "./logs/audit.json",
        "max_bytes": 10485760,
        "backup_count": 5,
        "compress": True
    },
    "operator": {
        "name": "unknown",
        "theme": "dark"
    },
    "profile": {
        "default": "HTTPS-Standard"
    },
    "security": {
        "require_auth": True,
        "token_ttl": 3600,
        "max_failed_logins": 5,
        "lockout_seconds": 300,
        "operators_file": "./data/keys/operators.json"
    },
    "paths": {
        "payload_artifacts": "./payloads/artifacts",
        "profiles": "./config/profiles",
        "logs": "./logs"
    },
    "payloads": {
        "mingw_path": "x86_64-w64-mingw32-gcc"
    },
    "evasion": {
        "test_mode": False,
        "litterbox_url": "",
        "virustotal_enabled": True,
        "virustotal_max_positives": 5
    }
}
```

### `ConfigManager` (Class)

Hierarchical config loader with environment-specific overrides.

#### Constructor

```python
def __init__(self, path: Optional[str] = None, environment: Optional[str] = None)
```

**Search order:**
1. Explicit path (if provided)
2. `pupyteer.yaml` / `.json` in cwd
3. `~/.config/pupyteer/config.yaml` / `.json`
4. `/etc/pupyteer/config.yaml` / `.json`
5. Environment-specific overlay (based on `PUPYTEER_ENV`)
6. `PUPYTEER_*` env vars (uppercase, double-underscore separator)

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `environment` | `str` | Current environment name (dev/staging/prod) |
| `sources` | `List[str]` | List of loaded config file paths |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `get` | `get(dotted_key: str, default: Any = None) -> Any` | Retrieve value via dotted path (e.g. `'server.port'`) |
| `set` | `set(dotted_key: str, value: Any) -> None` | Set value via dotted path, creating intermediate dicts |
| `all` | `all() -> Dict[str, Any]` | Return deep copy of full config |
| `all_safe` | `all_safe() -> Dict[str, Any]` | Return deep copy with sensitive values redacted |
| `validate` | `async validate() -> bool` | Validate loaded configuration |
| `save` | `save(path: str) -> None` | Persist config to YAML or JSON |
| `generate_default` | `@classmethod generate_default(path: str) -> None` | Write default config to file |

#### Usage Example

```python
from pupyteer.server.core.config import ConfigManager

config = ConfigManager(path="/path/to/config.yaml", environment="production")

# Get values
port = config.get("server.port", 8443)
tls_enabled = config.get("server.tls", True)

# Set values
config.set("server.port", 9443)

# Validate
is_valid = await config.validate()

# Save
config.save("/path/to/output.yaml")
```

---

## 4. Session Management (`pupyteer.server.sessions`)

### `SessionState` (Enum)

```python
class SessionState(str, Enum):
    CONNECTED    = "connected"
    DISCONNECTED = "disconnected"
    TIMEOUT      = "timeout"
    ERROR        = "error"
    KILLED       = "killed"
```

### `SessionInfo` (Dataclass)

```python
@dataclass
class SessionInfo:
    session_id: str
    hostname: str = ""
    os: str = ""
    arch: str = ""
    username: str = ""
    state: SessionState = SessionState.CONNECTED
    connected_at: float = 0.0
    last_checkin: float = 0.0
    killed_at: float = 0.0
    profile: str = ""
    agent_version: str = ""
    tags: List[str] = field(default_factory=list)
    task_status: str = "idle"
    remote_address: str = ""
    beacon_token: str = ""
    capabilities: List[str] = field(default_factory=list)
    max_line: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `uptime_seconds` | `float` | Seconds since connection |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `to_dict` | `to_dict() -> Dict[str, Any]` | Serialize to dict (excludes beacon_token) |

### `SessionManager` (Class)

Manages agent session lifecycle: registration, lookup, filtering, state tracking, heartbeat monitoring, tagging, search, graceful termination.

#### Constructor

```python
def __init__(self, config: ConfigManager, transports: Any, audit: AuditLogger, profiles: Any = None)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `async initialize() -> None` | Start session manager background monitoring |
| `shutdown` | `async shutdown() -> None` | Terminate all sessions and stop monitoring |
| `register` | `async register(info: SessionInfo) -> str` | Register a new session, returns session ID |
| `get` | `async get(session_id: str) -> Optional[SessionInfo]` | Look up session by ID |
| `list_all` | `async list_all() -> List[SessionInfo]` | Return all sessions |
| `remove` | `async remove(session_id: str) -> bool` | Remove session from tracking |
| `kill` | `async kill(session_id: str, reason: str = "operator") -> bool` | Order agent shutdown, purge after grace period |
| `search` | `async search(query: str) -> List[SessionInfo]` | Search by tag/hostname/OS/username/ID substring |
| `filter_by` | `async filter_by(**kwargs) -> List[SessionInfo]` | Filter by keyword args matching SessionInfo fields |
| `tag` | `async tag(session_id: str, tags: List[str]) -> bool` | Add tags to a session |
| `untag` | `async untag(session_id: str, tags: List[str]) -> bool` | Remove tags from a session |
| `set_task_status` | `async set_task_status(session_id: str, status: str) -> bool` | Set task status |
| `interact` | `async interact(session_id: str, command: str) -> Optional[str]` | Queue command for execution, returns command_id |
| `get_pending_commands` | `async get_pending_commands(session_id: str) -> List[Dict[str, Any]]` | Get pending commands (called by transport) |
| `ack_command` | `async ack_command(session_id: str, command_id: str, result: str = "") -> bool` | Acknowledge command completion |
| `get_command_history` | `async get_command_history(session_id: str, limit: int = 50) -> List[Dict[str, Any]]` | Get command history |
| `filter_by_tag` | `async filter_by_tag(tag: str) -> List[SessionInfo]` | Filter by specific tag |
| `filter_by_state` | `async filter_by_state(state: SessionState) -> List[SessionInfo]` | Filter by state |
| `rename` | `async rename(session_id: str, new_hostname: str) -> bool` | Rename session hostname |

---

## 5. Task Management (`pupyteer.server.tasks`)

### `TaskState` (Enum)

```python
class TaskState(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"
```

### `TaskInfo` (Dataclass)

```python
@dataclass
class TaskInfo:
    task_id: str
    name: str
    module: str = ""
    session_id: Optional[str] = None
    args: Dict[str, Any] = field(default_factory=dict)
    state: TaskState = TaskState.PENDING
    priority: int = 0
    created_at: float = 0.0
    started_at: float = 0.0
    completed_at: float = 0.0
    result: Optional[str] = None
    error: Optional[str] = None
```

### `TaskManager` (Class)

Manages task dispatch, execution tracking, and result collection.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `async initialize() -> None` | Start task manager |
| `shutdown` | `async shutdown() -> None` | Stop task manager |
| `submit` | `async submit(name: str, module: str = "", session_id: Optional[str] = None, args: Optional[Dict[str, Any]] = None, priority: int = 0) -> str` | Submit a new task |
| `get` | `async get(task_id: str) -> Optional[TaskInfo]` | Get task by ID |
| `list_all` | `async list_all() -> List[TaskInfo]` | List all tasks |
| `list_by_session` | `async list_by_session(session_id: str) -> List[TaskInfo]` | List tasks for a session |
| `list_by_state` | `async list_by_state(state: TaskState) -> List[TaskInfo]` | List tasks by state |
| `cancel` | `async cancel(task_id: str) -> bool` | Cancel a pending/running task |
| `complete` | `async complete(task_id: str, result: str) -> bool` | Mark task as completed |
| `fail` | `async fail(task_id: str, error: str) -> bool` | Mark task as failed |
| `cleanup` | `async cleanup(max_age_seconds: float = 3600.0) -> int` | Remove old completed/failed tasks |

---

## 6. Module System (`pupyteer.server.modules`)

### `ModuleCategory` (Enum)

```python
class ModuleCategory(str, Enum):
    RECON         = "recon"
    EXPLOITATION  = "exploitation"
    IMPLANT       = "implant"
    ANTI_FORENSICS = "antiforensics"
    EVASION       = "evasion"
    GENERAL       = "general"
```

### `ModuleState` (Enum)

```python
class ModuleState(str, Enum):
    UNLOADED  = "unloaded"
    LOADING   = "loading"
    LOADED    = "loaded"
    ERROR     = "error"
    DISABLED  = "disabled"
```

### `ModuleRegistry` (Class)

Discovers, loads, and manages post-exploitation modules.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `async initialize() -> None` | Discover and load all modules |
| `shutdown` | `async shutdown() -> None` | Unload all modules |
| `list_all` | `list_all() -> List[Dict[str, Any]]` | List all registered modules |
| `get` | `get(name: str) -> Optional[PupyModule]` | Get module instance by name |
| `get_class` | `get_class(name: str) -> Optional[type]` | Get module class by name |
| `list_by_category` | `list_by_category(category: ModuleCategory) -> List[Dict[str, Any]]` | List modules by category |
| `search` | `search(query: str) -> List[Dict[str, Any]]` | Search modules by name/description |
| `reload` | `async reload() -> None` | Reload all modules |
| `health_check` | `health_check() -> Dict[str, Any]` | Get registry health state |

### `ModuleExecutor` (Class)

Executes modules against agent sessions.

#### Constructor

```python
def __init__(self, registry: ModuleRegistry, session_manager: SessionManager, audit_logger: Any = None)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `registry` | `ModuleRegistry` | Module registry |
| `sessions` | `SessionManager` | Session manager |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `execute_module` | `async execute_module(module_name: str, session_id: str, args: Dict[str, Any]) -> Dict[str, Any]` | Execute a module on a session |
| `execute_on_all` | `async execute_on_all(module_name: str, args: Dict[str, Any]) -> List[Dict[str, Any]]` | Execute a module on all active sessions |
| `execute_job` | `async execute_job(module_name: str, session_id: str, args: Dict[str, Any]) -> str` | Execute as background job, returns job_id |
| `get_job` | `async get_job(job_id: str) -> Optional[Dict[str, Any]]` | Get job status/result |
| `list_jobs` | `async list_jobs(status: Optional[JobStatus] = None) -> List[Dict[str, Any]]` | List background jobs |
| `cancel_job` | `async cancel_job(job_id: str) -> bool` | Cancel a background job |
| `cleanup_jobs` | `async cleanup_jobs(max_age_seconds: float = 3600.0) -> int` | Clean up old jobs |
| `wait_for_job` | `async wait_for_job(job_id: str, timeout: float = 60.0) -> Optional[Dict[str, Any]]` | Wait for job completion |

### `PupyModule` (Base Class)

Base class for all post-exploitation modules.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `__init__` | `__init__(self, module_info: Dict[str, Any])` | Initialize module |
| `run` | `async run(self, session_id: str, args: Dict[str, Any]) -> Dict[str, Any]` | Execute the module |
| `validate_args` | `validate_args(self, args: Dict[str, Any]) -> List[str]` | Validate arguments, return errors |
| `get_info` | `get_info(self) -> Dict[str, Any]` | Get module metadata |
| `get_options` | `get_options(self) -> Dict[str, Dict[str, Any]]` | Get module options |

### Built-in Modules

#### `pupyteer.server.modules.builtin.recon`

Reconnaissance modules for system enumeration.

| Module | Description |
|--------|-------------|
| `system_info` | Collect system information (OS, arch, hostname, users) |
| `network_info` | Collect network configuration (interfaces, routes, DNS) |
| `process_list` | Enumerate running processes |
| `file_search` | Search for files matching patterns |
| `screenshot` | Capture screenshot from target |
| `keylog_start` | Start keystroke logging |
| `keylog_stop` | Stop keystroke logging |
| `keylog_dump` | Retrieve logged keystrokes |

#### `pupyteer.server.modules.builtin.exploitation`

Exploitation modules for privilege escalation and lateral movement.

| Module | Description |
|--------|-------------|
| `privesc_bypass_uac` | Attempt UAC bypass techniques |
| `privesc_token_impersonation` | Token impersonation for privilege escalation |
| `lateral_wmi` | Lateral movement via WMI |
| `lateral_smb` | Lateral movement via SMB |
| `lateral_rdp` | Lateral movement via RDP |
| `lateral_ssh` | Lateral movement via SSH |

#### `pupyteer.server.modules.builtin.implant_actions`

Implant control and management modules.

| Module | Description |
|--------|-------------|
| `sleep` | Change sleep interval |
| `jitter` | Change jitter percentage |
| `kill` | Terminate the implant |
| `migrate` | Migrate to a new process |
| `screenshot` | Take a screenshot |
| `download` | Download a file from target |
| `upload` | Upload a file to target |
| `shell` | Execute a shell command |
| `powershell` | Execute a PowerShell command |
| `python` | Execute Python code |

#### `pupyteer.server.modules.builtin.antiforensics`

Anti-forensics modules.

| Module | Description |
|--------|-------------|
| `clear_event_logs` | Clear Windows event logs |
| `timestomp` | Modify file timestamps |
| `delete_shadow_copies` | Delete volume shadow copies |
| `clear_prefetch` | Clear prefetch files |
| `clear_amcache` | Clear Amcache |

#### `pupyteer.server.modules.builtin.evasion`

Evasion testing modules.

| Module | Description |
|--------|-------------|
| `test_amsi` | Test AMSI bypass |
| `test_etw` | Test ETW bypass |
| `test_wdac` | Test Windows Defender Application Control bypass |
| `test_sandbox` | Test sandbox detection |

---

## 7. Transports & Listener (`pupyteer.server.transports`)

### `Transport` (Base Class)

Abstract base class for all transports.

#### Constructor

```python
def __init__(self, name: str, config: Dict[str, Any])
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `state` | `str` | Current transport state |
| `stats` | `Dict[str, Any]` | Transport statistics |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `initialize() -> None` | Initialize transport |
| `shutdown` | `shutdown() -> None` | Shutdown transport |

### `TransportManager` (Class)

Manages transport lifecycle and listener creation.

#### Constructor

```python
def __init__(self, config: ConfigManager, profiles: Any, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `initialize() -> None` | Initialize transport manager |
| `start_listener` | `start_listener(session_manager: Any, agent_keys: Any = None) -> None` | Start the agent listener |
| `shutdown` | `shutdown() -> None` | Shutdown all transports |
| `set_listener_session_manager` | `set_listener_session_manager(session_manager: Any) -> None` | Set session manager on listener |
| `create` | `create(transport_type, name, config) -> Optional[Transport]` | Create a transport instance |
| `register` | `register(name: str, transport: Transport) -> None` | Register a transport |
| `unregister` | `unregister(name: str) -> bool` | Unregister a transport |
| `get` | `get(name: str) -> Optional[Transport]` | Get a transport by name |
| `list` | `list() -> List[Dict[str, Any]]` | List all transports |
| `available_types` | `available_types() -> List[str]` | List available transport types |

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `listener` | `AgentListener` | Current listener instance |
| `listener_tls` | `bool` | Whether listener uses TLS |
| `listener_requires_auth` | `bool` | Whether listener requires agent auth |
| `enrollment` | `EnrollmentLedger` | Enrollment ledger |

### `AgentListener` (Class)

Async TCP agent listener.

#### Constructor

```python
def __init__(self, config: ConfigManager, session_manager: SessionManager, audit_logger: AuditLogger, agent_keys: AgentKeyRegistry)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `stats` | `Dict[str, Any]` | Listener statistics |
| `is_running` | `bool` | Whether listener is running |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `start` | `start() -> None` | Start listening for agent connections |
| `stop` | `stop() -> None` | Stop listening |
| `get_connection_sessions` | `get_connection_sessions() -> Dict[str, str]` | Map connection IDs to session IDs |

### `TCPTransport` (Class)

TCP transport implementation.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `connect` | `connect(host: str, port: int, **kwargs) -> bool` | Connect to C2 server |
| `disconnect` | `disconnect() -> None` | Disconnect from server |
| `send` | `send(data: bytes) -> int` | Send data |
| `receive` | `receive(timeout: float = 30.0) -> Optional[bytes]` | Receive data |
| `health_check` | `health_check() -> bool` | Check transport health |
| `close` | `close() -> None` | Close transport |

### `HTTPTransport` (Class)

HTTP/HTTPS transport implementation.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `connect` | `connect(host: str, port: int, **kwargs) -> bool` | Connect to C2 server |
| `disconnect` | `disconnect() -> None` | Disconnect from server |
| `send` | `send(data: bytes) -> int` | POST with encoding: raw/base64/hex |
| `receive` | `receive(timeout: float = 30.0) -> Optional[bytes]` | GET (beacon poll) |
| `health_check` | `health_check() -> bool` | Check transport health |
| `close` | `close() -> None` | Alias for disconnect |
| `beacon` | `beacon(data: bytes) -> Optional[bytes]` | POST + wait for response |

### `HTTPSTransport` (Class)

HTTPS transport with certificate pinning.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `_build_ssl_context` | `_build_ssl_context() -> ssl.SSLContext` | Custom ciphers, pinning, SNI |
| `_do_connect` | `_do_connect(host: str, port: int, **kwargs) -> bool` | TLS connect + pin verification |

### `SUPPORTED_LISTENER_PROTOCOLS`

```python
SUPPORTED_LISTENER_PROTOCOLS = ("tcp", "http", "https")
```

---

## 8. Profiles (`pupyteer.server.profiles`)

### `C2Profile` (Dataclass)

```python
@dataclass
class C2Profile:
    name: str
    description: str = ""
    author: str = ""
    version: str = ""
    # HTTP settings
    http_uri: str = "/index.html"
    http_method: str = "GET"
    http_headers: Dict[str, str] = field(default_factory=dict)
    http_user_agent: str = ""
    # Beacon settings
    sleep: int = 60
    jitter: int = 10
    max_output: int = 1024
    # TLS settings
    tls_enabled: bool = True
    tls_cert_path: str = ""
    tls_key_path: str = ""
    # Profile metadata
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### `ProfileManager` (Class)

Manages C2 profile loading, validation, and selection.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `async initialize() -> None` | Load all profiles from disk |
| `shutdown` | `async shutdown() -> None` | Cleanup |
| `list_all` | `list_all() -> List[Dict[str, Any]]` | List all profiles |
| `get` | `get(name: str) -> Optional[C2Profile]` | Get profile by name |
| `load` | `load(name: str) -> bool` | Load and activate a profile |
| `unload` | `unload() -> None` | Unload current profile |
| `validate` | `validate(profile: C2Profile) -> List[str]` | Validate a profile |
| `create` | `create(profile: C2Profile) -> bool` | Create a new profile |
| `delete` | `delete(name: str) -> bool` | Delete a profile |
| `reload` | `async reload() -> None` | Reload all profiles |

---

## 9. Payload System (`pupyteer.payloads`)

### Enums

```python
class PayloadPlatform(str, Enum):
    WINDOWS = "windows"
    LINUX   = "linux"
    MACOS   = "macos"
    ANDROID = "android"

class PayloadArch(str, Enum):
    X86      = "x86"
    X64      = "x64"
    ARM      = "arm"
    ARM64    = "arm64"
    UNIVERSAL = "universal"

class PayloadType(str, Enum):
    EXECUTABLE = "executable"
    LIBRARY    = "library"
    SCRIPT     = "script"
    APK        = "apk"
    ONELINER   = "oneliner"

class PayloadStatus(str, Enum):
    CONFIGURED = "configured"
    VALIDATING  = "validating"
    PENDING     = "pending"
    BUILDING    = "building"
    BUILT       = "built"
    VERIFIED    = "verified"
    FAILED      = "failed"
    DEPLOYED     = "deployed"
    EXPIRED     = "expired"

class PayloadDelivery(str, Enum):
    STAGE     = "stage"
    STAGELESS = "stageless"
```

### `PayloadConfig` (Dataclass)

```python
@dataclass
class PayloadConfig:
    name: str
    platform: PayloadPlatform
    arch: PayloadArch
    payload_type: PayloadType
    transport: str
    host: str
    port: int
    profile: str
    delivery: PayloadDelivery = PayloadDelivery.STAGE
    compiler: str = ""
    sleep: int = 60
    jitter: int = 10
    persistence: bool = False
    screenshot: bool = False
    anti_analysis: bool = False
    obfuscation: str = ""
    rc4_key: str = ""
    migration: str = ""
    extra: Dict[str, Any] = field(default_factory=dict)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `to_dict` | `to_dict() -> Dict[str, Any]` | Serialize to dict |
| `stub_modules` | `stub_modules() -> List[str]` | Get list of modules to embed |

### `PayloadMetadata` (Dataclass)

```python
@dataclass
class PayloadMetadata:
    payload_id: str
    name: str
    version: str
    platform: PayloadPlatform
    arch: PayloadArch
    payload_type: PayloadType
    profile: str
    status: PayloadStatus
    created_at: float
    build_timestamp: float
    hash_sha256: str
    hash_md5: str
    size_bytes: int
    artifact_path: str
    operator: str
    config: PayloadConfig
    build_log: str
    tags: List[str]
    expiration: Optional[float]
    signed: bool
    signature_path: str
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `is_expired` | `bool` | Whether payload has expired |
| `is_valid` | `bool` | Whether payload is valid |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `to_dict` | `to_dict() -> Dict[str, Any]` | Serialize to dict |

### `PayloadSigner` (Class)

Handles payload signing.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `enabled` | `bool` | Whether signing is enabled |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `sign` | `sign(artifact_path: str, payload_id: str) -> Tuple[bool, str]` | Sign a payload artifact |

### `PayloadBuilder` (Class)

Builds payload artifacts from configuration.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger, agent_keys: AgentKeyRegistry)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `validate_config` | `validate_config(payload_config: PayloadConfig) -> List[str]` | Validate payload configuration |
| `generate_payload_id` | `generate_payload_id() -> str` | Generate unique payload ID |
| `compute_hashes` | `compute_hashes(path: str) -> Dict[str, str]` | Compute SHA256 and MD5 hashes |
| `get_next_version` | `get_next_version(name: str, store: PayloadStore) -> str` | Get next version string |
| `build` | `async build(payload_config: PayloadConfig, payload_id: str, version: str, expiration_days: int, sign: bool) -> PayloadMetadata` | Build a payload |

### `PayloadStore` (Class)

Persistent storage for payload metadata.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `add` | `add(metadata: PayloadMetadata) -> None` | Add payload metadata |
| `get` | `get(payload_id: str) -> Optional[PayloadMetadata]` | Get payload by ID |
| `list_all` | `list_all() -> List[PayloadMetadata]` | List all payloads |
| `list_by_name` | `list_by_name(name: str) -> List[PayloadMetadata]` | List payloads by name |
| `search` | `search(query: str) -> List[PayloadMetadata]` | Search payloads |
| `remove` | `remove(payload_id: str) -> bool` | Remove a payload |
| `cleanup_expired` | `cleanup_expired(max_age_days: int) -> int` | Remove expired payloads |
| `cleanup_old_versions` | `cleanup_old_versions(name: str, keep: int) -> int` | Keep only N latest versions |
| `mark_expired` | `mark_expired() -> int` | Mark expired payloads |
| `get_version_history` | `get_version_history(name: str) -> List[PayloadMetadata]` | Get version history |

### `PayloadManager` (Class)

High-level payload management facade.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger, agent_keys: AgentKeyRegistry)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `build` | `async build(payload_config: PayloadConfig, version: str = "", expiration_days: int = 30, sign: bool = True) -> PayloadMetadata` | Build a new payload |
| `get` | `get(payload_id: str) -> Optional[PayloadMetadata]` | Get payload by ID |
| `list_all` | `list_all() -> List[PayloadMetadata]` | List all payloads |
| `list_by_name` | `list_by_name(name: str) -> List[PayloadMetadata]` | List payloads by name |
| `search` | `search(query: str) -> List[PayloadMetadata]` | Search payloads |
| `remove` | `remove(payload_id: str) -> bool` | Remove a payload |
| `cleanup` | `cleanup(max_age_days: int = 90) -> int` | Clean up old payloads |
| `cleanup_old_versions` | `cleanup_old_versions(name: str, keep: int = 5) -> int` | Keep only N latest versions |
| `mark_expired` | `mark_expired() -> int` | Mark expired payloads |
| `get_version_history` | `get_version_history(name: str) -> List[PayloadMetadata]` | Get version history |
| `get_stats` | `get_stats() -> Dict[str, Any]` | Get payload statistics |
| `get_generation_log` | `get_generation_log(payload_id: str) -> str` | Get build log |
| `verify` | `verify(payload_id: str) -> Tuple[bool, str]` | Verify payload integrity |

### `PEBuilder` (Class)

Windows PE executable builder via MinGW cross-compilation.

#### Constructor

```python
def __init__(self, config: Any, audit: Any, *, template_path: Optional[str] = None)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `build` | `async build(stub_cfg: StubConfig, output_path: Path) -> PEBuildResult` | Full PE build pipeline |

### `PEBuildResult` (Dataclass)

```python
@dataclass
class PEBuildResult:
    artifact_path: str
    hash_sha256: str
    status: str
    error_message: str
    size_bytes: int
    build_timestamp: float
    compiler_used: str
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `to_dict` | `to_dict() -> Dict[str, Any]` | Serialize to dict |

---

## 10. Evasion System (`pupyteer.server.evasion`)

### `EvasionTestManager` (Class)

Manages evasion testing lifecycle.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `async initialize() -> None` | Initialize evasion system |
| `shutdown` | `async shutdown() -> None` | Shutdown evasion system |
| `run_test` | `async run_test(artifact_path: str, config: EvasionTestConfig) -> EvasionTestResult` | Run a single evasion test |
| `run_suite` | `async run_suite(artifact_path: str, configs: List[EvasionTestConfig]) -> List[EvasionTestResult]` | Run a suite of tests |
| `get_history` | `get_history(limit: int = 50) -> List[EvasionTestResult]` | Get test history |
| `get_stats` | `get_stats() -> Dict[str, Any]` | Get evasion statistics |

### `EvasionTestRunner` (Class)

Executes evasion tests against detection engines.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `run` | `async run(artifact_path: str, config: EvasionTestConfig) -> EvasionTestResult` | Run a single test |
| `run_obfuscated` | `async run_obfuscated(artifact_path: str, obfuscation: ObfuscationConfig, config: EvasionTestConfig) -> EvasionTestResult` | Run test with obfuscation |

### `ObfuscationEngine` (Class)

Applies obfuscation techniques to payloads.

#### Constructor

```python
def __init__(self, config: ConfigManager)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `obfuscate` | `async obfuscate(artifact_path: str, config: ObfuscationConfig) -> str` | Obfuscate a payload, returns new path |
| `deobfuscate` | `async deobfuscate(artifact_path: str, config: ObfuscationConfig) -> str` | Deobfuscate a payload |

### `ObfuscationConfig` (Dataclass)

```python
@dataclass
class ObfuscationConfig:
    scheme: EncodingScheme
    key: Optional[bytes] = None
    iterations: int = 1
    junk_code: bool = True
    rename_vars: bool = True
    rename_functions: bool = True
    flatten_control_flow: bool = False
    encrypt_strings: bool = True
    anti_debug: bool = False
    anti_vm: bool = False
```

### `EncodingScheme` (Enum)

```python
class EncodingScheme(str, Enum):
    XOR    = "xor"
    AES    = "aes"
    RC4    = "rc4"
    CHAIN  = "chain"
```

### `EvasionTestConfig` (Dataclass)

```python
@dataclass
class EvasionTestConfig:
    name: str
    test_type: str
    environment: str = "default"
    controls: List[str] = field(default_factory=list)
    timeout: int = 60
    retry_count: int = 3
    metadata: Dict[str, Any] = field(default_factory=dict)
```

### `EvasionTestResult` (Dataclass)

```python
@dataclass
class EvasionTestResult:
    test_id: str
    test_name: str
    artifact_path: str
    timestamp: float
    verdict: str
    detected: bool
    detection_count: int
    total_engines: int
    details: Dict[str, Any]
    duration_seconds: float
    obfuscation_applied: bool
    obfuscation_config: Optional[ObfuscationConfig]
    recommendations: List[str]
```

---

## 11. CLI & Entry Points (`pupyteer.cli`, `pupyteer.main`)

### `pupyteer.main`

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `configure_stdio` | `configure_stdio() -> None` | Force UTF-8 on stdout/stderr. Prevents UnicodeEncodeError on Windows consoles. |
| `setup_logging` | `setup_logging(level: str = "INFO") -> None` | Configure root logging with format `%(asctime)s [%(levelname)s] %(name)s: %(message)s`. |
| `async_main` | `async_main(config_path: str \| None = None, no_tui: bool = False, environment: str \| None = None) -> int` | Async entry. Loads ConfigManager, sets up logging, builds PupyteerEngine. Returns exit code. |
| `build_arg_parser` | `build_arg_parser() -> argparse.ArgumentParser` | Build top-level argument parser with `-c/--config`, `--headless`, `--version`, `-e/--environment`, `--debug`. |
| `main` | `main() -> int` | Synchronous entry point. Checks for CLI subcommand via `run_cli()`, otherwise runs `asyncio.run(async_main(...))`. |

#### CLI Arguments

| Argument | Description |
|----------|-------------|
| `-c` / `--config` | Path to configuration file |
| `--headless` | Run engine without TUI |
| `--version` | Print version |
| `-e` / `--environment` | Environment overlay name (dev/staging/prod/ctf) |
| `--debug` | Enable debug logging |

### `pupyteer.cli`

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `add_subcommands` | `add_subcommands(parser: argparse.ArgumentParser) -> None` | Register subcommands: `list-modules`, `module-info`, `module-health`, `build-payload`, `server-info`. |
| `run_cli` | `run_cli(argv: Optional[List[str]] = None) -> Optional[int]` | Parse and execute a subcommand. Returns exit code or `None` if no subcommand. |

#### CLI Subcommands

| Subcommand | Description |
|------------|-------------|
| `list-modules` | List registered post-exploitation modules. Filters by `--category`. Supports `--json`. |
| `module-info` | Show one module's metadata by name. |
| `module-health` | Report registry load/health state. |
| `build-payload` | Generate one payload artifact. The only mutating subcommand. Supports `--dry-run`. |
| `server-info` | Dump effective config (secrets redacted). `--reveal` disables redaction. |

#### Usage Examples

```bash
# List all modules
python -m pupyteer list-modules

# List modules in a category
python -m pupyteer list-modules --category recon

# Get module info
python -m pupyteer module-info --name system_info

# Check module health
python -m pupyteer module-health

# Build a payload
python -m pupyteer build-payload --platform windows --arch x64 --type executable --host 192.168.1.100 --port 443

# Show server config
python -m pupyteer server-info

# Run with custom config
python -m pupyteer -c /path/to/config.yaml

# Run headless
python -m pupyteer --headless

# Run with environment overlay
python -m pupyteer -e production
```

---

## 12. TUI System (`pupyteer.tui`)

### `PupyteerTUI` (Class)

Main terminal user interface.

#### Constructor

```python
def __init__(self, engine: PupyteerEngine)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `engine` | `PupyteerEngine` | Engine instance |
| `logged_in` | `bool` | Whether operator is logged in |
| `current_operator` | `Optional[str]` | Current operator name |
| `active_module` | `Optional[str]` | Currently selected module |
| `active_session` | `Optional[str]` | Currently selected session |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `run` | `async run() -> None` | Main TUI event loop |
| `prompt_login` | `prompt_login() -> None` | Prompt for operator credentials |
| `render_banner` | `render_banner() -> None` | Print startup banner with TLS/auth status |
| `render_dashboard` | `render_dashboard() -> None` | Render session dashboard |
| `render_table` | `render_table(headers: List[str], rows: List[List[str]]) -> None` | Render boxed table |
| `render_error` | `render_error(message: str) -> None` | Render error message |
| `render_warning` | `render_warning(message: str) -> None` | Render warning message |
| `render_success` | `render_success(message: str) -> None` | Render success message |
| `render_info` | `render_info(message: str) -> None` | Render info message |

#### TUI Commands

| Command | Description |
|---------|-------------|
| `login` | Authenticate as operator |
| `sessions` | Manage sessions (list/info/interact/results/download/upload/screenshot/kill/rename/tag/search/route) |
| `tasks` | Manage tasks (list/info/cancel) |
| `modules` | List all modules |
| `use` | Select a module |
| `set` | Set module option |
| `unset` | Unset module option |
| `options` | Show module options |
| `info` | Show active module info |
| `back` | Deselect active module |
| `exploit` | Execute (exploit) active module |
| `run` | Run active module |
| `reload` | Reload module registry |
| `search` | Search modules |
| `jobs` | Manage background jobs |
| `profiles` | Manage C2 profiles (list/show/validate/load/unload/new) |
| `transports` | List active transports |
| `config` | View/modify configuration |
| `logs` | View recent audit logs |
| `evasion` | Evasion testing commands |
| `pipeline` | Unified payload-to-evasion pipeline |
| `payloads` | Payload lifecycle management |
| `operator` | Manage operator credentials (list/add/role/remove) |
| `enrollment` | Manage enrollment secrets (show/rotate/revoke) |
| `status` | Show engine status |
| `theme` | Change TUI theme |
| `help` | Show help |
| `banner` | Display banner |
| `clear` | Clear screen |
| `exit` | Exit Pupyteer |

### `CommandRegistry` (Class)

Manages TUI command registration and dispatch.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `register` | `register(name: str, handler: Callable, help_text: str = "") -> None` | Register a command |
| `get` | `get(name: str) -> Optional[Callable]` | Get command handler |
| `list_commands` | `list_commands() -> List[str]` | List all commands |
| `get_help` | `get_help(name: str) -> str` | Get help text for a command |
| `get_all_help` | `get_all_help() -> Dict[str, str]` | Get all help texts |

### `TabCompleter` (Class)

Tab completion for TUI commands.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `complete` | `complete(text: str, state: int) -> Optional[str]` | Return completion for given text/state |

### `SessionDashboard` (Class)

Renders session information dashboard.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `render` | `render() -> str` | Render full dashboard |
| `render_compact` | `render_compact() -> str` | Render compact dashboard |

### `StatusBar` (Class)

Renders status bar.

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `render` | `render() -> str` | Render status bar |
| `render_full` | `render_full() -> str` | Render full status bar |

### `ModuleContext` (Class)

MSF-style module interaction context.

#### Constructor

```python
def __init__(self, registry: ModuleRegistry)
```

#### Properties

| Property | Type | Description |
|----------|------|-------------|
| `has_active_module` | `bool` | Whether a module is selected |
| `module_name` | `Optional[str]` | Active module name |
| `module` | `Optional[PupyModule]` | Active module instance |
| `module_class` | `Optional[type]` | Active module class |
| `registry` | `ModuleRegistry` | Module registry |

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `use` | `use(module_name: str) -> Dict[str, Any]` | Select a module |
| `set_option` | `set_option(name: str, value: str) -> Dict[str, Any]` | Set a module option |
| `unset_option` | `unset_option(name: str) -> Dict[str, Any]` | Unset a module option |
| `get_option` | `get_option(name: str) -> Optional[Dict[str, Any]]` | Get a module option |
| `get_all_options` | `get_all_options() -> Dict[str, Dict[str, Any]]` | Get all module options |
| `validate_required` | `validate_required() -> List[str]` | Validate required options |
| `get_effective_args` | `get_effective_args() -> Dict[str, Any]` | Get effective arguments |
| `clear` | `clear() -> None` | Clear module selection |

---

## 13. Authentication & RBAC

### `AuthLayer` (Class)

Handles operator authentication and session management.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `authenticate` | `async authenticate(username: str, password: str) -> Optional[str]` | Authenticate operator, returns token |
| `validate_token` | `validate_token(token: str) -> Optional[str]` | Validate token, returns username |
| `revoke_token` | `revoke_token(token: str) -> bool` | Revoke a token |
| `change_password` | `async change_password(username: str, old_password: str, new_password: str) -> bool` | Change operator password |
| `create_operator` | `async create_operator(username: str, password: str, role: Role) -> bool` | Create new operator |
| `delete_operator` | `async delete_operator(username: str) -> bool` | Delete an operator |
| `list_operators` | `list_operators() -> List[Dict[str, Any]]` | List all operators |
| `lockout_check` | `lockout_check(username: str) -> bool` | Check if account is locked out |
| `record_failed_login` | `record_failed_login(username: str) -> None` | Record failed login attempt |
| `clear_failed_logins` | `clear_failed_logins(username: str) -> None` | Clear failed login attempts |

### `Role` (Enum)

```python
class Role(str, Enum):
    VIEWER   = "viewer"
    OPERATOR = "operator"
    ADMIN    = "admin"
    SYSTEM   = "system"
```

### `Permission` (Class)

String constants for all permissions.

```python
class Permission:
    SESSION_READ      = "session.read"
    SESSION_KILL      = "session.kill"
    SESSION_TAG       = "session.tag"
    SESSION_INTERACT  = "session.interact"
    TASK_READ         = "task.read"
    TASK_CREATE       = "task.create"
    TASK_CANCEL       = "task.cancel"
    JOB_READ          = "job.read"
    JOB_CANCEL        = "job.cancel"
    MODULE_READ       = "module.read"
    MODULE_RUN        = "module.run"
    PAYLOAD_READ      = "payload.read"
    PAYLOAD_BUILD     = "payload.build"
    PAYLOAD_REMOVE    = "payload.remove"
    PROFILE_READ      = "profile.read"
    PROFILE_LOAD      = "profile.load"
    PROFILE_MODIFY    = "profile.modify"
    CONFIG_READ       = "config.read"
    CONFIG_WRITE      = "config.write"
    EVASION_READ      = "evasion.read"
    EVASION_RUN       = "evasion.run"
    AUDIT_READ        = "audit.read"
    OPERATOR_MANAGE   = "operator.manage"
    SYSTEM_ADMIN      = "system.admin"
```

### `ROLE_PERMISSIONS` (Constant)

```python
ROLE_PERMISSIONS: Dict[Role, Set[str]]
```

Maps each role to its set of permissions.

### `AccessDenied` (Exception)

```python
class AccessDenied(Exception):
    def __init__(self, permission: str, operator: str = "unknown")
```

### `PermissionChecker` (Class)

Checks operator permissions.

#### Constructor

```python
def __init__(self, auth_layer: "AuthLayer", store: Any = None)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `assign_role` | `assign_role(operator: str, role: Role) -> None` | Assign role to operator |
| `get_role` | `get_role(operator: str) -> Role` | Get operator's role |
| `has_permission` | `has_permission(operator: str, permission: str) -> bool` | Check if operator has permission |
| `check_permission` | `check_permission(operator: str, permission: str) -> None` | Check permission, raises AccessDenied |
| `require_permission` | `require_permission(permission: str)` | Decorator for TUI command handlers |
| `get_accessible_commands` | `get_accessible_commands(operator: str) -> Set[str]` | Get commands accessible to operator |
| `filter_command_args` | `filter_command_args(operator: str, command: str, args: list) -> tuple` | Filter command args based on permissions |

### `SessionAuthorization` (Class)

Handles session-level authorization.

#### Constructor

```python
def __init__(self, auth_layer: AuthLayer, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `authorize_session` | `authorize_session(session_id: str, token: str) -> bool` | Authorize a session |
| `validate_session_token` | `validate_session_token(session_id: str, token: str) -> bool` | Validate session token |
| `revoke_session` | `revoke_session(session_id: str) -> bool` | Revoke a session |
| `get_session_token` | `get_session_token(session_id: str) -> Optional[str]` | Get session token |

### `AgentKeyRegistry` (Class)

Registry of trusted per-agent public keys.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `load_keys` | `load_keys(path: str) -> None` | Load agent keys from JSON file |
| `register_key` | `register_key(agent_id: str, public_key: str) -> None` | Register an agent public key |
| `get_key` | `get_key(agent_id: str) -> Optional[str]` | Get agent public key |
| `remove_key` | `remove_key(agent_id: str) -> bool` | Remove an agent key |
| `verify_agent` | `verify_agent(agent_id: str, signature: bytes, data: bytes) -> bool` | Verify agent signature |
| `list_agents` | `list_agents() -> List[str]` | List all registered agents |

### `AuditLogger` (Class)

Structured JSON audit trail.

#### Constructor

```python
def __init__(self, config: ConfigManager)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `log` | `log(event_type: str, **kwargs) -> None` | Log an audit event |
| `log_auth` | `log_auth(username: str, success: bool, **kwargs) -> None` | Log authentication event |
| `log_session` | `log_session(session_id: str, action: str, **kwargs) -> None` | Log session event |
| `log_task` | `log_task(task_id: str, action: str, **kwargs) -> None` | Log task event |
| `log_module` | `log_module(module_name: str, action: str, **kwargs) -> None` | Log module event |
| `log_payload` | `log_payload(payload_id: str, action: str, **kwargs) -> None` | Log payload event |
| `log_config` | `log_config(action: str, **kwargs) -> None` | Log config event |
| `get_recent` | `get_recent(limit: int = 100) -> List[Dict[str, Any]]` | Get recent audit events |
| `search` | `search(query: str) -> List[Dict[str, Any]]` | Search audit events |
| `cleanup` | `cleanup(max_age_days: int = 90) -> int` | Clean up old audit events |

### `EnrollmentLedger` (Class)

Manages enrollment secrets and beacon tokens.

#### Constructor

```python
def __init__(self, config: ConfigManager, audit: AuditLogger)
```

#### Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `initialize` | `async initialize() -> None` | Initialize enrollment ledger |
| `get_secret` | `get_secret() -> str` | Get current enrollment secret |
| `rotate_secret` | `rotate_secret() -> str` | Rotate enrollment secret |
| `revoke_secret` | `revoke_secret(secret: str) -> bool` | Revoke a retired secret |
| `validate_secret` | `validate_secret(secret: str) -> bool` | Validate an enrollment secret |
| `generate_beacon_token` | `generate_beacon_token(session_id: str) -> str` | Generate a beacon token |
| `validate_beacon_token` | `validate_beacon_token(session_id: str, token: str) -> bool` | Validate a beacon token |

---

## 14. Utilities & Tools

### `pupyteer.agent.core.sleep_mask`

Memory obfuscation during sleep — ChaCha20, RC4, or XOR masking.

#### Constants

| Name | Value |
|------|-------|
| `PREFERRED_CIPHERS` | `("chacha20", "rc4", "xor")` |

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `cryptography_available` | `cryptography_available() -> bool` | Check if `cryptography` package is usable. |
| `scrub_buffer` | `scrub_buffer(buf: Union[bytearray, memoryview], passes: int = 2) -> None` | Overwrite sensitive buffer with random bytes, then zero it. |
| `sleep_masked` | `sleep_masked(sleep_sec: float, jitter_percent: int = 0, mask_key: Optional[bytes] = None, cipher: str = "chacha20", data_ref: Optional[bytearray] = None, scrub: bool = True) -> Dict[str, Any]` | **Primary public API for agent beacon loops.** Returns `{"slept": float, "masked": bool, "cipher": str}`. |
| `patch_stub_template_for_sleep_mask` | `patch_stub_template_for_sleep_mask(template_source: str) -> str` | Inject sleep_masked import into Jinja2 template. |
| `generate_mask_key` | `generate_mask_key(length: int = 32) -> bytes` | Generate cryptographically random mask key. |
| `mask_string` | `mask_string(s: str, key: bytes, cipher: str = "xor") -> bytearray` | Mask a string (XOR or RC4). |
| `unmask_string` | `unmask_string(data: bytearray, key: bytes, cipher: str = "xor") -> str` | Unmask a previously masked bytearray. |

#### `SleepMask` (Class)

| Method/Property | Signature | Description |
|-----------------|-----------|-------------|
| `__init__` | `(self, key: Optional[bytes] = None, cipher: str = "chacha20")` | Initialize masker. Random 32-byte key if None. |
| `is_masked` | property -> `bool` | Whether data is currently masked. |
| `cipher` | property -> `str` | Configured cipher name. |
| `key` | property -> `bytes` | Current encryption key. |
| `encrypt` | `(self, data: Union[bytearray, bytes], offset: int = 0, length: int = -1) -> bytearray` | Encrypt (chacha20 prepends nonce). |
| `decrypt` | `(self, data: Optional[bytearray] = None, offset: int = -1, length: int = -1) -> bytearray` | Decrypt (strips nonce for chacha20). |
| `mask_region` | `(self, address: int, size: int) -> None` | Mask memory region by address (ctypes). |
| `unmask_region` | `(self, address: int, size: int) -> None` | Unmask memory region by address. |
| `secure_scrub` | `(self, passes: int = 3) -> None` | Securely scrub key from memory. |

**Class constant:** `SUPPORTED_CIPHERS = ("chacha20", "rc4", "xor")`

### `pupyteer.agent.core.stub`

Agent stub generator — renders standalone Python agent scripts from a declarative StubConfig.

#### `StubConfig` (Dataclass)

37 fields including: `name`, `transport`, `host`, `port`, `profile`, `platform`, `arch`, `sleep`, `jitter`, `max_output`, `persistence`, `migration`, `relay`, `anti_analysis`, `obfuscation`, `rc4_key`, `modules`, `user_agent`, `dns_domain`, `dns_key`, `http_uri`, `http_method`, `tls`, `tls_cert_pem`, `auth_secret`, `relay_pipe`, `relay_bind`, `relay_port`, `relay_peers`, `migrate_target`, `migrate_technique`, `obfuscation_key`, `compiler`, `onefile`, `icon`, `console`, `operator`, `tags`, `extra`.

| Method | Signature | Description |
|--------|-----------|-------------|
| `validate` | `(self) -> List[str]` | Validate config, return error strings. |
| `technique` | property -> `str` | Alias for `migrate_technique`. |
| `to_dict` | `(self) -> dict` | Return `asdict(self)`. |

#### `AgentStubGenerator` (Class)

| Method | Signature | Description |
|--------|-----------|-------------|
| `__init__` | `(self, template: Optional[str] = None)` | Initialize with optional custom Jinja2 template. |
| `generate` | `(self, config: StubConfig, *, validate: bool = True) -> str` | Render agent source from StubConfig. |
| `write` | `(self, config: Union[StubConfig, str], path: Union[str, Path], *, validate: bool = True) -> Path` | Write agent source to path. |
| `artifact_stem` | `(self, config: StubConfig) -> str` | Return slugified name (no extension). |
| `pyinstaller_stub` | `(self, config: StubConfig) -> str` | Return PyInstaller launcher snippet. |
| `nuitka_stub` | `(self, config: StubConfig) -> str` | Return Nuitka wrapper snippet. |
| `compile_command` | `(self, config: StubConfig, src_path: Union[str, Path]) -> str` | Return CLI command for compilation. |

### `pupyteer.tools.callback_test`

End-to-end C2 callback testing harness.

#### `CallbackTestHarness` (Class)

| Method | Signature | Description |
|--------|-----------|-------------|
| `__init__` | `(self, config: ConfigManager)` | Initialize test harness. |
| `run_test` | `async run_test() -> Dict[str, Any]` | Run full callback test. |
| `test_tcp` | `async test_tcp() -> Dict[str, Any]` | Test TCP transport. |
| `test_http` | `async test_http() -> Dict[str, Any]` | Test HTTP transport. |
| `test_https` | `async test_https() -> Dict[str, Any]` | Test HTTPS transport. |

### `pupyteer.server.core.errors`

Error hierarchy for the Pupyteer framework.

```python
class C2EngineError(Exception):
    """Base exception for all Pupyteer errors."""
    def __init__(self, message: str, code: ErrorCode = ErrorCode.UNKNOWN, subsystem: str = "")

class ConfigError(C2EngineError):
    """Configuration error."""

class SubsystemError(C2EngineError):
    """Subsystem initialization/operation error."""
    def __init__(self, message: str, subsystem: str, operation: str)

class SessionError(C2EngineError):
    """Session management error."""

class TaskError(C2EngineError):
    """Task management error."""

class TransportError(C2EngineError):
    """Transport error."""

class ProfileError(C2EngineError):
    """Profile error."""

class AuthError(C2EngineError):
    """Authentication error."""
```

### `ErrorCode` (Enum)

```python
class ErrorCode(str, Enum):
    UNKNOWN          = "unknown"
    CONFIG_INVALID   = "config_invalid"
    CONFIG_MISSING   = "config_missing"
    AUTH_FAILED      = "auth_failed"
    SESSION_NOT_FOUND = "session_not_found"
    TASK_NOT_FOUND   = "task_not_found"
    MODULE_NOT_FOUND = "module_not_found"
    TRANSPORT_ERROR  = "transport_error"
    PROFILE_ERROR    = "profile_error"
    PAYLOAD_ERROR    = "payload_error"
    EVASION_ERROR    = "evasion_error"
```

### `pupyteer.server.core.queue`

Priority task queue implementation.

#### `TaskPriority` (Enum)

```python
class TaskPriority(IntEnum):
    LOW      = 0
    NORMAL   = 1
    HIGH     = 2
    CRITICAL = 3
```

#### `TaskQueue` (Class)

| Method | Signature | Description |
|--------|-----------|-------------|
| `put` | `async put(task: TaskInfo) -> None` | Add task to queue |
| `get` | `async get() -> TaskInfo` | Get highest priority task |
| `peek` | `peek() -> Optional[TaskInfo]` | Peek at highest priority task |
| `empty` | `empty() -> bool` | Check if queue is empty |
| `size` | `size() -> int` | Get queue size |
| `clear` | `clear() -> None` | Clear all tasks |

### `pupyteer.server.core.pipeline`

Unified payload-to-evasion pipeline orchestrator.

#### Enums

```python
class PipelineStage(str, Enum):
    BUILD      = "build"
    OBFUSCATE  = "obfuscate"
    TEST       = "test"
    REPORT     = "report"

class Verdict(str, Enum):
    PASS       = "pass"
    PARTIAL    = "partial"
    FAIL       = "fail"
    ERROR      = "error"
    INCOMPLETE = "incomplete"
```

#### Dataclasses

**`StageResult`**: `stage`, `success`, `duration_seconds`, `message`, `data`. Method: `to_dict()`.

**`PipelineResult`**: `pipeline_id`, `name`, `timestamp`, `verdict`, `stages`, `payload_metadata`, `evasion_result`, `obfuscated_artifact_path`, `obfuscated_artifact_hash`, `detection_overall`, `detected_count`, `undetected_count`, `total_duration_seconds`, `recommendations`, `tags`. Methods: `__post_init__()`, `to_dict()`.

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `generate_recommendations` | `generate_recommendations(result: PipelineResult) -> List[str]` | Generate recommendations based on pipeline result |

#### `PipelineManager` (Class)

| Method | Signature | Description |
|--------|-----------|-------------|
| `__init__` | `(self, engine: PupyteerEngine)` | Initialize pipeline manager |
| `run_count` | property -> `int` | Number of pipeline runs |
| `history` | property -> `List[PipelineResult]` | Pipeline run history |
| `initialize` | `async initialize() -> None` | Initialize pipeline |
| `shutdown` | `async shutdown() -> None` | Shutdown pipeline |
| `build_and_test` | `async build_and_test(payload_config, evasion_config) -> PipelineResult` | BUILD -> TEST -> REPORT |
| `build_only` | `async build_only(payload_config) -> PayloadMetadata` | Build only |
| `test_only` | `async test_only(artifact_path, evasion_config) -> EvasionTestResult` | Test only |
| `build_obfuscate_test` | `async build_obfuscate_test(payload_config, obfuscation_config, evasion_config) -> PipelineResult` | Full flow |
| `auto` | `async auto(name, platform, arch, payload_type, transport, host, port, profile_name, environment) -> PipelineResult` | One-shot |
| `get_history` | `get_history(limit: int = 50) -> List[PipelineResult]` | Get run history |
| `get_stats` | `get_stats() -> Dict[str, Any]` | Get pipeline statistics |

### `pupyteer.server.core.tls`

TLS certificate management.

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `generate_self_signed_cert` | `generate_self_signed_cert(hostname: str, cert_path: str, key_path: str, days_valid: int = 365) -> None` | Generate self-signed certificate |
| `load_cert` | `load_cert(cert_path: str) -> ssl.SSLContext` | Load certificate into SSL context |
| `verify_cert` | `verify_cert(cert_path: str, hostname: str) -> bool` | Verify certificate matches hostname |

### `pupyteer.server.core.validation`

Configuration validation.

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `validate_config` | `validate_config(config: Dict[str, Any]) -> List[str]` | Validate configuration, return errors |
| `validate_profile` | `validate_profile(profile: Dict[str, Any]) -> List[str]` | Validate profile, return errors |
| `validate_payload_config` | `validate_payload_config(config: Dict[str, Any]) -> List[str]` | Validate payload config, return errors |

### `pupyteer.server.core.logging`

Logging setup.

#### Functions

| Function | Signature | Description |
|----------|-----------|-------------|
| `setup_logging` | `setup_logging(level: str = "INFO", format: str = "json") -> None` | Configure logging |
| `get_logger` | `get_logger(name: str) -> logging.Logger` | Get a logger instance |

---

## Cross-Reference: Module Dependencies

```
PupyteerEngine
├── ConfigManager
├── AuditLogger
├── AuthLayer
│   └── AuditLogger
├── AgentKeyRegistry
│   └── AuditLogger
├── SessionAuthorization
│   ├── AuthLayer
│   └── AuditLogger
├── PermissionChecker (RBAC)
│   └── AuthLayer
├── SessionManager
│   ├── ConfigManager
│   ├── AuditLogger
│   └── TransportManager
├── TaskManager
│   ├── ConfigManager
│   └── AuditLogger
├── ProfileManager
│   ├── ConfigManager
│   └── AuditLogger
├── TransportManager
│   ├── ConfigManager
│   ├── ProfileManager
│   └── AuditLogger
├── EvasionTestManager
│   ├── ConfigManager
│   └── AuditLogger
├── PayloadManager
│   ├── ConfigManager
│   ├── AuditLogger
│   └── AgentKeyRegistry
├── PipelineManager
│   └── PupyteerEngine
├── ModuleExecutor
│   ├── ModuleRegistry
│   ├── SessionManager
│   └── AuditLogger
└── ModuleRegistry
    ├── ConfigManager
    └── AuditLogger
```

---

## Summary Statistics

| Category | Count |
|----------|-------|
| Public Classes | 50+ |
| Public Methods | 200+ |
| Public Functions | 50+ |
| Enums | 10+ |
| Dataclasses | 15+ |
| Constants | 30+ |
| TUI Commands | 30+ |
| Built-in Modules | 25+ |
| Transport Types | 5+ |

---

*This document was generated from source code analysis of the Pupyteer framework. All signatures and descriptions are based on actual code inspection.*
