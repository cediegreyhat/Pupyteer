# Pupyteer Core Server — Code Review Report

---

## File: `pupyteer/server/core/config.py`

**Imports**
- `os`, `copy`, `logging`
- `typing: Any, Dict, Optional`
- `pathlib: Path`
- `yaml`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `ConfigManager` | `__init__(path)` | Loads from explicit path, then 3 standard search locations, then env vars. |
| | `get(dotted_key, default)` | Dotted-path lookup into nested dict. |
| | `set(dotted_key, value)` | Dotted-path write, creates intermediate dicts. |
| | `all()` | Returns deep copy of full config. |
| | `async validate()` | Checks required sections, port range, log level. |
| | `save(path)` | Persists to YAML. |
| | `_load_file(path)` | Loads + deep-merges one YAML file; logs warnings on failure (swallows exceptions). |
| | `_apply_env_overrides()` | Maps `PUPYTEER_*` env vars (double-underscore → dotted key). |
| | `_static _deep_merge(base, overlay)` | Recursive dict merge. |
| | `_static _coerce(value)` | Casts strings to bool/int/float. |

**Key Data**
- `DEFAULT_CONFIG: Dict[str, Any]` — module-level defaults (server, logging, operator, profile, security, paths).

**Issues**
- `_coerce` silently converts `"0"` to `0` (int), `"false"` to `False`, etc. — could break legitimate string config values that happen to look like numbers/booleans.
- `_load_file` catches bare `Exception` and only logs a warning; file-not-found is expected, but parse errors are silently ignored.

---

## File: `pupyteer/server/core/engine.py`

**Imports**
- `asyncio`, `logging`, `signal`, `sys`
- `typing: Optional, Dict, Any`
- `dataclasses: dataclass, field`
- `pupyteer.server.sessions.manager: SessionManager`
- `pupyteer.server.tasks.manager: TaskManager`
- `pupyteer.server.profiles.manager: ProfileManager`
- `pupyteer.server.transports.manager: TransportManager`
- `pupyteer.server.core.config: ConfigManager`
- `pupyteer.server.core.logging: AuditLogger`
- `pupyteer.server.core.auth: AuthLayer`
- `pupyteer.server.evasion.manager: EvasionTestManager`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `EngineState` (dataclass) | Fields: `started`, `shutting_down`, `active_sessions`, `queued_tasks`, `loaded_profile`, `uptime_seconds` |
| `PupyteerEngine` | `__init__(config_path)` | Instantiates all subsystems in dependency order. |
| | `async start()` | Validates config, initializes all subsystems sequentially; on failure calls `stop()` and re-raises. |
| | `async stop()` | Reverse-order shutdown of all subsystems; idempotent via `shutting_down` guard. |
| | `async wait_for_shutdown()` | Awaits `_shutdown_event`. |
| | `get_status()` | Returns snapshot dict with state, config, profiles, transports. |

**Issues**
- `uptime_seconds` field in `EngineState` is never updated anywhere — always 0.0.
- `signal` and `sys` are imported but unused.
- No periodic state refresh for `state.active_sessions` / `state.queued_tasks` (they stay at 0 despite `get_status()` reading live counts via managers).

---

## File: `pupyteer/server/core/auth.py`

**Imports**
- `hashlib`, `hmac`, `logging`, `os`, `secrets`, `time`
- `dataclasses: dataclass, field`
- `typing: Dict, Optional, Set`
- `pupyteer.server.core.config: ConfigManager`
- `pupyteer.server.core.logging: AuditLogger`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `OperatorSession` (dataclass) | Fields: `operator`, `token`, `issued_at`, `expires_at`, `permissions` (default `{read, execute}`) |
| | `expired` (property) | `time.time() > expires_at` |
| `AuthLayer` | `__init__(config, audit)` | Loads `_ttl`, `_max_failed`, calls `_load_credentials()`. |
| | `_load_credentials()` | Reads `security.operators` dict from config, hashes plaintext passwords with SHA-256. |
| | `authenticate(username, password)` | Checks lockout, verifies hash via `hmac.compare_digest`, issues token, creates session. |
| | `authorize(token, required_permission)` | Validates token + permission; lazily deletes expired sessions. |
| | `get_operator(token)` | Returns operator name for valid token. |
| | `revoke(token)` | Removes session, audits. |
| | `active_sessions()` | Purges expired sessions, returns remaining. |
| | `add_operator(username, password, permissions)` | Hashes + stores new credential, audits. |

**Issues**
- **Security**: Passwords hashed with unsalted SHA-256 — vulnerable to rainbow tables. No password complexity enforcement. Should use bcrypt/scrypt/argon2.
- **Security**: No account lockout duration — once `_failed_attempts >= _max_failed`, the user is locked out permanently until server restart. No unlock mechanism.
- **Security**: Tokens stored in in-memory dict with no periodic GC; `active_sessions()` is the only cleanup point and is only called when explicitly invoked.
- `permissions` default is hardcoded `{"read", "execute"}` — `add_operator` accepts a custom set but `authenticate` always creates the session with the default set (the parameter is ignored at session creation).

---

## File: `pupyteer/server/core/logging.py`

**Imports**
- `json`, `logging`, `os`, `sys`, `uuid`
- `datetime: datetime, timezone`
- `pathlib: Path`
- `typing: Any, Dict, Optional`
- `pupyteer.server.core.config: ConfigManager`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `AuditLogger` | `__init__(config)` | Sets operator name, optional log file path. |
| | `log_event(event, data, session, result)` | Builds structured JSON entry, logs to `pupyteer.audit` logger, appends to file. |
| | `_redact(data)` | Recursive redaction of keys matching `REDACTED_FIELDS` (`password`, `secret`, `token`, `key`, `credential`). |

**Issues**
- `os`, `sys`, `uuid` imported but unused.
- `_redact` uses substring match (`any(r in k.lower() ...)`) — a key like `"monkey"` would be redacted. Consider exact/segment matching.
- File append in `log_event` is not atomic/concurrent-safe — under high throughput from multiple async tasks, log lines could interleave.

---

## File: `pupyteer/server/sessions/manager.py`

**Imports**
- `asyncio`, `logging`, `time`
- `dataclasses: dataclass, field, asdict`
- `enum: Enum`
- `typing: Dict, List, Optional, Any`
- `pupyteer.server.core.config: ConfigManager`
- `pupyteer.server.core.logging: AuditLogger`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `SessionState` (str, Enum) | `CONNECTED`, `DISCONNECTED`, `TIMEOUT`, `ERROR`, `KILLED` |
| `SessionInfo` (dataclass) | Fields: `session_id`, `hostname`, `os`, `arch`, `username`, `state`, `connected_at`, `last_checkin`, `profile`, `agent_version`, `tags`, `task_status`, `remote_address`, `metadata` |
| | `uptime_seconds` (property) | |
| | `to_dict()` | Serializes with state value + uptime. |
| `SessionManager` | `__init__(config, transports, audit)` | `transports` typed as `Any`. |
| | `async initialize()` | Spawns `_monitor_loop` task. |
| | `async shutdown()` | Cancels monitor, kills all sessions. |
| | `async register(info)` | Assigns ID/timestamps if missing; audits. |
| | `async get(session_id)` | Simple dict lookup. |
| | `async list_all()` | Returns all sessions. |
| | `async remove(session_id)` | Removes under lock. |
| | `async kill(session_id, reason)` | Sets state to KILLED, audits, removes. |
| | `async search(query)` | Substring search across multiple fields. |
| | `async filter_by(**kwargs)` | Field-based filtering (supports str contains or exact match). |
| | `async tag(session_id, tags)` | Appends tags. |
| | `async rename(session_id, new_hostname)` | Updates hostname. |
| | `async update_checkin(session_id)` | Updates `last_checkin`, recovers from TIMEOUT. |
| | `count()` | Synchronous count. |
| | `async count_active()` | Counts CONNECTED sessions. |
| | `async summary()` | Aggregates by OS and state. |
| | `async _monitor_loop()` | Sleeps 30s, scans for timed-out sessions. |

**Issues**
- **Race condition**: `tag`, `rename`, `update_checkin`, `search`, `filter_by`, `get`, `count`, `count_active` access `self._sessions` without holding `self._lock`. Only `register`, `remove`, `kill`, `summary` are locked. Under concurrent access, dict mutations could race.
- `_monitor_loop` acquires the lock for the full scan — if many sessions exist, this blocks other operations for the duration.
- `import uuid` is done inside `register` (lazy import) — unnecessary since `uuid` is in stdlib; should be at top.
- `search` uses `any([...])` with a list comprehension inside — minor; `any(...)` with a generator is more idiomatic.

---

## File: `pupyteer/server/tasks/manager.py`

**Imports**
- `asyncio`, `logging`, `time`, `uuid`
- `dataclasses: dataclass, field`
- `enum: Enum`
- `typing: Any, Callable, Dict, List, Optional`
- `pupyteer.server.core.config: ConfigManager`
- `pupyteer.server.core.logging: AuditLogger`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `TaskState` (str, Enum) | `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED` |
| `TaskInfo` (dataclass) | Fields: `task_id`, `name`, `state`, `session_id`, `module`, `args`, `result`, `error`, `created_at`, `started_at`, `completed_at`, `progress` |
| | `duration_seconds` (property) | |
| | `to_dict()` | Full serialization. |
| `TaskManager` | `__init__(config, sessions, audit)` | `sessions` typed as `Any`. Creates `asyncio.Queue()` (unbounded). |
| | `async initialize()` | Spawns N worker tasks. |
| | `async shutdown()` | Cancels all workers and running tasks, gathers workers. |
| | `async create(name, module, session_id, args)` | Creates `TaskInfo`, enqueues. |
| | `async get(task_id)` | Dict lookup. |
| | `async cancel(task_id)` | Cancels queued (sets state) or running (cancels asyncio.Task). |
| | `async list_all()` | Returns all tasks. |
| | `async list_by_state(state)` | Filters by state. |
| | `async list_by_session(session_id)` | Filters by session. |
| | `count()` | Synchronous count. |
| | `async _worker(name)` | Dequeues, executes, handles cancellation. |
| | `async _execute(task)` | Placeholder: sleeps 0.1s, sets COMPLETED. |

**Issues**
- `_execute` is a stub — no actual task dispatch logic. Real implementation needed for production.
- `asyncio.Queue()` is unbounded — under heavy load, memory could grow without backpressure.
- `cancel` on a running task calls `task.cancel()` but does not `await` it; the worker may continue briefly after cancellation is reported.
- Worker catches bare `Exception` and logs but continues — could swallow unexpected errors (e.g., `MemoryError`) and loop forever.
- `create` puts task on queue under lock but `TaskInfo` is already in `_tasks` dict — if `_worker` picks it up before `audit.log_event` runs, ordering is fine, but there's a tiny race window where `get()` returns a task not yet fully initialized.
- `args` is passed through to audit log — could contain sensitive data; consider redacting.

---

## File: `pupyteer/server/profiles/manager.py`

**Imports**
- `copy`, `logging`, `os`
- `pathlib: Path`
- `typing: Any, Dict, List, Optional`
- `yaml`
- `pupyteer.server.core.config: ConfigManager`
- `pupyteer.server.core.logging: AuditLogger`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `C2Profile` | `__init__(data, source)` | Stores raw dict, extracts name/version. |
| | `name`, `version`, `source`, `transport_protocol` (properties) | |
| | `get(dotted_key, default)` | Dotted-path lookup into profile data. |
| | `as_dict()` | Deep copy of raw data. |
| | `summary()` | Compact dict. |
| | `validate()` | Checks required sections, name, protocol, port. |
| `ProfileManager` | `__init__(config, audit)` | Builds search paths. |
| | `async initialize()` | Loads default profile, scans for `.yaml`/`.yml` files. |
| | `async shutdown()` | Clears active profile. |
| | `_load_file(path)` | Loads + validates one file. |
| | `create(data, name)` | Creates profile; if `name` given, mutates `_data` and `_name` directly. |
| | `save(name, path)` | Persists to YAML. |
| | `get(name)`, `remove(name)`, `list()`, `active_name()`, `active()`, `load(name)`, `unload()`, `validate(name)` | Standard CRUD. |

**Issues**
- `create(name=...)` directly mutates `profile._data["profile"]["name"]` and `profile._name` — bypasses encapsulation; if `profile` key doesn't exist in data, this will `KeyError`.
- `DEFAULT_PROFILE` is deep-copied on every `initialize()` call — minor overhead but acceptable.
- No thread safety / lock on `_profiles` dict or `_active_name` — unlike other managers, this one has no `asyncio.Lock`.
- `remove` blocks deletion of the `"default"` profile by checking `source == "default"`, but a profile loaded from a file that happens to also be named `"default"` could be deleted (the check is on source string, not a flag).
- `os` imported but unused.

---

## File: `pupyteer/server/transports/manager.py`

**Imports**
- `logging`
- `typing: Any, Dict, List`
- `pupyteer.server.core.config: ConfigManager`
- `pupyteer.server.core.logging: AuditLogger`

**Classes**
| Class | Methods | Notes |
|---|---|---|
| `TransportManager` | `__init__(config, profiles, audit)` | `profiles` typed as `Any`. |
| | `async initialize()` | Hardcodes an `"https"` transport entry. |
| | `async shutdown()` | Clears all transports. |
| | `list()` | Returns transport dicts. |

**Issues**
- Stub implementation — `initialize()` hardcodes a fake `"listening"` entry without actually binding a socket or starting a server.
- No support for multiple transports, config-driven transport setup, or actual network I/O.
- `profiles` dependency is accepted but never used.

---

## Cross-File Dependencies

```
engine.py
  ├── config.ConfigManager
  ├── logging.AuditLogger
  ├── auth.AuthLayer
  ├── profiles.ProfileManager ──► config, logging
  ├── transports.TransportManager ──► config, profiles (unused), logging
  ├── sessions.SessionManager ──► config, transports (Any), logging
  ├── tasks.TaskManager ──► config, sessions (Any), logging
  └── evasion.EvasionTestManager ──► config, logging
```

- All managers depend on `ConfigManager` and `AuditLogger` (injected via constructor).
- `SessionManager` and `TaskManager` accept each other's dependencies but type them as `Any`, bypassing type checking.
- `TransportManager` accepts `profiles` but doesn't use it.

---

## Summary of Notable Issues

| Severity | File | Issue |
|---|---|---|
| 🔴 Security | `auth.py` | Unsalted SHA-256 for password hashing; no lockout expiry; token GC only on explicit call. |
| 🔴 Race condition | `sessions/manager.py` | `tag`, `rename`, `update_checkin`, `search`, `filter_by`, `get`, `count`, `count_active` access shared dict without lock. |
| 🟡 Logic | `tasks/manager.py` | `_execute` is a placeholder; unbounded queue; cancel doesn't await. |
| 🟡 Logic | `profiles/manager.py` | `create(name=...)` mutates private fields directly; no thread safety; `remove` source check is fragile. |
| 🟡 Logic | `engine.py` | `uptime_seconds` never updated; `active_sessions`/`queued_tasks` never refreshed. |
| 🟡 Stub | `transports/manager.py` | No real transport implementation. |
| 🟢 Minor | `config.py` | `_coerce` may misclassify string values. |
| 🟢 Minor | `logging.py` | `_redact` substring match too broad; unused imports. |
| 🟢 Minor | `auth.py` | `add_operator` permissions param ignored at session creation. |
| 🟢 Minor | `auth.py`, `logging.py`, `profiles/manager.py` | Unused imports (`os`, `sys`, `uuid`). |
| 🟢 Style | `sessions/manager.py` | Lazy `import uuid` inside method. |
| 🟢 Style | `sessions/manager.py` | `_monitor_loop` holds lock for full scan. |
