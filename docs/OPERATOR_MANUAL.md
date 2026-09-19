# Pupyteer Operator Manual

**Version:** 1.0.0 (Nightfall)
**Last Updated:** 2026-09-19

---

## Table of Contents

1. [Introduction](#introduction)
2. [Quick Start](#quick-start)
3. [The TUI](#the-tui)
4. [Sessions Management](#sessions-management)
5. [Tasks Management](#tasks-management)
6. [Payload Management](#payload-management)
7. [Profiles](#profiles)
8. [Transports](#transports)
9. [Configuration](#configuration)
10. [Logging & Auditing](#logging--auditing)
11. [Troubleshooting](#troubleshooting)

---

## Introduction

Pupyteer is a modular red-team operations framework built as a modernized fork of Pupy. It provides a unified terminal interface for managing C2 sessions, executing post-exploitation modules, and monitoring agent telemetry during authorized security assessments.

### What Pupyteer Does

- **Session Management** — Track and interact with connected agents across platforms (Windows, Linux, macOS, Android).
- **Task Queue** — Dispatch commands and modules asynchronously to one or many sessions with progress tracking.
- **Malleable C2 Profiles** — Shape C2 traffic to blend with legitimate network activity.
- **Modular Architecture** — Built-in and third-party modules organized by category (recon, execution, file ops, red-team, evasion).
- **Structured Auditing** — Every operator action emits a JSON audit log with redaction of sensitive fields.

### Architecture at a Glance

```
                  PUPYTEER
                     |
          +----------+----------+
          |                     |
        Server                TUI
          |
    +-----+-----+
    |           |
 Session      Task
 Manager     Manager
    |           |
    +-----+-----+
          |
     C2 Engine
          |
   +------+------+------+
   |      |      |      |
Profile  Auth   Queue  Transport
Manager  Layer  Engine Manager
```

---

## Quick Start

### Prerequisites

- Python 3.8+
- pip or pipx
- Network access to the C2 listener port (default: 8443)

### Launch

```bash
# From source
python3 -m pupyteer.main

# Or if installed via pipx
pupyteer

# Headless mode (no TUI)
pupyteer --headless

# With custom config
pupyteer -c /path/to/config.yaml

# Show version
pupyteer --version

# Enable debug logging
pupyteer --debug
```

### First Run

On startup, the TUI displays the Pupyteer banner, server address, operator name, and a dashboard showing server status, active agents, queued tasks, and loaded profile.

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██████╗ ██╗   ██╗██████╗ ██╗   ██╗████████╗███████╗███████╗  ║
║   ██╔══██╗██║   ██║██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝██╔════╝  ║
║   ██████╔╝██║   ██║██████╔╝ ╚████╔╝    ██║   █████╗  █████╗    ║
║   ██╔═══╝ ██║   ██║██╔═══╝   ╚██╔╝     ██║   ██╔══╝  ██╔══╝    ║
║   ██║     ╚██████╔╝██║        ██║      ██║   ███████╗███████╗  ║
║   ╚═╝      ╚═════╝ ╚═╝        ╚═╝      ╚═╝   ╚══════╝╚══════╝  ║
║                                                                  ║
║          Red Team Operations Framework  vNightfall 1.0.0         ║
╚══════════════════════════════════════════════════════════════════╝

  [Server] 0.0.0.0:8443
  [Operator] redteam-operator
  [Profile] HTTPS-Standard
  [Agents] 0

pupyteer >
```

---

## The TUI

### Command System

Pupyteer uses a `readline`-based command line with:

- **Tab Completion** — Press TAB to complete a command, its subcommand, then a
  live object name (session IDs, module names, profile names, payload IDs).
- **Command History** — Up/Down arrows navigate history (stored in `~/.pupyteer_history`).
- **Structured Output** — Tables and colored output for readability.
- **Error Handling** — Errors appear in red; successes in green; warnings in yellow.

`readline` is optional. Where the platform has no `readline` (native Windows
Python), the console still runs — commands and tables work, but history recall
and TAB completion are unavailable. Install `pyreadline3` if you want them there.

### Global Commands

| Command | Description |
|---------|-------------|
| `help [command]` | Show help for all commands or a specific one |
| `banner` | Display the startup banner |
| `status` | Show server status and dashboard |
| `clear` | Clear the terminal screen |
| `exit` / `quit` | Shut down Pupyteer |

### Console Command Reference

| Command | Subcommands |
|---------|-------------|
| `sessions` | `list`, `info <id>`, `interact <id>`, `kill <id>`, `rename <id> <name>`, `tag <id> <tag>`, `search <query>` |
| `payloads` | `status`, `list`, `build`, `info <id>`, `verify <id>`, `remove <id>`, `cleanup`, `versions <name>` |
| `profiles` | `list`, `show <name>`, `validate <name>`, `load <name>`, `unload`, `new <file>` |
| `jobs` | `list`, `info <id>`, `kill <id>` |
| `tasks` | `list`, `info <id>`, `cancel <id>` |
| `evasion` | `status`, `run`, `list`, `stats`, `profiles`, `runner` |
| `pipeline` | `run`, `build`, `test`, `auto`, `status`, `history`, `profiles`, `info` |
| `modules` / `use` / `set` / `options` / `run` | Metasploit-style module workflow |
| `config` | `get <key>`, `set <key> <value>` |
| `search`, `info`, `back`, `reload`, `exploit` | Module discovery and execution |
| `transports`, `logs`, `theme` | Operator QoL |

### Theming

Set your preferred theme in config:

```yaml
operator:
  theme: dark   # or light
```

The theme affects ANSI color rendering. The `dark` theme uses bright ANSI colors suitable for dark terminals. If stdout is not a TTY, colors are automatically disabled.

---

## Sessions Management

### Listing Sessions

```
pupyteer > sessions list

  ID           Hostname             OS          Arch        User            State       Tags
  ───────────  ───────────────────  ──────────  ──────────  ──────────────  ──────────  ──────
  a1b2c3d4e5f6 win10-pro            Windows     x64         admin           connected   dc,file
  f6e5d4c3b2a1 ubuntu-srv           Linux       x64         root            connected

  Total: 2 sessions
```

### Session Info

```
pupyteer > sessions info a1b2c3d4e5f6

    session_id: a1b2c3d4e5f6
    hostname: win10-pro
    os: Windows
    arch: x64
    username: admin
    state: connected
    connected_at: 1789790231.0
    last_checkin: 1789795380.0
    profile: HTTPS-Standard
    agent_version: 1.0.0
    tags: ['dc', 'file']
    task_status: idle
    remote_address: 192.168.1.100:54321
    uptime_seconds: 5149.0
```

### Searching Sessions

```
pupyteer > sessions search linux

  Found 1 matching sessions
    f6e5d4c3b2a1 ubuntu-srv (Linux)
```

Search matches against: session ID, hostname, OS, username, arch, profile, remote address, and tags.

### Tagging Sessions

```
pupyteer > sessions tag a1b2c3d4e5f6 production sql

  Tagged session a1b2c3d4e5f6
```

Tags help organize sessions across large operations.

### Renaming Sessions

```
pupyteer > sessions rename a1b2c3d4e5f6 web-frontend-01
```

Relabels the session's hostname field for the operator. This changes only the
console label, not the agent's reported identity.

### Killing Sessions

```
pupyteer > sessions kill a1b2c3d4e5f6

  Session a1b2c3d4e5f6 killed.
```

Killing a session terminates the agent connection and removes it from tracking. The audit log records the operator, session ID, and reason.

### Session Lifecycle

```
CONNECTED → DISCONNECTED (network loss)
          → TIMEOUT      (no checkin within timeout_seconds)
          → ERROR        (protocol error)
          → KILLED       (operator action)
```

The background monitor runs every 30 seconds and marks sessions as TIMEOUT when `last_checkin` exceeds `session.timeout_seconds` (default: 300).

---

## Tasks Management

### Listing Tasks

```
pupyteer > tasks list

  ID           Name                      State      Session      Module          Progress
  ───────────  ────────────────────────  ─────────  ───────────  ──────────────  ────────
  t1k2j3h4g5f6 sysinfo-a1b2c3            completed  a1b2c3d4e5f6 sysinfo         100%
  g5f6h7j8k9l0 ps-f6e5d4c                running    f6e5d4c3b2a1 ps              45%

  Total: 2 tasks
```

### Task Info

```
pupyteer > tasks info t1k2j3h4g5f6

    task_id: t1k2j3h4g5f6
    name: sysinfo-a1b2c3
    state: completed
    session_id: a1b2c3d4e5f6
    module: sysinfo
    args: {}
    result: {'status': 'ok', 'data': {...}}
    created_at: 1789790231.0
    started_at: 1789790232.0
    completed_at: 1789790245.0
    progress: 1.0
    duration_seconds: 13.0
```

### Cancelling Tasks

```
pupyteer > tasks cancel g5f6h7j8k9l0

  Task g5f6h7j8k9l0 cancelled.
```

Cancelling a QUEUED task marks it CANCELLED without execution. Cancelling a RUNNING task sends a cancellation signal to the worker.

### Task Lifecycle

```
QUEUED → RUNNING → COMPLETED
                  → FAILED
                  → CANCELLED
        → CANCELLED (if cancelled before execution)
```

### Concurrency

The task manager runs up to `tasks.max_concurrent` workers simultaneously (default: 5). Additional tasks remain QUEUED until a worker becomes available.

---

## Payload Management

Payloads move through a fixed lifecycle:

```
Configuration → Validation → Build → Verification → Artifact Management → Controlled Deployment
```

Every artifact is tracked with metadata: payload ID, version, platform, architecture,
build timestamp, configuration profile, build status, SHA-256, operator and expiry.

### Building a Payload

```
pupyteer > payloads build --name web01 --platform windows --arch x64 \
             --type executable --transport tcp --host 127.0.0.1 --port 8443 \
             --profile HTTPS-Standard --expiration 30
```

| Flag | Meaning |
|------|---------|
| `--name` | Payload name (required) |
| `--platform` / `--arch` | Target platform and architecture |
| `--type` | Artifact type (`executable`, ...) |
| `--transport` / `--host` / `--port` | Callback endpoint baked into the stub |
| `--profile` | C2 profile the agent should speak |
| `--expiration` | Validity window in days; expired payloads are marked and cleaned up |
| `--version` | Explicit version, otherwise auto-incremented |
| `--sign` | Sign the artifact if signing is configured |

Unrecognised flags are rejected rather than ignored, so a mistyped option cannot
silently produce a payload without the expiry or profile you intended.

### Inspecting and Verifying

```
pupyteer > payloads list                     # table of all artifacts
pupyteer > payloads info <payload_id>        # metadata + recorded build log
pupyteer > payloads verify <payload_id>      # recompute and compare hashes
pupyteer > payloads versions <name>          # version history for a name
```

`payloads info` reports the exact configuration used, which is what makes a build
reproducible: same config in, same SHA-256 out.

### Retention

```
pupyteer > payloads cleanup --max-age 30             # drop artifacts older than 30 days
pupyteer > payloads cleanup --name web01 --keep 3    # keep the 3 newest versions
pupyteer > payloads remove <payload_id>              # delete one artifact and its record
```

Cleanup also marks any payload past its `--expiration` window as expired.

Artifacts are written under `paths.payload_artifacts` (default
`./payloads/artifacts`), which is git-ignored — payload binaries should never be
committed.

---

## Profiles

Profiles define how agents communicate with the server — protocol, timing, headers, jitter, and encoding.

### Listing Profiles

```
pupyteer > profiles list

  Name              Version  Transport  Source   Active
  ────────────────  ───────  ─────────  ───────  ──────
  HTTPS-Standard    1.0      https      config   ✓
```

### Showing a Profile

```
pupyteer > profiles show HTTPS-Standard

    name: HTTPS-Standard
    transport: https
    user_agent: Mozilla/5.0
    jitter: 0.2
    poll_interval: 5.0
```

### Loading a Profile

```
pupyteer > profiles load HTTPS-Standard

  Profile HTTPS-Standard loaded.
```

### Validating a Profile

```
pupyteer > profiles validate HTTPS-Standard

  Profile HTTPS-Standard is valid.
```

`profiles load` validates before activating, so an invalid profile can never go
live. Failures print one error per problem.

### Unloading and Adding Profiles

```
pupyteer > profiles unload            # deactivate the current profile
pupyteer > profiles new ./my_profile.yaml   # load a profile file into the registry
```

### Profile Structure

```yaml
profile:
  name: "HTTPS-Standard"
  version: "1.0"

transport:
  protocol: "tcp"
  host: "0.0.0.0"
  port: 8443

session:
  heartbeat_interval: 30
  timeout: 300
  jitter: 0.2

encoding:
  mode: "raw"

logging:
  level: "INFO"

timeouts:
  connect: 30
  response: 60

security:
  require_auth: true
  token_ttl: 3600
```

### Profile Fields

| Field | Description |
|-------|-------------|
| `profile.name` | Unique profile identifier |
| `profile.version` | Semantic version of the profile |
| `transport.protocol` | Network protocol (tcp, https, dns, websocket) |
| `transport.host` | Listener bind address |
| `transport.port` | Listener port |
| `session.heartbeat_interval` | Agent check-in frequency in seconds |
| `session.timeout` | Seconds before an agent is considered disconnected |
| `session.jitter` | Randomization factor (0.0–1.0) for beacon timing |
| `encoding.mode` | Payload encoding (raw, base64, aes256) |
| `timeouts.connect` | Connection establishment timeout |
| `timeouts.response` | Agent response timeout |

---

## Transports

### Listing Transports

```
pupyteer > transports

    https [listening]  sent=1024B  recv=2048B
```

Transports are the network listeners that agents connect through. Pupyteer abstracts transport implementations so new protocols can be added without modifying the session layer.

### Transport Interface

```python
class Transport:
    async def connect(self) -> None
    async def disconnect(self) -> None
    async def send(self, data: bytes) -> None
    async def receive(self) -> Optional[bytes]
    async def health_check(self) -> bool
    async def close(self) -> None
```

Built-in transport types include: `https`, `http`, `dns`, `websocket`, `tcp_cleartext`, `udp_secure`.

---

## Configuration

### Configuration Search Order

Pupyteer loads configuration from multiple sources with later sources overriding earlier ones:

1. `./pupyteer.yaml` (current directory)
2. `~/.config/pupyteer/config.yaml` (user config)
3. `/etc/pupyteer/config.yaml` (system-wide)
4. `PUPYTEER_*` environment variables

### Environment Variables

Environment variables use the prefix `PUPYTEER_` with double-underscore as the dotted-key separator:

```bash
# Set server port to 9443
export PUPYTEER_SERVER__PORT=9443

# Set logging level to DEBUG
export PUPYTEER_LOGGING__LEVEL=DEBUG

# Override operator name
export PUPYTEER_OPERATOR__NAME=operator-alice
```

### Configuration Reference

```yaml
server:
  host: "0.0.0.0"        # Listener bind address
  port: 8443             # Listener port (1-65535)
  backlog: 10            # Socket listen backlog

logging:
  level: "INFO"          # DEBUG, INFO, WARNING, ERROR, CRITICAL
  format: "json"         # Output format
  file: null             # Path to log file (null = stdout only)

operator:
  name: "redteam-operator"  # Operator attribution for audit logs
  theme: "dark"             # Terminal theme (dark/light)

profile:
  default: "HTTPS-Standard"  # Profile loaded on startup

session:
  timeout_seconds: 300   # Agent timeout threshold

tasks:
  max_concurrent: 5      # Simultaneous task workers

security:
  require_auth: true     # Require operator authentication
  token_ttl: 3600        # Session token lifetime in seconds
  max_failed_logins: 5   # Lockout threshold
  operators:             # Development credential store
    admin: "changeme"    # CHANGE IN PRODUCTION

paths:
  payload_artifacts: "./payloads/artifacts"
  profiles: "./config/profiles"
  logs: "./logs"
```

### Viewing and Modifying Config

```
pupyteer > config list          # Show full configuration
pupyteer > config get server.port
  server.port = 8443
pupyteer > config set logging.level DEBUG
  Set logging.level = DEBUG
```

---

## Logging & Auditing

### Audit Events

Every significant operator action emits a structured JSON audit entry:

```json
{
  "timestamp": "2026-09-19T10:00:00+00:00",
  "event": "session_killed",
  "operator": "redteam-operator",
  "session": "a1b2c3d4e5f6",
  "result": "ok",
  "details": {
    "reason": "operator",
    "hostname": "win10-pro"
  }
}
```

### Event Types

| Event | Description |
|-------|-------------|
| `engine_start` | Engine initialization begins |
| `engine_ready` | All subsystems started successfully |
| `engine_shutdown` | Graceful shutdown initiated |
| `auth_success` | Operator authenticated |
| `auth_failed` | Authentication failed (bad credentials) |
| `auth_lockout` | Account locked after max failed attempts |
| `session_registered` | New agent connected |
| `session_killed` | Session terminated by operator |
| `session_timeout` | Agent timed out (no checkin) |
| `session_tagged` | Tags added to session |
| `session_renamed` | Session hostname changed |
| `task_created` | Task queued |
| `task_completed` | Task finished successfully |
| `task_failed` | Task encountered an error |
| `auth_operator_added` | New operator credential registered |
| `auth_revoke` | Session token revoked |

### Security Redaction

The audit logger automatically redacts fields containing sensitive keywords (`password`, `secret`, `token`, `key`, `credential`) by replacing their values with `***REDACTED***`.

### Log File Output

When `logging.file` is set, audit entries are appended as newline-delimited JSON (NDJSON), suitable for ingestion by SIEMs or log analysis tools.

```
pupyteer > logs 50          # Show last 50 log lines
```

---

## Troubleshooting

### Engine Fails to Start

**Symptom:** `Engine failed to start: <error>`

**Check:**
- Is port 8443 already in use? (`ss -tlnp | grep 8443`)
- Is the configuration valid? (Check `server.port`, `logging.level`)
- Are all required dependencies installed? (`pip install -r requirements.txt`)

### No Agents Connecting

**Symptom:** Engine starts but agents don't appear.

**Check:**
- Is the transport listening? (Check `transports` command output)
- Are firewall rules blocking inbound connections?
- Is the agent configured with the correct C2 address and profile?
- Check the audit log for connection attempts.

### Sessions Timeout Immediately

**Symptom:** Agents connect but quickly show TIMEOUT state.

**Check:**
- `session.timeout_seconds` may be too low
- Network latency or jitter exceeding heartbeat interval
- Agent-side errors preventing check-in responses

### Command Unknown

**Symptom:** `Unknown command: <name>`

- Type `help` for the full command list
- Check for typos (commands are case-sensitive)
- TAB completion shows available commands

### Authentication Lockout

**Symptom:** `Auth locked out for user: <name>`

- After `max_failed_logins` consecutive failures, the account is locked
- Restart Pupyteer to reset (development mode)
- In production, integrate with an identity provider

---

## Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| `TAB` | Complete current command |
| `↑` / `↓` | Navigate command history |
| `Ctrl+C` | Interrupt current operation / exit |
| `Ctrl+D` | Exit (EOF) |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Clean shutdown |
| 1 | Unhandled exception |
| 130 | Keyboard interrupt |

---

## Support & Reporting

- **Bug Reports:** File an issue on the Pupyteer repository
- **Feature Requests:** Open a discussion thread
- **Security Vulnerabilities:** Do NOT file public issues. Contact the maintainers privately.
