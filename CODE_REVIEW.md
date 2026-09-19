# Pupyteer Code Review Report

**Date:** 2026-09-19
**Scope:** TUI files, agent, package init, and project config files

---

## 1. `pupyteer/tui/app.py`

### Overview
Terminal User Interface with branding, ANSI color helpers, command registry, tab completion, and main TUI loop.

### Imports
| Import | Type |
|--------|------|
| `asyncio` | stdlib |
| `logging` | stdlib |
| `os` | stdlib |
| `readline` | stdlib |
| `shlex` | stdlib |
| `sys` | stdlib |
| `time` | stdlib |
| `typing.Any, Callable, Dict, List, Optional` | stdlib |
| `pupyteer.server.core.config.ConfigManager` | local |
| `pupyteer.server.core.engine.PupyteerEngine` | local |

### Classes

#### `Color`
- Static ANSI color constants: `RESET`, `BOLD`, `DIM`, `RED`, `GREEN`, `YELLOW`, `BLUE`, `MAGENTA`, `CYAN`, `WHITE`, `GRAY`
- `@staticmethod supports_color() -> bool` — checks `sys.stdout.isatty()`

#### `CommandRegistry`
- `__init__(self)` — initializes `_commands` dict
- `register(self, name, handler, help_text, usage)` — registers command
- `get(self, name)` — returns command dict or None
- `list_commands(self)` — sorted list of command names
- `get_help(self, name)` — formatted help string
- `get_all_help(self)` — formatted all-help string

#### `TabCompleter`
- `__init__(self, commands)` — stores command list
- `complete(self, text, state)` — readline-compatible completer callback

#### `PupyteerTUI`
- `__init__(self, engine: PupyteerEngine)` — sets up registry, config, theme, prompt
- `_register_commands(self)` — registers all TUI commands (help, banner, status, sessions, tasks, profiles, transports, config, logs, clear, exit, quit)
- `_setup_readline(self)` — configures history + tab completion
- `render_banner(self)` — prints banner + server status
- `render_dashboard(self)` — prints session dashboard
- `render_table(self, headers, rows)` — ASCII table rendering
- `cmd_help(self, args)` async
- `cmd_banner(self, args)` async
- `cmd_status(self, args)` async
- `cmd_sessions(self, args)` async — list/search/info/kill/tag
- `cmd_tasks(self, args)` async — list/info/cancel
- `cmd_profiles(self, args)` async — list/show/load/validate
- `cmd_transports(self, args)` async
- `cmd_config(self, args)` async — list/get/set
- `cmd_logs(self, args)` async — tail log file
- `cmd_clear(self, args)` async
- `cmd_exit(self, args)` async
- `run(self)` async — main event loop

### Module-level
- `BANNER` — raw string with ANSI art, formatted with `.format(codename="Nightfall", version="1.0.0")`
- `c(text, *codes)` — ANSI color wrapper function

### Cross-file Dependencies
- Depends on `pupyteer.server.core.engine.PupyteerEngine` (used for all server interaction)
- Depends on `pupyteer.server.core.config.ConfigManager` (imported but not directly used in code)
- `evasion.py` is NOT imported here — commands are defined inline

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **Medium** | `cmd_status` calls `self._engine.get_status()` but discards result — only `render_dashboard()` output is shown. The status call result is unused. |
| 2 | **Medium** | `cmd_clear` uses `print("\033[2J\033[H", end="")` — hardcoded ANSI escape; doesn't use `os.system("clear")` or `Color` class. Inconsistent with rest of file. |
| 3 | **Low** | `TabCompleter` only handles top-level commands; subcommand completion is stubbed with empty list. |
| 4 | **Low** | `_setup_readline` swallows all exceptions with bare `except Exception: pass` — makes debugging difficult. |
| 5 | **Low** | `BANNER` is formatted at module load time — version/codename can't change at runtime. |
| 6 | **Info** | `import json` inside `cmd_config` method — should be at top of file. |
| 7 | **Info** | `time` imported but never used. |
| 8 | **Info** | `ConfigManager` imported but never directly referenced in the code. |

---

## 2. `pupyteer/tui/commands/evasion.py`

### Overview
Provides command-line and TUI-accessible commands for detection-resilience/evasion testing.

### Imports
| Import | Type |
|--------|------|
| `asyncio` | stdlib |
| `sys` | stdlib |
| `typing.Any, Dict, List, Optional` | stdlib |
| `pupyteer.server.core.engine.PupyteerEngine` | local |

### Functions
- `evasion_status(args: List[str]) -> Dict[str, Any]` async — shows evasion system status
- `evasion_run(args: List[str]) -> Dict[str, Any]` async — runs an evasion test with `--name`, `--artifact`, `--env`, `--controls` args
- `evasion_list(args: List[str]) -> Dict[str, Any]` async — lists recent test results
- `evasion_stats(args: List[str]) -> Dict[str, Any]` async — shows test statistics

### Module-level
- `COMMANDS` dict — maps command names to handler functions

### Cross-file Dependencies
- `pupyteer.server.core.engine.PupyteerEngine`
- `pupyteer.server.evasion.models.EvasionTestConfig` (local import inside `evasion_run`)

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **High** | Each function creates a **new** `PupyteerEngine()` instance and calls `engine.evasion.initialize()` / `shutdown()` — no engine lifecycle management, creates/shuts down on every call. Very inefficient. |
| 2 | **High** | Engine instances are **never started** — `engine.start()` is not called before using `engine.evasion`, which likely means the engine is in an uninitialized state. |
| 3 | **Medium** | `evasion_run` — `artifact_hash_sha256=""` is hardcoded empty; comment says "will be computed on-the-fly" but there's no implementation. |
| 4 | **Medium** | `evasion_run` — `test_mode=True` is hardcoded; not configurable via args. |
| 5 | **Medium** | `evasion_run` — no validation that `artifact_path` exists before passing to test. |
| 6 | **Low** | `sys` imported but never used. |
| 7 | **Low** | `Optional` imported but never used. |
| 8 | **Low** | No error handling for `engine.evasion.initialize()` failure — exception propagates raw. |
| 9 | **Info** | This module is NOT wired into the TUI — `app.py` doesn't import `evasion` commands. They exist as standalone functions only. |

---

## 3. `pupyteer/agent/core/agent.py`

### Overview
Core agent runtime — connects to server and executes tasks (skeleton implementation).

### Imports
| Import | Type |
|--------|------|
| `asyncio` | stdlib |
| `logging` | stdlib |
| `platform` | stdlib |
| `uuid` | stdlib |
| `dataclasses.dataclass, field` | stdlib |
| `typing.Any, Dict, List, Optional` | stdlib |

### Dataclasses

#### `AgentInfo`
- Fields: `agent_id`, `hostname`, `os`, `arch`, `username`, `version`, `transport`, `profile`, `extra`
- `__post_init__` — auto-fills defaults (uuid, platform.node, platform.system, platform.machine, getpass.getuser)

### Classes

#### `PupyteerAgent`
- `__init__(self, server_host, server_port, transport="tcp")`
- `async start(self)` — main connect loop with 10s reconnect delay
- `async _connect_and_serve(self)` — placeholder (sleeps 1s)
- `stop(self)` — sets `_running = False`

### Cross-file Dependencies
- None — completely self-contained (only stdlib imports)

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **Medium** | `_connect_and_serve` is a stub — just `await asyncio.sleep(1)`. No actual connection logic. |
| 2 | **Medium** | `start()` has no max reconnect attempts — infinite reconnect loop on failure. |
| 3 | **Low** | `List` imported but never used. |
| 4 | **Low** | `uuid.uuid4()[:12]` truncates to 12 chars — potential collision risk with many agents. |
| 5 | **Info** | Docstring says "skeleton implementation" — confirmed incomplete. |
| 6 | **Info** | `stop()` is synchronous but `start()` is async — inconsistent API. |

---

## 4. `pupyteer/__init__.py`

### Overview
Package init — exports core components.

### Module-level
- `__version__ = "1.0.0"`
- `__codename__ = "Nightfall"`
- `__author__ = "Pupyteer Team"`
- `__description__ = "Modular Red-Team Operations Framework"`

### Imports
| Import | Source |
|--------|--------|
| `PupyteerEngine` | `pupyteer.server.core.engine` |
| `SessionManager` | `pupyteer.server.sessions.manager` |
| `TaskManager` | `pupyteer.server.tasks.manager` |
| `ProfileManager` | `pupyteer.server.profiles.manager` |
| `TransportManager` | `pupyteer.server.transports.manager` |

### `__all__`
Lists all 5 imported classes.

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **High** | Package name mismatch: code lives in `pupyteer/` but `setup.py` declares `name='pupy'` and packages `pupy*`. This import path may not match actual installed package. |
| 2 | **Info** | Version hardcoded — consider using `importlib.metadata` for dynamic version. |

---

## 5. `setup.py`

### Overview
setuptools-based package setup (legacy style — reads requirements.txt directly).

### Key Configuration
| Key | Value |
|-----|-------|
| `name` | `'pupy'` |
| `version` | `'3.0.0'` |
| `packages` | `find_packages(where='.', include=['pupy*'])` |
| `package_data` | `{'pupy': ['conf/**', 'external/**', 'packages/**', ...]}` |
| `license_files` | `('LICENSE')` |
| `author` | `'n1nj4sec'` |
| `entry_points` | `{'console_scripts': ['pupysh = pupy.cli.pupysh:main']}` |
| `install_requires` | read from requirements.txt |

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **Critical** | `name='pupy'` — the project is called "Pupyteer" but setup.py declares the package as "pupy". This is a copy-paste from the original Pupy project. |
| 2 | **Critical** | `version='3.0.0'` — conflicts with `__init__.py` version of `1.0.0`. |
| 3 | **Critical** | `packages=find_packages(include=['pupy*'])` — won't find `pupyteer` source files. Package is misconfigured for this project. |
| 4 | **Critical** | `entry_points` references `pupy.cli.pupysh:main` — that module doesn't exist in this project. |
| 5 | **High** | `package_data` paths (`conf/**`, `external/**`, etc.) reference Pupy-specific directories that don't exist. |
| 6 | **High** | `author='n1nj4sec'` — copied from original Pupy; should be updated. |
| 7 | **Medium** | Uses `open("requirements.txt", "r")` without `with` statement — file handle leak (minor, since setup runs once). |
| 8 | **Medium** | `license_files` is a string `('LICENSE')` not a tuple — works but misleading (needs comma for tuple). |
| 9 | **Low** | Commented-out `long_description` blocks. |
| 10 | **Info** | `# -*- coding: UTF8 -*-` — unnecessary in Python 3 (UTF-8 is default). |

---

## 6. `requirements.txt`

### Contents
50 dependency lines covering crypto, networking, system tools, and dev tools.

### Notable Dependencies
| Package | Version | Notes |
|---------|---------|-------|
| `pycryptodome` | latest | Crypto |
| `pefile` | latest | PE parsing |
| `pyyaml` | latest | YAML |
| `paramiko` | `==2.0.2` | **Severely outdated** (2017) |
| `ecdsa` | `==0.13` | Outdated |
| `scapy` | latest | Network |
| `impacket` | latest | Network/security |
| `M2Crypto` | `>=0.30.1` | C extension, build issues common |
| `pypykatz` | git URL | Master branch |
| `dukpy` | latest | JS engine, C extension |
| `flake8` | latest | Dev only |
| `flake8-per-file-ignores` | latest | Dev only |
| `pyuv` | git URL | Master, Python 3.11+ compat fix |
| `tqdm` | latest | Progress bars |

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **High** | `paramiko==2.0.2` is extremely outdated (2017) — has known security vulnerabilities. |
| 2 | **High** | Git-URL dependencies (`tinyec`, `pypykatz`, `urllib-auth`, `pyuv`) are unpinned to commits — builds are not reproducible. |
| 3 | **Medium** | Dev dependencies (`flake8`, `flake8-per-file-ignores`) mixed with runtime deps — should be in `requirements-dev.txt`. |
| 4 | **Medium** | `ushlex` marked for Python 2 only (`python_version<'3'`) — this is a Python 2 legacy dep, not needed for Py3. |
| 5 | **Medium** | `scandir` — stdlib since Python 3.5, unnecessary. |
| 6 | **Low** | No hash checking or pinned versions for most packages — supply chain risk. |
| 7 | **Low** | `http_request` on line 44 — very generic name, likely a typo or custom package; unclear what this resolves to. |

---

## 7. `.travis.yml`

### Overview
Travis CI configuration for the project.

### Structure
- **OS:** Linux (xenial)
- **Services:** Docker
- **Jobs:** 2 parallel jobs (generic + Python 3.8 flake8)
- **Scripts:** Build Docker images, verify payload artifacts, push to Docker Hub

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **Critical** | Uses `dist: xenial` (Ubuntu 16.04) — EOL since April 2021, deprecated on Travis. |
| 2 | **Critical** | `language: generic` with Python 2 references (`pip2`, `python2 -m flake8`) — Python 2 is EOL. |
| 3 | **High** | `sudo pip2 install flake8` — installs pip2 globally, may fail on modern systems. |
| 4 | **High** | Hardcoded references to `alxchk/pupy` repo — this is Pupyteer, not Pupy. Config is copied from upstream. |
| 5 | **High** | `$TRAVIS_BUILD_DIR/pupy` paths assume project dir is named `pupy`, but actual project is `Pupyteer`. |
| 6 | **High** | `docker push alxchk/pupy:$TAG` — pushes to wrong Docker Hub repo. |
| 7 | **Medium** | `before_script: true  # override` — overrides Travis default but runs `true` (no-op). |
| 8 | **Medium** | `env.global.secure` contains encrypted secrets — may be tied to original Pupy repo, won't work for Pupyteer forks. |
| 9 | **Medium** | No testing of `pupyteer` package — only builds Docker images and lists files. |
| 10 | **Low** | `services: docker` with `language: generic` — unusual combination. |
| 11 | **Info** | Travis CI free tier has been deprecated; should migrate to GitHub Actions. |

---

## 8. `tox.ini`

### Overview
Flake8 configuration only (tox is not actually configured — this is just flake8 settings).

### Configuration
- **Ignore list:** E722, E501, E402, E241, E221, E211, E222, E225, E226, E227, E272, E231, E251, E265, E302, E305, E303, E228, E127, E128, E129, E502, E271, E261, E262, E122, E123, E124, E125, E126, E131, E121, E226, E266, E242, E731, W606
- **Per-file ignores:** Multiple files
- **Exclude:** conf, crypto, data, external, library_patches, output, payload_templates, proxy, webstatic, packages/patches, etc.

### Bugs & Issues

| # | Severity | Description |
|---|----------|-------------|
| 1 | **Critical** | File is named `tox.ini` but contains ONLY flake8 config — no `[tox]` section, no testenv. This is NOT a valid tox configuration. |
| 2 | **High** | `E226` listed twice in ignore list (line 13 + line 16). |
| 3 | **High** | `E261` listed twice (line 15 + line 16). |
| 4 | **Medium** | Excluded paths (`network/lib/transports/...`) reference Pupy paths, not Pupyteer paths. |
| 5 | **Medium** | Flake8 `ignore` list is enormous — effectively disables most style rules. |
| 6 | **Low** | `W606` is not a real flake8 code (it was for `pyrpastyle`/`pep8` tool, removed). |

---

## Cross-File Dependency Graph

```
pupyteer/__init__.py
    └── pupyteer.server.core.engine.PupyteerEngine
    └── pupyteer.server.sessions.manager.SessionManager
    └── pupyteer.server.tasks.manager.TaskManager
    └── pupyteer.server.profiles.manager.ProfileManager
    └── pupyteer.server.transports.manager.TransportManager

pupyteer/tui/app.py
    └── pupyteer.server.core.engine.PupyteerEngine
    └── pupyteer.server.core.config.ConfigManager (unused)

pupyteer/tui/commands/evasion.py
    └── pupyteer.server.core.engine.PupyteerEngine
    └── pupyteer.server.evasion.models.EvasionTestConfig

pupyteer/agent/core/agent.py
    └── (no local dependencies — fully self-contained)
```

---

## Summary of Critical/High Issues

| Priority | File | Issue |
|----------|------|-------|
| **Critical** | `setup.py` | Package name `pupy` doesn't match project `pupyteer` — package won't install correctly |
| **Critical** | `setup.py` | `version='3.0.0'` conflicts with `__init__.py` `__version__="1.0.0"` |
| **Critical** | `setup.py` | `find_packages(include=['pupy*'])` won't find source |
| **Critical** | `setup.py` | Entry point `pupy.cli.pupysh:main` doesn't exist |
| **Critical** | `tox.ini` | No actual tox configuration — misnamed flake8 config |
| **Critical** | `.travis.yml` | Python 2 / pip2 references (EOL) |
| **Critical** | `.travis.yml` | Hardcoded `alxchk/pupy` repo references |
| **High** | `.travis.yml` | `dist: xenial` EOL |
| **High** | `.travis.yml` | Wrong Docker Hub repo |
| **High` | `evasion.py` | Creates new engine instance per call — no lifecycle management |
| **High` | `evasion.py` | Engine never started before use |
| **High` | `requirements.txt` | `paramiko==2.0.2` outdated, known vulnerabilities |
| **High** | `requirements.txt` | Unpinned git URL dependencies |
| **High** | `tox.ini` | Duplicate ignore codes (E226, E261) |
| **High** | `tox.ini` | Excluded paths reference Pupy, not Pupyteer |

---

## Recommendations

1. **Rename package properly:** Update `setup.py` to use `name='pupyteer'` and `include=['pupyteer*']`.
2. **Standardize versioning:** Use a single version source (e.g., read from `__init__.py`).
3. **Fix CI:** Migrate from Travis CI to GitHub Actions; remove Python 2 references.
4. **Evasion commands:** Wire into TUI or provide a proper CLI entry point; use shared engine instance.
5. **Separate dev requirements:** Move flake8 and dev tools to `requirements-dev.txt`.
6. **Rename tox.ini:** Either add a proper `[tox]` section or rename to `flake8.ini` / `[flake8]` in `setup.cfg`.
7. **Pin all dependencies:** Use commit hashes for git URLs, pin all versions.
8. **Remove Pupy copyright:** Update author metadata and remove upstream Pupy references.
