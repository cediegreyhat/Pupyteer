# Graph Report - pupyteer  (2026-09-19)

## Corpus Check
- 47 files · ~18,559 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 892 nodes · 1602 edges · 68 communities (39 shown, 21 thin omitted)
- Extraction: 76% EXTRACTED · 24% INFERRED · 0% AMBIGUOUS · INFERRED: 390 edges (avg confidence: 0.89)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `56b7aac6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- asyncio
- PupyteerTUI
- PupyteerEngine
- PayloadStore
- TaskManager
- SessionManager
- TestConfigManager
- asyncio
- C2Profile
- ProfileManager
- test_evasion.py
- ConfigManager
- AuthLayer
- EvasionTestManager
- LitterboxClient
- PayloadConfig
- AuditLogger
- Pupyteer — Phase 10: Evasion Testing
- EvasionTestResult
- TransportManager
- Any
- Transport
- PupyteerAgent
- interfaces.py
- ISessions
- Any
- TransportManager
- models.py
- recon.py
- test_full_litterbox_flow
- ITransports
- EvasionTestModule
- PupyModule
- IProfiles
- ModuleCategory
- transports/__init__.py
- Any
- WebSocketTransport
- conftest.py
- async_main
- ._load_from_file
- TCPTransport
- ControlResult
- IConfig
- IEngine
- EvasionTestConfig
- .build
- .log_event
- ShellExecModule
- agent/core/__init__.py
- pupyteer/__init__.py
- payloads/__init__.py
- server/core/__init__.py
- evasion/__init__.py
- builtin/__init__.py
- modules/__init__.py
- profiles/__init__.py
- sessions/__init__.py
- tasks/__init__.py
- tui/__init__.py

## God Nodes (most connected - your core abstractions)
1. `ConfigManager` - 108 edges
2. `AuditLogger` - 89 edges
3. `PupyteerEngine` - 41 edges
4. `SessionInfo` - 39 edges
5. `ProfileManager` - 37 edges
6. `EvasionTestManager` - 35 edges
7. `SessionManager` - 33 edges
8. `TestSessionManager` - 33 edges
9. `TaskManager` - 27 edges
10. `PupyteerTUI` - 27 edges

## Surprising Connections (you probably didn't know these)
- `async_main()` --uses--> `ConfigManager`  [INFERRED]
  pupyteer/main.py → pupyteer/server/core/config.py
- `async_main()` --uses--> `PupyteerEngine`  [INFERRED]
  pupyteer/main.py → pupyteer/server/core/engine.py
- `async_main()` --uses--> `PupyteerTUI`  [INFERRED]
  pupyteer/main.py → pupyteer/tui/app.py
- `TestPayloadBuilder` --uses--> `PayloadConfig`  [INFERRED]
  pupyteer/tests/integration/test_engine.py → pupyteer/payloads/manager.py
- `TestPayloadValidationRegression` --uses--> `PayloadConfig`  [INFERRED]
  pupyteer/tests/regression/test_regression.py → pupyteer/payloads/manager.py

## Import Cycles
- None detected.

## Communities (68 total, 21 thin omitted)

### Community 0 - "asyncio"
Cohesion: 0.05
Nodes (13): Metadata for an active agent session., SessionInfo, audit(), config(), asyncio, fixture, Unit tests for Pupyteer core components — config, sessions, tasks, profiles,…, Create a temporary YAML config file. (+5 more)

### Community 1 - "PupyteerTUI"
Cohesion: 0.07
Nodes (17): TestTUI, c(), Color, CommandRegistry, PupyteerTUI, Any, Pupyteer TUI — Terminal User Interface with branding and command system., Pupyteer Terminal Interface Features: - Startup banner with version info -… (+9 more)

### Community 2 - "PupyteerEngine"
Cohesion: 0.07
Nodes (27): EngineState, PupyteerEngine, Any, Pupyteer Server Core Engine, Block until shutdown signal received., Return current engine status snapshot., Tracks the operational state of the Pupyteer engine., Central orchestrator for the Pupyteet red-team framework. Manages lifecycle of… (+19 more)

### Community 3 - "PayloadStore"
Cohesion: 0.08
Nodes (22): PayloadArch, PayloadMetadata, PayloadPlatform, PayloadStatus, PayloadStore, PayloadType, Any, Enum (+14 more)

### Community 4 - "TaskManager"
Cohesion: 0.06
Nodes (20): Any, Enum, str, Task Manager — Async task queue and tracking for Pupyteer., Create and queue a new task., Cancel a queued or running task., Filter tasks by state., Filter tasks by session. (+12 more)

### Community 5 - "SessionManager"
Cohesion: 0.06
Nodes (20): Any, Enum, str, Session Manager — Agent/session lifecycle management for Pupyteer., Register a new session. Returns session ID., Look up a session by ID., Remove a session from tracking., Terminate a session and notify the agent. (+12 more)

### Community 6 - "TestConfigManager"
Cohesion: 0.07
Nodes (5): Any, Validate the loaded configuration., Retrieve value via dotted path (e.g. 'server.port')., Set value via dotted path, creating intermediate dicts as needed., TestConfigManager

### Community 7 - "asyncio"
Cohesion: 0.10
Nodes (17): asyncio, Regression tests — verifying fixed bugs don't return. These tests exist because…, TaskManager.get() must return None for missing tasks., TaskManager.get() returns TaskInfo after creation., String port should be rejected by validate()., Valid integer port should pass validation., Engine's TransportManager has initialize/list/shutdown API., Simple TransportManager can init and shutdown. (+9 more)

### Community 8 - "C2Profile"
Cohesion: 0.09
Nodes (10): C2Profile, Any, Path, Profile Manager — C2 malleable profile loading and validation for Pupyteer., Load default profile and scan for profile files., Create and register a new profile., Persist a profile to YAML file., Represents a validated C2 communication profile. (+2 more)

### Community 9 - "ProfileManager"
Cohesion: 0.10
Nodes (10): ProfileManager, Manages C2 malleable profiles: - Load from YAML files in config/profiles/ -…, Clear active profile., TestTransportManager, ProfileManager.get() returns a C2Profile object., C2Profile has validate() method., C2Profile.get() supports dotted key access., C2Profile.summary() returns name and metadata. (+2 more)

### Community 10 - "test_evasion.py"
Cohesion: 0.15
Nodes (23): Verify an artifact matches its expected SHA256 hash., verify_artifact_hash(), main(), asyncio, Standalone test script for the Pupyteer evasion subsystem. Run: python -m…, EvasionTestResult -> dict -> JSON -> dict preserves data., EvasionTestManager runs a local test end-to-end., Tests are rejected when test_mode is False. (+15 more)

### Community 11 - "ConfigManager"
Cohesion: 0.18
Nodes (9): PayloadBuilder, Handles payload compilation and generation. Supports: - Configuration…, Generate a unique payload ID., ConfigManager, Centralized configuration management for Pupyteer., Persist current config to YAML., Hierarchical config loader with environment-specific overrides. Search order:…, TestPayloadBuilder (+1 more)

### Community 12 - "AuthLayer"
Cohesion: 0.10
Nodes (12): AuthLayer, OperatorSession, Authentication and authorization layer for Pupyteer operators., Check if a token is valid and has the required permission., Return the operator name for a valid token., Revoke a session token., Return all non-expired sessions., Add a new operator credential. (+4 more)

### Community 13 - "EvasionTestManager"
Cohesion: 0.10
Nodes (12): EvasionTestManager, Any, Evasion Test Manager — core orchestrator for detection-resilience testing.…, Persist test history to disk., Load persisted test history from disk., Return recent test results., Aggregate statistics across all tests., Central facade for all evasion-test operations. Requires explicit laboratory… (+4 more)

### Community 14 - "LitterboxClient"
Cohesion: 0.14
Nodes (12): Exception, LitterboxClient, LitterboxError, Any, Litterbox integration client for Pupyteer. Submits payloads to Litterbox…, Fetch the analysis report for a completed job., Verify Litterbox is reachable and responding., Async sleep that can be overridden in tests. (+4 more)

### Community 15 - "PayloadConfig"
Cohesion: 0.18
Nodes (7): PayloadConfig, PayloadManager, Validate payload configuration., Central facade for payload operations. Provides: - Build orchestration -…, Build a new payload artifact., Configuration for a payload build., TestPayloadManager

### Community 16 - "AuditLogger"
Cohesion: 0.19
Nodes (6): AuditLogger, Structured audit logging for Pupyteer., Emits structured JSON audit events for operator actions and system lifecycle.…, ModuleRegistry, Module discovery, loading, and lifecycle management. Supports loading from: -…, TestModuleSystem

### Community 17 - "Pupyteer — Phase 10: Evasion Testing"
Cohesion: 0.12
Nodes (16): API Usage, Architecture, CLI Commands (headless), Configuration, Data Flow, Evaluation Metrics, Files Added, Installation (+8 more)

### Community 18 - "EvasionTestResult"
Cohesion: 0.14
Nodes (8): Execute a full evasion test run. Flow: 1. Validate config (lab mode, artifact…, Submit artifact to Litterbox and parse results., Run local detection checks (hash-only, static scan placeholders). In a full…, Map a Litterbox report to our internal result format., Look up a specific test by ID., Return all test results., EvasionTestResult, Complete result record for an evasion test run.

### Community 19 - "TransportManager"
Cohesion: 0.12
Nodes (9): Manages transport lifecycle and registry. Provides a unified interface for…, Transport manager ready., Close all active transports., Register an active transport., Remove and close a registered transport., Retrieve a registered transport., List available transport type names., Register a custom transport implementation. (+1 more)

### Community 20 - "Any"
Cohesion: 0.17
Nodes (3): ITasks, Any, Async task queue and tracking contract.

### Community 21 - "Transport"
Cohesion: 0.14
Nodes (8): Abstract transport interface. All transport implementations must provide: -…, Establish connection to remote endpoint., Gracefully disconnect from remote endpoint., Send data. Returns bytes sent., Receive data with optional timeout., Verify transport is healthy and responsive., Close transport and release all resources., Transport

### Community 22 - "PupyteerAgent"
Cohesion: 0.18
Nodes (7): AgentInfo, PupyteerAgent, Pupyteer Agent — Core agent runtime., Agent identification and metadata., Agent runtime — connects to server and executes tasks. This is a skeleton…, Start the agent and connect to the server., Connect to server and handle commands.

### Community 23 - "interfaces.py"
Cohesion: 0.18
Nodes (6): Protocol, IAudit, IAuth, Abstract protocols defining clear API boundaries between engine subsystems.…, Structured audit event emitter contract., Operator authentication and authorization contract.

### Community 25 - "Any"
Cohesion: 0.18
Nodes (6): Any, Validate module arguments. Return list of errors., List all registered modules with info., List modules by category., List modules compatible with target platform., Execute the module against a target session. Args: session: Target session info…

### Community 26 - "TransportManager"
Cohesion: 0.18
Nodes (7): Any, Transport Manager — Transport abstraction layer for Pupyteer., Manages communication transport listeners. Transports are the actual network…, Initialize transport listeners based on config., Stop all transport listeners., Return all transport configurations., TransportManager

### Community 27 - "models.py"
Cohesion: 0.31
Nodes (10): DefensiveControl, DetectionResult, ExecutionResult, Enum, str, Data models for the Pupyteer evasion testing subsystem. Covers: - Test…, Outcome of a detection test., Whether the payload actually ran. (+2 more)

### Community 28 - "recon.py"
Cohesion: 0.18
Nodes (7): NetworkInfoModule, ProcessListModule, Built-in Pupyteer modules., List running processes on target., Gather network information from target., Gather system information from target., SystemInfoModule

### Community 29 - "test_full_litterbox_flow"
Cohesion: 0.31
Nodes (9): compute_file_hash(), Compute hash of a local artifact., main(), asyncio, Integration test for evasion testing subsystem., Test complete flow: configure → run → verify history → stats., Multiple tests accumulate in history., test_full_litterbox_flow() (+1 more)

### Community 31 - "EvasionTestModule"
Cohesion: 0.20
Nodes (6): EvasionConfigModule, EvasionTestModule, Any, Built-in evasion module for Pupyteer. Exposes the EvasionTestManager through…, Run evasion detection-resilience tests., Show current evasion testing configuration.

### Community 32 - "PupyModule"
Cohesion: 0.20
Nodes (6): PupyModule, Instantiate a module by name., Get a module class by name., Standardized module interface for Pupyteer. All modules must implement: - name,…, Optional cleanup after execution. Override if needed., Check if module is compatible with target platform.

### Community 34 - "ModuleCategory"
Cohesion: 0.25
Nodes (7): ModuleCategory, ModuleRequirement, ABC, Enum, str, Module discovery, loading, and lifecycle management. Supports loading from: -…, Represents a module dependency.

### Community 35 - "transports/__init__.py"
Cohesion: 0.25
Nodes (7): ABC, Enum, str, Transport abstraction layer for Pupyteer C2., Runtime transport statistics., TransportState, TransportStats

### Community 36 - "Any"
Cohesion: 0.28
Nodes (3): Any, Create a transport instance by type name., List all registered transports.

### Community 38 - "conftest.py"
Cohesion: 0.32
Nodes (7): config_factory(), project_root(), pupyteer_package(), fixture, Pupyteer pytest configuration and shared fixtures., Import the main package to verify it loads cleanly., Factory for creating isolated ConfigManager instances.

### Community 39 - "async_main"
Cohesion: 0.38
Nodes (6): async_main(), main(), Configure root logging., Pupyteer — Red Team Operations Framework Entry point for the Pupyteer C2…, Synchronous entry point., setup_logging()

### Community 40 - "._load_from_file"
Cohesion: 0.29
Nodes (4): Path, Scan paths and register all discovered modules., Load all PupyModule subclasses from a file., Register a module class.

### Community 42 - "ControlResult"
Cohesion: 0.33
Nodes (3): ControlResult, Any, Result against a specific defensive control.

### Community 45 - "EvasionTestConfig"
Cohesion: 0.40
Nodes (3): EvasionTestConfig, Configuration for a single evasion test run., Execute an evasion test.

## Knowledge Gaps
- **12 isolated node(s):** `LitterBox Integration`, `Data Flow`, `Installation`, `TUI Commands`, `CLI Commands (headless)` (+7 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 376 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **21 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ConfigManager` connect `ConfigManager` to `asyncio`, `PupyteerEngine`, `PayloadStore`, `TaskManager`, `SessionManager`, `TestConfigManager`, `asyncio`, `ProfileManager`, `test_evasion.py`, `AuthLayer`, `EvasionTestManager`, `PayloadConfig`, `AuditLogger`, `TransportManager`, `TransportManager`, `test_full_litterbox_flow`, `PupyModule`, `Any`, `conftest.py`, `async_main`?**
  _High betweenness centrality (0.299) - this node is a cross-community bridge._
- **Why does `AuditLogger` connect `AuditLogger` to `PupyModule`, `asyncio`, `PupyteerEngine`, `PayloadStore`, `TaskManager`, `SessionManager`, `Any`, `asyncio`, `ProfileManager`, `test_evasion.py`, `ConfigManager`, `AuthLayer`, `EvasionTestManager`, `PayloadConfig`, `.log_event`, `TransportManager`, `TransportManager`, `test_full_litterbox_flow`?**
  _High betweenness centrality (0.200) - this node is a cross-community bridge._
- **Why does `PupyteerEngine` connect `PupyteerEngine` to `PupyteerTUI`, `TaskManager`, `SessionManager`, `async_main`, `asyncio`, `ProfileManager`, `ConfigManager`, `AuthLayer`, `EvasionTestManager`, `AuditLogger`, `TransportManager`?**
  _High betweenness centrality (0.153) - this node is a cross-community bridge._
- **Are the 83 inferred relationships involving `ConfigManager` (e.g. with `async_main()` and `PayloadBuilder`) actually correct?**
  _`ConfigManager` has 83 INFERRED edges - model-reasoned connections that need verification._
- **Are the 72 inferred relationships involving `AuditLogger` (e.g. with `PayloadBuilder` and `PayloadManager`) actually correct?**
  _`AuditLogger` has 72 INFERRED edges - model-reasoned connections that need verification._
- **Are the 33 inferred relationships involving `PupyteerEngine` (e.g. with `async_main()` and `AuthLayer`) actually correct?**
  _`PupyteerEngine` has 33 INFERRED edges - model-reasoned connections that need verification._
- **Are the 30 inferred relationships involving `SessionInfo` (e.g. with `TestSubsystemWiring` and `.test_full_lifecycle_with_sessions_and_tasks()`) actually correct?**
  _`SessionInfo` has 30 INFERRED edges - model-reasoned connections that need verification._