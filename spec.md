# Pupy Red-Team Framework Rework

## Technical Specification / Project Requirements

**Project Type:** Authorized Red-Team / Adversary Emulation Framework
**Base Project:** Pupy C2 Framework
**Primary Goal:** Modernize the existing framework into a modular, operator-focused red-team platform suitable for controlled security assessments and adversary-emulation exercises.

---

## 1. Project Objectives

The project aims to rework the existing Pupy framework by improving its:

* Operator interface and TUI experience
* Branding and visual identity
* Payload management architecture
* Core engine and module architecture
* Agent/session management
* Configuration management
* C2 communication profiles
* Logging and operational visibility
* Extensibility for future red-team modules

The redesigned framework should prioritize **modularity, maintainability, reliability, and controlled deployment**.

---

# 2. Major Features

## 2.1 Pupyteer Branding and TUI Revamp

### Requirements

* Replace the existing visual identity with the new **Pupyteer** branding.
* Create a redesigned terminal interface.
* Implement consistent color, spacing, and command formatting.
* Provide a startup banner and version information.
* Add command autocomplete where supported.
* Implement command history.
* Provide structured session information.
* Improve error and warning messages.
* Support terminal resizing.
* Provide configurable TUI themes.

### Example Interface

```text
╔══════════════════════════════════════════════════════╗
║                    PUPYTEER                           ║
║          Red Team Operations Framework               ║
╚══════════════════════════════════════════════════════╝

[Server] Online
[Agents] 4
[Tasks]  12
[Profile] HTTPS-Default

pupyteer >
```

---

# 3. Payload Management System

The existing payload workflow should be redesigned into a dedicated payload-management subsystem.

### Requirements

* Centralized payload configuration.
* Payload metadata tracking.
* Payload versioning.
* Target-platform selection.
* Architecture selection.
* Build status tracking.
* Payload validation before deployment.
* Payload generation logs.
* Payload artifact cleanup.
* Optional payload signing workflow for controlled environments.
* Separation between payload configuration and payload compilation.

### Payload Metadata

Each generated artifact should maintain metadata such as:

```text
Payload ID
Version
Platform
Architecture
Build Timestamp
Configuration Profile
Build Status
Hash
Operator
Expiration/Validity
```

### Payload Lifecycle

```text
Configuration
      |
      v
Validation
      |
      v
Build
      |
      v
Verification
      |
      v
Artifact Management
      |
      v
Controlled Deployment
```

---

# 4. Engine Modernization

The framework's underlying engine should be redesigned into modular components.

### Proposed Architecture

```text
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

### Engine Requirements

* Modular component architecture.
* Clear API boundaries.
* Centralized configuration.
* Asynchronous task handling.
* Session lifecycle management.
* Improved error handling.
* Structured logging.
* Plugin/module loading.
* Graceful shutdown.
* Configuration validation.
* Unit and integration testing.

---

# 5. Agent / Session Management

The operator should be able to manage active sessions from one interface.

### Required Functions

```text
sessions
sessions list
sessions info <id>
sessions interact <id>
sessions rename <id>
sessions kill <id>
sessions tag <id>
sessions search <query>
```

### Session Information

```text
ID
Hostname
Operating System
Architecture
Username
Connection Status
Last Check-in
Profile
Agent Version
Tags
Task Status
```

Sensitive operational information should only be displayed to authorized operators.

---

# 6. C2 Profile System

Implement a configurable **malleable C2 profile system** inspired by the general concept used by established red-team frameworks.

The objective is to separate C2 behavior from the core engine.

## Profile Structure

```yaml
profile:
  name: "HTTPS-Standard"
  version: "1.0"

transport:
  protocol: "HTTPS"

session:
  heartbeat: configurable

encoding:
  mode: configurable

logging:
  level: "operator"

timeouts:
  connect: configurable
  response: configurable
```

### Profile Manager

Required functionality:

```text
profile list
profile show <name>
profile validate <name>
profile load <name>
profile unload <name>
profile create
```

Profiles should be validated before activation.

---

# 7. Transport Abstraction

The C2 engine should not directly depend on one transport implementation.

### Proposed Interface

```text
Transport
├── connect()
├── disconnect()
├── send()
├── receive()
├── health_check()
└── close()
```

This allows additional transport implementations to be developed without rewriting the session-management layer.

---

# 8. Payload Security / Detection-Resilience Research

The project may include a controlled **detection-resilience/FUD evasion capability** for engagements and assessments.

The implementation should focus on AV/EDR evasion and up-to-date evasion capabilities controls to provide unrestricted malware-evasion functionality.

### Requirements

* Support controlled test configurations.
* Record which configuration was tested.
* Maintain reproducible builds.
* Provide artifact hashes.
* Record test results.
* Provide an explicit laboratory/testing mode.
* Use of Litterbox and/or other open-source detection frameworks as a testing.

### Evaluation Metrics

```text
Detection Result
Execution Result
False Positive Result
Telemetry Generated
Defensive Control Triggered
Test Configuration
Timestamp
Environment
```

---

# 9. Function / Module Modernization

Existing functionality should be reviewed and reorganized into modular components.

### Module Categories

```text
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
```

Each module should expose a standardized interface.

```text
Module
├── name
├── version
├── description
├── author
├── requirements
├── execute()
└── cleanup()
```

---

# 10. Configuration Management

Centralize framework configuration.

### Requirements

* YAML/JSON configuration support.
* Environment-specific configuration.
* Profile configuration.
* Operator configuration.
* Logging configuration.
* Default configuration.
* Configuration validation.
* Safe handling of credentials and cryptographic material.

Example:

```yaml
server:
  host: "127.0.0.1"
  port: 8443

logging:
  level: "INFO"

profile:
  default: "HTTPS-Standard"

operator:
  name: "redteam-operator"
```

---

# 11. Logging and Auditing

Every important operator action should be auditable.

### Events

```text
Server Started
Operator Login
Profile Loaded
Payload Built
Agent Connected
Task Created
Task Completed
Module Executed
Configuration Changed
Session Terminated
```

### Log Format

```json
{
  "timestamp": "...",
  "operator": "...",
  "event": "...",
  "session": "...",
  "result": "..."
}
```

Logs should avoid unnecessarily storing secrets or sensitive payload contents.

---

# 12. Security Requirements

The framework itself must be treated as security-sensitive software.

### Requirements

* Authentication for administrative interfaces.
* Secure credential handling.
* Cryptographic key protection.
* Input validation.
* Configuration validation.
* Secure defaults.
* Dependency auditing.
* Permission checks.
* Operator attribution.
* Session authorization.
* Secure logging.
* No hardcoded production credentials.

---

# 13. Testing Requirements

## Unit Testing

Test:

* Profile parsing
* Configuration validation
* Session management
* Task management
* Payload metadata
* Transport interfaces
* Module loading

## Integration Testing

Test:

```text
TUI
 ↓
Server
 ↓
Session Manager
 ↓
C2 Engine
 ↓
Transport
 ↓
Controlled Test Agent
```

## Regression Testing

Existing supported functionality should be tested after every major engine modification.

---

# 14. Proposed Project Structure

```text
pupyteer/
│
├── server/
│   ├── core/
│   ├── sessions/
│   ├── tasks/
│   ├── transports/
│   ├── profiles/
│   └── modules/
│
├── agent/
│   ├── core/
│   ├── transport/
│   └── modules/
│
├── payloads/
│   ├── builders/
│   ├── profiles/
│   └── artifacts/
│
├── tui/
│   ├── screens/
│   ├── widgets/
│   └── commands/
│
├── config/
│   ├── defaults/
│   └── profiles/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   └── regression/
│
├── docs/
│
└── README.md
```

---

# 15. Development Phases

## Phase 1 — Codebase Assessment

* Analyze existing Pupy architecture.
* Identify deprecated components.
* Map dependencies.
* Identify security issues.
* Document existing functionality.

## Phase 2 — TUI and Branding

* Implement Pupyteer branding.
* Redesign TUI.
* Implement command system.
* Implement session dashboard.

## Phase 3 — Engine Refactoring

* Separate core components.
* Implement interfaces.
* Improve task management.
* Improve session management.
* Implement structured logging.

## Phase 4 — Payload System

* Implement payload metadata.
* Implement build management.
* Implement artifact management.
* Implement validation.

## Phase 5 — C2 Profiles

* Implement profile parser.
* Implement profile validation.
* Implement profile manager.
* Connect profiles to transport abstraction.

## Phase 6 — Module System

* Reorganize existing functions.
* Implement module interfaces.
* Add module discovery/loading.
* Add module versioning.

## Phase 7 — Testing

* Unit tests.
* Integration tests.
* Regression tests.
* Controlled adversary-emulation tests.

## Phase 8 — Documentation

* Operator manual.
* Developer documentation.
* Profile documentation.
* Module-development guide.
* Installation guide.
* Security documentation.

---

# 16. Definition of Done

The reworked framework will be considered ready for a development release when:

* [ ] Pupyteer TUI is operational.
* [ ] Core engine is modularized.
* [ ] Sessions can be reliably managed.
* [ ] Tasks can be queued and tracked.
* [ ] Payload lifecycle is centralized.
* [ ] C2 profiles can be created and validated.
* [ ] Transport implementations are abstracted.
* [ ] Modules follow a standardized interface.
* [ ] Structured logging is implemented.
* [ ] Authentication and authorization are implemented.
* [ ] Unit tests cover core components.
* [ ] Integration tests pass.
* [ ] Documentation is complete.
* [ ] Controlled red-team testing has been completed.

---

# 17. Design Principles

The project should follow these principles:

1. **Modular** — Components should be replaceable without rewriting the entire framework.
2. **Operator-focused** — Common operations should require minimal commands.
3. **Secure by default** — Unsafe configuration should not be the default.
4. **Observable** — Important actions should be auditable.
5. **Testable** — Components should have clear interfaces and automated tests.
6. **Extensible** — New transports, profiles, and modules should be easy to add.
7. **Controlled** — Security-testing capabilities should be designed for authorized environments.
8. **Maintainable** — Avoid unnecessary coupling and legacy technical debt.
