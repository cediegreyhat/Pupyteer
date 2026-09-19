# ╔══════════════════════════════════════════════════════════╗
# ║                    PUPYTEER                               ║
# ║          Red Team Operations Framework                   ║
# ╚══════════════════════════════════════════════════════════╝

> **Pupyteer** is a modular, operator-focused C2 and adversary-emulation framework built for authorized security assessments and red-team engagements.

Built as a modernization of the Pupy framework, Pupyteer prioritizes **modularity, reliability, controlled deployment, and detection resilience**. All components follow clear interface boundaries, enabling extensibility without coupling.

---

## ⚡ Quick Start

### From Source (Recommended for Development)

```bash
git clone https://github.com/yourorg/pupyteer
cd pupyteer

python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Run the TUI

```bash
pupyteer-tui
```

### Run the Server

```bash
pupyteer-server --config config/default.yaml
```

### Generate a Payload

```python
from pupyteer.payloads.manager import PayloadBuilder, PayloadConfig, PayloadType

config = PayloadConfig(
    name="test-payload",
    payload_type=PayloadType.SCRIPT,
    transport="https",
    host="192.168.100.100",
    port=443,
    profile="HTTPS-Standard"
)

metadata = await builder.build(config)
print(f"Artifact: {metadata.artifact_path} ({metadata.size_bytes} bytes)")
print(f"SHA256: {metadata.hash_sha256}")
```

---

## 🏗️ Architecture

```
PUPYTEER
  ├── Server (C2 Engine)
  │   ├── Session Manager      — agent lifecycle, tagging, interaction
  │   ├── Task Queue           — async priority task scheduling
  │   ├── Profile Manager      — malleable C2 profiles (YAML)
  │   ├── Transport Manager    — HTTP/HTTPS/TCP/DNS/DoH/DoT/NamedPipe
  │   ├── Module Registry      — pluggable modules with ABC interface
  │   ├── Payload Manager      — build, versioning, artifact lifecycle
  │   ├── Evasion Engine       — obfuscation + Litterbox analysis
  │   ├── Auth Layer           — mTLS + JWT + challenge-response
  │   ├── Audit Logger         — structured JSON with redaction
  │   └── RBAC                 — VIEWER/OPERATOR/ADMIN/SYSTEM
  │
  ├── Agent (Stub)
  │   ├── Core agent loop
  │   ├── Transport clients
  │   ├── Recon/Execution/FS modules
  │   └── Persistence & migration
  │
  └── TUI
      ├── Startup banner & status bar
      ├── Session dashboard
      ├── Payload & evasion commands
      └── Command history & autocomplete
```

---

## 📋 Features

| Category | Capabilities |
|----------|-------------|
| **Payloads** | Python script, PE executable, versioning, metadata tracking, signing stub |
| **Transports** | HTTP, HTTPS (mTLS), DNS, DoH, DoT, TCP, WebSocket, NamedPipe |
| **C2 Profiles** | YAML-based malleable C2 — heartbeat, encoding, timeouts, headers, URIs |
| **Modules** | Core, Recon, Execution, File Ops, Red-Team, Evasion — standardized ABC |
| **Sessions** | list/info/interact/rename/kill/tag/search, audit trail |
| **Tasks** | Priority queue (CRITICAL → BACKGROUND), async execution, tracking |
| **Evasion** | XOR/AES/RC4 obfuscation, PE manipulation, anti-sandbox/debug/VM, Litterbox integration |
| **Security** | mTLS 1.2+, JWT, RBAC, input validation, credential redaction, session auth |
| **Audit** | JSON-structured logs, operator attribution, redaction, rotation, query API |
| **TUI** | ASCII banner, themes, autocomplete, history, resize handling, dashboard |

---

## 📂 Project Structure

```
pupyteer/
├── server/
│   ├── core/          # engine, config, auth, audit, errors, queue, c2
│   ├── sessions/      # session lifecycle, tagging, interaction
│   ├── tasks/         # task manager
│   ├── transports/    # Transport ABC + concrete implementations
│   ├── profiles/      # malleable C2 profile parser/validator/manager
│   ├── modules/       # registry, builtin modules (recon, evasion, file ops)
│   ├── evasion/       # obfuscator, litterbox client, test runner
│   └── payloads/      # payload builder, artifact management
│
├── agent/
│   ├── core/          # agent loop, auth, stub generator
│   └── modules/        # recon, execution, fs, persistence
│
├── payloads/
│   ├── builders/      # platform-specific builders
│   └── artifacts/     # generated payload artifacts
│
├── tui/
│   ├── app.py         # main TUI application
│   ├── themes.py      # dark/light theme definitions
│   ├── screens/       # TUI screens
│   ├── widgets/       # custom widgets
│   └── commands/      # command handlers (sessions, payloads, evasion)
│
├── config/
│   ├── defaults/      # default configuration files
│   └── profiles/      # C2 profile definitions
│
├── tests/
│   ├── unit/          # unit tests
│   ├── integration/    # integration tests
│   └── regression/    # regression tests
│
└── docs/
    ├── OPERATOR_MANUAL.md
    ├── DEVELOPER_DOCUMENTATION.md
    ├── MODULE_DEVELOPMENT_GUIDE.md
    ├── PROFILE_DOCUMENTATION.md
    ├── SECURITY_DOCUMENTATION.md
    └── INSTALLATION_GUIDE.md
```

---

## 🧪 Testing

```bash
# All tests
.venv/bin/python -m pytest pupyteer/tests/ -v

# Unit only
.venv/bin/python -m pytest pupyteer/tests/unit/ -v

# Integration only
.venv/bin/python -m pytest pupyteer/tests/integration/ -v
```

**Current test count: 681+ tests passing**

---

## 🔒 Security

Pupyteer is designed as security-sensitive software:

- **Authentication** — mTLS 1.2+, JWT with TTL, challenge-response registration
- **Authorization** — RBAC with VIEWER/OPERATOR/ADMIN/SYSTEM roles
- **Secure Defaults** — No hardcoded credentials, encrypted channels by default
- **Input Validation** — All operator inputs validated before execution
- **Audit Logging** — Every action logged with operator attribution
- **Credential Redaction** — Secrets never stored in audit logs
- **Dependency Auditing** — `scripts/audit_deps.py` for vulnerability scanning

---

## ⚠️ Legal & Ethical Notice

This framework is intended **exclusively for authorized security testing and adversary emulation**. Unauthorized use against systems without explicit written permission is illegal and unethical.

---

## 📜 License

MIT License — See [LICENSE](LICENSE) for details.

---

**Built for authorized red-team operations. Test responsibly.**
