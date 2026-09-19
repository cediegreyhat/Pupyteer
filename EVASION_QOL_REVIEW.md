# Pupyteer Evasion & QoL Code Review Report

> **Scope**: Evasion subsystem, payload builder, transport layer, session/task management, and operator QoL features across the core server files.

---

## 1. Current State of FUD / Evasion

### Verdict: **Pre-alpha — no actual FUD exists**

The "evasion testing" infrastructure is a **measurement harness**, not an evasion engine. It records whether a payload *would* be detected but does nothing to make the payload undetectable.

| Layer | Status | Notes |
|---|---|---|
| Payload builder | ❌ Stub | `PayloadBuilder.build()` writes `b"PUPAYLOAD_PLACEHOLDER_" + json.dumps(config)` to disk. No compilation, no PE generation, no agent stager. |
| Obfuscation | ❌ None | Zero string encryption, no import table hashing, no API resolving, no polymorphic engine. |
| AV/EDR bypass | ❌ None | No AMSI patching, no ETW bypass, no direct syscalls, no Call Stack Spoofing, no module stomping. |
| Transport encryption | ⚠️ Placeholder | `TransportManager.initialize()` hardcodes a fake `"listening"` entry. No TLS, no cert management, no DoH. |
| Reflective loader | ⚠️ Client-side only | `client/sources-windows-py3/` has `main_reflective.c`, `LoadLibraryR`, `GetProcAddressR` — but these are **not wired** to `PayloadBuilder` or the new server core. They belong to the legacy Pupy codebase. |

### Key Finding: `PayloadBuilder.build()` is a dead end

```python
# pupyteer/payloads/manager.py:189-190
artifact_path.write_bytes(b"PUPAYLOAD_PLACEHOLDER_" + json.dumps(payload_config.to_dict()).encode())
```

Every "built" payload is a text file starting with `PUPAYLOAD_PLACEHOLDER_`. This will be flagged instantly by any AV.

---

## 2. EvasionTestManager — What It Actually Does

| Method | Status | Notes |
|---|---|---|
| `initialize()` | ✅ | Loads history JSON, initializes Litterbox if configured. |
| `run_test(config)` | ⚠️ | Validates → checks hash → routes to Litterbox or local → persists. |
| `_run_litterbox_test()` | ✅ | Uploads to Litterbox sandbox, polls for results. |
| `_run_local_test()` | ❌ Stub | Returns `UNDETECTED` for every control with `"Local scan placeholder — no actual AV engine integrated"`. |
| `_map_litterbox_report()` | ✅ | Maps Litterbox detections to internal format. |
| `get_stats()` | ✅ | Aggregates by detection result, execution result, reproducibility. |

### Issue: Local test is a false-positive generator

`_run_local_test()` always returns `UNDETECTED`. An operator running `evasion_test` against local controls will see green across the board — this is **dangerously misleading** before a real engagement.

### Issue: No control enforcement

`EvasionTestConfig.controls` accepts arbitrary strings. There's no validation that the controls actually exist or are running in the target environment. The test will "pass" against controls that aren't even present.

---

## 3. Payload Obfuscation — Gap Analysis

| Technique | Present | Notes |
|---|---|---|
| XOR encryption | ❌ | `pupy/network/lib/transports/cryptoutils/xor.py` exists in legacy Pupy, not integrated. |
| RC4 | ❌ | Same — legacy only. |
| AES | ❌ | Legacy `cryptoutils/aes.py` exists, not wired. |
| RSA+AES hybrid | ❌ | `pupy/network/lib/transports/rsa_aes.py` — legacy. |
| TLS/SSL transport | ❌ | `ssl_rsa` transport exists in Pupy, not in new server. |
| DNS tunneling | ❌ | `dnscnc.py` + `picocmd/dns_encoder.py` in Pupy, not integrated. |
| DoH (DNS-over-HTTPS) | ❌ | `doh.py` in Pupy, not integrated. |
| Obfs3 | ❌ | `obfs3/` in Pupy, not integrated. |
| Reflective DLL injection | ⚠️ | `main_reflective.c`, `LoadLibraryR.c` in `client/sources-windows-py3/` — not compiled or called from new builder. |
| Process hollowing | ❌ | `base_inject.c` has APC stub + migrate stub but no process hollowing implementation. |
| String encryption | ❌ | None. |
| Import table obfuscation | ❌ | None. |
| Timestomping | ❌ | None. |
| Code signing | ⚠️ | `pyoxidizer.bzl:321-339` has signing cert placeholder commented out. |

---

## 4. AV/EDR Bypass Techniques — Gap Analysis

| Technique | Present | Notes |
|---|---|---|
| AMSI bypass | ❌ | Modeled as `DefensiveControl.AMSI` but never actually bypassed. |
| ETW bypass | ❌ | Modeled, never implemented. |
| Direct syscalls (HellsGate/HalosGate/Tartarus) | ❌ | None. |
| Indirect syscalls | ❌ | None. |
| Module stomping | ❌ | None. |
| DLL hollowing | ❌ | None. |
| APC injection | ⚠️ | `base_inject.c` has x86/x64 APC stubs but no orchestrator. |
| Thread hijacking | ❌ | None. |
| Early bird injection | ❌ | None. |
| Parent PID spoofing | ❌ | None. |
| Kernel callbacks evasion | ❌ | None. |
| Call stack spoofing | ❌ | None. |
| Hardware breakpoint unhooking | ❌ | None. |

---

## 5. Operator QoL Features

### ✅ Implemented

| Feature | Location | Quality |
|---|---|---|
| Session tagging | `SessionManager.tag()` | Works, not locked. |
| Session search | `SessionManager.search()` | Substring across 8 fields. |
| Session filter | `SessionManager.filter_by()` | Dynamic kwargs, supports str contains. |
| Session rename | `SessionManager.rename()` | Simple hostname swap. |
| Heartbeat monitor | `SessionManager._monitor_loop()` | 30s interval, marks TIMEOUT. |
| Task queue | `TaskManager` | Async workers, concurrency limit. |
| Task cancel | `TaskManager.cancel()` | Cancel queued or running. |
| Audit logging | `AuditLogger` | Structured JSON, redaction. |
| Operator lockout | `AuthLayer` | After N failures. |
| Token TTL | `AuthLayer` | Configurable expiration. |
| Profile management | `ProfileManager` | Load/activate/unload/validate. |
| Evasion test history | `EvasionTestManager` | Persisted to JSON. |
| Litterbox integration | `LitterboxClient` | Full HTTP client. |

### ❌ Missing / Broken

| Feature | Status |
|---|---|
| Interactive TUI/CLI | Not found in reviewed files — likely exists elsewhere. |
| Command history | Unknown. |
| Tab completion | Stubbed per CODE_REVIEW.md line 80. |
| Module hot-reload | Not present. |
| Session interact (shell/RDP/SOCKS) | Not implemented. |
| Credential vault | Not present. |
| Pivot chaining | Not present. |
| Auto-migrate | Not present. |
| Module dependency resolution | `registry.py` exists but not reviewed. |
| Real-time event stream (WebSocket/SSE) | Not present. |

---

## 6. Critical Actionable Findings for Building Undetectable C2

### 🔴 Blockers (must fix before field use)

1. **Payload builder is fake.**
   - `PayloadBuilder.build()` produces a text file with config metadata.
   - Need: integrate actual agent compilation pipeline (legacy Pupy `build_library_zip.py` → reflective loader → PyOxidizer binary).

2. **Evasion tests lie.**
   - `_run_local_test()` always returns UNDETECTED.
   - Either remove local testing or integrate actual scanning (YARA, AMSI, Defender offline).

3. **No transport layer.**
   - `TransportManager` is a dict of hardcoded strings.
   - Need: TLS server, DoH, DNS tunneling — Pupy has these, just not wired.

4. **No obfuscation pipeline.**
   - Zero XOR/AES/string encryption in the new server.
   - Legacy `cryptoutils/` exists but is orphaned.

### 🟡 High-priority (significantly improve evasion)

5. **Wire Pupy transports into new server.**
   - `pupy/network/lib/transports/` has 10+ transports (HTTP, WS, TLS, DNS, obfs3, EC4).
   - These should be adapted as `TransportManager` backends.

6. **Wire reflective loader.**
   - `client/sources-windows-py3/main_reflective.c` + `LoadLibraryR` → integrate into build pipeline.

7. **Add syscalls layer.**
   - Implement HellsGate/HalosGate for direct syscalls.
   - Or integrate SysWhispers3/SysWhispers2.

8. **Add AMSI/ETW bypass module.**
   - Runtime patching or hardware breakpoint technique.

### 🟢 Medium-priority (QoL for operators)

9. **Real-time event bus.**
   - WebSocket/SSE stream for task completion, session events.

10. **Module auto-reload.**
    - Watch filesystem, hot-reload modules without restart.

11. **Credential vault.**
    - Encrypted credential storage, reuse across sessions.

12. **Pivot management.**
    - SOCKS proxy chaining, session-to-session routing.

---

## 7. File-by-File Summary (Evasion-Relevant)

| File | Evasion Relevance | State |
|---|---|---|
| `server/evasion/manager.py` | Test orchestrator | Functional but local tests are fake |
| `server/evasion/models.py` | Detection result models | Complete, well-structured |
| `server/evasion/litterbox_client.py` | Litterbox API client | Functional HTTP client |
| `server/modules/builtin/evasion.py` | TUI module wrapper | Thin wrapper, works |
| `payloads/manager.py` | Payload builder | **Stub — produces placeholder files** |
| `server/core/engine.py` | Orchestration | No evasion integration |
| `server/sessions/manager.py` | Session lifecycle | No implant-specific features |
| `server/tasks/manager.py` | Task queue | No execution logic |
| `server/transports/manager.py` | Transport layer | **Hardcoded fake entry** |
| `server/profiles/manager.py` | C2 profiles | Validates but doesn't enforce |
| `server/core/auth.py` | Operator auth | Basic, works |
| `server/core/logging.py` | Audit logging | Works, minor issues |
| `server/core/config.py` | Configuration | Works |

---

## 8. Bottom Line

Pupyteer currently has:
- A **solid infrastructure layer** (config, auth, sessions, tasks, profiles, audit logging).
- A **detection-measurement harness** (evasion test framework + Litterbox integration).
- **Zero actual evasion capability** in the new server code.

To build a fully-undetectable C2 framework, the team needs to:
1. **Replace the payload builder** with a real compilation pipeline.
2. **Wire legacy Pupy transports** (TLS, DNS, DoH, obfs3) into `TransportManager`.
3. **Add runtime evasion modules** (syscalls, AMSI/ETR bypass, module stomping).
4. **Integrate the reflective loader** from `client/sources-windows-py3/`.
5. **Fix the local evasion test** to use real engines or remove it.

The legacy Pupy codebase already contains most of the building blocks — they just need to be adapted to the new async server architecture.
