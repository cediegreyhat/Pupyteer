# Pupyteer — Complete Code Review Report

**Date:** 2026-10-22
**HEAD:** `cad54f49`
**Source LOC:** ~159,009 (Python + C agent template) / Tests: ~20,497
**Overall grade:** A− (solid; residual defects are narrow and documented)

## Per-subsystem grades

| Subsystem | Grade |
|---|---|
| Security boundary (auth, RBAC, audit, enrollment, config) | A− |
| Transports & sessions (listener, manager, transfer, capabilities) | B+ |
| Payloads & agent (builder, stub, PE template, fs_put) | B+ |
| Evasion engine (obfuscator, profiles, runner, litterbox) | B+ |
| Modules (registry, builtins, post-*) | A− |
| TUI (app, commands, themes, completion) | A− |
| Build / tests | A (1452 passed, 9 skipped) |

## Findings

Severity tags: Critical / High / Medium / Low. Only verified defects listed.

### Security

1. **Medium** — `pupyteer/server/core/validation.py:332` — `validate_file_path("..")` accepted because the regex only catches `../` or `..\`. **Fixed** (commit `92e960df`): reject any path whose normalized segments contain `..`.
2. **Medium** — `pupyteer/server/core/config.py:121` — `_redact_sensitive` used exact key match, so composite names like `litterbox_token` leaked. **Fixed**: substring containment against `_SENSITIVE_KEYS`.
3. **Medium** — `pupyteer/server/core/auth.py:117-120` — failed-login lockout keyed on raw username, so `admin `/`Admin` bypassed the counter. **Fixed**: canonicalize (strip) username before lockout key and lookup.

### Transports & sessions (remaining — concurrency)

4. **Medium** — `pupyteer/server/transports/listener.py:199,489` — `_rc4_buf` is instance-level and reset per connection; concurrent RC4 connections clobber stream state. *Not yet fixed* (requires per-connection scoping).
5. **Medium** — `pupyteer/server/sessions/manager.py:180,278,289,300,308,376,380,424,434` — session/command-queue reads and mutations are not guarded by `_lock` → data races under concurrent callers. *Not yet fixed*.
6. **Low** — `pupyteer/server/sessions/transfer.py:158` — `chunk_budget` does `getattr(session, "max_line", ...)` without a None check; an unknown session raises `AttributeError`. *Not yet fixed*.
7. **Low** — `pupyteer/server/sessions/manager.py:170,198` — `get()`/`list_all()` expose live dict views without locking. *Not yet fixed*.

### Payloads & agent

8. **Medium** — `pupyteer/payloads/pe_builder.py:284` — RC4 key precedence used `or`, so an explicit empty `rc4_key` (plaintext wire) fell through to `dns_key`/config. **Fixed** (commit `78b8bd04`).
9. **Medium** — `pupyteer/agent/core/stub.py:523-530` — `_Obfuscator` defined `__init__` twice; the second (omitting `_mask`) won, causing `AttributeError` on `store()`. **Fixed**.
10. **Low** — `pupyteer/agent/core/stub.py:437` — template referenced `{% if enc %}` though `enc` was never added to render context, so the cipher block was always skipped. *Reverted activation* (commit `cad54f49`): enabling it breaks HTTP agents because the target lacks `cryptography`; cipher remains off by default. Documented in README.
11. **Low** — `pupyteer/agent/core/pe_template.c:1005` — `json_get_string` may overflow by up to 3 bytes near capacity. *Not yet fixed* (C fuzzing not run).
12. **Low** — `pupyteer/agent/core/pe_template.c:1705` — `task_fs_put` allocation not bounds-checked against base64 decode length. *Not yet fixed*.
13. **Low** — `pupyteer/payloads/manager.py:611` — non-script payloads always advertised `screenshot` capability even when `screenshot=False`. **Fixed**.

### Evasion, modules, TUI

14. **Low** — `pupyteer/tui/app.py:288,289` — tab-completion omitted `profiles`/`runner` (evasion) and `profiles`/`info` (pipeline). **Fixed** (commit `78b8bd04`).
15. **Low** — Unused imports: `tui/commands/evasion.py:10` (`sys`), `tui/commands/payloads.py:8` (`sys`), `server/modules/registry.py:40` (`os`), `server/modules/builtin/package_ops.py:15-19`. Partially fixed (first three); package_ops still pending.
16. **Low** — `pupyteer/server/evasion/obfuscator.py:1148-1177` — `apc` and `thread_hijack` injection stubs are comment-only; fallback returns `"# Injection method not implemented"`. Feature gap, not a crash.
17. **Low** — `pupyteer/server/evasion/obfuscator.py:918,962` — generated anti-sandbox stubs used `random.randint` without `import random`. **Fixed** (commit `d440d2f7`).

## What is genuinely good

- Full test suite green (1452 passed, 9 skipped) against real engines and listeners; fixtures repoint all writes into temp dirs.
- Auth: default-deny RBAC table, salted scrypt, lockout with decay, token-bound authority.
- Enrollment secret lifecycle: rotation/revocation with fingerprints, re-read without restart.
- TLS with certificate pinning in both Python and C (Schannel) agents; handshake refusals counted/audited.
- Capability gating with manifest verification (Gap 4) and chunked transfers sized to `max_line`.
- Evasion engine: XOR/AES/RC4, PE manipulation, Hell's Gate syscall stubs, Litterbox integration.
- Clean project structure, ABC-based modules, documented security model.

## Recommended next 3 commits

1. Guard session manager reads/mutations with `_lock` (concurrency correctness).
2. Scope `_rc4_buf` per-connection in the listener (RC4 stream integrity).
3. Bounds-check `json_get_string` and `task_fs_put` in the C template (buffer safety).

## Out-of-scope observations

- Agent-side AEAD channel cipher (Gap 3) is deferred: server-side primitive exists (`pupyteer/server/crypto/channel.py`) but agent-side C integration and the `cryptography` dependency on targets are unresolved.
- `package_ops.py` unused imports remain.
- FUD/evasion: injection stubs (APC, thread hijack) are placeholders; Litterbox API returns metadata only (FUD must be confirmed in web UI).
- Listener routes commands to `sessions[0]` rather than the most recent session (noted in prior sessions; not in this review's verified defects but worth fixing).
EOF
echo "written"