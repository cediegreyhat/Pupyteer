# Pupyteer Polishing & Upgrading Plan

Derived from README.md gaps + docs/MODERNIZATION_ROADMAP.md follow-ups.
Ordered by risk/dependency. Each item must keep the full suite green.

## Phase 1 — Security (highest impact, ordered)

1. **Per-agent identity for enrollment** (Gap 1)
   - Add Ed25519 keypair generation at payload build; store public key in PayloadStore manifest.
   - Listener verifies agent signature in `register`; shared secret becomes legacy fallback gated by `agent_auth`.
   - Revoke by agent_id. Backward-compat path for pre-cutover payloads.
   - Files: payloads/manager.py, agent/core/stub.py, server/transports/listener.py, server/core/enrollment.py, server/core/engine.py
   - Tests: registration challenge tests, legacy fallback tests.

2. **Verified capability claims** (Gap 4)
   - Add `payload_id` to SessionInfo; listener looks up build manifest in PayloadStore.
   - Verify `capabilities`/`max_line` are subset of shipped manifest; audit mismatch.
   - Old payloads (no payload_id) default to shell-only trust.
   - Files: payloads/manager.py metadata, server/sessions/*, server/transports/listener.py, server/core/session_auth.py
   - Tests: capability-subset tests, mismatch audit tests.

3. **Optional payload-level AEAD cipher** (Gap 3)
   - Add `transport.channel_cipher` opt-in; negotiate in `register`; retain TLS-only fallback.
   - Files: server/transports/*, agent/core/stub.py, profiles, config defaults
   - Tests: cipher round-trip tests.

4. **Network access control documentation** (Gap 2)
   - Document reverse-proxy/mTLS; add optional `server.allowed_operator_cidrs` + startup warning.
   - Files: config/defaults, server/transports/manager.py, docs
   - Scope: documentation-first, avoid overstating protection.

## Phase 2 — TUI Modernization

5. **Extract remaining screens/widgets from app.py**
   - BannerScreen (~818), TableRenderer (~884), enrollment render helpers (747/784).
   - Keep PupyteerTUI delegating.
6. **Keyboard shortcuts**
   - Add `tui/widgets/keyboard.py` `KeyboardShortcuts` with readline bindings:
     Tab (existing), Ctrl+L clear+status, Ctrl+D exit, Ctrl+K dashboard, Ctrl+T theme cycle.
   - No-readline guard.
7. **StatusBar enhancements**
   - Refresh tick, compact status + shortcut hints, render_full, resize-safe reprint.
8. **Tests**: mock-readline bind assertions, status bar compact/full, resize handler, screen render parity.

## Phase 3 — Performance & Reliability

9. **Registry metadata cache** (list_all/get_info), invalidate on register/unload/reload.
10. **Parallel async discovery** (per-file asyncio.to_thread + semaphore, sorted registration).
11. **Fix create_and_init** (truly async, cache initialized instances).
12. **Transport bind resilience** (retry/backoff, explicit bind errors, idempotent start, graceful partial shutdown).
13. **Task queue hardening** (bounded queue/backpressure, worker restart, cancellation cleanup, retention TTL, metrics).
14. **Engine startup timeouts/rollback** (asyncio.wait_for per subsystem, reverse rollback on failure).

## Execution order

Phase 1.1 → 1.2 → 1.3 → 1.4 → Phase 2 → Phase 3.
Each step: implement, add tests, run full suite, commit+push.

## Immediate next step

Phase 1.1 (per-agent identity for enrollment) — largest security gap and foundation for 1.2/1.3.
"""