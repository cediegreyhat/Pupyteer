# Pupyteer Polishing & Upgrading Plan

Status of the plan derived from the README gaps and `MODERNIZATION_ROADMAP.md`.
Ordered by risk/dependency. Each item keeps the full suite green.

Items marked **done** are verified against the code, not against this document.

## Phase 1 — Security

### 1. Per-agent identity for enrollment — **done**

Ed25519 keypair minted at payload build; the private half is compiled into that
one payload, the public half is kept in `security.agent_keys_file`. The listener
issues a single-use challenge and `register` answers with a signature, so a
recovered binary yields one agent's key rather than the shared secret. Revocation
is per agent (`agents list` / `agents revoke <agent_id>`), and the shared
enrollment secret remains as the legacy path.

Still open: the compiled Windows PE does not carry the signed handshake — it
enrols with the shared secret and says so in its build log.

### 2. Verified capability claims — **done**

`register` carries a `payload_id`; the listener looks the claim up in the build
manifest and downgrades an over-claim to the verified subset, auditing the
mismatch as `session_capability_mismatch`. Payloads that predate the field
declare nothing and keep the shell-only trust they had before. A name outside
`KNOWN_CAPABILITIES` is still ignored, so a payload cannot grant itself a
permission by inventing a word for it.

### 3. Optional payload-level AEAD cipher — **open**

`security.channel_cipher` (default off) reserves the config slot and
`server/crypto/channel.py` holds a correct AES-256-GCM primitive, but nothing
imports it and there is no negotiation in `register`. Confidentiality comes from
TLS alone. This is the last item of Phase 1 and the largest remaining security
gap: it touches both agents, the listener, the profiles and the config template.

### 4. Network access control documentation — **done**

`security.allowed_operator_cidrs` is enforced at registration on both listeners,
and the README/Security documentation states that everything else is a
deployment concern (reverse proxy or mTLS in front of the team server).

## Phase 2 — TUI Modernization — **done**

Screens (`tui/screens/banner.py`, `session_dashboard.py`) and widgets
(`tui/widgets/keyboard.py`, `status_bar.py`, `table.py`) are extracted from
`app.py`, which keeps the command registry and the completer. `KeyboardShortcuts`
binds Tab, Ctrl+L, Ctrl+D, Ctrl+K and Ctrl+T behind a no-readline guard.

## Phase 3 — Performance & Reliability

| Item | Status |
|---|---|
| Registry metadata cache, invalidated on register/unload/reload | **done** |
| Parallel async discovery (per-file `to_thread`, sorted registration) | **done** |
| `create_and_init` | **removed** — `execute()` does the work; nothing called it |
| Transport bind resilience (retry/backoff, explicit bind errors, idempotent start, graceful partial shutdown) | **done** |
| Task queue hardening (real dispatch, cancellation cleanup, retention pruning, metrics) | **done** |
| Engine startup timeouts/rollback (`wait_for` per subsystem, reverse rollback on failure) | **done** |

## Execution order

Phase 1.1 → 1.2 → 1.3 → 1.4 → Phase 2 → Phase 3.
Each step: implement, add tests, run full suite, commit and push.

## Immediate next step

Phase 1.3, the optional payload-level AEAD cipher. It is the only remaining
Phase 1 item and the last thing the Security section lists as not wired.
