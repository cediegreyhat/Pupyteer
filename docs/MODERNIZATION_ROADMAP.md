# Pupyteer Modernization Roadmap

## Status
- Parity integration: COMPLETE (122/122 upstream modules classified; 101 registered; full suite green)
- Modernization: IN PROGRESS (TUI + evasion tracks)

## Priority Frame
1. TUI modernization (operator UX, session management, theming)
2. Evasion capabilities (new techniques, profiles, runner hardening)
3. Performance and reliability (async, caching, error handling)
4. Security hardening (auth, audit, sandboxing)

## Architecture Tradeoffs
- Keep TUI monolithic in app.py vs. extract screens/widgets: monolithic is simpler but harder to test; extraction improves testability. Decision: extract incrementally, screens first.
- Native reimplementation vs. vendoring Pupy packages: native (already decided) — no vendor tree.
- Shell-dispatched modules vs. agent-native: shell-dispatched for stdlib; agent-native for complex (smb/ssh/etc.) deferred to load_package.

## Delivery Risks
- Full suite takes ~2.5 min; commit cadence must batch changes.
- Wine/PE integration test flaky (enrollment secret env) — pre-existing, not blocking.
- Large app.py (~1500 lines) — refactoring risk; must keep tests green.

## Decision Note (accepted)
- Continue modernization via small, testable, committed steps.
- Each step must keep full suite green (modulo pre-existing env failure).
- Use verb-table classification for any new TUI command.

## Follow-up Handoffs
- [ ] Extract TUI screens into pupyteer/tui/screens/
- [ ] Add keyboard shortcuts / status bar
- [ ] Add new evasion profiles and techniques
- [ ] Improve session dashboard
- [ ] Add command alias expansion in dispatch
- [ ] Performance: async module loading
- [ ] Security: input validation hardening
