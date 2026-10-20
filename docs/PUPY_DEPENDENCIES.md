# Pupy's dependency tree — feasibility assessment

What it would actually take to make the **57 PY_DEP modules** portable, and why
"vendor it into the generated agent script" is the wrong plan.

Investigated 2026-10 against `github.com/n1nj4sec/pupy` (`requirements.txt`,
`pupy/packages/*`). Read this before starting any PY_DEP work.

## What the tree actually contains

`requirements.txt` is ~50 packages. The heavy ones:

| Kind | Packages |
|---|---|
| Crypto | `pycryptodome`, `M2Crypto`, `pyOpenSSL`, `rsa`, `ecdsa`, `pyaes`, `ed25519` |
| Offensive | `impacket`, `scapy`, `pypykatz`, `pywerview`, `memorpy` |
| Remote access | `paramiko`, `pyuv`, `kcp`, `http-parser` |
| System | `psutil`, `netifaces`, `pyelftools`, `fusepy`, `xattr`, `filemagic`, `pylzma` |
| Other | `dukpy` (embedded JS engine), `mss` (screenshots), `tornado`, `msgpack`, `pygments` |

Plus `pupy/packages/all/*.py` — ~28 entries, but these are mostly **Pupy's own
glue modules** (`ad.py`, `cloudinfo.py`, `tasks.py`, `screenshot.py`, …), not
third-party libraries. Two entries (`memorpy`, `pywerview`) are **symlinks** to
external repos.

## The blocker

**Many of these are native C extensions**, compiled per-platform and per-Python
version: `M2Crypto`, `pylzma`, `netifaces`, `dukpy`, `kcp`, `pyuv`,
`http-parser`, `filemagic`, `xattr`. Others are **git-sourced forks pinned to
`master`** (`tinyec`, `urllib-auth`, `pykcp`, `pyuv`), which is not a
reproducible dependency even for Pupy.

Pupy itself does not solve this by vendoring into a script. It ships a **Python
environment** — see `pupy/packages/windows/{all,amd64,x86}` and
`packages/src/VideoCapture` — and already ships a compiled binary
(`windows/amd64/vidcap.pyd`, 17,920 bytes).

## Conclusion: the plan in PUPY_PARITY.md was wrong

I proposed "vendor `pupy/packages/*` into the generated payload" as a single
unblock for all 57 modules. That is not viable:

- The generated agent is a **single Python script**. A single script can carry
  pure-Python modules; it cannot carry compiled C extensions without a
  compatible interpreter on the target *and* prebuilt binaries per platform.
- Several deps are unreproducible (`@ master` forks).
- `dukpy`, `M2Crypto` and `fusepy` are large, platform-specific, and would
  dominate the payload.

This is a **project, not a slice** — on the order of building and distributing a
Python runtime bundle, which is a different thing from the module ports done so
far.

## REVISED STRATEGY (2026-10, user directive): reimplement natively

The user's direction supersedes the `load_package` plan below: **for any feature
that would need the third-party tree, write a C or Python implementation that
integrates directly into Pupyteer.** The upstream projects are open source, so
they are the *specification*, not a dependency to ship.

This dissolves the blocker. Re-reading the tree with that lens, most of the
"needs a dependency" classification was wrong — the packages were an
implementation detail of how *Pupy* solved it, not an inherent requirement.

### Three ways a PY_DEP feature actually gets implemented

**1. Pure-stdlib / pure-socket reimplementation** — the real workhorse.
A dependency was only ever a convenience here:

| Feature | Pupy's dep | Native implementation |
|---|---|---|
| `socks5proxy` | (none, sockets) | SOCKS5 handshake over `socket` — ~200 lines |
| `portfwd` | (none, sockets) | TCP relay over `socket` |
| `dns` | `dnslib` | DNS query over `socket` — the wire format is small |
| `http` | `requests` | `urllib.request` (stdlib) |
| `zip` | `pylzma` | `zipfile` / `zlib` (stdlib) |
| `isearch` | (none) | regex over the file walk already implemented |
| `stat`, `env`, `date`, `getpid`… | — | stdlib one-liners |

**2. Host-tool wrapper** — the pattern the C agent already uses for recon
verbs. No code to port, just a mapping:

| Feature | Wraps |
|---|---|
| `reg` | `reg query` / `reg add` |
| `services` | `sc query` |
| `tasks` | `schtasks /query` |
| `users` | `net user` |
| `drives` | `wmic logicaldisk` or `GetLogicalDrives` |
| `logs` | `wevtutil` (Windows) / `journalctl` (Linux) |
| `ssh` | the host's own `ssh` client |

**3. Genuinely native payload** — the 38 NATIVE modules. These really do need
compiled code (`mimikatz`, `keylogger` via `SetWindowsHookEx`, reflective
loaders), and they stay in that bucket. But they are C, which is what the PE
agent is for.

### Consequence for the plan

`load_package` is **deprioritised** — it was the answer to a problem we no
longer have. The work becomes ordinary module ports again, with the agent side
written natively. That puts most of PY_DEP back in reach without a runtime
bundle, and it keeps the payload self-contained.

---

## Superseded: the `load_package` plan

Pupy already answers this question. It ships a `load_package` module whose whole
purpose is **loading additional Python packages into a running agent** at
runtime. That is the mechanism, and it is the correct first step:

1. Port `load_package` — the transport for shipping a package into an agent and
   registering it on `sys.path`.
2. Then each PY_DEP module becomes a payload delivered through it, not a
   compile-time dependency of the agent.
3. Prebuilt native extensions stay a per-platform distribution problem, but a
   *deferred* one, and only for the modules that genuinely need them.

Ordering it the other way — trying to bake the tree into the agent — would
produce a payload that cannot be built.

## What is still cheap

Not everything in PY_DEP is blocked. Several modules need only **Pupy's own glue
code**, which is pure Python and small: `ad.py`, `cloudinfo.py`, `fsutils.py`,
`hwuuid.py`, `tasks.py`, `winerror.py`, `whole.py`. Those are portable on their
own and should be pulled forward rather than waiting on the package mechanism.
