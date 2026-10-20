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

## The right mechanism: port `load_package` first

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
