# Pupyteer Profile Documentation

**Version:** 1.0.0 (Nightfall)
**Last Updated:** 2026-09-19

---

## Table of Contents

1. [What is a C2 Profile?](#what-is-a-c2-profile)
2. [Profile Structure](#profile-structure)
3. [Field Reference](#field-reference)
4. [Profile Manager Operations](#profile-manager-operations)
5. [Built-in Profiles](#built-in-profiles)
6. [Creating Custom Profiles](#creating-custom-profiles)
7. [Profile Validation](#profile-validation)
8. [Profile Lifecycle](#profile-lifecycle)
9. [Examples](#examples)
10. [Troubleshooting](#troubleshooting)

---

## What is a C2 Profile?

A C2 (Command and Control) profile defines how agents communicate with the Pupyteer server. It specifies the network protocol, timing parameters, encoding methods, and behavioral patterns that shape C2 traffic.

### Why Profiles Matter

- **Traffic Shaping** — Blend C2 communications with legitimate traffic patterns.
- **Operational Security** — Vary beacon timing, jitter, and encoding to evade network detection.
- **Protocol Flexibility** — Support different network environments (HTTP-only, DNS-only, WebSocket-friendly).
- **Reproducibility** — Save and reload profiles for consistent engagement configurations.

### Profile vs Transport

| Concept | Purpose |
|---------|---------|
| **Profile** | Declares C2 behavior (timing, encoding, headers, jitter) |
| **Transport** | Implements the actual network listener (TCP, HTTPS, DNS) |

A profile references a transport. The transport provides the network socket; the profile shapes what flows through it.

---

## Structure

A profile is a YAML document with these top-level sections:

```yaml
profile:
  name: "HTTPS-Standard"
  version: "1.0"

transport:
  protocol: "tcp"
  host: "0.0.0.0"
  port: 8443

session:
  heartbeat_interval: 30
  timeout: 300
  jitter: 0.2

encoding:
  mode: "raw"

logging:
  level: "INFO"

timeouts:
  connect: 30
  response: 60

security:
  require_auth: true
  token_ttl: 3600
```

---

## Field Reference

### `profile`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | Yes | Unique profile identifier. Used in commands and listings. |
| `version` | string | Yes | Semantic version (e.g., "1.0", "2.1.0"). |

### `transport`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `protocol` | string | Yes | Network protocol: `tcp`, `https`, `dns`, `websocket`, `smb`. |
| `host` | string | Yes | Bind address for the listener (e.g., "0.0.0.0", "192.168.1.10"). |
| `port` | integer | Yes | Listener port (1-65535). |

### `session`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `heartbeat_interval` | integer | Yes | Agent check-in frequency in seconds. |
| `timeout` | integer | Yes | Seconds without check-in before session is marked TIMEOUT. |
| `jitter` | float | No | Randomization factor 0.0–1.0 for beacon timing. Default: 0.2. |

**Jitter Explained:** A jitter of 0.2 means beacon timing varies by ±20%. If heartbeat_interval is 30s, agents check in every 24–36 seconds. This defeats simple frequency-based detection.

### `encoding`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | Yes | Payload encoding: `raw`, `base64`, `aes256-gcm`. |

### `logging`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `level` | string | No | Profile-specific log level: DEBUG, INFO, WARNING, ERROR. |

### `timeouts`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `connect` | integer | No | Seconds to wait for connection establishment. Default: 30. |
| `response` | integer | No | Seconds to wait for agent response. Default: 60. |

### `security`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `require_auth` | boolean | No | Whether agents must authenticate. Default: true. |
| `token_ttl` | integer | No | Agent session token lifetime in seconds. Default: 3600. |

---

## Profile Manager Operations

The ProfileManager provides these operations (accessible via TUI or programmatically):

### List All Profiles

```python
profiles = profile_mgr.list()
# [{"name": "HTTPS-Standard", "transport": "https", ...}]
```

TUI: `profiles list`

### Get Profile Details

```python
profile = profile_mgr.get("HTTPS-Standard")
```

TUI: `profiles show HTTPS-Standard`

### Load a Profile

```python
profile_mgr.load("HTTPS-Standard")
```

TUI: `profiles load HTTPS-Standard`

Loading a profile sets it as the active profile for new agent connections.

### Validate a Profile

```python
errors = profile_mgr.validate("HTTPS-Standard")
# Returns list of error strings (empty = valid)
```

TUI: `profiles validate HTTPS-Standard`

### Get Active Profile

```python
name = profile_mgr.active_name()
```

---

## Built-in Profiles

### HTTPS-Standard

The default profile. Optimized for HTTPS-based C2 with moderate timing.

```yaml
profile:
  name: "HTTPS-Standard"
  version: "1.0"

transport:
  protocol: "tcp"
  host: "0.0.0.0"
  port: 8443

session:
  heartbeat_interval: 30
  timeout: 300
  jitter: 0.2

encoding:
  mode: "raw"

logging:
  level: "INFO"

timeouts:
  connect: 30
  response: 60

security:
  require_auth: true
  token_ttl: 3600
```

**Characteristics:**
- 30-second heartbeat with 20% jitter
- Raw encoding (TLS provides encryption)
- Suitable for most network environments

---

## Creating Custom Profiles

### Step 1: Create the YAML File

Create a new file in `pupyteer/config/profiles/`:

```yaml
# pupyteer/config/profiles/dns_stealth.yaml
profile:
  name: "DNS-Stealth"
  version: "1.0"

transport:
  protocol: "dns"
  host: "0.0.0.0"
  port: 53

session:
  heartbeat_interval: 300
  timeout: 900
  jitter: 0.4

encoding:
  mode: "base64"

logging:
  level: "WARNING"

timeouts:
  connect: 60
  response: 120

security:
  require_auth: true
  token_ttl: 7200
```

### Step 2: Load and Validate

```python
profile_mgr.load("DNS-Stealth")
errors = profile_mgr.validate("DNS-Stealth")
```

Or via TUI:

```
pupyteer > profiles load DNS-Stealth
pupyteer > profiles validate DNS-Stealth
```

### Step 3: Restart Listeners

After loading a new profile, restart the engine or reload transports for changes to take effect.

### Best Practices

1. **Use Descriptive Names** — Profile names should indicate their purpose (e.g., `HTTPS-FastBeacon`, `DNS-LowAndSlow`).

2. **Document Jitter Rationale** — Higher jitter (0.3–0.5) defeats timing detection but slows response time. Document the trade-off.

3. **Version Your Profiles** — When changing a profile, bump the version. Existing agents on the old version continue until they update.

4. **Test Before Deployment** — Validate profiles in a lab before using them in an engagement.

5. **Match Encoding to Transport** — Use `raw` over TLS (HTTPS), `base64` over DNS, `aes256-gcm` for custom encryption.

---

## Profile Validation

Validation checks:

- Required fields are present
- `profile.name` is non-empty
- `transport.protocol` is a supported protocol
- `transport.port` is in range 1–65535
- `session.timeout` > `session.heartbeat_interval`
- `session.jitter` is between 0.0 and 1.0
- `encoding.mode` is a known mode
- `timeouts.connect` > 0

Invalid profiles produce specific error messages:

```
  ERROR: transport.port must be between 1 and 65535 (got 70000)
  ERROR: session.jitter must be between 0.0 and 1.0 (got 1.5)
```

---

## Profile Lifecycle

```
Create → Validate → Load → Active → Unload
```

1. **Create** — Write the YAML file
2. **Validate** — Check for errors before loading
3. **Load** — Register as the active profile
4. **Active** — New agent connections use this profile
5. **Unload** — Remove when switching profiles

### Profile Switching

When switching from Profile A to Profile B:
- Existing sessions on Profile A remain active until timeout or kill
- New connections use Profile B
- Audit log records the profile change event

---

## Examples

### Fast Beacon (Aggressive)

For time-sensitive operations where speed matters more than stealth:

```yaml
profile:
  name: "HTTPS-FastBeacon"
  version: "1.0"

transport:
  protocol: "tcp"
  host: "0.0.0.0"
  port: 8443

session:
  heartbeat_interval: 5
  timeout: 30
  jitter: 0.05

encoding:
  mode: "raw"

timeouts:
  connect: 10
  response: 15
```

**Use Case:** Internal network, low risk of detection, need rapid command execution.

### Low and Slow (Stealthy)

For high-detection environments where stealth is critical:

```yaml
profile:
  name: "HTTPS-LowAndSlow"
  version: "1.0"

transport:
  protocol: "tcp"
  host: "0.0.0.0"
  port: 443

session:
  heartbeat_interval: 600
  timeout: 1800
  jitter: 0.5

encoding:
  mode: "aes256-gcm"

timeouts:
  connect: 120
  response: 300
```

**Use Case:** Targeted network with IDS/IPS, long-term persistence.

### DNS Tunnel

For environments where only DNS egress is allowed:

```yaml
profile:
  name: "DNS-Tunnel"
  version: "1.0"

transport:
  protocol: "dns"
  host: "0.0.0.0"
  port: 53

session:
  heartbeat_interval: 60
  timeout: 300
  jitter: 0.3

encoding:
  mode: "base64"

timeouts:
  connect: 30
  response: 60
```

**Use Case:** Restricted network with HTTP/HTTPS blocked.

### WebSocket (Corporate Proxy)

For networks that only allow WebSocket connections:

```yaml
profile:
  name: "WSS-Corporate"
  version: "1.0"

transport:
  protocol: "websocket"
  host: "0.0.0.0"
  port: 8443

session:
  heartbeat_interval: 30
  timeout: 300
  jitter: 0.2

encoding:
  mode: "raw"

timeouts:
  connect: 30
  response: 60
```

**Use Case:** Corporate environment with deep packet inspection that allows TLS WebSocket.

---

## Troubleshooting

### Profile Not Found

**Symptom:** `Profile not found: <name>`

- Check the file is in `pupyteer/config/profiles/` or an external path in `modules.paths`
- Ensure the YAML file is valid (`python -c "import yaml; yaml.safe_load(open('file.yaml'))"`)

### Profile Invalid

**Symptom:** `Profile <name> has validation errors`

- Run `profiles validate <name>` to see specific errors
- Check all required fields are present
- Verify numeric ranges (port 1-65535, jitter 0.0-1.0)

### Profile Not Taking Effect

**Symptom:** New connections still use old profile

- Profile changes only affect NEW connections
- Existing sessions retain their original profile until timeout
- Restart the engine to force all connections to the new profile

### Transport Port Conflict

**Symptom:** `Transport manager failed to initialize`

- Another process is using the port: `ss -tlnp | grep <port>`
- Change `transport.port` in the profile or kill the conflicting process
