# Pupyteer Security Documentation

**Version:** 1.0.0 (Nightfall)
**Last Updated:** 2026-09-19

---

## Table of Contents

1. [Security Model](#security-model)
2. [Authentication & Authorization](#authentication--authorization)
3. [Secure Configuration](#secure-configuration)
4. [Audit Logging](#audit-logging)
5. [Network Security](#network-security)
6. [Credential Management](#credential-management)
7. [Payload Security](#payload-security)
8. [Detection Resilience Testing](#detection-resilience-testing)
9. [Operational Security](#operational-security)
10. [Security Checklist](#security-checklist)
11. [Incident Response](#incident-response)
12. [Compliance & Legal](#compliance--legal)

---

## Security Model

### Threat Model

Pupyteer is designed for authorized red-team operations. Its security model assumes:

- **Operators are trusted** — Authentication controls who can operate; authorization controls what they can do.
- **The server is a high-value target** — All stored data (sessions, tasks, logs) must be protected.
- **Agents operate in hostile environments** — Communications must be encrypted and authenticated.
- **Detection is inevitable** — Audit logs must be tamper-evident and secrets must never leak.

### Security Principles

1. **Secure by Default** — Unsafe configurations are not the default.
2. **Least Privilege** — Operators get minimum required permissions.
3. **Defense in Depth** — Multiple overlapping controls protect critical assets.
4. **Fail Secure** — Failures default to denied access, not open access.
5. **Audit Everything** — Every significant action is logged with attribution.

### Security Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    OPERATOR WORKSTATION                   │
│  ┌───────────────────────────────────────────────────┐  │
│  │              Pupyteer TUI (local)                  │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────┘
                          │ localhost only
┌─────────────────────────┴───────────────────────────────┐
│                    PUPYTEER SERVER                        │
│  ┌───────────────────────────────────────────────────┐  │
│  │  Auth Layer (token-based)                          │  │
│  │  Session Manager (encrypted state)                 │  │
│  │  Audit Logger (append-only)                        │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────┬───────────────────────────────┘
                          │ TLS/mTLS
┌─────────────────────────┴───────────────────────────────┐
│                    AGENT (TARGET)                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │  C2 Transport (profile-encoded)                    │  │
│  │  Module Executor (sandboxed)                       │  │
│  └───────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
```

---

## Authentication & Authorization

### Authentication Flow

```
Operator → TUI → AuthLayer.authenticate(username, password)
                        │
                        ├─ Check lockout (misses within the sliding window < max)
                        ├─ Load hashed record from operators_file (salted scrypt)
                        ├─ Constant-time verify (hmac.compare_digest)
                        ├─ Generate token (secrets.token_hex(32))
                        ├─ Store session (operator, token, expires_at)
                        └─ Return token
```

An unknown username and a wrong password return the same answer and cost the same
scrypt work (`OperatorStore.verify` runs a throwaway KDF on a lookup miss), so the
response is not a user-enumeration oracle.

### Password Storage

Passwords are never stored in the config and never in plaintext. Each credential
lives in the JSON file named by `security.operators_file` (default
`./data/keys/operators.json`, written mode `0600`), hashed with **salted scrypt**
(`pupyteer/server/core/operators.py:hash_password`):

```python
hashlib.scrypt(
    password.encode("utf-8"),
    salt=secrets.token_bytes(16),   # per-credential random salt
    n=2**15,                        # 32768 cost parameter
    r=8,
    p=1,
    dklen=32,
    maxmem=1 << 26,
)
```

The `kdf` name, the hex `salt`, the full `params` (`n`/`r`/`p`) and the hex digest
are all written next to each other. The parameters are stored rather than assumed
at read time so a hash is verified with exactly the `n` it was made with; a record
whose `kdf` is not `scrypt` is refused (no silent match, no crash).

`OperatorStore.add` rejects any password shorter than `MIN_PASSWORD_CHARS` (12).

**Note:** this replaced the earlier design that hashed with unsalted SHA-256 in the
config; a config file is pasted into tickets and backed up, so it is no longer a
credential store. Integrate with an identity provider (LDAP, OAuth, SAML) if you
need central, multi-user credential management.

### Rate Limiting

A wrong password is counted against the username only for a rolling window. After
`security.max_failed_logins` (default: 5) misses *within the last
`security.lockout_seconds` (default: 300) seconds*, further logins for that name
are refused until the oldest miss ages out. The lockout therefore expires on its
own (about five minutes after the last failure) — it is no longer a
process-lifetime lock that only a hand-edit of the credential file could clear.

```yaml
security:
  max_failed_logins: 5   # misses allowed within the window
  lockout_seconds: 300   # a name self-unlocks this long after the last miss
```

### Token-Based Authorization

```python
# Check permission
if auth.authorize(token, "execute"):
    # Operator has execute permission
    pass

# Token expiration
token_ttl: 3600  # 1 hour
```

### Permissions

| Permission | Description |
|------------|-------------|
| `read` | View sessions, tasks, logs, configuration |
| `execute` | Run modules, create tasks, kill sessions |
| `admin` | Add operators, change configuration |

Default permissions for new operators: `{"read", "execute"}`.

---

## Secure Configuration

### Default Security Settings

```yaml
security:
  require_auth: true                 # Authentication required
  token_ttl: 3600                    # Token expires after 1 hour
  max_failed_logins: 5               # Misses within the lockout window
  lockout_seconds: 300               # Rolling, self-expiring lockout window
  operators_file: "./data/keys/operators.json"  # salted-scrypt hashes, mode 0600
```

There is **no** default operator and **no** `changeme` password anywhere: the
config holds no credentials at all. A server with no `operators.json` is closed,
not open — see `scripts/verify_secure_defaults.py`, which fails any config that
still puts operator passwords under `security.operators`.

### Hardening Recommendations

#### 1. Bootstrap the First Credential

**Before any operational use**, create an operator. With no credential file
present, the console generates one strong password and prints it exactly once
(`OperatorStore.bootstrap`); the only copy kept afterwards is the scrypt hash in
`operators.json`:

```bash
# A random, high-entropy password Pupyteer prints once and then only hashes:
python3 -c "from pupyteer.server.core.operators import OperatorStore; \
print(OperatorStore.generate_password())"

# Or let the console bootstrap it for you on an empty store, which also writes
# the salted scrypt hash to operators_file (0600). Never hand-edit a hash into a
# config file — there is no longer a code path that reads passwords from config.
```

#### 2. Use Strong Passwords

Minimum password requirements (enforce externally):
- Length: 16+ characters
- Mix of uppercase, lowercase, digits, symbols
- No dictionary words or patterns

#### 3. Restrict Network Access

```yaml
server:
  host: "127.0.0.1"    # Localhost only for testing
  # host: "10.0.1.10"  # Specific interface for operations
  port: 8443
```

#### 4. Enable TLS

For any network-facing deployment, use TLS:

```yaml
transport:
  protocol: "https"
  # TLS certificate paths
  certfile: "/etc/pupyteer/server.crt"
  keyfile: "/etc/pupyteer/server.key"
```

#### 5. File Permissions

```bash
# Configuration file: owner read/write only
chmod 600 ~/.config/pupyteer/config.yaml

# Audit logs: owner read/write, group read
chmod 640 ~/.config/pupyteer/audit.log

# Directories: owner only
chmod 700 ~/.config/pupyteer/
```

#### 6. Disable Debug Mode in Production

Debug logging may leak sensitive information:

```bash
# Don't use in production
pupyteer --debug
```

---

## Audit Logging

### What Gets Logged

| Event Type | Risk Level | Description |
|------------|------------|-------------|
| `auth_success` | INFO | Successful operator login |
| `auth_failed` | WARNING | Failed authentication attempt |
| `auth_lockout` | CRITICAL | Account locked after max attempts |
| `session_registered` | INFO | New agent connected |
| `session_killed` | WARNING | Session terminated by operator |
| `task_created` | INFO | Task queued for execution |
| `task_completed` | INFO | Task finished successfully |
| `task_failed` | ERROR | Task encountered an error |
| `config_changed` | WARNING | Configuration modified |
| `auth_operator_added` | WARNING | New operator registered |

### What Never Gets Logged

- Passwords or password hashes
- Session tokens (full value)
- Module arguments containing secrets
- Payload contents
- Encryption keys

### Automatic Redaction

Fields containing these keywords are redacted:
- `password`
- `secret`
- `token`
- `key`
- `credential`

```python
# These are automatically redacted:
{"password": "hunter2"}           → {"password": "***REDACTED***"}
{"api_key": "abc123"}             → {"api_key": "***REDACTED***"}
{"token": "xyz..."}               → {"token": "***REDACTED***"}
```

### Log File Security

```bash
# Set appropriate permissions
chmod 600 ~/.config/pupyteer/audit.log

# Use append-only attribute (Linux)
chattr +a ~/.config/pupyteer/audit.log

# Forward to SIEM for tamper-evident storage
```

---

## Network Security

### Transport Security

| Transport | Encryption | Authentication |
|-----------|------------|----------------|
| HTTPS | TLS 1.2+ | Optional mTLS |
| WebSocket (WSS) | TLS 1.2+ | Optional |
| DNS | None (encoded) | Shared secret |
| TCP Cleartext | None | Pre-shared key |

### Recommended Configurations

#### Internet-Facing Operations

```yaml
transport:
  protocol: "https"
  certfile: "/etc/letsencrypt/live/c2.example.com/fullchain.pem"
  keyfile: "/etc/letsencrypt/live/c2.example.com/privkey.pem"

security:
  require_auth: true
  token_ttl: 1800  # 30 minutes
```

#### Internal Network Operations

```yaml
transport:
  protocol: "tcp"

security:
  require_auth: true
  token_ttl: 3600
```

### Firewall Rules

```bash
# Allow only specific IPs
sudo iptables -A INPUT -p tcp --dport 8443 -s 10.0.1.0/24 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 8443 -j DROP

# Rate limiting
sudo iptables -A INPUT -p tcp --dport 8443 -m connlimit --connlimit-above 10 -j DROP
```

---

## Credential Management

### Development vs Production

| Environment | Credential Store |
|-------------|------------------|
| Development / Testing / Production (default) | Salted-scrypt hashes in `operators_file` (JSON, mode 0600) — never in config |
| Multi-user / enterprise | External identity provider (LDAP, OAuth, SAML), if integrated |

### External Identity Provider Integration

To integrate with LDAP, OAuth, or SAML:

1. Implement the `IAuth` protocol from `pupyteer/server/interfaces.py`
2. Replace the default `AuthLayer` in your deployment
3. Update configuration to point to your IdP

```python
class LDAPAuthLayer:
    """Custom auth layer using LDAP."""

    def __init__(self, config, audit):
        self._ldap_url = config.get("auth.ldap_url")
        # ... initialize LDAP connection

    def authenticate(self, username: str, password: str) -> Optional[str]:
        # Validate against LDAP
        # Return token on success, None on failure
        pass

    def authorize(self, token: str, required_permission: str) -> bool:
        # Check LDAP groups/permissions
        pass

    # ... implement remaining IAuth methods
```

### Token Handling

- Tokens are generated with `secrets.token_hex(32)` (cryptographically secure)
- Tokens expire after `token_ttl` seconds
- Expired tokens are cleaned up on each `authorize()` call
- Revoked tokens are immediately removed from the session store

---

## Payload Security

### Payload Lifecycle

```
Configuration → Validation → Build → Verification → Artifact Management → Deployment
```

### Security Controls

#### Payload Signing

For controlled environments, payloads should be signed:

```python
import hashlib
import hmac

def sign_payload(data: bytes, key: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def verify_signature(data: bytes, signature: str, key: bytes) -> bool:
    expected = sign_payload(data, key)
    return hmac.compare_digest(expected, signature)
```

#### Artifact Storage

```yaml
paths:
  payload_artifacts: "/secure/pupyteer/payloads"  # Restricted access
```

```bash
# Secure the artifacts directory
chmod 700 /secure/pupyteer/payloads
chown pupyteer:pupyteer /secure/pupyteer/payloads
```

#### Payload Validation

Before deployment:
- Verify hash matches expected value
- Confirm target platform compatibility
- Check signature if signed
- Validate size is within expected range

### Detection Resilience Testing

Pupyteer supports controlled detection-resilience testing for authorized assessments.

#### Lab Mode

Evasion testing is gated off by default. `EvasionTestRunner` raises before
executing any test unless the flag below is set, so an unset configuration
fails closed rather than running:

```yaml
evasion:
  test_mode: false   # set true to enable lab testing explicitly
```

The gate is enforced in code (`server/evasion/runner.py`,
`_require_lab_mode`), not by operator discipline.

#### Disabled Capability Sets

The anti-forensics module file (`server/modules/builtin/antiforensics.py`) is
not loaded: it references a `ModuleCategory` member that is deliberately not
defined, and `show modules` reports the file as failed. Those modules clear
event logs, delete prefetch entries and modify file timestamps — they destroy
evidence on a host, which is a different class of capability from the rest of
the framework and has no test coverage. Enabling them requires an explicit
decision covering both the capability and its lab-only safeguards.

#### Test Configurations

Each test configuration records:
- Configuration identifier
- Build hash
- Test timestamp
- Target environment details

#### Evaluation Metrics

| Metric | Description |
|--------|-------------|
| Detection Result | Whether AV/EDR detected the artifact |
| Execution Result | Whether the payload executed successfully |
| False Positive Result | Whether legitimate activity was flagged |
| Telemetry Generated | What telemetry was produced |
| Defensive Control Triggered | Which security controls activated |
| Test Configuration | What configuration was tested |
| Timestamp | When the test occurred |
| Environment | OS version, AV product, etc. |

#### External Testing Tools

For comprehensive detection testing, integrate with open-source tools:

- **Litterbox** — Payload testing and analysis
- **ThreatCheck** — AV/EDR detection testing
- **InlineExecute-Assembly** — .NET assembly testing

---

## Operational Security

### Server Hardening

#### Before Each Engagement

- [ ] Rotate all credentials and tokens
- [ ] Verify audit logging is functional
- [ ] Confirm firewall rules are correct
- [ ] Check TLS certificates are valid
- [ ] Verify backup systems are operational

#### During Operations

- [ ] Monitor audit logs in real-time
- [ ] Limit operator access to required sessions
- [ ] Use minimal-necessary modules
- [ ] Avoid leaving payload artifacts on disk
- [ ] Use jitter in C2 profiles to evade detection

#### After Operations

- [ ] Revoke all operator tokens
- [ ] Archive and encrypt audit logs
- [ ] Clean up payload artifacts
- [ ] Rotate credentials for next engagement
- [ ] Review logs for anomalies

### Operator Workstation Security

- Use a dedicated, hardened workstation for C2 operations
- Full-disk encryption (LUKS, BitLocker)
- Screen lock when unattended
- No personal accounts on the C2 workstation
- Network segmentation from corporate LAN

### Communication Security

- Never transmit C2 credentials over unencrypted channels
- Use out-of-band communication for operator coordination
- Assume all C2 traffic will be captured and analyzed
- Use mTLS when possible for mutual authentication

---

## Security Checklist

### Pre-Deployment

- [ ] Default credentials changed
- [ ] Strong passwords configured (16+ characters)
- [ ] Audit logging enabled and tested
- [ ] Log file permissions set (600)
- [ ] Configuration file permissions set (600)
- [ ] TLS certificates configured
- [ ] Firewall rules restrict access
- [ ] Server bound to correct interface (not 0.0.0.0 if possible)
- [ ] Debug mode disabled
- [ ] Test authentication flow
- [ ] Test authorization controls
- [ ] Verify audit events are generated

### Operational

- [ ] All operators authenticated
- [ ] Tokens have appropriate TTL
- [ ] Session timeout configured correctly
- [ ] Concurrent task limit appropriate
- [ ] C2 profile jitter enabled
- [ ] Payloads signed and validated
- [ ] Artifact directory secured
- [ ] Backups encrypted
- [ ] Incident response plan in place

### Post-Engagement

- [ ] All tokens revoked
- [ ] Audit logs archived and encrypted
- [ ] Credentials rotated
- [ ] Payloads removed from targets
- [ ] Artifacts cleaned up
- [ ] Lessons learned documented

---

## Incident Response

### Compromised Operator Credentials

1. **Revoke all active tokens for the compromised operator**
2. **Rotate the compromised credential**
3. **Review audit logs for unauthorized actions**
4. **Assess blast radius** — what sessions/tasks were accessed?
5. **Notify the team** and document the incident

### Server Compromise

1. **Isolate the server** from the network
2. **Preserve logs** — copy audit logs to a secure location
3. **Do not restart** — forensic state may be needed
4. **Analyze logs** for attack vectors
5. **Rebuild from scratch** after investigation
6. **Rotate all credentials** — assume all were compromised

### Detection by Blue Team

1. **Cease active operations** immediately
2. **Assess what was detected** — profile? payload? traffic pattern?
3. **Review and update** C2 profiles
4. **Change infrastructure** — new IPs, domains, certificates
5. **Update modules** with detection-resistant techniques

---

## Compliance & Legal

### Authorization Requirements

Pupyteer must only be used:

- With explicit written authorization from the target organization
- Within the scope defined in the engagement agreement
- By trained and authorized operators
- In compliance with local laws and regulations

### Legal Considerations

- Unauthorized access to computer systems is illegal in most jurisdictions
- The framework's detection-resilience features are for authorized testing only
- Operators are responsible for ensuring legal compliance
- Document authorization before every engagement

### Data Retention

- Audit logs should be retained per engagement requirements
- Encrypt logs at rest
- Securely delete logs when retention period expires
- Follow organizational data classification policies

### Responsible Disclosure

If you discover a vulnerability in Pupyteer:

1. Do NOT file a public issue
2. Contact maintainers privately
3. Allow reasonable time for a fix before disclosure
4. Follow coordinated disclosure practices

---

## Reporting Security Vulnerabilities

To report a security issue:

1. Email: security@pupyteer.example (replace with actual contact)
2. Include: Description, impact, reproduction steps, suggested fix
3. Do not include: Active exploits, stolen data, or details that could enable attacks

We acknowledge reports within 48 hours and aim to release fixes within 90 days.

---

## Security Contacts

| Role | Contact |
|------|---------|
| Security Team | security@pupyteer.example |
| On-Call Engineer | oncall@pupyteer.example |
| Legal | legal@pupyteer.example |
