# Pupyteer Installation Guide

**Version:** 1.0.0 (Nightfall)
**Last Updated:** 2026-09-19

---

## Table of Contents

1. [System Requirements](#system-requirements)
2. [Installation Methods](#installation-methods)
   - [Method 1: pipx (Recommended)](#method-1-pipx-recommended)
   - [Method 2: Virtual Environment](#method-2-virtual-environment)
   - [Method 3: Development Install](#method-3-development-install)
3. [Post-Installation Setup](#post-installation-setup)
4. [Verifying Installation](#verifying-installation)
5. [Upgrading](#upgrading)
6. [Uninstallation](#uninstallation)
7. [Platform-Specific Notes](#platform-specific-notes)
8. [Troubleshooting](#troubleshooting)

---

## System Requirements

### Minimum

| Component | Requirement |
|-----------|-------------|
| OS | Linux, macOS, Windows (via WSL or native Python) |
| Python | 3.8 or higher |
| RAM | 512 MB (server); 2+ GB recommended for multiple agents |
| Disk | 100 MB (base); additional space for payload artifacts and logs |
| Network | Outbound/inbound access on configured listener port |

### Recommended

| Component | Recommendation |
|-----------|----------------|
| OS | Linux (Ubuntu 22.04+, Kali 2023+) for server |
| Python | 3.10+ for best asyncio performance |
| RAM | 4+ GB for production operations |
| Disk | 1+ GB for logs, artifacts, and module storage |

### Dependencies

| Package | Purpose |
|---------|---------|
| `pyyaml` | Configuration file parsing |
| `pycryptodome` | Cryptographic operations |
| `cerberus` | Configuration validation |
| `colorama` | Cross-platform colored terminal output |
| `readline` | Command history and tab completion (Unix) |
| `pyOpenSSL` | TLS/SSL for HTTPS transports |

Full dependency list in `requirements.txt`.

---

## Installation Methods

### Method 1: pipx (Recommended)

pipx installs Pupyteer in an isolated environment while making the `pupyteer` command globally available.

```bash
# Install pipx if not already available
python3 -m pip install --user pipx
python3 -m pipx ensurepath

# Install Pupyteer
pipx install /path/to/Pupyteer

# Or from a git repository
pipx install git+https://github.com/your-org/pupyteer.git
```

**Pros:**
- Isolated environment (no dependency conflicts)
- Global `pupyteer` command
- Easy uninstall

### Method 2: Virtual Environment

```bash
# Clone the repository
git clone https://github.com/your-org/pupyteer.git
cd Pupyteer

# Create virtual environment
python3 -m venv pupyteer-env
source pupyteer-env/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run Pupyteer
python3 -m pupyteer.main
```

**Pros:**
- Standard Python workflow
- Easy to upgrade dependencies
- Works on all platforms

### Method 3: Development Install

For contributors and module developers:

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/your-org/pupyteer.git
cd Pupyteer

# Create and activate environment
python3 -m venv pupyteer-dev
source pupyteer-dev/bin/activate

# Install in editable mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt  # if available

# Run tests
python -m pytest tests/ -v
```

**Pros:**
- Editable — changes take effect without reinstall
- Full test suite access
- Easy to switch branches

---

## Post-Installation Setup

### Step 1: Create Configuration Directory

```bash
mkdir -p ~/.config/pupyteer
```

### Step 2: Generate Default Configuration

```bash
# Copy the default config
cp pupyteer/config/defaults/pupyteer.yaml ~/.config/pupyteer/config.yaml

# Or create with custom values
cat > ~/.config/pupyteer/config.yaml << 'EOF'
server:
  host: "0.0.0.0"
  port: 8443

logging:
  level: "INFO"
  file: "~/.config/pupyteer/audit.log"

operator:
  name: "redteam-operator"
  theme: "dark"

profile:
  default: "HTTPS-Standard"

session:
  timeout_seconds: 300

tasks:
  max_concurrent: 5

security:
  require_auth: true
  token_ttl: 3600
  max_failed_logins: 5
  operators:
    admin: "changeme"

paths:
  payload_artifacts: "~/.config/pupyteer/payloads"
  profiles: "~/.config/pupyteer/profiles"
  logs: "~/.config/pupyteer/logs"
EOF
```

### Step 3: Secure the Default Credentials

**IMPORTANT:** The default configuration includes placeholder credentials. Change these before any operational use:

```bash
# Generate a secure password hash
python3 -c "import hashlib; print(hashlib.sha256(b'your-secure-password').hexdigest())"

# Update the config with the hash
# Edit ~/.config/pupyteer/config.yaml and replace the operator password
```

### Step 4: Create Required Directories

```bash
mkdir -p ~/.config/pupyteer/payloads
mkdir -p ~/.config/pupyteer/profiles
mkdir -p ~/.config/pupyteer/logs
```

### Step 5: Configure Firewall

Allow inbound traffic on the C2 listener port:

```bash
# UFW (Ubuntu)
sudo ufw allow 8443/tcp

# firewalld (RHEL/Fedora)
sudo firewall-cmd --permanent --add-port=8443/tcp
sudo firewall-cmd --reload

# iptables
sudo iptables -A INPUT -p tcp --dport 8443 -j ACCEPT
```

---

## Installation

### Quick Check

```bash
# Check Python version
python3 --version  # Should be 3.8+

# Check Pupyteer version
pupyteer --version
# Pupyteer v1.0.0 (Nightfall)

# Check configuration loads
pupyteer -c ~/.config/pupyteer/config.yaml --headless
# Pupyteer engine running (headless). Press Ctrl+C to stop.
```

### Full Verification

```bash
# 1. Start the server
pupyteer

# 2. Verify banner appears with correct config
# 3. Verify dashboard shows Server: online, Agents: 0
# 4. Test a command
pupyteer > status
pupyteer > help
pupyteer > exit

# 5. Verify audit log was written
cat ~/.config/pupyteer/audit.log | jq .
```

### Expected Output

```
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║                    PUPYTEER                                      ║
║          Red Team Operations Framework                           ║
╚══════════════════════════════════════════════════════════════════╝

  [Server] 0.0.0.0:8443
  [Operator] redteam-operator
  [Profile] HTTPS-Standard
  [Agents] 0

  ┌─── Dashboard ───────────────────────────────────┐
  │  Server:    online
  │  Agents:    0
  │  Tasks:     0
  │  Profile:   HTTPS-Standard
  └─────────────────────────────────────────────────┘

pupyteer >
```

---

## Upgrading

### pipx

```bash
pipx upgrade pupyteer
```

### Virtual Environment

```bash
cd Pupyteer
git pull origin main
pip install -r requirements.txt --upgrade
```

### Development Install

```bash
cd Pupyteer
git pull origin main
git submodule update --init --recursive
pip install -e . --upgrade
```

### Post-Upgrade Checklist

- [ ] Review changelog for breaking changes
- [ ] Back up configuration before upgrade
- [ ] Run test suite: `python -m pytest tests/ -v`
- [ ] Verify configuration still loads: `pupyteer --version`
- [ ] Check audit log for errors after restart

---

## Uninstallation

### pipx

```bash
pipx uninstall pupyteer
```

### Virtual Environment

```bash
deactivate
rm -rf pupyteer-env
```

### Remove Configuration and Data

```bash
# Remove config
rm -rf ~/.config/pupyteer

# Remove command history
rm -f ~/.pupyteer_history

# Remove logs and artifacts
rm -rf ~/.pupyteer
```

---

## Platform-Specific Notes

### Linux (Ubuntu/Debian)

```bash
# Install system dependencies
sudo apt update
sudo apt install -y python3 python3-pip python3-venv libssl-dev

# Readline support (usually pre-installed)
sudo apt install -y libreadline-dev
```

### Linux (RHEL/Fedora/CentOS)

```bash
# Install system dependencies
sudo dnf install -y python3 python3-pip openssl-devel readline-devel
```

### macOS

```bash
# Install Python via Homebrew
brew install python@3.10

# readline is included with macOS Python
# For better readline support:
brew install readline
```

### Windows

Pupyteer server is not officially supported on Windows. Use WSL2 or a Linux VM:

```bash
# In WSL2 Ubuntu
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
pip3 install pipx
pipx install /path/to/Pupyteer
```

---

## Troubleshooting

### Python Version Issues

**Error:** `SyntaxError: invalid syntax` or `ModuleNotFoundError: No module named 'typing'`

**Fix:** Upgrade to Python 3.8+:
```bash
python3 --version  # Check current version
# Install newer Python if needed
```

### Permission Denied on Port

**Error:** `[Errno 13] Permission denied` on port < 1024

**Fix:** Use a port above 1024, or run with elevated privileges (not recommended):
```yaml
server:
  port: 8443  # Use this instead of 443
```

### Missing Dependencies

**Error:** `ModuleNotFoundError: No module named 'yaml'`

**Fix:**
```bash
pip install -r requirements.txt
```

### Configuration Not Loading

**Error:** Config values are defaults, not your custom values.

**Fix:**
- Verify config file path: `pupyteer -c /path/to/config.yaml`
- Check YAML syntax: `python3 -c "import yaml; yaml.safe_load(open('config.yaml'))"`
- Check file permissions: `chmod 600 config.yaml`

### Readline Not Working (Windows)

**Error:** TAB completion and arrow keys don't work.

**Fix:** Use WSL2 on Windows. Native Windows Python doesn't include readline.

### SSL/TLS Errors

**Error:** `SSL: CERTIFICATE_VERIFY_FAILED`

**Fix:**
- For testing: Use self-signed certificates
- For production: Use proper certificates from a trusted CA
- Update certifi: `pip install --upgrade certifi`

### Still Having Issues?

1. Run with debug logging: `pupyteer --debug`
2. Check the audit log for error details
3. Search existing issues on the Pupyteer repository
4. File a bug report with debug output and system info
