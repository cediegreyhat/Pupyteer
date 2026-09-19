"""Litterbox integration client for Pupyteer v2.

Supports Litterbox v5.0.0 HTTP API:
- POST /upload — synchronous file upload, returns file_info immediately
- GET /health — service health check
- GET /files — list uploaded files with metadata

NOTE: Analysis (YARA/CheckPlz/EDR) runs asynchronously and is viewed
via the Litterbox web UI. The API only returns file metadata and
risk scores, not individual scanner results.

To trigger full analysis, the file must be submitted through the
web UI at http://<host>:<port>/files or via the upload form with
analysis_type parameter. The API /upload endpoint stores the file
but may not trigger full analysis pipeline.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

logger = logging.getLogger("pupyteer.litterbox")


class LitterboxError(Exception):
    """Raised when Litterbox communication fails."""


class LitterboxClient:
    """Client for Litterbox v5.0.0 HTTP API.

    Usage:
        client = LitterboxClient("http://192.168.100.85:1337")
        info = await client.upload("payload.exe")
        print(info["sha256"], info["risk_assessment"])
        files = await client.list_files()
    """

    # Analysis type values (may be used in web UI, not all via API)
    ANALYSIS_STATIC = "static"
    ANALYSIS_STATIC_EDR = "static_edr"
    ANALYSIS_STATIC_EDR_DYNAMIC = "static_edr_dynamic"
    ANALYSIS_DYNAMIC = "dynamic"
    ANALYSIS_HOLYGRAIL = "holygrail"
    ANALYSIS_DRIVER = "driver"

    def __init__(
        self,
        base_url: str = "http://localhost:1337",
        token: str = "",
        timeout: float = 60.0,
    ):
        self._base_url = base_url.rstrip("/")
        self._token = token
        self._timeout = timeout
        self._headers = {"Authorization": f"Bearer {token}"} if token else {}

    async def health_check(self) -> Dict[str, Any]:
        """Check Litterbox health and get scanner status."""
        async with httpx.AsyncClient(timeout=10.0, headers=self._headers) as client:
            resp = await client.get(f"{self._base_url}/health")
            if resp.status_code != 200:
                raise LitterboxError(f"Health check failed: {resp.status_code}")
            return resp.json()

    async def upload(
        self,
        artifact_path: str,
        analysis_type: str = "static",
        profile: str = "default",
        args: str = "",
        edr_profiles: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """Upload a file to Litterbox.

        Returns file_info dict with metadata (md5, sha256, size, etc.).
        Note: actual analysis results are only available via the web UI.
        """
        path = Path(artifact_path)
        if not path.exists():
            raise FileNotFoundError(f"Artifact not found: {artifact_path}")

        logger.info("Uploading %s to Litterbox (type=%s)", path.name, analysis_type)

        async with httpx.AsyncClient(timeout=self._timeout, headers=self._headers) as client:
            with open(artifact_path, "rb") as f:
                files = {"file": (path.name, f, "application/octet-stream")}
                data: Dict[str, str] = {
                    "analysis_type": analysis_type,
                    "profile": profile,
                }
                if args:
                    data["args"] = args
                if edr_profiles:
                    data["edr_profiles"] = ",".join(edr_profiles)

                resp = await client.post(
                    f"{self._base_url}/upload",
                    files=files,
                    data=data,
                )

            if resp.status_code not in (200, 201, 202):
                raise LitterboxError(
                    f"Upload failed: {resp.status_code} {resp.text}"
                )

            result = resp.json()

            if "error" in result:
                raise LitterboxError(f"Litterbox error: {result['error']}")

            file_info = result.get("file_info", {})
            logger.info("Upload complete: %s (md5=%s, size=%d, risk=%s)",
                        path.name,
                        file_info.get("md5", "?")[:16],
                        file_info.get("size", 0),
                        file_info.get("detection_risk", "unknown"))
            return file_info

    async def upload_bytes(
        self,
        data: bytes,
        filename: str = "payload.bin",
        analysis_type: str = "static",
        profile: str = "default",
    ) -> Dict[str, Any]:
        """Upload raw bytes without writing to disk."""
        import tempfile
        import os

        with tempfile.NamedTemporaryFile(delete=False, suffix=f"_{filename}") as tmp:
            tmp.write(data)
            tmp_path = tmp.name

        try:
            return await self.upload(tmp_path, analysis_type, profile)
        finally:
            os.unlink(tmp_path)

    async def list_files(self) -> Dict[str, Any]:
        """List all uploaded files with metadata (risk scores, sizes, etc.)."""
        async with httpx.AsyncClient(timeout=10.0, headers=self._headers) as client:
            resp = await client.get(f"{self._base_url}/files")
            if resp.status_code != 200:
                raise LitterboxError(f"Files list failed: {resp.status_code}")
            return resp.json()

    async def get_file_info(self, filename: str) -> Optional[Dict[str, Any]]:
        """Get metadata for a specific uploaded file by name."""
        files = await self.list_files()
        for section in ("payload_based", "driver_based"):
            items = files.get(section, {})
            payloads = items.get("payloads", items.get("drivers", {}))
            for key, info in payloads.items():
                if info.get("filename") == filename:
                    return info
        return None

    async def get_scanner_info(self) -> Dict[str, Any]:
        """Return info about available scanners from health check."""
        try:
            health = await self.health_check()
            return health.get("scanners", {})
        except Exception:
            return {}

    # Backward compatibility
    analyze = upload
    analyze_bytes = upload_bytes
