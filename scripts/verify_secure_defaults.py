#!/usr/bin/env python3
"""Secure defaults verification script for Pupyteer.

Verifies that the project follows security best practices:
- No hardcoded passwords or secrets in config files
- Secure default configuration values
- Proper file permissions on sensitive files
- SSL/TLS settings are secure

Usage:
    python scripts/verify_secure_defaults.py
    python scripts/verify_secure_defaults.py --strict
"""
from __future__ import annotations

import argparse
import os
import re
import stat
import sys
from pathlib import Path
from typing import List, Tuple

# Invoked as `python scripts/verify_secure_defaults.py`, only scripts/ lands on
# sys.path, so the pupyteer import in check_config_defaults() always failed and
# --strict reported that as a finding on an otherwise clean tree.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Patterns that indicate hardcoded secrets
SECRET_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # Password assignments (but not in test/doc contexts)
    (re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\'][^"\']{4,}["\']'), "Hardcoded password"),
    # API keys
    (re.compile(r'(?i)(api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*["\'][a-zA-Z0-9]{16,}["\']'), "Hardcoded API key"),
    # Private keys
    (re.compile(r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), "Private key embedded"),
    # JWT secrets
    (re.compile(r'(?i)(jwt[_-]?secret|secret[_-]?key)\s*[:=]\s*["\'][^"\']{8,}["\']'), "Hardcoded JWT secret"),
    # Auth tokens
    (re.compile(r'(?i)(auth[_-]?token|access[_-]?token)\s*[:=]\s*["\'][a-zA-Z0-9._-]{20,}["\']'), "Hardcoded auth token"),
    # Secret storage URLs with credentials
    (re.compile(r'(?i)(https?://[^:]+:[^@]+@)'), "URL with embedded credentials"),
]

# Files/directories to skip
SKIP_PATTERNS = [
    '.git', '.venv', '__pycache__', '.pytest_cache',
    '.tox', 'node_modules', '.mypy_cache',
    'test_windows_x64',  # Known test artifacts
    '.pyc',
]

# Directories to scan
SCAN_DIRS = ['pupyteer', 'scripts', 'config']


def check_file(filepath: Path) -> List[str]:
    """Check a single file for hardcoded secrets."""
    findings = []
    
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
    except (OSError, UnicodeDecodeError):
        return findings
    
    # Skip binary files
    if '\x00' in content:
        return findings
    
    lines = content.split('\n')
    for line_num, line in enumerate(lines, 1):
        # Skip comments (rough heuristic)
        stripped = line.lstrip()
        if stripped.startswith('#') or stripped.startswith('//'):
            continue
        if stripped.startswith('"""') or stripped.startswith("'''"):
            continue
        
        for pattern, desc in SECRET_PATTERNS:
            if pattern.search(line):
                # Skip test/example patterns
                if any(s in filepath.name.lower() for s in ['test_', '_test', 'example', 'sample']):
                    continue
                if 'fixture' in filepath.name.lower() or 'mock' in filepath.name.lower():
                    continue
                    
                findings.append(
                    f"  Line {line_num}: {desc}"
                )
    
    return findings


def scan_for_secrets(project_root: Path) -> List[Tuple[str, List[str]]]:
    """Scan project for hardcoded secrets."""
    all_findings = []
    
    for scan_dir in SCAN_DIRS:
        scan_path = project_root / scan_dir
        if not scan_path.exists():
            continue
        
        for filepath in scan_path.rglob('*'):
            if not filepath.is_file():
                continue
            
            # Skip patterns
            rel_path = str(filepath.relative_to(project_root))
            if any(skip in rel_path for skip in SKIP_PATTERNS):
                continue
            
            # Only scan Python, YAML, JSON, and config files
            if filepath.suffix not in ('.py', '.yaml', '.yml', '.json', '.toml', '.cfg', '.ini', '.env'):
                continue
            
            findings = check_file(filepath)
            if findings:
                all_findings.append((rel_path, findings))
    
    return all_findings


def check_config_defaults() -> List[str]:
    """Verify secure default configuration values."""
    findings = []
    
    try:
        from pupyteer.server.core.config import DEFAULT_CONFIG
        
        # Check that auth is required by default
        if not DEFAULT_CONFIG.get('security', {}).get('require_auth', False):
            findings.append("security.require_auth should default to True")
        
        # Check token TTL is reasonable (not too long)
        token_ttl = DEFAULT_CONFIG.get('security', {}).get('token_ttl', 0)
        if token_ttl > 86400:
            findings.append(f"security.token_ttl ({token_ttl}s) is too long (max 86400)")
        
        # Check max failed logins is set
        max_failed = DEFAULT_CONFIG.get('security', {}).get('max_failed_logins', 0)
        if max_failed <= 0 or max_failed > 10:
            findings.append(f"security.max_failed_logins ({max_failed}) should be between 1-10")
        
    except ImportError:
        findings.append("Could not import ConfigManager to verify defaults")
    
    return findings


def check_file_permissions(project_root: Path) -> List[str]:
    """Check file permissions on sensitive files."""
    findings = []
    
    # Files that should not be world-readable
    sensitive_patterns = [
        'config/*.yaml',
        'config/*.json',
        '*.key',
        '*.pem',
    ]
    
    for pattern in sensitive_patterns:
        for filepath in project_root.glob(pattern):
            if not filepath.is_file():
                continue
            
            try:
                mode = filepath.stat().st_mode
                if mode & stat.S_IROTH:
                    findings.append(f"{filepath.name} is world-readable")
                if mode & stat.S_IWOTH:
                    findings.append(f"{filepath.name} is world-writable")
            except OSError:
                pass
    
    return findings


def verify_ssl_defaults() -> List[str]:
    """Verify SSL/TLS secure defaults."""
    findings = []
    
    try:
        from pupyteer.agent.core.auth import AuthConfig
        # Default should not have insecure settings
        config = AuthConfig()
        if config.jwt_algorithm.lower() == 'none':
            findings.append("JWT algorithm should not default to 'none'")
    except ImportError:
        pass
    
    return findings


def main():
    # Status lines use check/cross glyphs; the default Windows console codepage
    # cannot encode them and raises, which would fail the check it just passed.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

    parser = argparse.ArgumentParser(description="Verify Pupyteer secure defaults")
    parser.add_argument(
        "--strict", "-s",
        action="store_true",
        help="Exit non-zero on findings",
    )
    parser.add_argument(
        "--project-root",
        default=".",
        help="Project root directory (default: current dir)",
    )
    args = parser.parse_args()
    
    project_root = Path(args.project_root).resolve()
    
    print("=" * 70)
    print("Pupyteer Secure Defaults Verification")
    print("=" * 70)
    
    all_findings = {}
    
    # Check 1: Hardcoded secrets
    print("\n[1/4] Scanning for hardcoded secrets...")
    secret_findings = scan_for_secrets(project_root)
    if secret_findings:
        all_findings["hardcoded_secrets"] = []
        for filepath, findings in secret_findings:
            print(f"  {filepath}:")
            for f in findings:
                print(f"    {f}")
            all_findings["hardcoded_secrets"].extend(
                [f"{filepath}: {f}" for f in findings]
            )
    else:
        print("  No hardcoded secrets found. ✓")
    
    # Check 2: Config defaults
    print("\n[2/4] Verifying config defaults...")
    config_findings = check_config_defaults()
    if config_findings:
        all_findings["config_defaults"] = config_findings
        for f in config_findings:
            print(f"  WARNING: {f}")
    else:
        print("  Config defaults are secure. ✓")
    
    # Check 3: File permissions
    print("\n[3/4] Checking file permissions...")
    perm_findings = check_file_permissions(project_root)
    if perm_findings:
        all_findings["file_permissions"] = perm_findings
        for f in perm_findings:
            print(f"  WARNING: {f}")
    else:
        print("  File permissions are appropriate. ✓")
    
    # Check 4: SSL/TLS defaults
    print("\n[4/4] Verifying SSL/TLS defaults...")
    ssl_findings = verify_ssl_defaults()
    if ssl_findings:
        all_findings["ssl_defaults"] = ssl_findings
        for f in ssl_findings:
            print(f"  WARNING: {f}")
    else:
        print("  SSL/TLS defaults are secure. ✓")
    
    # Summary
    print(f"\n{'=' * 70}")
    total = sum(len(v) for v in all_findings.values())
    if total == 0:
        print("All secure default checks passed. ✓")
    else:
        print(f"Total findings: {total}")
    
    if args.strict and total > 0:
        print("\nStrict mode: exiting with non-zero code.")
        sys.exit(1)
    
    sys.exit(0)


if __name__ == "__main__":
    main()
