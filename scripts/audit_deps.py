#!/usr/bin/env python3
"""Dependency audit script for Pupyteer.

Checks installed packages against a known-vulnerabilities list
and flags outdated or insecure dependencies.

Usage:
    python scripts/audit_deps.py
    python scripts/audit_deps.py --requirements requirements.txt
    python scripts/audit_deps.py --strict  (exit non-zero on findings)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Known vulnerable package versions (CVE database subset)
# Format: package_name -> [(affected_version_range, CVE, severity)]
KNOWN_VULNS: Dict[str, List[Tuple[str, str, str]]] = {
    "paramiko": [
        ("<2.4.0", "CVE-2018-1000807", "HIGH"),
        ("<2.4.0", "CVE-2018-1000808", "HIGH"),
    ],
    "pyyaml": [
        ("<5.1", "CVE-2017-18342", "CRITICAL"),
        ("<5.4", "CVE-2020-14343", "HIGH"),
    ],
    "requests": [
        ("<2.20.0", "CVE-2018-18074", "HIGH"),
    ],
    "pyopenssl": [
        ("<19.0.0", "CVE-2018-1000807", "MEDIUM"),
    ],
    "tornado": [
        ("<6.0.3", "CVE-2019-10902", "HIGH"),
    ],
    "msgpack": [
        ("<1.0.0", "CVE-2020-5243", "MEDIUM"),
    ],
    "m2crypto": [
        ("<0.36.0", "CVE-2020-10932", "MEDIUM"),
    ],
    "ecdsa": [
        ("<0.13.3", "CVE-2019-14857", "MEDIUM"),
    ],
    "rsa": [
        ("<4.1", "CVE-2020-13757", "MEDIUM"),
    ],
    "urllib3": [
        ("<1.24.2", "CVE-2019-11324", "HIGH"),
        ("<1.25.9", "CVE-2020-26137", "MEDIUM"),
    ],
    "jinja2": [
        ("<2.10.1", "CVE-2019-10906", "HIGH"),
        ("<2.11.3", "CVE-2020-28493", "MEDIUM"),
    ],
    "pillow": [
        ("<6.2.2", "CVE-2019-16865", "MEDIUM"),
        ("<8.1.0", "CVE-2020-35653", "HIGH"),
    ],
    "pycryptodome": [
        ("<3.9.7", "CVE-2020-15524", "MEDIUM"),
    ],
    "lxml": [
        ("<4.6.3", "CVE-2021-28957", "MEDIUM"),
    ],
    "cryptography": [
        ("<3.2", "CVE-2020-25659", "MEDIUM"),
    ],
    "aiohttp": [
        ("<3.7.4", "CVE-2021-21330", "HIGH"),
    ],
}

# Packages that should have pinned versions (no loose version specifiers)
SENSITIVE_PACKAGES = {
    "pycryptodome", "pyopenssl", "rsa", "ecdsa", "paramiko",
    "tornado", "requests", "pyyaml", "msgpack", "m2crypto",
}


def parse_version(version_str: str) -> Optional[Tuple[int, ...]]:
    """Parse a version string into a tuple of ints for comparison."""
    try:
        cleaned = re.sub(r'[^0-9.]', '', version_str)
        return tuple(int(x) for x in cleaned.split('.'))
    except (ValueError, AttributeError):
        return None


def version_matches_spec(installed: str, spec: str) -> bool:
    """Check if installed version matches a version spec like '<2.4.0'."""
    inst_ver = parse_version(installed)
    if inst_ver is None:
        return False

    spec = spec.strip()
    if spec.startswith('<='):
        target = parse_version(spec[2:])
        if target is None:
            return False
        return inst_ver <= target
    elif spec.startswith('<'):
        target = parse_version(spec[1:])
        if target is None:
            return False
        return inst_ver < target
    elif spec.startswith('>='):
        target = parse_version(spec[2:])
        if target is None:
            return False
        return inst_ver >= target
    elif spec.startswith('>'):
        target = parse_version(spec[1:])
        if target is None:
            return False
        return inst_ver > target
    elif spec.startswith('=='):
        target = parse_version(spec[2:])
        if target is None:
            return False
        return inst_ver == target
    return False


def get_installed_packages() -> Dict[str, str]:
    """Get currently installed packages via pip."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True, text=True, check=True,
        )
        packages = json.loads(result.stdout)
        return {pkg["name"].lower(): pkg["version"] for pkg in packages}
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return {}


def parse_requirements(path: str) -> Dict[str, str]:
    """Parse a requirements.txt file into {package: version_spec}."""
    reqs: Dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or line.startswith('-'):
                    continue
                # Handle inline comments
                if '#' in line:
                    line = line[:line.index('#')].strip()
                # Handle URL-based requirements
                if '@' in line:
                    pkg = line.split('@')[0].strip().lower()
                    reqs[pkg] = "*"
                    continue
                # Handle version specifiers
                for op in ['>=', '<=', '==', '!=', '~=', '<', '>']:
                    if op in line:
                        parts = line.split(op, 1)
                        pkg = parts[0].strip().lower()
                        ver = parts[1].strip().split(',')[0]
                        reqs[pkg] = f"{op}{ver}"
                        break
                else:
                    reqs[line.lower()] = "*"
    except FileNotFoundError:
        pass
    return reqs


def audit_dependencies(
    requirements_path: Optional[str] = None,
    strict: bool = False,
) -> int:
    """Run dependency audit. Returns number of findings."""
    installed = get_installed_packages()
    findings: List[str] = []

    # Check known vulnerabilities
    for pkg, vulns in KNOWN_VULNS.items():
        if pkg not in installed:
            continue
        installed_ver = installed[pkg]
        for spec, cve, severity in vulns:
            if version_matches_spec(installed_ver, spec):
                findings.append(
                    f"[{severity}] {pkg}=={installed_ver} is vulnerable to {cve} "
                    f"(affected: {spec})"
                )

    # Check for unpinned sensitive packages
    if requirements_path:
        reqs = parse_requirements(requirements_path)
        for pkg in SENSITIVE_PACKAGES:
            if pkg in reqs:
                spec = reqs[pkg]
                if spec == "*":
                    findings.append(
                        f"[MEDIUM] {pkg} is unpinned in requirements.txt "
                        f"(should pin to exact version)"
                    )

    # Print report
    print("=" * 70)
    print("Pupyteer Dependency Audit Report")
    print("=" * 70)

    if not findings:
        print("\nNo known vulnerabilities found. ✓")
        print(f"Packages checked: {len(installed)}")
        return 0

    # Group by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    findings.sort(key=lambda f: severity_order.get(f.split(']')[0][1:], 99))

    print(f"\n{len(findings)} finding(s):\n")
    for f in findings:
        severity = f.split(']')[0][1:]
        color = {
            "CRITICAL": "\033[91m",
            "HIGH": "\033[91m",
            "MEDIUM": "\033[93m",
            "LOW": "\033[90m",
        }.get(severity, "")
        reset = "\033[0m"
        print(f"  {color}[{severity}]{reset} {f.split(']', 1)[1].strip()}")

    print(f"\n{'=' * 70}")
    print(f"Total findings: {len(findings)}")
    print(f"Packages checked: {len(installed)}")

    if strict:
        print("\nStrict mode: exiting with non-zero code due to findings.")
        return len(findings)
    return 0


def main():
    parser = argparse.ArgumentParser(description="Pupyteer Dependency Auditor")
    parser.add_argument(
        "--requirements", "-r",
        default="requirements.txt",
        help="Path to requirements.txt (default: requirements.txt)",
    )
    parser.add_argument(
        "--strict", "-s",
        action="store_true",
        help="Exit non-zero on findings",
    )
    args = parser.parse_args()

    exit_code = audit_dependencies(
        requirements_path=args.requirements,
        strict=args.strict,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
