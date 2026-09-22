#!/usr/bin/env python3
"""Dependency audit script for Pupyteer.

Checks installed packages against a known-vulnerabilities list
and flags outdated or insecure dependencies.

Two independent coverage tiers, deliberately kept honest about each other:

  * BUILT-IN LOCAL LIST (always on). A hand-maintained, bounded, non-exhaustive
    snapshot of known vulnerabilities (``KNOWN_VULNS``) that stops around 2021.
    A clean local result means only "no match in this local list"; it is NOT a
    claim that no vulnerabilities exist. The report says this explicitly.

  * LIVE ADVISORY CHECK (opt-in via ``--live``). Shells out to ``pip-audit``
    (which queries the OSV / PyPA advisory feed). If pip-audit or the network
    is unavailable the live check is reported as NOT PERFORMED -- never as a
    silent clean pass. Offline default behaviour is unchanged.

Usage:
    python scripts/audit_deps.py
    python scripts/audit_deps.py --requirements requirements.txt
    python scripts/audit_deps.py --strict        (exit non-zero on findings)
    python scripts/audit_deps.py --live          (also run pip-audit, if present)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# The local list below is a hand-curated, BOUNDED snapshot. It is not refreshed
# automatically and is not a substitute for an advisory feed. Surfacing the date
# keeps the report honest about its own coverage.
LOCAL_LIST_AS_OF = "2021"

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

# Pin hygiene is judged against the packages *actually declared in
# requirements.txt* rather than a hand-maintained subset, so newly added runtime
# deps (for example ``cryptography`` and ``httpx``) are covered automatically and
# lower-bound-only pins are reported consistently for every dependency.
#
# classify_pin(spec) -> "unpinned" | "exact" | "range"
#   "unpinned": no version specifier at all (a hard finding -- non-reproducible).
#   "exact":    pinned to one version with ``==`` (acceptable).
#   "range":    only a lower/upper/range bound such as ``>=41.0`` (advisory -- it
#               does not freeze the resolved version for supply-chain integrity).
def classify_pin(spec: str) -> str:
    """Classify a requirements.txt version specifier for pin hygiene."""
    spec = (spec or "").strip()
    if spec == "*":
        return "unpinned"
    if spec.startswith("=="):
        return "exact"
    return "range"


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


def run_live_audit(
    requirements_path: Optional[str],
) -> Tuple[bool, str, List[str]]:
    """Best-effort LIVE advisory check via ``pip-audit`` (OSV / PyPA feed).

    Returns ``(available, detail, vuln_findings)``:

      * ``available`` is False when the check could NOT be performed (pip-audit
        missing, launch failure, timeout, or no parseable advisory output). In
        that case the caller MUST NOT report a clean pass.
      * ``available`` is True only when an advisory source was actually
        consulted; ``vuln_findings`` then reflects its real result (possibly
        empty, which is a genuine "no advisory hits" -- not an absence of data).

    Never fabricates a result and never treats "unavailable" as "clean".
    """
    if importlib.util.find_spec("pip_audit") is None:
        return (
            False,
            "pip-audit is not installed in this interpreter "
            "(install it to enable the live advisory check)",
            [],
        )

    cmd = [sys.executable, "-m", "pip_audit", "--format", "json"]
    # Scope to the declared requirements when we have them; otherwise pip-audit
    # audits the current environment.
    if requirements_path and Path(requirements_path).is_file():
        cmd += ["-r", requirements_path]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=180)
    except FileNotFoundError:
        return (False, "pip-audit could not be launched", [])
    except subprocess.TimeoutExpired:
        return (False, "pip-audit timed out (advisory feed or network unreachable)", [])
    except OSError as exc:
        return (False, f"pip-audit could not run: {exc}", [])

    # Only trust the feed when pip-audit emitted parseable JSON. An error path
    # (missing network, resolution failure) prints to stderr and yields no JSON,
    # which we surface as "not performed", never as a clean result.
    try:
        data: Dict[str, Any] = json.loads(proc.stdout)
    except (json.JSONDecodeError, TypeError):
        tail = (proc.stderr or proc.stdout or "").strip().splitlines()
        reason = tail[-1] if tail else f"no output (exit code {proc.returncode})"
        return (
            False,
            f"pip-audit produced no parseable advisory result: {reason}",
            [],
        )

    vulns: List[str] = []
    for dep in data.get("dependencies", []) or []:
        name = str(dep.get("name", "?")).lower()
        version = str(dep.get("version", "?"))
        for v in dep.get("vulns", []) or []:
            vid = v.get("id") or (v.get("aliases") or ["?"])[0]
            fix = v.get("fix_versions") or []
            fix_txt = ("fixed in " + ", ".join(str(f) for f in fix)) if fix \
                else "no fixed version listed"
            vulns.append(f"[HIGH] {name}=={version} advisory {vid} ({fix_txt})")

    return (True, f"pip-audit consulted successfully (exit code {proc.returncode})", vulns)


def audit_dependencies(
    requirements_path: Optional[str] = None,
    strict: bool = False,
    live: bool = False,
) -> int:
    """Run dependency audit. Returns number of gate findings (0 unless strict)."""
    installed = get_installed_packages()
    findings: List[str] = []          # gate findings -> drive the strict exit code
    advisories: List[str] = []        # pin-hygiene notes -> reported, never gate

    # 1. Known vulnerabilities (LOCAL, bounded, non-exhaustive list).
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

    # 2. Version-pin hygiene, judged against every package in requirements.txt.
    if requirements_path:
        reqs = parse_requirements(requirements_path)
        for pkg in sorted(reqs):
            spec = reqs[pkg]
            kind = classify_pin(spec)
            if kind == "unpinned":
                # No version at all is a reproducibility/supply-chain finding.
                findings.append(
                    f"[MEDIUM] {pkg} is listed in requirements.txt with no version "
                    f"specifier (not pinned at all)"
                )
            elif kind == "range":
                # Lower/upper/range-only: reported consistently as an advisory so a
                # reader sees that these are not exact pins, without failing the
                # security gate that --strict is meant to enforce.
                advisories.append(
                    f"{pkg} is only bound by {spec} in requirements.txt "
                    f"(not pinned to an exact version)"
                )

    # 3. Optional LIVE advisory check.
    live_available: Optional[bool] = None
    live_detail = ""
    if live:
        live_available, live_detail, live_vulns = run_live_audit(requirements_path)
        if live_available:
            findings.extend(live_vulns)
        else:
            # A requested live check that could not run is itself a non-clean signal.
            findings.append(
                f"[MEDIUM] LIVE advisory check could NOT be performed "
                f"({live_detail}); this is NOT a clean result"
            )

    # ── Report ─────────────────────────────────────────────────────────
    print("=" * 70)
    print("Pupyteer Dependency Audit Report")
    print("=" * 70)

    print("\nCOVERAGE OF THE BUILT-IN CHECK")
    print("  The local list below is a HAND-MAINTAINED, BOUNDED and NON-EXHAUSTIVE")
    print(f"  snapshot of known vulnerabilities (hand-maintained, curated ~{LOCAL_LIST_AS_OF}).")
    print("  It is NOT a current advisory feed. A clean local result means only")
    print("  \"no match in this local list\" -- it does NOT mean no vulnerabilities")
    print("  exist. Re-run with --live to consult a real advisory source.")
    print(f"  Local list checked against {len(installed)} installed package(s).")

    if live:
        print("\nLIVE ADVISORY CHECK (--live)")
        if live_available:
            print("  Source consulted: pip-audit (OSV / PyPA advisory feed).")
        else:
            print("  STATUS: COULD NOT BE PERFORMED -- this is NOT a clean result.")
        print(f"  Detail: {live_detail}")

    if advisories:
        print(f"\n{len(advisories)} pin-hygiene note(s) "
              f"(not security findings; do not affect the gate):")
        for note in advisories:
            print(f"  [NOTE] {note}")

    if not findings:
        print("\nRESULT: No matches in the local known-vulnerability list.")
        print("  This is a bounded local check, NOT a full advisory scan; it does")
        if live and live_available:
            print("  not prove the absence of vulnerabilities. (The --live advisory")
            print("  check was performed for the packages listed above.)")
        else:
            print("  not prove the absence of vulnerabilities. For a live advisory")
            print("  scan, run with --live.")
        return _finish(strict, len(findings))

    # Gate findings exist: sort by severity and print them.
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

    return _finish(strict, len(findings))


def _finish(strict: bool, finding_count: int) -> int:
    """Apply the --strict contract: non-zero on findings, otherwise zero."""
    if strict and finding_count:
        print("\nStrict mode: exiting with non-zero code due to findings.")
        return finding_count
    return 0


def main():
    # Status lines use check/cross glyphs; the default Windows console codepage
    # cannot encode them and raises, which would fail the check it just passed.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass

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
    parser.add_argument(
        "--live", "-l",
        action="store_true",
        help="Also run a LIVE advisory check via pip-audit (OSV/PyPA). Degrades "
             "to an honest 'not performed' warning if pip-audit/network is absent; "
             "never a silent clean pass.",
    )
    args = parser.parse_args()

    exit_code = audit_dependencies(
        requirements_path=args.requirements,
        strict=args.strict,
        live=args.live,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
