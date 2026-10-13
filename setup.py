#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import ast
import re
from pathlib import Path

from setuptools import find_packages, setup

HERE = Path(__file__).parent


def _read_version() -> str:
    """Single-source the version from pupyteer/__init__.py without importing it.

    The package __init__ pulls in heavy runtime deps (engine, managers), so we
    parse the file with ast instead of importing — safe at build time.
    """
    init_path = HERE / "pupyteer" / "__init__.py"
    text = ""
    try:
        text = init_path.read_text(encoding="utf-8")
        tree = ast.parse(text)
        for node in tree.body:
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id == "__version__":
                        return ast.literal_eval(node.value)
    except (OSError, SyntaxError, ValueError):
        pass
    # Fallback: regex, then a hard default so a build never hard-fails on this.
    m = re.search(r"__version__\s*=\s*['\"]([^'\"]+)['\"]", text)
    return m.group(1) if m else "1.0.0"


def _read_long_description() -> str:
    readme = HERE / "README.md"
    if readme.exists():
        return readme.read_text(encoding="utf-8")
    return ""


# Keep in sync with requirements.txt (runtime deps only — no dev/test extras)
install_requires = [
    "cryptography>=41.0",
    "httpx>=0.25.0",
    "jinja2>=3.1.0",
    "websockets>=12.0",
    "pyyaml>=6.0",
]

setup(
    name='pupyteer',
    version=_read_version(),
    packages=find_packages(where='.', include=['pupyteer*']),
    # Ship every non-.py artifact needed at runtime: the MinGW C agent template,
    # YAML defaults, and the default C2 profiles. include_package_data also
    # honors MANIFEST.in for sdist.
    include_package_data=True,
    package_data={
        'pupyteer': [
            # C agent template + any C/H sources
            'agent/**/*.c',
            'agent/**/*.h',
            # Config defaults and profiles (YAML + .profile)
            'config/**/*.yaml',
            'config/**/*.yml',
            'server/profiles/default_profiles/*.profile',
            # Bundled native libs if ever added
            'external/**',
        ],
    },
    # Explicitly exclude the graphify build cache from the distribution.
    exclude_package_data={
        'pupyteer': ['graphify-out/*', 'graphify-out/**/*'],
    },
    license_files=('LICENSE',),
    author='Pupyteer Team',
    author_email='',
    description='Pupyteer — Evasion-first C2 Framework for Red Team Operations',
    long_description=_read_long_description(),
    long_description_content_type='text/markdown',
    url='https://github.com/cediegreyhat/Pupyteer',
    keywords=["python", "pentest", "cybersecurity", "redteam", "C2", "command and control", "post-exploitation", "evasion"],
    entry_points={
        'console_scripts': [
            'pupyteer = pupyteer.main:main'
        ]
    },
    install_requires=install_requires,
    python_requires='>=3.10',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Security Researchers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Topic :: Security",
    ],
)
