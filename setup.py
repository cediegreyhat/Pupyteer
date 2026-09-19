#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from setuptools import setup, find_packages

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
    version='1.0.0',
    packages=find_packages(where='.', include=['pupyteer*']),
    package_data={'pupyteer': ['config/**']},
    license_files=('LICENSE',),
    author='Pupyteer Team',
    author_email='',
    description='Pupyteer — Evasion-first C2 Framework for Red Team Operations',
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
