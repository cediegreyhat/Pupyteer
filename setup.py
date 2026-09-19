#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

from setuptools import setup, find_packages
import os
import sys

requirements = [x.strip() for x in open("requirements.txt", "r").readlines() if x.strip() and not x.strip().startswith("#")]

setup(
    name='pupyteer',
    version='1.0.0',
    packages=find_packages(where='.', include=['pupyteer*']),
    package_data={'pupyteer': ['conf/**', 'external/**', 'config/**']},
    license_files=('LICENSE',),
    author='Pupyteer Team',
    author_email='',
    description='Pupyteer — Evasion-first C2 Framework for Red Team Operations',
    url='https://github.com/cediephyte/pupyteer',
    keywords=["python", "pentest", "cybersecurity", "redteam", "C2", "command and control", "post-exploitation", "evasion"],
    entry_points={
        'console_scripts': [
            'pupyteer = pupyteer.main:main'
        ]
    },
    install_requires=requirements,
    python_requires='>=3.9',
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Security Researchers",
        "License :: OSI Approved :: BSD License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
    ],
)
