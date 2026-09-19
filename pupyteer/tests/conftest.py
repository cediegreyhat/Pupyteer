"""Pupyteer pytest configuration and shared fixtures."""
import os
import sys
from pathlib import Path

# Ensure pupyteimport is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest


@pytest.fixture(scope="session")
def project_root():
    return PROJECT_ROOT


@pytest.fixture
def pupyteer_package(project_root):
    """Import the main package to verify it loads cleanly."""
    import pupyteer
    return pupyteer


@pytest.fixture
def config_factory(tmp_path):
    """Factory for creating isolated ConfigManager instances."""
    def _create(content=None, env_overrides=None):
        from pupyteer.server.core.config import ConfigManager
        if content:
            cfg_file = tmp_path / "test_config.yaml"
            cfg_file.write_text(content)
            return ConfigManager(str(cfg_file))
        return ConfigManager()
    return _create
