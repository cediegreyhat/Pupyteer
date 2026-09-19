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


@pytest.fixture(scope="session", autouse=True)
def enrollment_secret_home(tmp_path_factory):
    """Keep default-config listeners from writing a key into the checkout.

    A listener started with the shipped config generates its enrollment secret on
    first use. This repoints that default at a temp directory. It rewrites the
    default rather than setting a `PUPYTEER_*` variable, because environment
    overrides are applied last and would silently beat the explicit
    `server.agent_auth_file` that the enrollment tests pin.
    """
    from pupyteer.server.core.config import DEFAULT_CONFIG
    key_dir = tmp_path_factory.mktemp("keys")
    original = DEFAULT_CONFIG["server"]["agent_auth_file"]
    DEFAULT_CONFIG["server"]["agent_auth_file"] = str(key_dir / "enrollment.key")
    yield
    DEFAULT_CONFIG["server"]["agent_auth_file"] = original


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
