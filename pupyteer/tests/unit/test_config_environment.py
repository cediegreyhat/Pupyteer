"""Config layering: environment overlay reachability.

The overlay loader (_load_environment_config) reads pupyteer.<env>.yaml from
cwd / ~/.config/pupyteer / /etc/pupyteer, but before the -e/--environment flag
existed the environment could only come from PUPYTEER_ENV — and that variable
was spelled PUPTYEER_ENV (transposed T/Y), so the overlay was unreachable for
anyone who never set the var by hand. These tests pin the precedence chain so
the typo cannot silently return:

    CLI -e  >  PUPYTEER_ENV  >  "dev"
"""
from pathlib import Path

import pytest

from pupyteer.server.core.config import ConfigManager

ENV_VAR = "PUPYTEER_ENV"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    """No ambient PUPYTEER_ENV, and no overlay files leaking in from cwd."""
    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.chdir(tmp_path)
    yield


def _write_overlay(tmp_path: Path, env: str, payload: str) -> None:
    (tmp_path / f"pupyteer.{env}.yaml").write_text(payload)


def test_defaults_to_dev(monkeypatch):
    assert ConfigManager().environment == "dev"


def test_env_var_selects_environment(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "staging")
    assert ConfigManager().environment == "staging"


def test_explicit_environment_beats_env_var(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "staging")
    assert ConfigManager(environment="prod").environment == "prod"


def test_env_var_name_is_not_transposed(monkeypatch):
    """PUPYTEER_ENV, not PUPTYEER_ENV — the old spelling made the overlay dead."""
    monkeypatch.setenv("PUPTYEER_ENV", "staging")
    monkeypatch.delenv(ENV_VAR, raising=False)
    assert ConfigManager().environment == "dev"


def test_environment_overlay_is_applied(tmp_path):
    _write_overlay(tmp_path, "ctf", "logging:\n  level: WARNING\nserver:\n  bind: 127.0.0.1\n")
    cfg = ConfigManager(environment="ctf")
    assert cfg.environment == "ctf"
    assert cfg.get("logging.level") == "WARNING"
    assert cfg.get("server.bind") == "127.0.0.1"


def test_absent_environment_overlay_is_inert(tmp_path):
    cfg = ConfigManager(environment="ctf")
    # Overlay lookup finds nothing; defaults survive untouched.
    assert cfg.environment == "ctf"
    assert cfg.get("logging.level") is not None
