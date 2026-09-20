"""Pupyteer pytest configuration and shared fixtures."""
import os
import sys
from pathlib import Path

# Ensure pupyteimport is importable
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import pytest


#: The repository, which is not the same as PROJECT_ROOT above.
CHECKOUT_ROOT = Path(__file__).resolve().parents[2]

#: The files in the checkout that hold things an operator needs and a test run has
#: no business touching: the audit trail, the credentials, the keys. They are
#: git-ignored, which is why nothing but this check notices when a test writes one.
PROTECTED_CHECKOUT_FILES = ("logs/audit.json", "data/keys/operators.json")


def _generated_file_sizes() -> dict:
    """The size of each protected file, or None for one that does not exist.

    None is compared against as well as a number: a run that creates
    `logs/audit.json` where the operator had none has written their first audit
    entry, which is the same mistake in a harder-to-notice form.
    """
    sizes = {}
    for rel in PROTECTED_CHECKOUT_FILES:
        path = CHECKOUT_ROOT / rel
        sizes[rel] = path.stat().st_size if path.exists() else None
    return sizes


@pytest.fixture(scope="session")
def project_root():
    return PROJECT_ROOT


#: Defaults that name a file a running server writes. A test that builds an engine
#: without a config gets all of these, and the two that matter most are not the
#: bulky ones: the audit trail lands in the checkout's `logs/`, and the operator
#: credential file in `data/keys/`, which means a test can log in with a credential
#: a previous test left for a human to find.
GENERATED_DEFAULTS = {
    ("server", "agent_auth_file"): "enrollment.key",
    ("server", "tls_cert"): "listener.crt",
    ("server", "tls_key"): "listener.key",
    ("security", "operators_file"): "operators.json",
    ("audit", "log_file"): "audit.json",
    ("paths", "payload_artifacts"): "artifacts",
    ("evasion", "history_path"): "evasion_history.json",
}


def _stock_generated_defaults():
    """These defaults as the code ships them, before this session moves them.

    Taken at import because `generated_files_home` rewrites the same entries for
    the whole run: a test that checks the shipped YAML against the code's default
    has to compare what a real install gets, not what the lab run got.
    """
    from pupyteer.server.core.config import DEFAULT_CONFIG
    return {f"{section}.{key}": DEFAULT_CONFIG[section][key]
            for section, key in GENERATED_DEFAULTS}


STOCK_GENERATED_DEFAULTS = _stock_generated_defaults()


@pytest.fixture(scope="session", autouse=True)
def generated_files_home(tmp_path_factory):
    """Keep a default-config server's files out of the checkout.

    It rewrites the defaults rather than setting `PUPYTEER_*` variables, because
    environment overrides are applied last and would silently beat the explicit
    paths the enrollment and TLS tests pin for themselves.
    """
    from pupyteer.server.core.config import DEFAULT_CONFIG

    home = tmp_path_factory.mktemp("generated")
    before = _generated_file_sizes()

    originals = {}
    for (section, key), name in GENERATED_DEFAULTS.items():
        target = home / name
        if key == "payload_artifacts":
            target.mkdir(parents=True, exist_ok=True)
        originals[(section, key)] = DEFAULT_CONFIG[section][key]
        DEFAULT_CONFIG[section][key] = str(target)
    try:
        yield
    finally:
        for (section, key), value in originals.items():
            DEFAULT_CONFIG[section][key] = value
        violations = {rel: size
                      for rel, size in _generated_file_sizes().items()
                      if size != before[rel]}
        assert not violations, (
            f"this run wrote {violations} in the checkout; a server built without a"
            " config now files those under a temp directory, so the test that did it"
            " named the path itself"
        )


@pytest.fixture(scope="session")
def stock_generated_files():
    """Where a real install puts its generated files, unaffected by this run."""
    return dict(STOCK_GENERATED_DEFAULTS)


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
