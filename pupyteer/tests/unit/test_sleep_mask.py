"""Sleep masking reaches generated payloads.

`STANDALONE_MASK_SOURCE` is rendered into the stub template, so it has to work
in a file that imports nothing but the stdlib. The old
`patch_stub_template_for_sleep_mask` helper injected
`from pupyteer.agent.core.sleep_mask import sleep_masked` into the template,
which would have made every generated agent depend on the package it is supposed
to run without.
"""
from __future__ import annotations

import ast
import os
import sys
import time

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from pupyteer.agent.core.sleep_mask import STANDALONE_MASK_SOURCE, SleepMask
from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig


def _config(**kw) -> StubConfig:
    base = dict(
        name="mask-probe",
        platform="linux",
        transport="tcp",
        host="127.0.0.1",
        port=8443,
        sleep=5,
        jitter=10,
    )
    base.update(kw)
    return StubConfig(**base)


def _mask_namespace(source: str) -> dict:
    """Exec the rendered mask block *and* the template's ``_sleep_masked``.

    The template defines ``_sleep_masked`` itself (it has to exist whether or
    not masking was asked for); the block supplies the state it uses.
    """
    start = source.index("# --- sleep mask")
    end = source.index("# --- end sleep mask ---") + len("# --- end sleep mask ---")
    ns = {"_o": os, "_t": time}
    exec(source[start:end], ns)  # noqa: S102 - the block is our own constant
    if "def _sleep_masked" in source:
        fn_start = source.index("def _sleep_masked")
        fn_end = source.index("\ndef ", fn_start + 1)
        exec(source[fn_start:fn_end], ns)  # noqa: S102
    return ns


@pytest.fixture
def gen():
    return AgentStubGenerator()


def test_the_standalone_block_is_stdlib_only():
    """It is rendered into a payload that must run with nothing but an interpreter."""
    assert "from pupyteer" not in STANDALONE_MASK_SOURCE
    assert "import pupyteer" not in STANDALONE_MASK_SOURCE
    assert "cryptography" not in STANDALONE_MASK_SOURCE
    ast.parse(STANDALONE_MASK_SOURCE)


def test_the_standalone_block_actually_round_trips():
    ns = _mask_namespace(STANDALONE_MASK_SOURCE)
    ns["_remember_output"]("the target said this")
    original = bytes(ns["_MASK_BUF"])
    assert original == b"the target said this"

    ns["_mask_bytes"](ns["_MASK_BUF"], ns["_MASK_KEY"])
    assert bytes(ns["_MASK_BUF"]) != original, "the buffer was not masked"

    ns["_mask_bytes"](ns["_MASK_BUF"], ns["_MASK_KEY"])
    assert bytes(ns["_MASK_BUF"]) == original, "the buffer did not come back"


def test_a_masked_sleep_restores_the_buffer(gen):
    """An interrupted sleep must not leave the agent's own buffer scrambled."""
    ns = _mask_namespace(gen.generate(_config(sleep_mask=True)))
    ns["_remember_output"]("output that must survive the sleep")
    original = bytes(ns["_MASK_BUF"])

    sleeps = []
    ns["_t"].sleep = lambda d: sleeps.append(d)

    ns["_sleep_masked"](0.01)
    assert sleeps == [0.01]
    assert bytes(ns["_MASK_BUF"]) == original

    # A sleep that raises still restores, because the unmask is in a finally.
    def _boom(_d):
        raise KeyboardInterrupt

    ns["_t"].sleep = _boom
    with pytest.raises(KeyboardInterrupt):
        ns["_sleep_masked"](0.01)
    assert bytes(ns["_MASK_BUF"]) == original


def test_the_output_buffer_is_bounded(gen):
    ns = _mask_namespace(gen.generate(_config(sleep_mask=True)))
    ns["_remember_output"]("x" * 200_000)
    assert len(ns["_MASK_BUF"]) == 65536


def test_masking_is_opt_in(gen):
    """Off by default, like the other footprint-changing options."""
    plain = gen.generate(_config())
    ast.parse(plain)
    assert "_MASK_BUF" not in plain
    assert "_remember_output" not in plain
    # The sleep helper still exists; it is just a plain sleep.
    assert "_sleep_masked" in plain

    masked = gen.generate(_config(sleep_mask=True))
    ast.parse(masked)
    assert "_MASK_BUF" in masked
    assert "_remember_output" in masked


def test_the_generated_agent_remembers_its_output(gen):
    """Every command passes through _run_command; that is where the buffer fills."""
    masked = gen.generate(_config(sleep_mask=True))
    assert "_remember_output(rendered)" in masked
    # and it is not wired into a build that did not ask for it
    assert "_remember_output" not in gen.generate(_config())


def test_the_sleep_helper_masks_through_the_jittered_path(gen):
    """_jittered_sleep must go through _sleep_masked, or the mask never applies."""
    masked = gen.generate(_config(sleep_mask=True))
    start = masked.index("def _jittered_sleep")
    end = masked.index("\ndef ", start + 1)
    fn = masked[start:end]
    assert "_sleep_masked(" in fn
    assert "_t.sleep(" not in fn


def test_the_module_still_marks_its_own_buffers():
    """The library path is unchanged: this is the Python-side counterpart."""
    buf = bytearray(b"sensitive")
    masker = SleepMask(key=b"k" * 32, cipher="xor")
    masker.encrypt(buf)
    assert bytes(buf) != b"sensitive"
    masker.decrypt(buf)
    assert bytes(buf) == b"sensitive"
