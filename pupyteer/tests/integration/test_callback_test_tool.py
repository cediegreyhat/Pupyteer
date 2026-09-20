"""The operator's self-test, tested.

`callback_test` exists because a listener can be up and still not field a
payload, so nothing less than a real generated agent running as a real
subprocess answers the question. That made it the one place where drift is
silent: the tool spoke a dialect of its own — no enrollment secret, no TLS, no
beacon token — and could keep reporting PASS against a listener that refused
every payload built by the server beside it. These tests are what stops that
happening again, and the second one is the reason the tool is trusted: break
the listener's enrolment check and the self-test has to say so.
"""
from __future__ import annotations

import os
import sys

sys.path.insert(
    0,
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__))))),
)

from pupyteer.tools.callback_test import CallbackTestHarness


def test_the_self_test_passes_against_a_default_listener():
    """TLS on, registrations authenticated: the way a team server ships."""
    harness = CallbackTestHarness(timeout=45)
    assert harness.run() is True, harness.errors


def test_the_self_test_notices_a_listener_that_will_not_enrol_its_agent(
        monkeypatch):
    """A PASS is only worth anything if a broken loop turns it into a FAIL.

    The listener is told to reject every registration, which is what a payload
    built by another team server meets in the field. The self-test has to catch
    it *and* name the fix, because "no session appeared" is not actionable.
    """
    import pupyteer.server.transports.listener as listener_mod

    monkeypatch.setattr(listener_mod, "secret_accepts",
                        lambda expected, presented: False)

    harness = CallbackTestHarness(timeout=20)
    assert harness.run() is False, "the self-test passed a listener that enrols nobody"
    assert any("enrollment secret" in error for error in harness.errors), harness.errors


def test_the_self_test_still_round_trips_when_tls_is_off():
    """The opt-out has to be a supported path, not one that merely looks allowed.

    A payload built for a plaintext listener must pin nothing; if the harness
    resolved TLS from anywhere but the running engine's own config it would hand
    the agent a certificate the port never presents, and the failure would look
    like a broken listener rather than a test that disagrees with itself.
    """
    harness = CallbackTestHarness(tls=False, timeout=45)
    assert harness.run() is True, harness.errors
    assert not harness.refusals, (
        f"a plaintext round trip should leave no refusals counted: {harness.refusals}")
