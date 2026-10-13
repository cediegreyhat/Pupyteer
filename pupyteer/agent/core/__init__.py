"""Pupyteer Agent subpackage.

The agent that runs on a target is generated: payloads/ renders the stub in this
package into a standalone script, so there is no agent class to instantiate here.
"""
from pupyteer.agent.core.stub import AgentStubGenerator, StubConfig

__all__ = ["AgentStubGenerator", "StubConfig"]
