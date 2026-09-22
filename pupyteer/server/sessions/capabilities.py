"""What the implant behind a session can actually be asked to do.

Two agents speak this protocol and they are not the same size. The Python stub
carries module handlers for file transfer, recon, privilege checks and screens;
the Windows PE implant is a few thousand lines of C whose command execution has
always meant `cmd.exe /c "<the string>"`. Until this module existed, the server
knew the difference and pretended not to: `register` was asked only who the host
was, never what the payload could do, so a tasking that no implant can perform
still went down the queue, still came back, and came back as whatever the shell
said about a word it had never seen.

That is the failure this closes, and the reason it is worth closing is the
report, not the refusal. An operator who reads `screenshot is not recognized as
an internal or external command` believes the *target* said it. They have no
reason to suspect otherwise — the session is live, the command completed, and
the output came from the machine they are standing on. A wrong answer is worse
than no answer here, because a wrong answer is actionable: it decides the next
tasking, it goes in the report, and it is attributed to a host that never ran
anything.

So an implant declares what it does at registration and the queue enforces it.
Three things follow from that shape and are deliberate:

* The claim comes from the payload, not from the server's build records. A
  session is created from its `register` message and carries no payload id, so
  there is nothing to look the capability up on; anything the server believed
  about a binary it has never identified would be a guess wearing authority.
* Shell text still passes. Every implant in the tree can hand a string to a
  command interpreter, so refusing that would refuse the one thing the two
  agents genuinely agree on, and operators work in shell.
* A session that declares nothing is trusted with shell and nothing structured.
  Payloads built before this change cannot announce themselves, and the answer
  to "may I have a file off this one" is that nobody knows what it is — which is
  a thing to say out loud, not to discover by reading base64 that never arrives.
"""
from __future__ import annotations

import json
from typing import Any, Dict, List, Sequence

#: Every capability name the server will accept a claim for. Anything else in a
#: `register` is ignored rather than stored, so a payload cannot invent a
#: permission by naming it: the set below is the whole vocabulary, and the only
#: words that mean anything at the queue.
KNOWN_CAPABILITIES = (
    "exec",
    "ping",
    "sysinfo",
    "network",
    "processes",
    "fs_list",
    "fs_get",
    "fs_put",
    "privesc_check",
    "privesc_suggest",
    "screenshot",
    "migrate",
    "shutdown",
)

#: The words an operator types at `sessions interact`, and what each one needs.
#: This mirrors the Python agent's own verb table, because that is where the
#: meaning of these words comes from. A word that is not listed is not a
#: command the server recognises: it is text for a shell, and needs `exec`.
TYPED_VERBS: Dict[str, str] = {
    "ping": "ping",
    "sysinfo": "sysinfo",
    "network": "network",
    "ps": "processes",
    "processes": "processes",
    "fs_list": "fs_list",
    "fs_get": "fs_get",
    "fs_put": "fs_put",
    "privesc_check": "privesc_check",
    "privesc_suggest": "privesc_suggest",
    "screenshot": "screenshot",
    "migrate": "migrate",
    "exit": "shutdown",
    "shutdown": "shutdown",
}

#: The capability a plain shell line needs. Universal, and the only thing an
#: unannounced session is trusted with.
SHELL = "exec"

#: The longest line a session is assumed to be able to read when it did not say.
#: This is the Windows implant's own buffer rather than the listener's, and
#: guessing high is the dangerous direction: a chunk bigger than what the agent
#: reads in one piece is not a transfer that fails noisily, it is a short read
#: the server has to explain while believing it sent the whole thing.
DEFAULT_MAX_LINE = 64 * 1024

#: The largest claim to believe. The transfer layer sizes chunks from this
#: number, so an unbounded claim is a promise to read a line bigger than the
#: listener itself accepts, and the honest answer to a nonsense number is the
#: safe default rather than a big one that happens to be accepted.
MAX_LINE_CAP = 4 * 1024 * 1024


def declared_max_line(presented: Any) -> int:
    """How much of one message an agent says it can hold, clamped to what is sane."""
    try:
        value = int(presented)
    except (TypeError, ValueError):
        return DEFAULT_MAX_LINE
    if value <= 0:
        return DEFAULT_MAX_LINE
    return min(value, MAX_LINE_CAP)


def declared_capabilities(presented: Any) -> List[str]:
    """The recognised subset of what a payload claimed it can do.

    Order is kept as the payload sent it, and duplicates dropped: this list is
    printed back at the operator in `sessions info`, and a claim repeated twice
    reads like two different things.
    """
    if not isinstance(presented, Sequence) or isinstance(presented, (str, bytes)):
        return []
    seen = []
    for item in presented:
        if isinstance(item, str) and item in KNOWN_CAPABILITIES and item not in seen:
            seen.append(item)
    return seen


def required_capability(command: str) -> str:
    """The one capability a command line asks for.

    The server sends structured tasks as JSON and shell text otherwise, and an
    operator types the short verb forms the Python agent understands, so there
    are three shapes to read and they are read in that order. Anything that is
    not one of the recognised words is the shell's problem, and has been all
    along.
    """
    text = (command or "").strip()
    if not text:
        return SHELL
    if text.startswith("{"):
        try:
            task = json.loads(text)
        except ValueError:
            # Curly brace, not JSON. It goes to a shell like any other text,
            # which is what the agent that received it before this check existed
            # would have done, and the shell's own complaint is the honest one.
            return SHELL
        if isinstance(task, dict) and task.get("action"):
            return str(task["action"])
        return SHELL
    return TYPED_VERBS.get(text.split(None, 1)[0].lower(), SHELL)


def refusal(capability: str, declared: List[str]) -> str:
    """What the operator reads instead of a target's misunderstanding.

    It names the implant's own claim, because the useful next question after
    "this session cannot do that" is "then what did I drop on the host", and the
    answer to that decides whether the fix is a new payload or a different
    session.
    """
    listed = ", ".join(declared) if declared else "nothing beyond a shell"
    return (
        f"refused: this implant declared {listed}, and not '{capability}'. "
        f"Nothing ran on the target, so there is no output to read. "
        f"Build a payload that carries '{capability}' "
        f"(see `payloads build`) or run it where one is already listening."
    )
