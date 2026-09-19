"""Built-in evasion module for Pupyteer.

Exposes the EvasionTestManager through the standard module interface,
allowing operators to run detection-resilience tests from the TUI.
"""
from __future__ import annotations

from typing import Any, Dict

from pupyteer.server.modules.registry import PupyModule, ModuleCategory, ModuleRequirement


class EvasionTestModule(PupyModule):
    """Run evasion detection-resilience tests."""

    name = "evasion_test"
    version = "1.0.0"
    description = "Run payload evasion detection-resilience tests (lab mode only)"
    author = "Pupyteer Team"
    category = ModuleCategory.EVASION
    requirements = []

    def __init__(self, config, audit):
        super().__init__(config, audit)
        self._manager = None

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        """Execute an evasion test."""
        # Lazy init manager
        if self._manager is None:
            from pupyteer.server.evasion.manager import EvasionTestManager
            self._manager = EvasionTestManager(self.config, self.audit)
            await self._manager.initialize()

        action = args.get("action", "list")

        if action == "list":
            history = self._manager.get_history()
            return {
                "status": "ok",
                "tests": [r.to_dict() for r in history[-10:]],
            }

        if action == "stats":
            return {
                "status": "ok",
                "stats": self._manager.get_stats(),
            }

        if action == "run":
            test_name = args.get("name", "unnamed")
            artifact_path = args.get("artifact_path", "")
            environment = args.get("environment", "local")
            controls = args.get("controls", [])

            from pupyteer.server.evasion.models import EvasionTestConfig

            cfg = EvasionTestConfig(
                name=test_name,
                artifact_path=artifact_path,
                environment=environment,
                controls=controls,
                test_mode=True,
                tags=args.get("tags", []),
            )

            result = await self._manager.run_test(cfg)
            return {
                "status": "ok",
                "result": result.to_dict(),
            }

        return {"status": "error", "error": f"Unknown action: {action}"}

    async def cleanup(self) -> None:
        if self._manager:
            await self._manager.shutdown()


class EvasionConfigModule(PupyModule):
    """Show current evasion testing configuration."""

    name = "evasion_config"
    version = "1.0.0"
    description = "Display current evasion test configuration and status"
    author = "Pupyteer Team"
    category = ModuleCategory.EVASION

    async def execute(self, session: Any, args: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "status": "ok",
            "test_mode": self.config.get("evasion.test_mode", False),
            "litterbox_url": self.config.get("evasion.litterbox_url", "not configured"),
            "litterbox_token_set": bool(self.config.get("evasion.litterbox_token")),
            "history_path": self.config.get("evasion.history_path", "./logs/evasion_history.json"),
        }
