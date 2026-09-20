"""Session authorization for Pupyteer TUI command execution.

Enforces that operators are authorized to execute commands and
interact with sessions. Each TUI command execution is checked
against the active session's permissions.
"""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from pupyteer.server.core.auth import AuthLayer, OperatorSession
from pupyteer.server.core.rbac import PermissionChecker, Permission, AccessDenied

logger = logging.getLogger("pupyteer.security.session_auth")


@dataclass
class CommandContext:
    """Context for a TUI command execution including authorization state."""
    operator: str
    session_token: Optional[str]
    command: str
    args: List[str]
    timestamp: float = field(default_factory=time.time)
    authorized: bool = False
    permission: Optional[str] = None
    
    def to_audit_dict(self) -> Dict[str, Any]:
        """Convert to a dict suitable for audit logging."""
        return {
            "operator": self.operator,
            "command": self.command,
            "args_count": len(self.args),
            "timestamp": self.timestamp,
            "authorized": self.authorized,
            "permission": self.permission,
        }


class SessionAuthorization:
    """Enforces authorization checks before TUI command execution."""
    
    def __init__(self, auth_layer: AuthLayer, rbac: PermissionChecker):
        self._auth = auth_layer
        self._rbac = rbac
        self._command_log: List[CommandContext] = []
    
    # Which permission each console verb needs.
    #
    # This table is complete on purpose and `resolve_permission` refuses anything
    # missing from it. The version before this one listed twelve verbs and let
    # the rest through as public, which meant every verb added afterwards was
    # ungated until somebody remembered — and `run`, `exploit` and `payloads
    # build` were among the ones nobody had written down.
    #
    # None means genuinely public: it touches no session, no artifact and no
    # server state. `login` and `logout` have to be, or the gate cannot be passed.
    COMMAND_PERMISSIONS: Dict[str, Optional[str]] = {
        "help": None,
        "banner": None,
        "clear": None,
        "theme": None,
        "exit": None,
        "quit": None,
        "login": None,
        "logout": None,
        "whoami": None,

        "status": Permission.SESSION_READ,
        "sessions": Permission.SESSION_READ,   # refined by subcommand
        "transports": Permission.SESSION_READ,
        "jobs": Permission.JOB_READ,           # refined by subcommand
        "tasks": Permission.TASK_READ,         # refined by subcommand

        "modules": Permission.MODULE_READ,
        "search": Permission.MODULE_READ,
        "use": Permission.MODULE_READ,
        "set": Permission.MODULE_READ,
        "unset": Permission.MODULE_READ,
        "back": Permission.MODULE_READ,
        "options": Permission.MODULE_READ,
        "info": Permission.MODULE_READ,
        "reload": Permission.MODULE_RUN,
        "run": Permission.MODULE_RUN,
        "exploit": Permission.MODULE_RUN,

        "payloads": Permission.PAYLOAD_READ,   # refined by subcommand
        "profiles": Permission.PROFILE_READ,   # refined by subcommand
        "config": Permission.CONFIG_READ,      # refined by subcommand
        "logs": Permission.AUDIT_READ,
        "evasion": Permission.EVASION_READ,    # refined by subcommand
        "pipeline": Permission.PAYLOAD_BUILD,  # refined by subcommand
        "operator": Permission.OPERATOR_MANAGE,
    }
    
    # Subcommand refinement. `"*"` is what an unrecognised subcommand needs, and
    # it is the verb's mutating permission rather than its reading one: a
    # subcommand added without being written down here then needs the stronger
    # credential, which is the mistake you want to be left with.
    SUBCOMMAND_PERMISSIONS: Dict[str, Dict[str, Optional[str]]] = {
        "sessions": {
            "list": Permission.SESSION_READ,
            "info": Permission.SESSION_READ,
            "search": Permission.SESSION_READ,
            "interact": Permission.SESSION_INTERACT,
            "results": Permission.SESSION_INTERACT,
            "download": Permission.SESSION_INTERACT,
            "upload": Permission.SESSION_INTERACT,
            "kill": Permission.SESSION_KILL,
            "rename": Permission.SESSION_TAG,
            "tag": Permission.SESSION_TAG,
            "*": Permission.SESSION_INTERACT,
        },
        "jobs": {
            "list": Permission.JOB_READ,
            "info": Permission.JOB_READ,
            "kill": Permission.JOB_CANCEL,
            "*": Permission.JOB_CANCEL,
        },
        "tasks": {
            "list": Permission.TASK_READ,
            "info": Permission.TASK_READ,
            "create": Permission.TASK_CREATE,
            "cancel": Permission.TASK_CANCEL,
            "*": Permission.TASK_CANCEL,
        },
        "payloads": {
            "status": Permission.PAYLOAD_READ,
            "list": Permission.PAYLOAD_READ,
            "info": Permission.PAYLOAD_READ,
            "verify": Permission.PAYLOAD_READ,
            "versions": Permission.PAYLOAD_READ,
            "build": Permission.PAYLOAD_BUILD,
            "remove": Permission.PAYLOAD_REMOVE,
            "cleanup": Permission.PAYLOAD_REMOVE,
            "*": Permission.PAYLOAD_BUILD,
        },
        "profiles": {
            "list": Permission.PROFILE_READ,
            "show": Permission.PROFILE_READ,
            "validate": Permission.PROFILE_READ,
            "load": Permission.PROFILE_LOAD,
            "unload": Permission.PROFILE_MODIFY,
            "new": Permission.PROFILE_MODIFY,
            "*": Permission.PROFILE_MODIFY,
        },
        "config": {
            "list": Permission.CONFIG_READ,
            "get": Permission.CONFIG_READ,
            "set": Permission.CONFIG_WRITE,
            "*": Permission.CONFIG_WRITE,
        },
        "evasion": {
            "status": Permission.EVASION_READ,
            "list": Permission.EVASION_READ,
            "stats": Permission.EVASION_READ,
            "run": Permission.EVASION_RUN,
            "*": Permission.EVASION_RUN,
        },
        "pipeline": {
            "status": Permission.PAYLOAD_READ,
            "history": Permission.PAYLOAD_READ,
            "run": Permission.PAYLOAD_BUILD,
            "build": Permission.PAYLOAD_BUILD,
            "test": Permission.EVASION_RUN,
            "auto": Permission.EVASION_RUN,
            "*": Permission.PAYLOAD_BUILD,
        },
        # Written out rather than left to the verb's own permission, because the
        # tempting reading of `operator list` is "harmless": it prints every name
        # the team has credentials for, which is a target list for whoever is
        # already at a keyboard without one.
        "operator": {
            "list": Permission.OPERATOR_MANAGE,
            "add": Permission.OPERATOR_MANAGE,
            "role": Permission.OPERATOR_MANAGE,
            "remove": Permission.OPERATOR_MANAGE,
        },
    }

    #: What an unclassified verb resolves to. Not a permission anybody holds:
    #: refusing with this name says "nobody wrote this verb down", which is a
    #: different problem from "you lack session:kill" and needs a different fix.
    UNCLASSIFIED = "unclassified"

    def resolve_permission(self, command: str, args: List[str]) -> Optional[str]:
        """Determine which permission is required for a command + args.

        Returns None when the verb is public. Returns UNCLASSIFIED for a verb
        missing from the table: the old behaviour was to return None there, which
        quietly made an ungated verb out of every one that was added later.
        """
        if command not in self.COMMAND_PERMISSIONS:
            return self.UNCLASSIFIED
        base_perm = self.COMMAND_PERMISSIONS[command]
        if not args:
            return base_perm
        sub = self.SUBCOMMAND_PERMISSIONS.get(command)
        if sub is None:
            return base_perm
        return sub.get(args[0], sub.get("*", base_perm))

    def authorize_command(
        self,
        token: str,
        command: str,
        args: List[str],
    ) -> CommandContext:
        """Authorize a command execution.
        
        Args:
            token: The operator's session token.
            command: Command name to execute.
            args: Command arguments.
            
        Returns:
            CommandContext with authorization result.
            
        Raises:
            AccessDenied: If authorization fails.
        """
        # The verb is resolved before the token is looked at, because a public verb
        # has to stay reachable with nobody signed in: `help` and `whoami` are what
        # an operator uses to find out that they are locked out, and a gate that
        # demands a credential to ask the gate a question is a wall.
        required_perm = self.resolve_permission(command, args)
        operator = self._auth.get_operator(token)
        if operator is None and required_perm is not None:
            # Token is invalid, expired, or simply not there yet — the console
            # reads `valid_token` as "ask for a credential", and the distinction
            # between those three is not one this check is allowed to make.
            ctx = CommandContext(
                operator="unknown",
                session_token=token[:8] + "..." if token else None,
                command=command,
                args=args,
                authorized=False,
                permission=required_perm,
            )
            self._command_log.append(ctx)
            raise AccessDenied("valid_token", "unknown")
        
        # A public verb with nobody signed in still gets a name in the log, and
        # "unknown" is the honest one: leaving it blank would make an anonymous
        # `sessions list` indistinguishable from one whose attribution was lost.
        who = operator or "unknown"
        ctx = CommandContext(
            operator=who,
            session_token=token[:8] + "..." if token else None,
            command=command,
            args=args,
            permission=required_perm,
        )
        
        # If no permission required, allow
        if required_perm is None:
            ctx.authorized = True
            self._command_log.append(ctx)
            logger.debug("Command '%s' allowed for '%s' (public)", command, who)
            return ctx

        # The token decides, not the name. Asking the role of `operator` instead
        # would make the audit attribution the thing being checked: an operator
        # who can rewrite `operator.name` in the config — which the console could,
        # unauthenticated — would be renaming their way into another role. The
        # permission set is fixed at login from that operator's stored role, so a
        # name change cannot carry one.
        if not self._auth.authorize(token, required_perm):
            ctx.authorized = False
            self._command_log.append(ctx)
            logger.warning(
                "Access denied: '%s' lacks '%s' for command '%s'",
                operator, required_perm, command,
            )
            raise AccessDenied(required_perm, operator)

        ctx.authorized = True
        self._command_log.append(ctx)
        logger.info(
            "Command '%s' authorized for '%s' (perm: %s)",
            command, operator, required_perm,
        )
        return ctx
    
    def validate_session_access(
        self, token: str, session_id: str
    ) -> bool:
        """Validate that an operator can access a specific session.
        
        Currently allows all authenticated operators to access any session.
        Override for session-scoped access control.
        
        Args:
            token: Operator's session token.
            session_id: Target session ID.
            
        Returns:
            True if access is allowed.
        """
        operator = self._auth.get_operator(token)
        if operator is None:
            return False
        
        # Could add session ownership/scoping here
        return True
    
    def get_command_history(self) -> List[CommandContext]:
        """Return the command execution history for audit."""
        return list(self._command_log)
    
    def clear_history(self) -> None:
        """Clear command execution history."""
        self._command_log.clear()


class SecureCommandExecutor:
    """Wraps TUI command execution with authorization checks."""
    
    def __init__(self, session_auth: SessionAuthorization):
        self._session_auth = session_auth
    
    async def execute(
        self,
        handler,
        token: str,
        args: List[str],
        operator: str = "system",
    ) -> Any:
        """Execute a command handler with authorization.
        
        Args:
            handler: The async command handler function.
            token: Operator session token.
            args: Command arguments.
            operator: Operator name (fallback).
            
        Returns:
            Handler result.
            
        Raises:
            AccessDenied: If authorization fails.
        """
        # Determine command name from handler
        command = getattr(handler, '__name__', 'unknown')
        
        # Authorize
        ctx = self._session_auth.authorize_command(token, command, args)
        
        if not ctx.authorized:
            raise AccessDenied(ctx.permission or "execute", operator)
        
        return await handler(args)
