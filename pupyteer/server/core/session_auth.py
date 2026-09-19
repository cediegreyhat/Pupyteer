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
    
    # Map commands to required permissions
    COMMAND_PERMISSIONS: Dict[str, Optional[str]] = {
        "help": None,
        "banner": None,
        "status": Permission.SESSION_READ,
        "sessions": None,  # Checked at subcommand level
        "tasks": None,     # Checked at subcommand level
        "profiles": None,  # Checked at subcommand level
        "transports": Permission.SESSION_READ,
        "config": None,    # GET is read, SET is write
        "logs": Permission.AUDIT_READ,
        "evasion": None,   # Checked at subcommand level
        "clear": None,
        "exit": None,
        "quit": None,
    }
    
    # Subcommand-specific permissions
    SESSION_SUBCOMMAND_PERMS: Dict[str, Optional[str]] = {
        "list": Permission.SESSION_READ,
        "info": Permission.SESSION_READ,
        "search": Permission.SESSION_READ,
        "kill": Permission.SESSION_KILL,
        "tag": Permission.SESSION_TAG,
        "interact": Permission.SESSION_INTERACT,
    }
    
    TASK_SUBCOMMAND_PERMS: Dict[str, Optional[str]] = {
        "list": Permission.TASK_READ,
        "info": Permission.TASK_READ,
        "cancel": Permission.TASK_CANCEL,
        "create": Permission.TASK_CREATE,
    }
    
    PROFILE_SUBCOMMAND_PERMS: Dict[str, Optional[str]] = {
        "list": Permission.PROFILE_READ,
        "show": Permission.PROFILE_READ,
        "validate": Permission.PROFILE_READ,
        "load": Permission.PROFILE_LOAD,
    }
    
    EVASION_SUBCOMMAND_PERMS: Dict[str, Optional[str]] = {
        "status": Permission.EVASION_READ,
        "list": Permission.EVASION_READ,
        "stats": Permission.EVASION_READ,
        "run": Permission.EVASION_RUN,
    }
    
    CONFIG_SUBCOMMAND_PERMS: Dict[str, Optional[str]] = {
        "list": Permission.CONFIG_READ,
        "get": Permission.CONFIG_READ,
        "set": Permission.CONFIG_WRITE,
    }
    
    def resolve_permission(self, command: str, args: List[str]) -> Optional[str]:
        """Determine which permission is required for a command + args.
        
        Returns None if no permission is required (public command).
        Returns the required permission string if authorization is needed.
        """
        # Get base command permission
        base_perm = self.COMMAND_PERMISSIONS.get(command)
        
        # If no args provided, use base permission
        if not args:
            return base_perm
        
        subcmd = args[0] if args else None
        
        # Check subcommand-specific permissions
        subcmd_maps = {
            "sessions": self.SESSION_SUBCOMMAND_PERMS,
            "tasks": self.TASK_SUBCOMMAND_PERMS,
            "profiles": self.PROFILE_SUBCOMMAND_PERMS,
            "evasion": self.EVASION_SUBCOMMAND_PERMS,
            "config": self.CONFIG_SUBCOMMAND_PERMS,
        }
        
        if command in subcmd_maps and subcmd in subcmd_maps[command]:
            return subcmd_maps[command][subcmd]
        
        # Fall back to base permission
        return base_perm
    
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
        operator = self._auth.get_operator(token)
        if operator is None:
            # Token is invalid or expired
            ctx = CommandContext(
                operator="unknown",
                session_token=token[:8] + "..." if token else None,
                command=command,
                args=args,
                authorized=False,
            )
            self._command_log.append(ctx)
            raise AccessDenied("valid_token", "unknown")
        
        required_perm = self.resolve_permission(command, args)
        
        ctx = CommandContext(
            operator=operator,
            session_token=token[:8] + "..." if token else None,
            command=command,
            args=args,
            permission=required_perm,
        )
        
        # If no permission required, allow
        if required_perm is None:
            ctx.authorized = True
            self._command_log.append(ctx)
            logger.debug("Command '%s' authorized for '%s' (public)", command, operator)
            return ctx
        
        # Check if operator has the required permission
        if not self._rbac.has_permission(operator, required_perm):
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
