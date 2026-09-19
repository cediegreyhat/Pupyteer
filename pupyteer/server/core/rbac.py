"""Role-based access control for Pupyteer TUI commands.

Defines permission levels and decorators for enforcing access control
on TUI commands and server operations.
"""
from __future__ import annotations

import enum
import functools
import logging
from typing import Any, Callable, Dict, Optional, Set

from pupyteer.server.core.auth import AuthLayer

logger = logging.getLogger("pupyteer.security.rbac")


class Role(enum.Enum):
    """Operator permission roles."""
    VIEWER = "viewer"         # Read-only access
    OPERATOR = "operator"     # Standard operator (read + execute)
    ADMIN = "admin"           # Full administrative access
    SYSTEM = "system"         # Internal system operations


# Permission definitions
class Permission:
    """Permission constants."""
    # Session permissions
    SESSION_READ = "session:read"
    SESSION_KILL = "session:kill"
    SESSION_TAG = "session:tag"
    SESSION_INTERACT = "session:interact"
    
    # Task permissions
    TASK_READ = "task:read"
    TASK_CREATE = "task:create"
    TASK_CANCEL = "task:cancel"
    
    # Profile permissions
    PROFILE_READ = "profile:read"
    PROFILE_LOAD = "profile:load"
    PROFILE_MODIFY = "profile:modify"
    
    # Config permissions
    CONFIG_READ = "config:read"
    CONFIG_WRITE = "config:write"
    
    # Evasion permissions
    EVASION_READ = "evasion:read"
    EVASION_RUN = "evasion:run"
    
    # Admin permissions
    AUDIT_READ = "audit:read"
    OPERATOR_MANAGE = "operator:manage"
    SYSTEM_ADMIN = "system:admin"


# Role-to-permissions mapping
ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.VIEWER: {
        Permission.SESSION_READ,
        Permission.TASK_READ,
        Permission.PROFILE_READ,
        Permission.CONFIG_READ,
        Permission.EVASION_READ,
    },
    Role.OPERATOR: {
        Permission.SESSION_READ,
        Permission.SESSION_KILL,
        Permission.SESSION_TAG,
        Permission.SESSION_INTERACT,
        Permission.TASK_READ,
        Permission.TASK_CREATE,
        Permission.TASK_CANCEL,
        Permission.PROFILE_READ,
        Permission.PROFILE_LOAD,
        Permission.CONFIG_READ,
        Permission.EVASION_READ,
    },
    Role.ADMIN: {
        Permission.SESSION_READ,
        Permission.SESSION_KILL,
        Permission.SESSION_TAG,
        Permission.SESSION_INTERACT,
        Permission.TASK_READ,
        Permission.TASK_CREATE,
        Permission.TASK_CANCEL,
        Permission.PROFILE_READ,
        Permission.PROFILE_LOAD,
        Permission.PROFILE_MODIFY,
        Permission.CONFIG_READ,
        Permission.CONFIG_WRITE,
        Permission.EVASION_READ,
        Permission.EVASION_RUN,
        Permission.AUDIT_READ,
        Permission.OPERATOR_MANAGE,
    },
    Role.SYSTEM: {
        Permission.SESSION_READ,
        Permission.SESSION_KILL,
        Permission.SESSION_TAG,
        Permission.SESSION_INTERACT,
        Permission.TASK_READ,
        Permission.TASK_CREATE,
        Permission.TASK_CANCEL,
        Permission.PROFILE_READ,
        Permission.PROFILE_LOAD,
        Permission.PROFILE_MODIFY,
        Permission.CONFIG_READ,
        Permission.CONFIG_WRITE,
        Permission.EVASION_READ,
        Permission.EVASION_RUN,
        Permission.AUDIT_READ,
        Permission.OPERATOR_MANAGE,
        Permission.SYSTEM_ADMIN,
    },
}


class AccessDenied(Exception):
    """Raised when an operator lacks required permissions."""
    def __init__(self, permission: str, operator: str = "unknown"):
        self.permission = permission
        self.operator = operator
        super().__init__(
            f"Access denied: operator '{operator}' lacks permission '{permission}'"
        )


class PermissionChecker:
    """Enforce role-based access control."""
    
    def __init__(self, auth_layer: AuthLayer):
        self._auth = auth_layer
        self._operator_roles: Dict[str, Role] = {}
    
    def assign_role(self, operator: str, role: Role) -> None:
        """Assign a role to an operator."""
        self._operator_roles[operator] = role
        logger.info("Assigned role %s to operator %s", role.value, operator)
    
    def get_role(self, operator: str) -> Role:
        """Get the role assigned to an operator."""
        return self._operator_roles.get(operator, Role.VIEWER)
    
    def has_permission(self, operator: str, permission: str) -> bool:
        """Check if an operator has a specific permission."""
        role = self.get_role(operator)
        return permission in ROLE_PERMISSIONS.get(role, set())
    
    def check_permission(self, operator: str, permission: str) -> None:
        """Check permission and raise AccessDenied if missing."""
        if not self.has_permission(operator, permission):
            raise AccessDenied(permission, operator)
    
    def require_permission(self, permission: str):
        """Decorator for TUI command handlers that require a permission.
        
        Usage:
            @require_permission(Permission.SESSION_KILL)
            async def cmd_kill(self, args):
                ...
        """
        def decorator(func: Callable) -> Callable:
            @functools.wraps(func)
            async def wrapper(*args, **kwargs):
                # Expects self as first arg (TUI command instance)
                if not args:
                    raise AccessDenied(permission, "unknown")
                
                instance = args[0]
                # Try to get operator from instance context
                operator = getattr(instance, '_operator', None)
                if operator is None:
                    # Fall back to checking auth layer's active sessions
                    operator = "unknown"
                
                if not self.has_permission(operator, permission):
                    raise AccessDenied(permission, operator)
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    def get_accessible_commands(self, operator: str) -> Set[str]:
        """Return set of command names the operator can access."""
        role = self.get_role(operator)
        perms = ROLE_PERMISSIONS.get(role, set())
        
        accessible = set()
        command_permissions = {
            "status": Permission.SESSION_READ,
            "sessions": Permission.SESSION_READ,
            "tasks": Permission.TASK_READ,
            "profiles": Permission.PROFILE_READ,
            "transports": Permission.SESSION_READ,
            "config": Permission.CONFIG_READ,
            "logs": Permission.AUDIT_READ,
            "evasion": Permission.EVASION_READ,
            "help": None,  # Always accessible
            "banner": None,
            "clear": None,
            "exit": None,
            "quit": None,
        }
        
        for cmd, perm in command_permissions.items():
            if perm is None or perm in perms:
                accessible.add(cmd)
        
        return accessible
    
    def filter_command_args(
        self, operator: str, command: str, args: list
    ) -> tuple:
        """Filter command args based on operator permissions.
        
        Returns:
            Tuple of (allowed_args, blocked_actions)
        """
        role = self.get_role(operator)
        perms = ROLE_PERMISSIONS.get(role, set())
        
        blocked = []
        allowed = list(args)
        
        # Define restricted sub-commands
        restricted = {
            "sessions": {
                "kill": Permission.SESSION_KILL,
                "tag": Permission.SESSION_TAG,
                "interact": Permission.SESSION_INTERACT,
            },
            "tasks": {
                "create": Permission.TASK_CREATE,
                "cancel": Permission.TASK_CANCEL,
            },
            "profiles": {
                "load": Permission.PROFILE_LOAD,
            },
            "evasion": {
                "run": Permission.EVASION_RUN,
            },
        }
        
        if command in restricted and len(args) > 0:
            subcmd = args[0]
            if subcmd in restricted[command]:
                perm = restricted[command][subcmd]
                if perm not in perms:
                    blocked.append(subcmd)
                    allowed = []
        
        return allowed, blocked


def create_default_admin(auth_layer: AuthLayer) -> PermissionChecker:
    """Create a PermissionChecker with a default admin operator.
    
    For development only. In production, use proper operator management.
    """
    checker = PermissionChecker(auth_layer)
    checker.assign_role("admin", Role.ADMIN)
    return checker
