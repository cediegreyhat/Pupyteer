"""Role-based access control for Pupyteer TUI commands.

Defines permission levels and decorators for enforcing access control
on TUI commands and server operations.
"""
from __future__ import annotations

import enum
import functools
import logging
from typing import TYPE_CHECKING, Any, Callable, Dict, Optional, Set

if TYPE_CHECKING:
    # Only ever a name in an annotation. The layer that owns the credential file
    # needs the vocabulary defined here, so importing it at runtime would close
    # the loop auth -> operators -> rbac -> auth.
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

    # Background job permissions
    JOB_READ = "job:read"
    JOB_CANCEL = "job:cancel"

    # Module permissions: reading the library and driving a target with it are
    # different things. Listing modules is what a viewer looks at; `run` and
    # `exploit` put a command on a live session.
    MODULE_READ = "module:read"
    MODULE_RUN = "module:run"

    # Payload permissions: an artifact is the thing that goes onto a target, so
    # building one and deleting one are not the same act as looking at a list.
    PAYLOAD_READ = "payload:read"
    PAYLOAD_BUILD = "payload:build"
    PAYLOAD_REMOVE = "payload:remove"

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


# Role-to-permissions mapping.
#
# The line each role draws is what it may do to a *target*, not how much it may
# see: VIEWER reads state and touches nothing, OPERATOR works sessions and builds
# payloads, ADMIN changes the server itself (config, profiles, operators).
# OPERATOR can read the audit log on purpose — an operator who cannot see what
# they did last night cannot account for it — while VIEWER cannot, because the
# log names operators and hosts and is not a dashboard.
ROLE_PERMISSIONS: Dict[Role, Set[str]] = {
    Role.VIEWER: {
        Permission.SESSION_READ,
        Permission.TASK_READ,
        Permission.JOB_READ,
        Permission.MODULE_READ,
        Permission.PAYLOAD_READ,
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
        Permission.JOB_READ,
        Permission.JOB_CANCEL,
        Permission.MODULE_READ,
        Permission.MODULE_RUN,
        Permission.PAYLOAD_READ,
        Permission.PAYLOAD_BUILD,
        Permission.PROFILE_READ,
        Permission.PROFILE_LOAD,
        Permission.CONFIG_READ,
        Permission.EVASION_READ,
        Permission.AUDIT_READ,
    },
    Role.ADMIN: {
        Permission.SESSION_READ,
        Permission.SESSION_KILL,
        Permission.SESSION_TAG,
        Permission.SESSION_INTERACT,
        Permission.TASK_READ,
        Permission.TASK_CREATE,
        Permission.TASK_CANCEL,
        Permission.JOB_READ,
        Permission.JOB_CANCEL,
        Permission.MODULE_READ,
        Permission.MODULE_RUN,
        Permission.PAYLOAD_READ,
        Permission.PAYLOAD_BUILD,
        Permission.PAYLOAD_REMOVE,
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
        Permission.JOB_READ,
        Permission.JOB_CANCEL,
        Permission.MODULE_READ,
        Permission.MODULE_RUN,
        Permission.PAYLOAD_READ,
        Permission.PAYLOAD_BUILD,
        Permission.PAYLOAD_REMOVE,
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
    """Enforce role-based access control.

    Roles normally live on the stored credential, which is what makes them
    survive a restart and what `operator add --role` writes. The in-memory map is
    for callers with no credential file behind them, and is consulted first so a
    deliberate local override still wins.
    """

    def __init__(self, auth_layer: "AuthLayer", store: Any = None):
        self._auth = auth_layer
        self._store = store
        self._operator_roles: Dict[str, Role] = {}

    def assign_role(self, operator: str, role: Role) -> None:
        """Assign a role to an operator, and to their credential when they have one.

        The in-memory map is not a way to promote yourself: it is what
        `create_default_admin` and a caller with no credential file behind it use,
        and the console's `operator` verb goes through the store instead. Writing
        through only when a credential exists keeps the two from disagreeing about
        a name that is in one and not the other.
        """
        role = Role(role)
        self._operator_roles[operator] = role
        if self._store is not None and self._store.get(operator) is not None:
            self._store.set_role(operator, role)
        elif self._store is not None:
            logger.warning(
                "Role %s for %s is in-memory only: no credential by that name is "
                "stored, so it is gone on restart and cannot be logged in with",
                role.value, operator)
        logger.info("Assigned role %s to operator %s", role.value, operator)

    def get_role(self, operator: str) -> Role:
        """Get the role assigned to an operator."""
        remembered = self._operator_roles.get(operator)
        if remembered is not None:
            return remembered
        if self._store is not None:
            return self._store.role_of(operator)
        return Role.VIEWER
    
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
        """Return set of command names the operator can access.

        Read from the same verb table the console gates with, because the
        alternative is a second copy that says `sessions` is readable while the
        dispatcher says `sessions kill` is not.
        """
        from pupyteer.server.core.session_auth import SessionAuthorization

        perms = ROLE_PERMISSIONS.get(self.get_role(operator), set())
        return {
            name for name, perm in SessionAuthorization.COMMAND_PERMISSIONS.items()
            if perm is None or perm in perms
        }
    
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
