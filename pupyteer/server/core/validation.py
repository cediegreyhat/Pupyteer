"""Input validation helpers for Pupyteer server.

Provides validation functions for user-supplied data including
session IDs, hostnames, IP addresses, ports, module names, and
general string sanitization.

All validators raise ValueError on invalid input with descriptive messages.
"""
from __future__ import annotations

import ipaddress
import re
import unicodedata
from typing import Any, Dict, List, Optional, Set, Union

# Allowed characters for various identifier types
_RE_SESSION_ID = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$')
_RE_HOSTNAME = re.compile(
    r'^(?!-)[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?'
    r'(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
)
_RE_MODULE_NAME = re.compile(r'^[a-zA-Z_][a-zA-Z0-9_]{0,63}$')
_RE_USERNAME = re.compile(r'^[a-zA-Z][a-zA-Z0-9._-]{0,31}$')
_RE_TAG = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,31}$')
_RE_PROFILE_NAME = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._ -]{0,63}$')
_RE_PATH_TRAVERSAL = re.compile(r'(\.\.[\\/]|[\\/]\.\.)')
_RE_CONTROL_CHARS = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')

# Maximum lengths
MAX_SESSION_ID_LEN = 64
MAX_HOSTNAME_LEN = 253
MAX_MODULE_NAME_LEN = 64
MAX_USERNAME_LEN = 32
MAX_TAG_LEN = 32
MAX_ARGS_LEN = 4096
MAX_INPUT_FIELD_LEN = 1024


def validate_session_id(session_id: str) -> str:
    """Validate a session identifier.
    
    Args:
        session_id: The session ID to validate.
        
    Returns:
        The validated session ID.
        
    Raises:
        ValueError: If the session ID is invalid.
    """
    if not isinstance(session_id, str):
        raise ValueError("Session ID must be a string")
    
    session_id = session_id.strip()
    
    if not session_id:
        raise ValueError("Session ID cannot be empty")
    
    if len(session_id) > MAX_SESSION_ID_LEN:
        raise ValueError(f"Session ID too long (max {MAX_SESSION_ID_LEN} chars)")
    
    if not _RE_SESSION_ID.match(session_id):
        raise ValueError(
            "Session ID must start with alphanumeric and contain only "
            "alphanumeric, dots, hyphens, underscores"
        )
    
    return session_id


def validate_hostname(hostname: str) -> str:
    """Validate a hostname (FQDN or short name).
    
    Args:
        hostname: The hostname to validate.
        
    Returns:
        The validated hostname.
        
    Raises:
        ValueError: If the hostname is invalid.
    """
    if not isinstance(hostname, str):
        raise ValueError("Hostname must be a string")
    
    hostname = hostname.strip().lower()
    
    if not hostname:
        raise ValueError("Hostname cannot be empty")
    
    if len(hostname) > MAX_HOSTNAME_LEN:
        raise ValueError(f"Hostname too long (max {MAX_HOSTNAME_LEN} chars)")
    
    if not _RE_HOSTNAME.match(hostname):
        raise ValueError(f"Invalid hostname format: {hostname}")
    
    return hostname


def validate_ip_address(ip: str) -> str:
    """Validate an IPv4 or IPv6 address.
    
    Args:
        ip: The IP address string to validate.
        
    Returns:
        The validated IP address string.
        
    Raises:
        ValueError: If the IP address is invalid.
    """
    if not isinstance(ip, str):
        raise ValueError("IP address must be a string")
    
    ip = ip.strip()
    
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(f"Invalid IP address: {ip}")
    
    # Reject unspecified and loopback for certain contexts
    if addr.is_unspecified:
        raise ValueError("IP address cannot be unspecified (0.0.0.0 or ::)")
    
    return str(addr)


def validate_port(port: Union[str, int]) -> int:
    """Validate a TCP/UDP port number.
    
    Args:
        port: Port number as string or int.
        
    Returns:
        The validated port number as int.
        
    Raises:
        ValueError: If the port is invalid.
    """
    try:
        if isinstance(port, str):
            port = int(port.strip())
        else:
            port = int(port)
    except (ValueError, TypeError):
        raise ValueError(f"Port must be a number, got: {port}")
    
    if not (1 <= port <= 65535):
        raise ValueError(f"Port must be between 1 and 65535, got: {port}")
    
    return port


def validate_module_name(name: str) -> str:
    """Validate a module/command name.
    
    Args:
        name: The module name to validate.
        
    Returns:
        The validated module name.
        
    Raises:
        ValueError: If the module name is invalid.
    """
    if not isinstance(name, str):
        raise ValueError("Module name must be a string")
    
    name = name.strip()
    
    if not name:
        raise ValueError("Module name cannot be empty")
    
    if len(name) > MAX_MODULE_NAME_LEN:
        raise ValueError(f"Module name too long (max {MAX_MODULE_NAME_LEN} chars)")
    
    if not _RE_MODULE_NAME.match(name):
        raise ValueError(
            "Module name must start with letter/underscore and contain only "
            "alphanumeric and underscores"
        )
    
    return name


def validate_username(username: str) -> str:
    """Validate an operator username.
    
    Args:
        username: The username to validate.
        
    Returns:
        The validated username.
        
    Raises:
        ValueError: If the username is invalid.
    """
    if not isinstance(username, str):
        raise ValueError("Username must be a string")
    
    username = username.strip()
    
    if not username:
        raise ValueError("Username cannot be empty")
    
    if len(username) > MAX_USERNAME_LEN:
        raise ValueError(f"Username too long (max {MAX_USERNAME_LEN} chars)")
    
    if not _RE_USERNAME.match(username):
        raise ValueError(
            "Username must start with letter and contain only "
            "alphanumeric, dots, hyphens, underscores"
        )
    
    return username


def validate_tag(tag: str) -> str:
    """Validate a session/task tag.
    
    Args:
        tag: The tag to validate.
        
    Returns:
        The validated tag.
        
    Raises:
        ValueError: If the tag is invalid.
    """
    if not isinstance(tag, str):
        raise ValueError("Tag must be a string")
    
    tag = tag.strip().lower()
    
    if not tag:
        raise ValueError("Tag cannot be empty")
    
    if len(tag) > MAX_TAG_LEN:
        raise ValueError(f"Tag too long (max {MAX_TAG_LEN} chars)")
    
    if not _RE_TAG.match(tag):
        raise ValueError(
            "Tag must start with alphanumeric and contain only "
            "alphanumeric, dots, hyphens, underscores"
        )
    
    return tag


def validate_tags(tags: List[str]) -> List[str]:
    """Validate a list of tags.
    
    Args:
        tags: List of tags to validate.
        
    Returns:
        List of validated, deduplicated tags.
        
    Raises:
        ValueError: If any tag is invalid.
    """
    if not isinstance(tags, (list, tuple)):
        raise ValueError("Tags must be a list or tuple")
    
    validated = []
    seen: Set[str] = set()
    
    for tag in tags:
        vtag = validate_tag(tag)
        if vtag not in seen:
            validated.append(vtag)
            seen.add(vtag)
    
    return validated


def validate_profile_name(name: str) -> str:
    """Validate a C2 profile name.
    
    Args:
        name: The profile name to validate.
        
    Returns:
        The validated profile name.
        
    Raises:
        ValueError: If the profile name is invalid.
    """
    if not isinstance(name, str):
        raise ValueError("Profile name must be a string")
    
    name = name.strip()
    
    if not name:
        raise ValueError("Profile name cannot be empty")
    
    if len(name) > 64:
        raise ValueError("Profile name too long (max 64 chars)")
    
    if not _RE_PROFILE_NAME.match(name):
        raise ValueError(
            "Profile name must start with alphanumeric and contain only "
            "alphanumeric, dots, hyphens, spaces, underscores"
        )
    
    return name


def validate_file_path(path: str, allow_absolute: bool = False) -> str:
    """Validate a file path, rejecting path traversal attempts.
    
    Args:
        path: The file path to validate.
        allow_absolute: Whether to allow absolute paths.
        
    Returns:
        The validated file path.
        
    Raises:
        ValueError: If the path is invalid or contains traversal.
    """
    if not isinstance(path, str):
        raise ValueError("Path must be a string")
    
    path = path.strip()
    
    if not path:
        raise ValueError("Path cannot be empty")
    
    # Reject path traversal
    if _RE_PATH_TRAVERSAL.search(path):
        raise ValueError(f"Path contains directory traversal: {path}")
    
    # Reject absolute paths unless explicitly allowed
    if not allow_absolute and (path.startswith('/') or (len(path) > 1 and path[1] == ':')):
        raise ValueError(f"Absolute paths not allowed: {path}")
    
    # Reject null bytes
    if '\x00' in path:
        raise ValueError("Path contains null bytes")
    
    return path


def sanitize_string(value: str, max_len: int = MAX_INPUT_FIELD_LEN) -> str:
    """Sanitize a string value by removing control characters and truncating.
    
    Args:
        value: The string to sanitize.
        max_len: Maximum allowed length.
        
    Returns:
        The sanitized string.
    """
    if not isinstance(value, str):
        return ""
    
    # Remove control characters
    value = _RE_CONTROL_CHARS.sub('', value)
    
    # Normalize unicode
    value = unicodedata.normalize('NFKC', value)
    
    # Strip leading/trailing whitespace
    value = value.strip()
    
    # Truncate
    if len(value) > max_len:
        value = value[:max_len]
    
    return value


def validate_args_dict(args: Dict[str, Any]) -> Dict[str, Any]:
    """Validate a dictionary of command arguments.
    
    Ensures all keys are valid identifiers and values are safe.
    
    Args:
        args: Dictionary of arguments to validate.
        
    Returns:
        Validated argument dictionary.
        
    Raises:
        ValueError: If any argument is invalid.
    """
    if not isinstance(args, dict):
        raise ValueError("Args must be a dictionary")
    
    validated = {}
    for key, value in args.items():
        if not isinstance(key, str):
            raise ValueError(f"Argument key must be string: {key}")
        
        vkey = validate_module_name(key)  # Reuse module name rules for keys
        
        # Validate value types
        if isinstance(value, str):
            if len(value) > MAX_ARGS_LEN:
                raise ValueError(f"Argument '{vkey}' value too long")
            validated[vkey] = sanitize_string(value, MAX_ARGS_LEN)
        elif isinstance(value, (int, float, bool)):
            validated[vkey] = value
        elif isinstance(value, (list, tuple)):
            validated[vkey] = [
                sanitize_string(v, MAX_ARGS_LEN) if isinstance(v, str) else v
                for v in value
            ]
        elif isinstance(value, dict):
            validated[vkey] = validate_args_dict(value)  # Recursive
        elif value is None:
            validated[vkey] = None
        else:
            raise ValueError(
                f"Argument '{vkey}' has unsupported type: {type(value).__name__}"
            )
    
    return validated


def validate_command_line(line: str) -> List[str]:
    """Validate and split a command line into parts.
    
    Args:
        line: The raw command line input.
        
    Returns:
        List of command parts.
        
    Raises:
        ValueError: If the command line is invalid.
    """
    if not isinstance(line, str):
        raise ValueError("Command line must be a string")
    
    if len(line) > MAX_ARGS_LEN:
        raise ValueError("Command line too long")
    
    import shlex
    try:
        parts = shlex.split(line)
    except ValueError as e:
        raise ValueError(f"Malformed command line: {e}")
    
    if not parts:
        raise ValueError("Empty command")
    
    return parts


def validate_engine_config(config: Any) -> None:
    """Validate engine-specific configuration constraints.

    Called by C2Engine.start() after the base ConfigManager.validate().
    Raises ValueError on invalid config.
    """
    max_concurrent = config.get("tasks.max_concurrent", 5)
    if not isinstance(max_concurrent, int) or max_concurrent < 1:
        raise ValueError(f"Invalid tasks.max_concurrent: {max_concurrent} (must be >= 1)")

    queue_size = config.get("tasks.queue_size", 0)
    if not isinstance(queue_size, int) or queue_size < 0:
        raise ValueError(f"Invalid tasks.queue_size: {queue_size} (must be >= 0)")

    timeout = config.get("session.timeout_seconds", 300)
    if not isinstance(timeout, (int, float)) or timeout < 1:
        raise ValueError(f"Invalid session.timeout_seconds: {timeout} (must be >= 1)")
