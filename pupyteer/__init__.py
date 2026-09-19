"""Pupyteer — Red Team Operations Framework"""

__version__ = "1.0.0"
__codename__ = "Nightfall"
__author__ = "Pupyteer Team"
__description__ = "Modular Red-Team Operations Framework"

from pupyteer.server.core.engine import PupyteerEngine
from pupyteer.server.sessions.manager import SessionManager
from pupyteer.server.tasks.manager import TaskManager
from pupyteer.server.profiles.manager import ProfileManager
from pupyteer.server.transports.manager import TransportManager

__all__ = [
    "PupyteerEngine",
    "SessionManager",
    "TaskManager",
    "ProfileManager",
    "TransportManager",
]
