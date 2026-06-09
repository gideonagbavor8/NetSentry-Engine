"""Privilege checks used before starting live packet capture."""

from __future__ import annotations

import ctypes
import os


def is_running_with_admin_privileges() -> bool:
    """Return True when the current process has root or administrator access."""
    if os.name == "nt":
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except (AttributeError, OSError):
            return False

    get_effective_user_id = getattr(os, "geteuid", None)
    if get_effective_user_id is None:
        return False

    return get_effective_user_id() == 0


def require_admin_privileges(action: str = "capture live network packets") -> None:
    """Raise a clean error when live packet capture privileges are missing."""
    if is_running_with_admin_privileges():
        return

    raise PermissionError(
        "NetSentry Engine requires administrator or root privileges to "
        f"{action}. Restart this script from an elevated terminal."
    )
