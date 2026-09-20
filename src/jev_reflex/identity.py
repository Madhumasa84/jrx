"""Approver identity resolution for human overrides."""

from __future__ import annotations

import getpass
import os


def resolve_approver(explicit_approver: str | None = None) -> str | None:
    """Resolve approver identity in priority order:
    1. Explicit flag (--approver)
    2. $JRX_APPROVER environment variable
    3. OS user (getpass.getuser())

    Returns non-empty stripped string or None if no valid identity is available.
    """
    if explicit_approver is not None and explicit_approver.strip():
        return explicit_approver.strip()

    env_approver = os.environ.get("JRX_APPROVER")
    if env_approver is not None and env_approver.strip():
        return env_approver.strip()

    try:
        os_user = getpass.getuser()
        if os_user is not None and os_user.strip():
            return os_user.strip()
    except Exception:
        pass

    return None
