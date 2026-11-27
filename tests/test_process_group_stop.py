"""Stopping an owned command's process group on every POSIX host CI runs.

CI run 46022808978 (job 140586481461, macOS, commit 214f067) failed
``test_sandbox_timeout_stops_the_container_and_returns_timeout``: after the sandbox
timeout fired and the leader was reaped, ``os.killpg(pgid, SIGKILL)`` raised
``PermissionError`` (EPERM) and replaced the expected ``TimeoutExpired``. macOS refuses
to signal a process group whose remaining members have exited but are not yet reaped;
Linux delivers the signal. These tests create that state deterministically with an
owned, inert child process.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time

import pytest

from jev_reflex import cli

pytestmark = pytest.mark.skipif(os.name != "posix", reason="process groups are POSIX-only")


def _exited_unreaped_leader() -> subprocess.Popen[bytes]:
    """A new process group whose only member has exited but is not yet reaped."""
    process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
    # Nothing calls wait() on the child, so once it exits it stays a zombie. macOS Python
    # has no os.waitid(WNOWAIT), so ask ps for the state instead.
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        state = subprocess.run(
            ["ps", "-o", "stat=", "-p", str(process.pid)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if state.startswith("Z"):
            return process
        time.sleep(0.01)
    process.kill()
    process.wait()
    pytest.fail("the child process did not exit")


def test_stop_execution_tolerates_a_group_whose_members_have_all_exited() -> None:
    process = _exited_unreaped_leader()
    cli._stop_execution(process)
    assert process.returncode == 0


def test_stop_execution_reaps_the_leader_when_the_group_cannot_be_signalled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[int] = []

    def refuse(pgid: int, signum: int) -> None:
        sent.append(signum)
        raise PermissionError(1, "Operation not permitted")

    process = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"], start_new_session=True
    )
    monkeypatch.setattr(cli.os, "killpg", refuse)
    try:
        cli._stop_execution(process)
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()
    assert sent == [signal.SIGTERM, signal.SIGKILL]
    # The running leader was signalled directly and reaped, not left behind.
    assert process.returncode == -signal.SIGTERM
