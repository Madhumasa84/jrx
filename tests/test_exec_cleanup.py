"""Offline lifecycle regressions using only processes owned by each test."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from jev_reflex import cli
from jev_reflex.config import ReflexConfig, SessionLimitsConfig
from jev_reflex.session_limits import SessionLimitError

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="uses Linux process state")


def _running(pid: int) -> bool:
    path = Path(f"/proc/{pid}/stat")
    return path.exists() and path.read_text().split()[2] != "Z"


def test_execution_timeout_kills_descendants_after_leader_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("JRX_SESSION_ID", "cleanup-fixture")
    config = ReflexConfig(
        session=SessionLimitsConfig(
            enabled=True, path=str(tmp_path / "sessions.db"), max_execution_seconds=1
        )
    )
    pidfile = tmp_path / "descendant.pid"
    child_source = (
        "import os,signal,time;from pathlib import Path;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        f"Path({str(pidfile)!r}).write_text(str(os.getpid()));time.sleep(30)"
    )
    source = (
        f"import subprocess,sys,time;subprocess.Popen([sys.executable,'-c',{child_source!r}]);"
        "time.sleep(30)"
    )
    try:
        with pytest.raises(SessionLimitError, match="execution time limit"):
            cli._execute_argv([sys.executable, "-c", source], tmp_path, config)
        assert pidfile.exists()
        descendant = int(pidfile.read_text())
        deadline = time.monotonic() + 2
        while _running(descendant) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _running(descendant), "descendant survived execution timeout"
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("error", [RuntimeError, SystemExit])
def test_execution_unexpected_exception_reaps_owned_child(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, error: type[BaseException]
) -> None:
    monkeypatch.setenv("JRX_SESSION_ID", "cleanup-fixture")
    config = ReflexConfig(
        session=SessionLimitsConfig(enabled=True, path=str(tmp_path / "sessions.db"))
    )
    children: list[subprocess.Popen[bytes]] = []
    original = subprocess.Popen

    def spawn(*args: object, **kwargs: object) -> subprocess.Popen[bytes]:
        child = original(*args, **kwargs)
        children.append(child)
        wait = child.wait

        def failing_wait(*args: object, **kwargs: object) -> int:
            child.wait = wait
            raise error("fixture wait failed")

        child.wait = failing_wait
        return child

    monkeypatch.setattr(cli.subprocess, "Popen", spawn)
    try:
        with pytest.raises(error, match="fixture wait failed"):
            cli._execute_argv(
                [sys.executable, "-c", "import time;time.sleep(30)"], tmp_path, config
            )
        assert children[0].poll() is not None
    finally:
        if children and children[0].poll() is None:
            os.killpg(children[0].pid, signal.SIGKILL)
            children[0].wait()


def test_execution_sigterm_cleans_child_and_exits(tmp_path: Path) -> None:
    pidfile = tmp_path / "child.pid"
    source = (
        "import os,signal,time;from pathlib import Path;"
        f"Path({str(pidfile)!r}).write_text(str(os.getpid()));"
        "os.kill(os.getppid(),signal.SIGTERM);time.sleep(30)"
    )
    wrapper = (
        "import os,sys;from pathlib import Path;"
        "from jev_reflex.cli import _execute_argv;"
        "from jev_reflex.config import ReflexConfig,SessionLimitsConfig;"
        "os.environ['JRX_SESSION_ID']='cleanup-fixture';"
        f"config=ReflexConfig(session=SessionLimitsConfig(enabled=True,path={str(tmp_path / 'session.db')!r}));"
        f"_execute_argv([sys.executable,'-c',{source!r}],Path({str(tmp_path)!r}),config)"
    )
    try:
        # Child inherits terminal streams, so use DEVNULL to avoid waiting on
        # orphan-held capture pipes if the wrapper fails to clean up.
        result = subprocess.run(
            [sys.executable, "-c", wrapper],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )
        assert result.returncode == 143
        assert not _running(int(pidfile.read_text()))
    finally:
        if pidfile.exists():
            try:
                os.killpg(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass


@pytest.mark.parametrize("limited", [False, True])
def test_completed_execution_stops_background_descendants_and_restores_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, limited: bool
) -> None:
    monkeypatch.setenv("JRX_SESSION_ID", "cleanup-fixture")
    config = ReflexConfig(
        session=SessionLimitsConfig(enabled=limited, path=str(tmp_path / "sessions.db"))
    )
    pidfile = tmp_path / "descendant.pid"
    child = (
        "import os,signal,time;from pathlib import Path;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        f"Path({str(pidfile)!r}).write_text(str(os.getpid()));time.sleep(30)"
    )
    leader = (
        "import subprocess,sys,time;from pathlib import Path;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        f"p=Path({str(pidfile)!r});"
        "deadline=time.monotonic()+5\n"
        "while not p.exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
        "assert p.exists()\n"
        "sys.exit(7)"
    )
    old_term = signal.getsignal(signal.SIGTERM)
    try:
        assert cli._execute_argv([sys.executable, "-c", leader], tmp_path, config) == 7
        assert signal.getsignal(signal.SIGTERM) == old_term
        descendant = int(pidfile.read_text())
        deadline = time.monotonic() + 2
        while _running(descendant) and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not _running(descendant)
    finally:
        if pidfile.exists():
            try:
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
