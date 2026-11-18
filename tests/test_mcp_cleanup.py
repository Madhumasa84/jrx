"""Real upstream process cleanup on EOF and interrupted gateway input."""

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Linux process-state checks")


@pytest.mark.parametrize("outcome", ["completed", "RuntimeError", "SystemExit"])
def test_gateway_exit_cleans_upstream_and_descendants(tmp_path, outcome):
    parent_pid = tmp_path / "parent.pid"
    child_pid = tmp_path / "child.pid"
    child = (
        "import os,signal,time;from pathlib import Path;"
        "signal.signal(signal.SIGTERM,signal.SIG_IGN);"
        f"Path({str(child_pid)!r}).write_text(str(os.getpid()));time.sleep(30)"
    )
    parent = (
        "import os,subprocess,sys,time;from pathlib import Path;"
        f"Path({str(parent_pid)!r}).write_text(str(os.getpid()));"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        f"p=Path({str(child_pid)!r});deadline=time.monotonic()+5\n"
        "while not p.exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
        "assert p.exists()\n" + ("sys.exit(0)" if outcome == "completed" else "time.sleep(30)")
    )
    failure = "return b''" if outcome == "completed" else f"raise {outcome}('input failed')"
    wrapper = (
        "import io,sys,time;from pathlib import Path\n"
        "from jev_reflex.config import ReflexConfig\n"
        "from jev_reflex.mcp_gateway import MCPGateway\n"
        "class Source:\n"
        " def readline(self, limit):\n"
        f"  p=Path({str(child_pid)!r});deadline=time.monotonic()+5\n"
        "  while not p.exists() and time.monotonic()<deadline: time.sleep(0.01)\n"
        "  assert p.exists()\n"
        f"  {failure}\n"
        f"gateway=MCPGateway(ReflexConfig(),'test',[sys.executable,'-c',{parent!r}],source=Source(),sink=io.BytesIO())\n"
        "try:\n"
        " code=gateway.run()\n"
        "except BaseException as exc:\n"
        f" assert type(exc).__name__=={outcome!r}\n"
        "else:\n"
        f" assert {outcome!r}=='completed' and code==0\n"
        "assert gateway._upstream_group is None\n"
    )
    try:
        result = subprocess.run(
            [sys.executable, "-c", wrapper],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=10,
        )
        assert result.returncode == 0, result.stderr.decode()
        path = Path(f"/proc/{int(child_pid.read_text())}/stat")
        deadline = time.monotonic() + 2
        while path.exists() and path.read_text().split()[2] != "Z" and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not path.exists() or path.read_text().split()[2] == "Z"
    finally:
        if parent_pid.exists():
            try:
                os.killpg(int(parent_pid.read_text()), signal.SIGKILL)
            except ProcessLookupError:
                pass
