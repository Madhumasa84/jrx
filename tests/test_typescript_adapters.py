"""The OpenRouter and Pi TypeScript bridges fail closed whenever jrx does not answer.

Each case runs the real example file under Node (type stripping, no build step) with a
fake ``jev-reflex`` on PATH that exits, hangs or prints a chosen answer. One case per
bridge also runs the real ``jrx`` hook to check that a HOLD reaches the host as a block.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
OPENROUTER = ROOT / "examples" / "openrouter" / "jev-reflex.ts"
PI = ROOT / "examples" / "pi" / "jev-reflex.ts"

DRIVER = r"""
const [, , modulePath, kind, event, command] = process.argv;
const mod = await import(modulePath);
let result;
if (kind === "openrouter") {
  result = await mod.hooks[event][0].handler({ toolName: "bash", toolInput: { command } });
} else {
  let handler;
  mod.default({ on: (_name, fn) => { handler = fn; } });
  result = await handler({ toolName: "bash", input: { command } });
}
process.stdout.write(JSON.stringify(result ?? null));
"""


def _node() -> str | None:
    node = shutil.which("node")
    if node is None:
        return None
    probe = subprocess.run(
        [node, "--experimental-strip-types", "-e", ""], capture_output=True, check=False
    )
    return node if probe.returncode == 0 else None


NODE = _node()
pytestmark = pytest.mark.skipif(NODE is None, reason="needs Node.js with type stripping (22.6+)")

FAKES = {
    "verdict": '#!/bin/sh\ncat >/dev/null\nprintf \'%s\' \'{"block":"held","decision":"deny"}\'\n',
    "proceed": "#!/bin/sh\ncat >/dev/null\nprintf '{}'\n",
    "crash": "#!/bin/sh\ncat >/dev/null\nexit 1\n",
    "crash_with_json": "#!/bin/sh\ncat >/dev/null\nprintf '{}'\nexit 1\n",
    "null": "#!/bin/sh\ncat >/dev/null\nprintf 'null'\n",
    "array": "#!/bin/sh\ncat >/dev/null\nprintf '[]'\n",
    "garbage": "#!/bin/sh\ncat >/dev/null\nprintf 'not json'\n",
    "hang": "#!/bin/sh\nexec sleep 30\n",
    # Exits before reading its input, as a usage error or import failure would.
    "early_exit": "#!/bin/sh\nexit 2\n",
}


def _run(
    tmp_path: Path,
    module: Path,
    kind: str,
    event: str,
    *,
    fake: str | None,
    command: str = "ls",
    cwd: Path | None = None,
    real_jrx: bool = False,
) -> object:
    assert NODE is not None
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    target = bin_dir / "jev-reflex"
    if real_jrx:
        target.write_text(f'#!/bin/sh\nexec "{sys.executable}" -m jev_reflex "$@"\n')
    elif fake is not None:
        target.write_text(FAKES[fake])
    if target.exists():
        target.chmod(0o755)
    driver = tmp_path / "driver.mjs"
    driver.write_text(DRIVER)
    env = {
        "PATH": os.pathsep.join([str(bin_dir), str(Path(NODE).parent), "/usr/bin", "/bin"]),
        "HOME": str(tmp_path),
        "JRX_HOOK_TIMEOUT_MS": "1500",
    }
    completed = subprocess.run(
        [NODE, "--experimental-strip-types", "--no-warnings", str(driver), str(module), kind]
        + [event, command],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd or tmp_path,
        timeout=60,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


BRIDGES = [
    pytest.param(OPENROUTER, "openrouter", "PreToolUse", id="openrouter-pre"),
    pytest.param(OPENROUTER, "openrouter", "PermissionRequest", id="openrouter-permission"),
    pytest.param(PI, "pi", "tool_call", id="pi"),
]


def _blocked(kind: str, event: str, output: object) -> bool:
    assert isinstance(output, dict), output
    if kind == "pi" or event == "PreToolUse":
        return bool(output.get("block"))
    return output.get("decision") == "deny"


@pytest.mark.parametrize(("module", "kind", "event"), BRIDGES)
@pytest.mark.parametrize(
    "fake",
    ["crash", "crash_with_json", "early_exit", "null", "array", "garbage", "hang", None],
)
def test_bridge_blocks_when_jrx_does_not_answer(tmp_path, module, kind, event, fake) -> None:
    # None: no jev-reflex on PATH at all.
    output = _run(tmp_path, module, kind, event, fake=fake)
    assert _blocked(kind, event, output), output


@pytest.mark.parametrize(("module", "kind", "event"), BRIDGES)
def test_bridge_passes_jrx_answers_through(tmp_path, module, kind, event) -> None:
    assert _blocked(kind, event, _run(tmp_path, module, kind, event, fake="verdict"))
    proceed = _run(tmp_path, module, kind, event, fake="proceed")
    assert proceed in ({}, None), proceed  # Pi's handler returns nothing to proceed


@pytest.mark.parametrize(("module", "kind", "event"), BRIDGES)
def test_real_jrx_hold_reaches_the_host_as_a_block(tmp_path, module, kind, event) -> None:
    workspace = tmp_path / "workspace"
    (workspace / ".git").mkdir(parents=True)
    (workspace / "reflex.yaml").write_text("mode: enforce\n")
    held = _run(
        tmp_path,
        module,
        kind,
        event,
        fake=None,
        command="rm -rf ./cache",
        cwd=workspace,
        real_jrx=True,
    )
    assert _blocked(kind, event, held), held
