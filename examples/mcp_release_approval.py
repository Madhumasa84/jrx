"""Run with python examples/mcp_release_approval.py in an installed JRX environment."""

import json
import shlex
import sys
from contextlib import chdir
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch


def fake_upstream(log: Path, *, drop_reply: bool = False) -> None:
    """Record each call received over stdio before responding."""
    for line in sys.stdin:
        message = json.loads(line)
        if message.get("method") != "tools/call":
            continue
        with log.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(message) + "\n")
        if drop_reply:
            return
        result = {"content": [{"type": "text", "text": "Fake release published"}]}
        print(json.dumps({"jsonrpc": "2.0", "id": message["id"], "result": result}), flush=True)


def demo(directory: Path) -> None:
    import yaml
    from typer.testing import CliRunner

    from jev_reflex.cli import app
    from jev_reflex.enterprise import Identity
    from jev_reflex.models import EvaluationResult, RiskInfo

    config = directory / "reflex.yaml"
    log = directory / "received.jsonl"
    policy = {
        "mode": "enforce",
        "access": {
            "issuer": "https://idp.example",
            "audience": "jrx",
            "jwks_uri": "https://idp.example/jwks",
            "environment": "development",
            "approval_db": str(directory / "approvals.sqlite3"),
            "rules": [
                {
                    "role": role,
                    "actions": [action],
                    "repositories": [str(directory)],
                    "environments": ["development"],
                }
                for role, action in [("developer", "execute"), ("reviewer", "review")]
            ],
        },
        "mcp": {
            "tools": [
                {
                    "server": "github-demo",
                    "name": "publish_release",
                    "effect": "write",
                    "require_approval": True,
                    "argument_constraints": {"/repository": ["example/widgets"]},
                }
            ]
        },
    }
    config.write_text(yaml.safe_dump(policy, sort_keys=False), encoding="utf-8")
    print("Demo uses local identity and semantic evaluator stubs.")
    print(config.read_text(encoding="utf-8"))
    config_args = ["--config", str(config)]
    serve = ["mcp", "serve", "--server", "github-demo", *config_args]
    upstream = ["--", sys.executable, str(Path(__file__).resolve()), "--fake-upstream", str(log)]
    request = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "publish_release",
            "arguments": {
                "repository": "example/widgets",
                "tag": "v1.2.3",
                "notes": "Fix empty release listings.",
            },
        },
    }

    runner = CliRunner()

    def invoke(args: list[str], request_body: dict | None = None) -> str:
        print("$", shlex.join(["jrx", *args]))
        stdin = json.dumps(request_body) + "\n" if request_body is not None else None
        if stdin:
            print(stdin, end="")
        result = runner.invoke(app, args, input=stdin)
        print(result.output, end="")
        if result.exit_code != 0:
            raise SystemExit(result.exit_code)
        return result.stdout

    alice = Identity("alice", frozenset({"developer"}))
    bob = Identity("bob", frozenset({"reviewer"}))
    allow = EvaluationResult(decision="ALLOW", risk=RiskInfo(choice="low"), semantic_source="jev")
    with (
        patch("jev_reflex.mcp_gateway.verified_identity", return_value=alice),
        patch("jev_reflex.mcp_gateway.evaluate_context", return_value=allow),
    ):
        response = json.loads(invoke(serve + upstream, request))
        approval_id = response["result"]["structuredContent"]["approval_id"]
        assert not log.exists()
        print("Upstream calls before review: 0")
        with patch("jev_reflex.cli.verified_identity", return_value=bob):
            invoke(["approval", "pending", *config_args])
            invoke(["approval", "grant", approval_id, *config_args])
        request["id"] = 2
        invoke([*serve, "--approval-id", approval_id, *upstream], request)
        received = [json.loads(line) for line in log.read_text(encoding="utf-8").splitlines()]
        assert received == [request]
        print("Upstream calls after retry:", len(received), json.dumps(received[0]))


if __name__ == "__main__":
    if sys.argv[1:2] == ["--fake-upstream"]:
        fake_upstream(Path(sys.argv[2]), drop_reply="--drop-reply" in sys.argv[3:])
    else:
        with TemporaryDirectory(prefix="jrx-mcp-release-") as temporary, chdir(temporary):
            demo(Path(temporary).resolve())
