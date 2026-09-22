"""Read-only, OIDC-protected operations dashboard over existing host data."""

from __future__ import annotations

import json
import sqlite3
import time
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import requests
import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .audit import AuditLog
from .broker import BrokerClient
from .config import AccessConfig, ReflexConfig
from .enterprise import AccessDenied, Identity, authorize, verified_identity
from .policy_rollout import RolloutStore, policy_hash


class DashboardSource(BaseModel):
    model_config = ConfigDict(extra="forbid")

    team: str
    repository: str
    policy_path: str
    audit_path: str
    audit_public_key_path: str | None = None
    approval_db: str | None = None
    rollout_state_path: str | None = None
    broker_socket: str | None = None
    metrics_port: int | None = Field(default=None, ge=1, le=65535)


class DashboardConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    access: AccessConfig
    sources: list[DashboardSource]

    @model_validator(mode="after")
    def _validate_dashboard(self) -> DashboardConfig:
        if self.access.environment != "dashboard" or not self.sources:
            raise ValueError("dashboard requires access.environment=dashboard and sources")
        return self


def load_dashboard_config(path: Path) -> DashboardConfig:
    return DashboardConfig.model_validate(yaml.safe_load(path.read_text(encoding="utf-8")))


def _pending(path: str | None, repository: str) -> list[dict[str, Any]]:
    if not path or not Path(path).expanduser().exists():
        return []
    uri = Path(path).expanduser().resolve().as_uri() + "?mode=ro"
    with sqlite3.connect(uri, uri=True, timeout=2) as connection:
        rows = connection.execute(
            "SELECT id, requester, repository, environment, summary, expires, required "
            "FROM approvals WHERE consumed=0 AND expires>? AND repository=? ORDER BY expires LIMIT 100",
            (time.time(), repository),
        ).fetchall()
        return [
            {
                "id": approval_id,
                "requester": requester,
                "repository": repository,
                "environment": environment,
                "summary": summary,
                "expires": expires,
                "grants": connection.execute(
                    "SELECT COUNT(*) FROM grants WHERE approval_id=?", (approval_id,)
                ).fetchone()[0],
                "required": required,
            }
            for approval_id, requester, repository, environment, summary, expires, required in rows
        ]


def _metrics(port: int | None) -> dict[str, float]:
    if port is None:
        return {}
    response = requests.get(f"http://127.0.0.1:{port}/metrics", timeout=2, allow_redirects=False)
    response.raise_for_status()
    if len(response.content) > 200_000:
        raise ValueError("metrics response is too large")
    allowed = {
        "jrx_broker_uptime_seconds",
        "jrx_policy_reload_total",
        "jrx_degraded_evaluations_total",
        "jrx_decisions_total",
    }
    values: dict[str, float] = {}
    for line in response.text.splitlines():
        if line.startswith("#") or " " not in line:
            continue
        name, value = line.split(" ", 1)
        if name.split("{", 1)[0] in allowed and len(values) < 30:
            values[name] = float(value.strip())
    return values


def snapshot(config: DashboardConfig, identity: Identity) -> dict[str, Any]:
    """Aggregate authorized teams; never expose data from an invalid audit chain."""
    teams = []
    for source in config.sources:
        try:
            authorize(identity, config.access, "view", source.repository, "dashboard")
        except AccessDenied:
            continue
        result: dict[str, Any] = {"team": source.team, "repository": source.repository}
        try:
            policy = ReflexConfig.model_validate(
                yaml.safe_load(Path(source.policy_path).expanduser().read_text(encoding="utf-8"))
            )
            result["active_policy_hash"] = policy_hash(policy)
            if source.rollout_state_path:
                rollout = RolloutStore(Path(source.rollout_state_path)).status()
                result["rollout"] = rollout
                if rollout["active_hash"]:
                    result["active_policy_hash"] = rollout["active_hash"]
            audit_path = Path(source.audit_path).expanduser()
            audit_config = policy.model_copy(
                update={"audit": policy.audit.model_copy(update={"path": str(audit_path)})}
            )
            valid, message = AuditLog(audit_config).verify(
                Path(source.audit_public_key_path).expanduser()
                if source.audit_public_key_path
                else None
            )
            result["audit_integrity"] = {"valid": valid, "message": message}
            if not valid:
                result["error"] = "Audit chain verification failed"
                teams.append(result)
                continue
            entries = []
            if audit_path.exists():
                with audit_path.open(encoding="utf-8") as handle:
                    entries = [json.loads(line) for line in handle if line.strip()]
            decisions = Counter(
                entry.get("policy_decision")
                for entry in entries
                if entry.get("event_type", "policy_decision") == "policy_decision"
                and entry.get("policy_decision") in {"ALLOW", "REVIEW", "HOLD"}
            )
            result["decisions"] = {name: decisions[name] for name in ("ALLOW", "REVIEW", "HOLD")}
            result["blocked"] = [
                {
                    "timestamp": entry.get("timestamp_utc"),
                    "action": entry.get("action_summary"),
                    "policy_hash": entry.get("policy_version_hash"),
                }
                for entry in entries
                if entry.get("policy_decision") == "HOLD"
            ][-20:][::-1]
            result["overrides"] = [
                {
                    "timestamp": entry.get("timestamp_utc"),
                    "identity": entry.get("identity"),
                    "action": entry.get("action_summary"),
                    "original_decision": entry.get("original_decision"),
                }
                for entry in entries
                if entry.get("event_type") == "human_override"
            ][-20:][::-1]
            result["pending_approvals"] = _pending(source.approval_db, source.repository)
            if source.broker_socket:
                broker_config = policy.model_copy(
                    update={
                        "jev": policy.jev.model_copy(
                            update={"socket": source.broker_socket, "transport": "broker"}
                        )
                    }
                )
                result["broker"] = BrokerClient(broker_config).health()
            else:
                result["broker"] = {"running": False, "status": "not configured"}
            try:
                result["metrics"] = _metrics(source.metrics_port)
            except (requests.RequestException, ValueError):
                result["metrics"] = {}
        except (OSError, ValueError, sqlite3.Error) as exc:
            result["error"] = type(exc).__name__
        teams.append(result)
    return {"generated_at": time.time(), "teams": teams}


_HTML = b"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>JEV Reflex Operations</title><style>body{font:16px system-ui;margin:2rem;max-width:90rem;color:#162235;background:#f7f9fc}h1{margin-bottom:.2rem}label{display:block;margin:1rem 0}input{width:min(32rem,90%);padding:.5rem}button{padding:.55rem 1rem}section{background:white;border:1px solid #d5dce6;border-radius:.5rem;padding:1rem;margin:1rem 0}pre{white-space:pre-wrap;overflow-wrap:anywhere}.bad{color:#aa1f31}</style></head><body><h1>JEV Reflex Operations</h1><p>Verified policy and approval status across authorized teams.</p><label>OIDC token <input id="token" type="password" autocomplete="off"></label><button id="load">Load dashboard</button><p id="message" role="status"></p><main id="teams"></main><script src="/app.js"></script></body></html>"""

_JS = """document.getElementById('load').onclick=async()=>{const token=document.getElementById('token').value;const message=document.getElementById('message');const root=document.getElementById('teams');root.replaceChildren();try{const response=await fetch('/api/summary',{headers:{Authorization:'Bearer '+token},cache:'no-store'});if(!response.ok)throw Error('Access denied or dashboard unavailable');const data=await response.json();message.textContent=data.teams.length+' team(s) visible';for(const team of data.teams){const section=document.createElement('section');const title=document.createElement('h2');title.textContent=team.team+' · '+team.repository;section.append(title);for(const [label,value] of Object.entries({ 'Active policy':team.active_policy_hash,'Rollout':team.rollout,'Broker':team.broker,'Decisions':team.decisions,'Blocked actions':team.blocked,'Pending approvals':team.pending_approvals,'Overrides':team.overrides,'Metrics':team.metrics,'Audit integrity':team.audit_integrity,'Error':team.error})){if(value===undefined)continue;const heading=document.createElement('h3');heading.textContent=label;const body=document.createElement('pre');body.textContent=typeof value==='string'?value:JSON.stringify(value,null,2);section.append(heading,body)}root.append(section)}}catch(error){message.textContent=error.message;message.className='bad'}};""".encode()


def make_handler(config: DashboardConfig):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.path == "/":
                self._send(200, "text/html; charset=utf-8", _HTML)
            elif self.path == "/app.js":
                self._send(200, "application/javascript; charset=utf-8", _JS)
            elif self.path == "/api/summary":
                authorization = self.headers.get("Authorization", "")
                if not authorization.startswith("Bearer "):
                    self._send(401, "application/json", b'{"error":"authentication required"}')
                    return
                try:
                    identity = verified_identity(config.access, authorization[7:])
                    body = json.dumps(snapshot(config, identity)).encode()
                    self._send(200, "application/json", body)
                except AccessDenied:
                    self._send(403, "application/json", b'{"error":"access denied"}')
            else:
                self._send(404, "text/plain", b"Not found")

        def _send(self, status: int, content_type: str, body: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header(
                "Content-Security-Policy",
                "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
            )
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format: str, *args: object) -> None:
            return

    return Handler


def serve(config: DashboardConfig, host: str = "127.0.0.1", port: int = 8080) -> None:
    if host not in {"127.0.0.1", "::1"}:
        raise ValueError("dashboard must bind to loopback; use an authenticated HTTPS proxy")
    with ThreadingHTTPServer((host, port), make_handler(config)) as server:
        server.serve_forever()
