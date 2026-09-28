"""Bounded parsers and session-bound approval state for structured CLI events."""

from __future__ import annotations

import hashlib
import json
import re
import time
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Literal

EventKind = Literal[
    "output", "tool_activity", "approval_request", "failure", "cancelled", "turn_ended", "unknown"
]
MAX_EVENT_CHARS = 1_048_576
MAX_RENDER_CHARS = 16_000
MAX_PENDING_APPROVALS = 1_000
MAX_RETIRED_APPROVALS = 10_000

_OSC = re.compile(r"\x1b\][^\x07]*(?:\x07|\x1b\\)")
_CSI = re.compile(r"\x1b(?:\[|\x9b)[0-?]*[ -/]*[@-~]")
_BIDI = re.compile(r"[\u202a-\u202e\u2066-\u2069]")


@dataclass(frozen=True)
class NormalizedEvent:
    provider: str
    kind: EventKind
    raw_type: str
    session_id: str | None = None
    request_id: str | None = None
    text: str = ""
    action: Any = None
    details: dict[str, Any] | None = None


def sanitize_terminal_text(value: str, limit: int = MAX_RENDER_CHARS) -> str:
    value = _OSC.sub("", value)
    value = _CSI.sub("", value)
    value = _BIDI.sub("", value)
    value = "".join(
        char
        for char in value
        if char in "\n\t" or (ord(char) >= 32 and not 127 <= ord(char) <= 159)
    )
    return value[:limit]


def _small_json(value: Any) -> str:
    try:
        result = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    except (TypeError, ValueError):
        return "[unavailable provider details]"
    return sanitize_terminal_text(result, MAX_RENDER_CHARS)


def _event(
    provider: str,
    kind: EventKind,
    raw_type: str,
    *,
    session: str | None = None,
    request: str | None = None,
    text: str = "",
    action: Any = None,
    details: dict[str, Any] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        provider,
        kind,
        raw_type[:200],
        session,
        request,
        sanitize_terminal_text(text),
        action,
        details,
    )


def parse_provider_event(
    provider: str, line: bytes | str, session_id: str | None = None
) -> NormalizedEvent:
    """Parse one complete JSONL record; malformed and unknown records are contained."""
    if isinstance(line, bytes):
        if len(line) > MAX_EVENT_CHARS:
            return _event(
                provider,
                "failure",
                "oversized",
                session=session_id,
                text="Oversized provider event ignored",
            )
        line = line.decode("utf-8", errors="replace")
    if len(line) > MAX_EVENT_CHARS:
        return _event(
            provider,
            "failure",
            "oversized",
            session=session_id,
            text="Oversized provider event ignored",
        )
    try:
        payload = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return _event(
            provider,
            "failure",
            "malformed",
            session=session_id,
            text="Malformed provider event ignored",
        )
    if not isinstance(payload, dict):
        return _event(
            provider,
            "failure",
            "malformed",
            session=session_id,
            text="Non-object provider event ignored",
        )

    if provider == "antigravity":
        raw_type = str(payload.get("event", "unknown"))
        session = payload.get("conversation_id")
        session = session if isinstance(session, str) and session else session_id
        if raw_type == "init":
            init = payload.get("init")
            model = init.get("model") if isinstance(init, dict) else None
            if not isinstance(model, str) or not model:
                model = payload.get("model")
            return _event(
                provider,
                "tool_activity",
                raw_type,
                session=session,
                text="Antigravity session started",
                details={"model": model} if isinstance(model, str) and len(model) <= 128 else None,
            )
        if raw_type == "step_update":
            item = payload.get("step_update")
            if isinstance(item, dict):
                delta = item.get("text_delta")
                if isinstance(delta, str) and delta:
                    return _event(provider, "output", raw_type, session=session, text=delta)
                step = str(item.get("step_type", "step"))[:100]
                return _event(
                    provider, "tool_activity", raw_type, session=session, text=f"Antigravity {step}"
                )
        if raw_type == "result":
            item = payload.get("result")
            if isinstance(item, dict):
                status = str(item.get("status", "unknown"))
                response = item.get("response", "")
                if isinstance(response, str) and response:
                    return _event(
                        provider,
                        "turn_ended" if status == "SUCCESS" else "failure",
                        raw_type,
                        session=session,
                        text=response,
                        details={"provider_status": status},
                    )
                return _event(
                    provider,
                    "turn_ended" if status == "SUCCESS" else "failure",
                    raw_type,
                    session=session,
                    text=f"Antigravity provider status: {status}",
                    details={"provider_status": status},
                )
        return _event(
            provider,
            "unknown",
            raw_type,
            session=session,
            text=f"Unrecognized Antigravity event: {raw_type}",
        )

    if provider == "claude":
        raw_type = str(payload.get("type", "unknown"))
        session = payload.get("session_id")
        session = session if isinstance(session, str) and session else session_id
        if raw_type == "result":
            subtype = str(payload.get("subtype", "unknown"))
            if subtype in {"error", "error_max_turns", "error_during_execution"}:
                return _event(
                    provider,
                    "failure",
                    raw_type,
                    session=session,
                    text=f"Claude provider result: {subtype}",
                )
            return _event(
                provider,
                "turn_ended",
                raw_type,
                session=session,
                text="Claude Code turn ended (review the result and workspace)",
                details={"provider_subtype": subtype},
            )
        if raw_type == "stream_event":
            event = payload.get("event")
            if isinstance(event, dict):
                delta = event.get("delta")
                if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                    return _event(provider, "output", raw_type, session=session, text=delta["text"])
        if raw_type in {"assistant", "user"}:
            message = payload.get("message")
            content = message.get("content") if isinstance(message, dict) else None
            if isinstance(content, list):
                rendered: list[str] = []
                for item in content:
                    if not isinstance(item, dict):
                        continue
                    if item.get("type") == "text" and isinstance(item.get("text"), str):
                        rendered.append(item["text"])
                    elif item.get("type") == "tool_use":
                        return _event(
                            provider,
                            "tool_activity",
                            raw_type,
                            session=session,
                            text=f"Claude tool: {item.get('name', 'unknown')}",
                            action=item.get("input"),
                        )
                if rendered:
                    return _event(
                        provider, "output", raw_type, session=session, text="".join(rendered)
                    )
        if raw_type == "system":
            return _event(
                provider,
                "tool_activity",
                raw_type,
                session=session,
                text="Claude Code session event",
            )
        if raw_type in {"control_request", "control_response"}:
            return _event(
                provider,
                "unknown",
                raw_type,
                session=session,
                text="Claude control event was not used as an approval",
            )
        return _event(
            provider,
            "unknown",
            raw_type,
            session=session,
            text=f"Unrecognized Claude event: {raw_type}",
        )

    if provider == "codex":
        raw_type = str(payload.get("type", payload.get("method", "unknown")))
        if raw_type == "thread.started":
            thread = payload.get("thread_id")
            session = thread if isinstance(thread, str) else session_id
            return _event(
                provider, "tool_activity", raw_type, session=session, text="Codex thread started"
            )
        if raw_type in {"item.agent_message.delta", "item/agentMessage/delta"}:
            delta = payload.get("delta")
            return _event(
                provider,
                "output",
                raw_type,
                session=session_id,
                text=delta if isinstance(delta, str) else "",
            )
        if raw_type in {"item.started", "item.updated", "item.completed"}:
            item = payload.get("item")
            if not isinstance(item, dict):
                return _event(
                    provider,
                    "failure",
                    "malformed",
                    session=session_id,
                    text="Codex item event did not contain an item object",
                )
            item_type = item.get("type")
            if raw_type == "item.completed" and item_type == "agent_message":
                message = item.get("text")
                if isinstance(message, str):
                    return _event(
                        provider,
                        "output",
                        raw_type,
                        session=session_id,
                        text=message,
                        details={"provider_item_type": "agent_message"},
                    )
            if item_type == "error":
                error = item.get("message")
                return _event(
                    provider,
                    "failure",
                    raw_type,
                    session=session_id,
                    text=error if isinstance(error, str) else "Codex reported an item error",
                    details={"provider_item_type": "error"},
                )
            if item_type in {"command_execution", "file_change", "mcp_tool_call", "web_search"}:
                item_status = item.get("status")
                suffix = (
                    f" ({item_status})"
                    if item_status in {"in_progress", "completed", "failed"}
                    else ""
                )
                return _event(
                    provider,
                    "tool_activity",
                    raw_type,
                    session=session_id,
                    text=f"Codex activity: {item_type}{suffix}",
                    details={"provider_item_type": item_type},
                )
            if raw_type == "item.updated" and item_type in {"todo_list", "reasoning"}:
                return _event(
                    provider,
                    "tool_activity",
                    raw_type,
                    session=session_id,
                    text=f"Codex activity: {item_type} updated",
                    details={"provider_item_type": item_type},
                )
            label = item_type if isinstance(item_type, str) else "item"
            return _event(
                provider,
                "unknown",
                raw_type,
                session=session_id,
                text=f"Codex activity: {label}",
            )
        if raw_type in {"turn.completed", "turn/completed"}:
            return _event(
                provider,
                "turn_ended",
                raw_type,
                session=session_id,
                text="Codex turn ended (review the result and workspace)",
            )
        if raw_type in {"error", "turn.failed"}:
            return _event(
                provider, "failure", raw_type, session=session_id, text="Codex reported a failure"
            )
        if raw_type in {"item/commandExecution/requestApproval", "item/fileChange/requestApproval"}:
            request_id = payload.get("id")
            request_id = str(request_id) if request_id is not None else None
            raw_params = payload.get("params")
            params: dict[str, Any] = raw_params if isinstance(raw_params, dict) else {}
            return _event(
                provider,
                "approval_request",
                raw_type,
                session=str(params.get("threadId", session_id)) if params else session_id,
                request=request_id,
                text=f"Codex requests approval for {raw_type.rsplit('/', 1)[-1]}",
                action=params,
                details={"thread_id": params.get("threadId"), "turn_id": params.get("turnId")},
            )
        return _event(
            provider,
            "unknown",
            raw_type,
            session=session_id,
            text=f"Unrecognized Codex event: {raw_type}",
        )

    return _event(
        provider, "unknown", "unknown-provider", session=session_id, text="Unknown provider event"
    )


@dataclass(frozen=True)
class ApprovalTicket:
    ticket_id: str
    provider: str
    session_id: str
    request_id: str
    action_sha256: str
    expires_at: float


class PendingApprovals:
    """One-time decisions bound to an originating live session and exact action."""

    def __init__(self, *, ttl_seconds: float = 300.0, clock: Any = time.monotonic) -> None:
        self.ttl_seconds = ttl_seconds
        self.clock = clock
        self._pending: dict[str, ApprovalTicket] = {}
        self._consumed: OrderedDict[tuple[str, str, str], None] = OrderedDict()

    @staticmethod
    def _action_digest(action: Any) -> str:
        canonical = json.dumps(
            action, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str
        )
        if len(canonical) > MAX_EVENT_CHARS:
            raise ValueError("approval action exceeds the safe size limit")
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _retire(self, key: tuple[str, str, str]) -> None:
        self._consumed[key] = None
        self._consumed.move_to_end(key)
        while len(self._consumed) > MAX_RETIRED_APPROVALS:
            self._consumed.popitem(last=False)

    def issue(self, provider: str, session_id: str, request_id: str, action: Any) -> ApprovalTicket:
        if not provider or not session_id or not request_id:
            raise ValueError("approval requires provider, session, and request identities")
        if len(self._pending) >= MAX_PENDING_APPROVALS:
            raise ValueError("too many pending provider approval requests")
        key = (provider, session_id, request_id)
        if key in self._consumed or any(
            (ticket.provider, ticket.session_id, ticket.request_id) == key
            for ticket in self._pending.values()
        ):
            raise ValueError("duplicate provider approval request")
        ticket = ApprovalTicket(
            str(uuid.uuid4()),
            provider,
            session_id,
            request_id,
            self._action_digest(action),
            self.clock() + self.ttl_seconds,
        )
        self._pending[ticket.ticket_id] = ticket
        return ticket

    def decide(
        self,
        ticket_id: str,
        *,
        provider: str,
        session_id: str,
        request_id: str,
        action: Any,
        choice: str,
    ) -> str:
        if choice not in {"allow", "deny", "cancel"}:
            raise ValueError("approval choice must be allow, deny, or cancel")
        ticket = self._pending.get(ticket_id)
        if ticket is None:
            raise ValueError("approval request is stale or already consumed")
        if ticket.expires_at <= self.clock():
            del self._pending[ticket_id]
            self._retire((ticket.provider, ticket.session_id, ticket.request_id))
            raise ValueError("approval request expired")
        if (
            ticket.provider != provider
            or ticket.session_id != session_id
            or ticket.request_id != request_id
            or ticket.action_sha256 != self._action_digest(action)
        ):
            raise ValueError("approval response does not match the originating request")
        del self._pending[ticket_id]
        self._retire((provider, session_id, request_id))
        return choice

    def close_session(self, provider: str, session_id: str) -> None:
        for ticket_id, ticket in tuple(self._pending.items()):
            if ticket.provider == provider and ticket.session_id == session_id:
                del self._pending[ticket_id]
                self._retire((ticket.provider, ticket.session_id, ticket.request_id))

    def expire(self) -> None:
        now = self.clock()
        for ticket_id, ticket in tuple(self._pending.items()):
            if ticket.expires_at <= now:
                del self._pending[ticket_id]
                self._retire((ticket.provider, ticket.session_id, ticket.request_id))
