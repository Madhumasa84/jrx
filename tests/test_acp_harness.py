"""Exercise the actual ACP SDK against an isolated JSON-RPC agent process."""

import asyncio
import sys

import pytest

pytest.importorskip("acp")

from jev_reflex.workspace.acp_harness import run_acp
from jev_reflex.workspace.state import WorkspaceError, WorkspaceLock

AGENT = r"""
import json,sys,time
mode=sys.argv[1]
def send(obj):
 print(json.dumps(obj),flush=True)
for line in sys.stdin:
 req=json.loads(line); method=req.get('method'); params=req.get('params',{})
 if method=='initialize':
  assert params.get('clientCapabilities',{}).get('terminal',False) is False
  assert params.get('clientCapabilities',{}).get('fs',{}).get('readTextFile',False) is False
  result={'protocolVersion':1,'agentCapabilities':{'loadSession':True}}
 elif method=='session/new': result={'sessionId':'current'}
 elif method=='session/load': result={}
 elif method=='session/prompt':
  if mode=='timeout': time.sleep(30)
  if mode=='filesystem':
   send({'jsonrpc':'2.0','id':'read','method':'fs/read_text_file','params':{'sessionId':params['sessionId'],'path':'/etc/passwd'}})
   response=json.loads(sys.stdin.readline())
   assert response['error']['code']==-32601, response
  send({'jsonrpc':'2.0','method':'session/update','params':{'sessionId':'current','update':{'sessionUpdate':'agent_message_chunk','content':{'type':'text','text':'hello'}}}})
  send({'jsonrpc':'2.0','id':'permission','method':'session/request_permission','params':{'sessionId':'stale' if mode=='stale' else params['sessionId'],'toolCall':{'toolCallId':'call','title':'edit'},'options':[{'optionId':'once','name':'Once','kind':'allow_once'},{'optionId':'always','name':'Always','kind':'allow_always'}]}})
  response=json.loads(sys.stdin.readline())
  outcome=response['result']['outcome']
  expected='selected' if mode=='allow' else 'cancelled'
  assert outcome['outcome']==expected, response
  result={'stopReason':'end_turn'}
 elif method=='session/cancel': continue
 else: continue
 send({'jsonrpc':'2.0','id':req['id'],'result':result})
"""


@pytest.fixture
def setup(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    agent = tmp_path / "agent.py"
    agent.write_text(AGENT)
    return tmp_path, agent


@pytest.mark.parametrize(
    "mode,selection", [("deny", None), ("allow", "once"), ("always", "always"), ("stale", "once")]
)
def test_permissions_and_events(setup, mode, selection):
    workspace, agent = setup
    events, approvals = [], []

    async def approve(request):
        approvals.append(request)
        assert all(x["kind"] == "allow_once" for x in request["options"])
        return selection

    result = asyncio.run(
        run_acp(
            [sys.executable, str(agent), mode],
            workspace,
            "hello",
            events.append,
            approve,
            timeout=5,
        )
    )
    assert result.session_id == "current"
    assert result.stop_reason == "end_turn"
    assert any(e["type"] == "session_update" for e in events)
    assert bool(approvals) == (mode != "stale")


def test_resume(setup):
    workspace, agent = setup
    result = asyncio.run(
        run_acp(
            [sys.executable, str(agent), "deny"],
            workspace,
            "hello",
            lambda e: None,
            resume_session_id="saved",
            timeout=5,
        )
    )
    assert result.session_id == "saved"


def test_timeout_releases_lock(setup):
    workspace, agent = setup
    with pytest.raises(TimeoutError):
        asyncio.run(
            run_acp(
                [sys.executable, str(agent), "timeout"],
                workspace,
                "hello",
                lambda e: None,
                timeout=0.2,
            )
        )
    with WorkspaceLock(workspace):
        pass


def test_cancellation_releases_lock(setup):
    workspace, agent = setup

    async def run():
        started = asyncio.Event()
        task = asyncio.create_task(
            run_acp(
                [sys.executable, str(agent), "timeout"], workspace, "hello", lambda e: started.set()
            )
        )
        await asyncio.wait_for(started.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    asyncio.run(run())
    with WorkspaceLock(workspace):
        pass


def test_existing_writer_blocks_agent(setup):
    workspace, agent = setup
    with WorkspaceLock(workspace), pytest.raises(WorkspaceError, match="already writing"):
        asyncio.run(
            run_acp([sys.executable, str(agent), "deny"], workspace, "hello", lambda e: None)
        )


def test_filesystem_callback_denied(setup):
    workspace, agent = setup
    result = asyncio.run(
        run_acp(
            [sys.executable, str(agent), "filesystem"],
            workspace,
            "hello",
            lambda e: None,
            timeout=5,
        )
    )
    assert result.stop_reason == "end_turn"


def test_permission_callback_failure_denied(setup):
    workspace, agent = setup

    async def broken(request):
        raise RuntimeError("approval unavailable")

    result = asyncio.run(
        run_acp(
            [sys.executable, str(agent), "deny"],
            workspace,
            "hello",
            lambda e: None,
            broken,
            timeout=5,
        )
    )
    assert result.stop_reason == "end_turn"
