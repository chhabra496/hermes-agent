"""End-to-end: the kanban service credential under the dashboard login gate.

Real ``web_server.app`` with ``auth_required`` True (as with ``dashboard.public_url`` set), the
real kanban plugin router mounted, and the bundled ``kanban_service`` provider registered from
``HERMES_DASHBOARD_KANBAN_TOKEN``. Pins: the bridge calls succeed with the bearer; everything
else (no/wrong bearer, DELETE, other kanban routes, non-kanban routes, the drain route, the
legacy session-token header) is still refused by the gate.
"""
from __future__ import annotations

import importlib.util
import secrets
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from hermes_cli import kanban_db as kb
from hermes_cli import web_server
from hermes_cli.dashboard_auth import clear_providers, register_provider, token_auth
from tests.hermes_cli.conftest_dashboard_auth import StubAuthProvider

_SECRET = secrets.token_urlsafe(32)
_K = "/api/plugins/kanban"


def _kanban_router():
    plugin_file = Path(__file__).resolve().parents[2] / "plugins" / "kanban" / "dashboard" / "plugin_api.py"
    spec = importlib.util.spec_from_file_location("hermes_dashboard_plugin_kanban_gate_test", plugin_file)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod.router


@pytest.fixture(scope="module", autouse=True)
def _mount_kanban():
    web_server.app.include_router(_kanban_router(), prefix=_K)


@pytest.fixture
def gated(tmp_path, monkeypatch):
    home = tmp_path / ".hermes"
    home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    kb.init_db()
    monkeypatch.setattr(web_server, "_get_dashboard_plugins", lambda: [{"name": "kanban", "source": "bundled"}])
    monkeypatch.setenv("HERMES_DASHBOARD_KANBAN_TOKEN", _SECRET)

    import plugins.dashboard_auth.kanban_service as ks

    clear_providers()
    token_auth.clear_token_routes()
    register_provider(StubAuthProvider())

    class _Ctx:
        @staticmethod
        def register_dashboard_auth_provider(p):
            register_provider(p)

    ks.register(_Ctx())
    state = web_server.app.state
    prev = {k: getattr(state, k, None) for k in ("bound_host", "bound_port", "auth_required")}
    state.bound_host, state.bound_port, state.auth_required = "127.0.0.1", 9119, True
    yield TestClient(web_server.app, base_url="http://127.0.0.1:9119")
    for k, v in prev.items():
        setattr(state, k, v)
    clear_providers()
    token_auth.clear_token_routes()


def _auth(token=_SECRET):
    return {"Authorization": f"Bearer {token}"}


def test_bridge_calls_succeed_with_bearer(gated):
    r = gated.get(f"{_K}/board?board=default", headers=_auth())
    assert r.status_code == 200, r.text
    r = gated.post(f"{_K}/tasks?board=default", json={"title": "from cortex"}, headers=_auth())
    assert r.status_code == 200, r.text
    tid = r.json()["task"]["id"]
    assert gated.get(f"{_K}/tasks/{tid}?board=default", headers=_auth()).status_code == 200
    r = gated.post(f"{_K}/tasks/{tid}/comments?board=default", json={"body": "hi", "author": "cortex"}, headers=_auth())
    assert r.status_code == 200, r.text
    r = gated.patch(f"{_K}/tasks/{tid}?board=default", json={"status": "done", "summary": "ok"}, headers=_auth())
    assert r.status_code == 200, r.text
    assert r.json()["task"]["status"] == "done"


def test_gate_still_refuses_without_valid_bearer(gated):
    assert gated.get(f"{_K}/board").status_code == 401
    assert gated.get(f"{_K}/board", headers=_auth("not-the-token")).status_code == 401
    # The legacy loopback session-token header is ignored under the gate.
    assert gated.get(f"{_K}/board", headers={"X-Hermes-Session-Token": _SECRET}).status_code == 401


def test_token_never_authenticates_unbound_routes(gated):
    r = gated.post(f"{_K}/tasks", json={"title": "x"}, headers=_auth())
    tid = r.json()["task"]["id"]
    assert gated.delete(f"{_K}/tasks/{tid}", headers=_auth()).status_code == 401
    assert gated.get(f"{_K}/stats", headers=_auth()).status_code == 401
    assert gated.post(f"{_K}/dispatch", headers=_auth()).status_code == 401
    assert gated.get(f"{_K}/tasks/{tid}/log", headers=_auth()).status_code == 401
    assert gated.get("/api/sessions", headers=_auth()).status_code == 401
    assert gated.get("/api/config", headers=_auth()).status_code == 401
    # Even with the drain route registered as an exact token route, this credential is not consulted.
    token_auth.register_token_route("/api/gateway/drain")
    assert gated.post("/api/gateway/drain", json={"action": "cancel"}, headers=_auth()).status_code == 401
