"""Tests for the KanbanServiceTokenProvider plugin (kanban API service credential)."""
from __future__ import annotations

import secrets
from unittest.mock import MagicMock

import pytest

import plugins.dashboard_auth.kanban_service as ks
from hermes_cli.dashboard_auth import TokenPrincipal, assert_protocol_compliance
from hermes_cli.dashboard_auth import token_auth


@pytest.fixture(autouse=True)
def _clean_env_and_routes(monkeypatch):
    monkeypatch.delenv("HERMES_DASHBOARD_KANBAN_TOKEN", raising=False)
    token_auth.clear_token_routes()
    yield
    token_auth.clear_token_routes()


def _strong() -> str:
    return secrets.token_urlsafe(32)


class TestProvider:
    def test_protocol_compliance(self):
        assert_protocol_compliance(ks.KanbanServiceTokenProvider(secret=_strong()))

    def test_flags(self):
        p = ks.KanbanServiceTokenProvider(secret=_strong())
        assert p.supports_token is True
        assert p.supports_session is False
        assert p.bound_token_routes_only is True

    def test_verify_token(self):
        secret = _strong()
        p = ks.KanbanServiceTokenProvider(secret=secret)
        assert p.verify_token(token=secret) == TokenPrincipal(
            principal="kanban-service", provider=ks.PROVIDER_NAME, scopes=("kanban",))
        assert p.verify_token(token="") is None
        assert p.verify_token(token=secret + "x") is None
        assert p.verify_session(access_token=secret) is None

    def test_weak_secret_rejected(self):
        with pytest.raises(ValueError):
            ks.KanbanServiceTokenProvider(secret="short")

    def test_repr_does_not_leak_secret(self):
        secret = _strong()
        assert secret not in repr(ks.KanbanServiceTokenProvider(secret=secret))


class TestRegister:
    def test_skips_when_unset(self):
        ctx = MagicMock()
        ks.register(ctx)
        ctx.register_dashboard_auth_provider.assert_not_called()
        assert "HERMES_DASHBOARD_KANBAN_TOKEN" in ks.LAST_SKIP_REASON
        assert token_auth.match_bound_token_route("GET", "/api/plugins/kanban/board") is None

    def test_weak_secret_fails_closed(self, monkeypatch, caplog):
        weak = "a" * 60
        monkeypatch.setenv("HERMES_DASHBOARD_KANBAN_TOKEN", weak)
        ctx = MagicMock()
        ks.register(ctx)
        ctx.register_dashboard_auth_provider.assert_not_called()
        assert token_auth.match_bound_token_route("GET", "/api/plugins/kanban/board") is None
        assert weak not in caplog.text and weak not in ks.LAST_SKIP_REASON

    def test_registers_and_binds_only_bridge_routes(self, monkeypatch, caplog):
        secret = _strong()
        monkeypatch.setenv("HERMES_DASHBOARD_KANBAN_TOKEN", secret)
        ctx = MagicMock()
        with caplog.at_level("DEBUG"):
            ks.register(ctx)
        ctx.register_dashboard_auth_provider.assert_called_once()
        assert secret not in caplog.text
        bound = {ks.PROVIDER_NAME}
        m = token_auth.match_bound_token_route
        assert m("GET", "/api/plugins/kanban/board") == bound
        assert m("POST", "/api/plugins/kanban/tasks") == bound
        assert m("GET", "/api/plugins/kanban/tasks/t_0a1b2c3d") == bound
        assert m("PATCH", "/api/plugins/kanban/tasks/t_0a1b2c3d") == bound
        assert m("POST", "/api/plugins/kanban/tasks/t_0a1b2c3d/comments") == bound
        for method, path in [
            ("DELETE", "/api/plugins/kanban/tasks/t_0a1b2c3d"),
            ("POST", "/api/plugins/kanban/board"),
            ("GET", "/api/plugins/kanban/tasks"),
            ("POST", "/api/plugins/kanban/dispatch"),
            ("POST", "/api/plugins/kanban/tasks/t_0a1b2c3d/reclaim"),
            ("GET", "/api/plugins/kanban/tasks/t_0a1b2c3d/log"),
            ("POST", "/api/plugins/kanban/tasks/bulk/comments/x"),
            ("PATCH", "/api/plugins/kanban/boards/default"),
            ("POST", "/api/gateway/drain"),
            ("GET", "/api/config"),
        ]:
            assert m(method, path) is None, (method, path)
        # Never registered as a legacy exact (any-provider, 401-owning) route.
        assert not token_auth.is_token_route("/api/plugins/kanban/board")
