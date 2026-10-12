"""Contract tests for the generic non-interactive (bearer-token) auth seam.

Covers Task 2.0a: the reusable token-auth capability in the dashboard auth
framework — NOT the drain plugin (that's 2.0b/2.1). Asserts the ABC capability
flag, the registry filter, bearer extraction, provider stacking (verify_token),
and the route-agnostic middleware seam's fail-closed / 503 / pass-through
behaviour.
"""
from __future__ import annotations

import asyncio
from typing import Optional

import pytest

from hermes_cli.dashboard_auth import (
    DashboardAuthProvider,
    LoginStart,
    Session,
    TokenPrincipal,
    clear_providers,
    list_providers,
    list_session_providers,
    list_token_providers,
    register_provider,
)
from hermes_cli.dashboard_auth.base import ProviderError
from hermes_cli.dashboard_auth import token_auth


# --------------------------------------------------------------------------
# Test doubles
# --------------------------------------------------------------------------


class _OAuthOnly(DashboardAuthProvider):
    """A pure interactive provider — never token-authable."""

    name = "oauth-only"
    display_name = "OAuth Only"

    def start_login(self, *, redirect_uri):
        return LoginStart(redirect_url="x", cookie_payload={})

    def complete_login(self, *, code, state, code_verifier, redirect_uri):
        return Session("u", "e", "n", "o", self.name, 0, "a", "r")

    def verify_session(self, *, access_token):
        return None

    def refresh_session(self, *, refresh_token):
        return Session("u", "e", "n", "o", self.name, 0, "a", "r")

    def revoke_session(self, *, refresh_token):
        return None


class _TokenProvider(_OAuthOnly):
    """A token provider that accepts exactly one secret."""

    name = "tok"
    display_name = "Token Provider"
    supports_token = True

    def __init__(self, *, secret: str = "good-secret", scopes=("drain",)):
        self._secret = secret
        self._scopes = tuple(scopes)

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        if token == self._secret:
            return TokenPrincipal(
                principal=self.name, provider=self.name, scopes=self._scopes
            )
        return None


class _UnreachableTokenProvider(_OAuthOnly):
    name = "tok-down"
    display_name = "Unreachable Token Provider"
    supports_token = True

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        raise ProviderError("backing store down")


class _BuggyTokenProvider(_OAuthOnly):
    name = "tok-buggy"
    display_name = "Buggy Token Provider"
    supports_token = True

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        raise RuntimeError("kaboom")


# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _isolated_state():
    clear_providers()
    token_auth.clear_token_routes()
    yield
    clear_providers()
    token_auth.clear_token_routes()


class _FakeURL:
    def __init__(self, path):
        self.path = path


class _FakeClient:
    host = "1.2.3.4"


class _FakeRequest:
    """Minimal Request stand-in for the seam (no real Starlette needed)."""

    def __init__(self, path="/api/gateway/drain", headers=None):
        self.url = _FakeURL(path)
        self.headers = headers or {}
        self.client = _FakeClient()

        class _State:
            pass

        self.state = _State()


def _run(coro):
    return asyncio.run(coro)


# --------------------------------------------------------------------------
# ABC + registry
# --------------------------------------------------------------------------


def test_oauth_provider_defaults_supports_token_false():
    assert _OAuthOnly().supports_token is False




class _NonInteractiveProvider(_TokenProvider):
    """A token-only credential with no interactive session."""

    name = "svc-cred"
    display_name = "Service Credential"
    supports_session = False


# --------------------------------------------------------------------------
# Bearer extraction
# --------------------------------------------------------------------------




# --------------------------------------------------------------------------
# authenticate_token (provider stacking)
# --------------------------------------------------------------------------


def test_authenticate_token_accepts_valid():
    register_provider(_TokenProvider(secret="good-secret"))
    req = _FakeRequest(headers={"authorization": "Bearer good-secret"})
    principal, unreachable = token_auth.authenticate_token(req)
    assert unreachable is None
    assert principal is not None
    assert principal.provider == "tok"
    assert principal.scopes == ("drain",)


def test_authenticate_token_rejects_wrong_secret():
    register_provider(_TokenProvider(secret="good-secret"))
    req = _FakeRequest(headers={"authorization": "Bearer wrong"})
    principal, unreachable = token_auth.authenticate_token(req)
    assert principal is None
    assert unreachable is None


def test_authenticate_token_stacks_first_match_wins():
    register_provider(_TokenProvider(secret="aaa"))
    second = _TokenProvider(secret="bbb")
    second.name = "tok2"
    register_provider(second)
    req = _FakeRequest(headers={"authorization": "Bearer bbb"})
    principal, _ = token_auth.authenticate_token(req)
    assert principal is not None and principal.provider == "tok2"


def test_authenticate_token_unreachable_then_valid_provider_wins():
    register_provider(_UnreachableTokenProvider())
    register_provider(_TokenProvider(secret="good"))
    req = _FakeRequest(headers={"authorization": "Bearer good"})
    principal, unreachable = token_auth.authenticate_token(req)
    # A later provider accepting the token beats the earlier outage.
    assert principal is not None and principal.provider == "tok"
    assert unreachable is None


def test_authenticate_token_buggy_provider_does_not_crash():
    register_provider(_BuggyTokenProvider())
    register_provider(_TokenProvider(secret="good"))
    req = _FakeRequest(headers={"authorization": "Bearer good"})
    principal, _unreachable = token_auth.authenticate_token(req)
    assert principal is not None and principal.provider == "tok"


# --------------------------------------------------------------------------
# Middleware seam (route-agnostic)
# --------------------------------------------------------------------------


async def _call_next_ok(request):
    from fastapi.responses import JSONResponse

    return JSONResponse({"ok": True}, status_code=200)






def test_seam_rejects_wrong_token_401():
    register_provider(_TokenProvider(secret="good"))
    token_auth.register_token_route("/api/gateway/drain")
    req = _FakeRequest(
        path="/api/gateway/drain", headers={"authorization": "Bearer bad"}
    )
    resp = _run(token_auth.token_auth_middleware(req, _call_next_ok))
    assert resp.status_code == 401




# --------------------------------------------------------------------------
# Provider-bound pattern routes (register_bound_token_route)
# --------------------------------------------------------------------------


class _BoundOnlyProvider(_TokenProvider):
    """A token provider that may only vouch for routes bound to it."""

    name = "bound"
    display_name = "Bound Provider"
    bound_token_routes_only = True

    def __init__(self, *, secret: str = "bound-secret"):
        super().__init__(secret=secret, scopes=("kanban",))


class _MethodRequest(_FakeRequest):
    def __init__(self, method="GET", **kw):
        super().__init__(**kw)
        self.method = method


_TASK = r"/api/plugins/kanban/tasks/[A-Za-z0-9_-]{1,64}"


async def _call_next_state(request):
    from fastapi.responses import JSONResponse

    return JSONResponse(
        {"token_authenticated": getattr(request.state, "token_authenticated", False)}, status_code=200)


def _seam(req):
    import json as _json

    resp = _run(token_auth.token_auth_middleware(req, _call_next_state))
    return resp.status_code, _json.loads(resp.body)


def test_bound_route_requires_method_and_provider():
    with pytest.raises(ValueError):
        token_auth.register_bound_token_route(_TASK, methods=(), providers=("bound",))
    with pytest.raises(ValueError):
        token_auth.register_bound_token_route(_TASK, methods=("GET",), providers=())


def test_bound_route_full_match_and_method_only():
    token_auth.register_bound_token_route(_TASK, methods=("get", "PATCH"), providers=("bound",))
    assert token_auth.match_bound_token_route("GET", "/api/plugins/kanban/tasks/t_ab12") == {"bound"}
    assert token_auth.match_bound_token_route("PATCH", "/api/plugins/kanban/tasks/t_ab12") == {"bound"}
    # Method not bound, sibling/child paths, traversal and encoded separators never match.
    for method, path in [
        ("DELETE", "/api/plugins/kanban/tasks/t_ab12"),
        ("GET", "/api/plugins/kanban/tasks/t_ab12/log"),
        ("GET", "/api/plugins/kanban/tasks/.."),
        ("GET", "/api/plugins/kanban/tasks/t_ab12/../../config"),
        ("GET", "/api/plugins/kanban/tasks/t%2Fx"),
        ("GET", "/api/plugins/kanban/tasks/"),
        ("GET", "/x/api/plugins/kanban/tasks/t_ab12"),
    ]:
        assert token_auth.match_bound_token_route(method, path) is None, (method, path)


def test_bound_route_valid_token_authenticates():
    register_provider(_BoundOnlyProvider())
    token_auth.register_bound_token_route(_TASK, methods=("GET",), providers=("bound",))
    req = _MethodRequest(path="/api/plugins/kanban/tasks/t_1", headers={"authorization": "Bearer bound-secret"})
    assert _seam(req) == (200, {"token_authenticated": True})
    assert req.state.token_principal.provider == "bound"


def test_bound_route_missing_or_wrong_token_falls_through_unauthenticated():
    """Additive: no 401 from the seam, and nothing attached — the normal gates decide."""
    register_provider(_BoundOnlyProvider())
    token_auth.register_bound_token_route(_TASK, methods=("GET",), providers=("bound",))
    for headers in ({}, {"authorization": "Bearer wrong"}, {"authorization": "Basic Ym91bmQtc2VjcmV0"}):
        req = _MethodRequest(path="/api/plugins/kanban/tasks/t_1", headers=headers)
        assert _seam(req) == (200, {"token_authenticated": False})
        assert not hasattr(req.state, "token_principal")


def test_bound_route_ignores_unbound_providers():
    """A different token provider (e.g. drain) can never vouch for a bound route."""
    register_provider(_TokenProvider(secret="drain-secret"))
    register_provider(_BoundOnlyProvider())
    token_auth.register_bound_token_route(_TASK, methods=("GET",), providers=("bound",))
    req = _MethodRequest(path="/api/plugins/kanban/tasks/t_1", headers={"authorization": "Bearer drain-secret"})
    assert _seam(req) == (200, {"token_authenticated": False})


def test_bound_only_provider_never_authenticates_exact_token_route():
    """A bound-only credential is not consulted on a legacy exact route (/api/gateway/drain)."""
    register_provider(_BoundOnlyProvider())
    token_auth.register_token_route("/api/gateway/drain")
    req = _MethodRequest(method="POST", path="/api/gateway/drain", headers={"authorization": "Bearer bound-secret"})
    resp = _run(token_auth.token_auth_middleware(req, _call_next_ok))
    assert resp.status_code == 401
    assert not getattr(req.state, "token_authenticated", False)


def test_bound_route_unmatched_path_untouched():
    register_provider(_BoundOnlyProvider())
    token_auth.register_bound_token_route(_TASK, methods=("GET",), providers=("bound",))
    req = _MethodRequest(path="/api/sessions", headers={"authorization": "Bearer bound-secret"})
    assert _seam(req) == (200, {"token_authenticated": False})
