"""Route-agnostic non-interactive (bearer-token) auth seam for the dashboard.

Any machine-credential provider plugs in here. A route opts in by registering its exact path via
:func:`register_token_route`; only registered paths are token-authable, so the auth surface of
existing routes never widens. :func:`token_auth_middleware` runs OUTERMOST (installed last) and
owns the decision for a token route: a recognised token attaches ``request.state.token_principal``
+ ``token_authenticated`` (the cookie gates honour that flag and never bounce to /login);
otherwise 401, or 503 when a provider's backing store was unreachable. Fails closed.

Provider-bound pattern routes (:func:`register_bound_token_route`) are the additive variant for
routes that carry path parameters AND keep serving cookie sessions (e.g. the kanban plugin API):
a full-match regex + an explicit method set + the provider names allowed to vouch for it. Only
those providers are consulted; a missing or unrecognised bearer falls through untouched to the
normal gates, so a cookie session or the native bearer keeps working and nothing is widened.
A provider with ``bound_token_routes_only = True`` is consulted ONLY on routes bound to it — it
can never authenticate an exact (legacy) token route such as ``/api/gateway/drain``.
"""
from __future__ import annotations

import logging
import re
import threading
from dataclasses import dataclass
from typing import Awaitable, Callable, Iterable, Optional, Tuple

from fastapi import Request
from fastapi.responses import JSONResponse, Response

from hermes_cli.dashboard_auth import list_token_providers
from hermes_cli.dashboard_auth.audit import AuditEvent, audit_log
from hermes_cli.dashboard_auth.base import ProviderError, TokenPrincipal
from hermes_cli.dashboard_auth.request_utils import (
    client_ip as _client_ip, extract_bearer as extract_bearer_token, unreachable_response)

_log = logging.getLogger(__name__)

_token_routes: set[str] = set()  # exact paths that accept bearer-token auth


@dataclass(frozen=True)
class _BoundTokenRoute:
    """One provider-bound token route: full-match ``pattern`` x ``methods`` -> ``providers``."""
    pattern: re.Pattern[str]
    methods: frozenset[str]
    providers: frozenset[str]


_bound_routes: list[_BoundTokenRoute] = []
_lock = threading.Lock()


def register_token_route(path: str) -> None:
    """Mark ``path`` (exact match) as token-authable. Idempotent; does NOT make the route public."""
    with _lock:
        _token_routes.add(path)


def is_token_route(path: str) -> bool:
    """True if ``path`` was registered as token-authable (exact match)."""
    with _lock:
        return path in _token_routes


def register_bound_token_route(pattern: str, *, methods: Iterable[str], providers: Iterable[str]) -> None:
    """Accept bearer auth on ``pattern`` (``re.fullmatch`` against the decoded path) for
    ``methods`` only, vouched for ONLY by the named ``providers``. Additive: a request with no /
    an unrecognised bearer passes through to the normal gates (never a 401 from this seam).
    Raises ``ValueError`` on an empty method or provider set — binding is mandatory."""
    method_set = frozenset(m.strip().upper() for m in methods if m and m.strip())
    provider_set = frozenset(p.strip() for p in providers if p and p.strip())
    if not method_set or not provider_set:
        raise ValueError("bound token route needs at least one method and one provider")
    route = _BoundTokenRoute(re.compile(pattern), method_set, provider_set)
    with _lock:
        if route not in _bound_routes:
            _bound_routes.append(route)


def match_bound_token_route(method: str, path: str) -> Optional[frozenset[str]]:
    """Provider names bound to ``(method, path)``, or ``None`` when no bound route matches."""
    method = (method or "").upper()
    with _lock:
        routes = list(_bound_routes)
    allowed: set[str] = set()
    for route in routes:
        if method in route.methods and route.pattern.fullmatch(path):
            allowed |= route.providers
    return frozenset(allowed) if allowed else None


def clear_token_routes() -> None:
    """Test-only: drop all registered token routes (exact and bound)."""
    with _lock:
        _token_routes.clear()
        _bound_routes.clear()


def _eligible_providers(allowed: Optional[frozenset[str]]):
    """``allowed`` None (exact route): every token provider except bound-only ones; otherwise
    exactly the named providers."""
    for provider in list_token_providers():
        if allowed is None:
            if getattr(provider, "bound_token_routes_only", False):
                continue
        elif provider.name not in allowed:
            continue
        yield provider


def authenticate_token(
    request: Request, *, allowed: Optional[frozenset[str]] = None,
) -> tuple[Optional[TokenPrincipal], Optional[str]]:
    """Try the eligible token providers against the request's bearer token. Returns
    ``(principal, None)`` on success; ``(None, None)`` for no token or no recogniser (401);
    ``(None, name)`` when no provider accepted it AND at least one was unreachable (caller
    surfaces 503). ``allowed`` restricts the stack to the providers bound to a route. Never raises."""
    token = extract_bearer_token(request)
    if not token:
        return None, None
    unreachable: Optional[str] = None
    for provider in _eligible_providers(allowed):
        try:
            principal = provider.verify_token(token=token)
        except ProviderError as e:
            _log.warning("dashboard-auth: token provider %r unreachable during verify: %s",
                         provider.name, e)
            if unreachable is None:
                unreachable = provider.name
            continue
        except Exception as e:
            _log.warning("dashboard-auth: token provider %r raised during verify: %s",
                         provider.name, e)
            continue
        if principal is not None:
            return principal, None
    return None, unreachable


async def token_auth_middleware(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
    """Pass-through for unregistered paths; for a token route, valid token -> attach principal +
    flag, unreachable -> 503, else 401."""
    path = request.url.path
    if not is_token_route(path):
        allowed = match_bound_token_route(request.method, path)
        if allowed is not None:
            principal, _unreachable = authenticate_token(request, allowed=allowed)
            if principal is not None and principal.provider in allowed:
                request.state.token_principal = principal
                request.state.token_authenticated = True
        # Bound routes are additive: anything not vouched for falls through to the normal gates.
        return await call_next(request)
    principal, unreachable = authenticate_token(request)
    if principal is not None:
        request.state.token_principal = principal
        request.state.token_authenticated = True
        return await call_next(request)
    if unreachable:
        audit_log(
            AuditEvent.TOKEN_AUTH_FAILURE, provider=unreachable, reason="provider_unreachable",
            path=path, ip=_client_ip(request))
        return unreachable_response(unreachable)

    audit_log(
        AuditEvent.TOKEN_AUTH_FAILURE, reason="no_provider_recognises_token", path=path,
        ip=_client_ip(request))
    return JSONResponse({"error": "unauthenticated", "detail": "Unauthorized"}, status_code=401)
