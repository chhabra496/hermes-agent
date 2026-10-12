"""KanbanServiceTokenProvider — shared-bearer service credential for the kanban plugin API.

Lets a local service (an MCP server, a ticket bridge) create, read, comment on and complete
kanban tasks over HTTP while the dashboard login gate is on (``dashboard.public_url`` set or a
non-loopback bind), where the loopback session token is ignored. ``HERMES_DASHBOARD_KANBAN_TOKEN``
(env-only — it is a credential) is compared constant-time against the inbound
``Authorization: Bearer`` value and vouched for as the ``kanban-service`` principal.

Scope is enforced by the token-auth seam, not here: the provider is ``bound_token_routes_only``
and binds itself to the exact method + path-shape pairs in :data:`KANBAN_TOKEN_ROUTES`. It is
never consulted on any other route (``/api/gateway/drain``, other kanban routes, ``DELETE``), and
on a bound route a missing/unrecognised bearer falls through to the normal gate, so cookie
sessions keep working and no route's auth surface widens. Same entropy gate as ``drain``.
"""
from __future__ import annotations

import hmac
import logging
import os
from typing import Optional

from hermes_cli.dashboard_auth import DashboardAuthProvider, Session, TokenPrincipal
from plugins.dashboard_auth._shared import NonInteractiveMixin, SkipRegistration, register_provider
from plugins.dashboard_auth.drain import assess_secret_strength

logger = logging.getLogger(__name__)
_TAG = "dashboard-auth-kanban-service"
PROVIDER_NAME = "kanban-service-token"

_KANBAN = "/api/plugins/kanban"
# One path segment of a task id: ``t_<hex>`` today; a strict charset (no ``/``, ``.``, ``%``) so
# a pattern can never reach a sibling or parent route. Matched against the decoded path.
_TASK_ID = r"[A-Za-z0-9_-]{1,64}"
# (methods, full-match path pattern). Exactly the calls a task bridge needs; nothing destructive.
KANBAN_TOKEN_ROUTES: tuple[tuple[frozenset[str], str], ...] = (
    (frozenset({"GET"}), rf"{_KANBAN}/board"),
    (frozenset({"POST"}), rf"{_KANBAN}/tasks"),
    (frozenset({"GET", "PATCH"}), rf"{_KANBAN}/tasks/{_TASK_ID}"),
    (frozenset({"POST"}), rf"{_KANBAN}/tasks/{_TASK_ID}/comments"),
)

LAST_SKIP_REASON: str = ""


class KanbanServiceTokenProvider(NonInteractiveMixin, DashboardAuthProvider):
    """Non-interactive shared-bearer-secret provider for the kanban plugin API."""

    name = PROVIDER_NAME
    display_name = "Kanban API (service credential)"
    supports_token = True
    supports_session = False
    bound_token_routes_only = True
    _NOT_INTERACTIVE = "KanbanServiceTokenProvider is a non-interactive service credential."
    _NO_START_LOGIN = "KanbanServiceTokenProvider is a non-interactive service credential; there is no login flow."

    def __init__(self, *, secret: str) -> None:
        reason = assess_secret_strength(secret)
        if reason is not None:
            raise ValueError(f"kanban service token rejected: {reason}")
        self._secret = secret

    def verify_token(self, *, token: str) -> Optional[TokenPrincipal]:
        """Constant-time compare; ``kanban-service`` principal on match, else ``None``."""
        if token and hmac.compare_digest(token.encode("utf-8"), self._secret.encode("utf-8")):
            return TokenPrincipal(principal="kanban-service", provider=self.name, scopes=("kanban",))
        return None

    def verify_session(self, *, access_token: str) -> Optional[Session]:
        return None

    def refresh_session(self, *, refresh_token: str) -> Session:
        raise NotImplementedError(self._NOT_INTERACTIVE)

    def revoke_session(self, *, refresh_token: str) -> None:
        return None


def _settings() -> dict:
    """Resolve provider kwargs from env; raises ``SkipRegistration``."""
    secret = os.environ.get("HERMES_DASHBOARD_KANBAN_TOKEN", "").strip()
    if not secret:
        raise SkipRegistration(
            "HERMES_DASHBOARD_KANBAN_TOKEN is not set; the kanban API stays login-only.")
    reason = assess_secret_strength(secret)
    if reason is not None:
        raise SkipRegistration(
            f"HERMES_DASHBOARD_KANBAN_TOKEN rejected — {reason}. The kanban service credential "
            "stays disabled (fail-closed).", level="warning")
    return {"secret": secret}


def register(ctx) -> None:
    """Register the provider and bind it to :data:`KANBAN_TOKEN_ROUTES` when a strong secret is
    set; no-op (records a skip reason) otherwise."""
    global LAST_SKIP_REASON
    LAST_SKIP_REASON = ""
    kwargs, LAST_SKIP_REASON = register_provider(ctx, logger, _TAG, KanbanServiceTokenProvider, _settings)
    if kwargs is None:
        return
    try:
        from hermes_cli.dashboard_auth.token_auth import register_bound_token_route

        for methods, pattern in KANBAN_TOKEN_ROUTES:
            register_bound_token_route(pattern, methods=methods, providers=(PROVIDER_NAME,))
    except Exception as exc:
        logger.warning("%s: could not bind kanban token routes: %s", _TAG, exc)
        return
    logger.info("%s: registered kanban service credential (%d bound routes)", _TAG, len(KANBAN_TOKEN_ROUTES))
