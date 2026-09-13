"""Credential broker contract — the enforcement point for axiom 1.

    Agent ∌ PAT / private key / long-lived token

Agents submit *action requests*. Only the governance core calls a broker, and the
broker hands back a :class:`Grant` whose token:

* is never returned through any MCP tool result,
* never appears in ``repr``/``str``/logs/JSON,
* carries an explicit scope and an expiry, checked on every use,
* is the narrowest and shortest-lived thing that satisfies the request (axiom 5).
"""

from __future__ import annotations

import abc
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum


class TokenScope(StrEnum):
    """Scopes the broker understands, ordered from least to most dangerous."""

    READ_METADATA = "read_metadata"
    READ_CONTENT = "read_content"
    WRITE_METADATA = "write_metadata"
    WRITE_CONTENT_PR = "write_content_pr"
    WRITE_CONTENT_DIRECT = "write_content_direct"
    ADMIN = "admin"


SCOPE_RANK: dict[TokenScope, int] = {
    TokenScope.READ_METADATA: 0,
    TokenScope.READ_CONTENT: 1,
    TokenScope.WRITE_METADATA: 2,
    TokenScope.WRITE_CONTENT_PR: 3,
    TokenScope.WRITE_CONTENT_DIRECT: 4,
    TokenScope.ADMIN: 5,
}

READ_SCOPES = frozenset({TokenScope.READ_METADATA, TokenScope.READ_CONTENT})


class CredentialError(RuntimeError):
    """Broker could not satisfy the request. Never contains secret material."""


class GrantExpired(CredentialError):
    pass


@dataclass
class Grant:
    """A short-lived, scoped authorization to talk to GitHub.

    The secret lives in a private field and is only reachable through
    :meth:`authorization_header`, which re-checks expiry every single time.
    """

    scope: TokenScope
    expires_at: datetime
    backend: str
    credential_type: str
    reason: str
    account_login: str | None = None
    repositories: tuple[str, ...] = ()
    installation_id: int | None = None
    _secret: str = field(default="", repr=False)

    @property
    def expired(self) -> bool:
        return datetime.now(timezone.utc) >= self.expires_at

    @property
    def seconds_remaining(self) -> int:
        return max(0, int((self.expires_at - datetime.now(timezone.utc)).total_seconds()))

    def authorization_header(self) -> dict[str, str]:
        if self.expired:
            raise GrantExpired(f"grant for scope {self.scope} expired")
        if not self._secret:
            raise CredentialError("grant carries no credential material")
        return {"Authorization": f"Bearer {self._secret}"}

    def covers(self, repository_full_name: str) -> bool:
        """Empty ``repositories`` means account-wide; otherwise it is an allowlist."""
        return not self.repositories or repository_full_name in self.repositories

    def revoke(self) -> None:
        """Drop the secret from memory and mark the grant unusable."""
        self._secret = ""
        self.expires_at = datetime.now(timezone.utc)

    # Defensive stringification — a grant must never leak through a log line.
    def __repr__(self) -> str:  # pragma: no cover - trivial
        return (
            f"<Grant scope={self.scope} backend={self.backend} "
            f"expires_in={self.seconds_remaining}s secret=REDACTED>"
        )

    __str__ = __repr__

    def __getstate__(self) -> dict[str, object]:
        state = self.__dict__.copy()
        state["_secret"] = ""
        return state


class CredentialBroker(abc.ABC):
    """Base class for credential backends.

    Subclasses implement :meth:`_mint`. The public :meth:`mint` applies the
    invariants that must hold for *every* backend.
    """

    name: str = "abstract"
    #: Highest scope this backend is permitted to issue at all.
    max_scope: TokenScope = TokenScope.READ_METADATA
    #: Which discovery surface the minted credential can actually reach.
    #:
    #: ``"user"``     — a delegated user token: ``/user``, ``/user/repos``, ``/user/orgs``.
    #: ``"installation"`` — an App installation token, which acts as the *App*, not as
    #: a person. Every ``/user*`` endpoint answers 403 "Resource not accessible by
    #: integration"; the equivalent surface is ``/installation/repositories``.
    #:
    #: This is a property of the credential, not of the caller, so it lives here
    #: rather than being sniffed downstream.
    identity_mode: str = "user"

    #: A cached grant is reused only while it still has at least this long to live,
    #: so a caller never receives one that expires under its first request.
    reuse_floor_seconds: int = 30

    def __init__(self, *, max_lifetime_seconds: int = 600) -> None:
        self.max_lifetime_seconds = max_lifetime_seconds
        self._live: dict[tuple[TokenScope, tuple[str, ...], int | None], Grant] = {}

    @abc.abstractmethod
    def _mint(
        self,
        scope: TokenScope,
        lifetime_seconds: int,
        repositories: tuple[str, ...],
        reason: str,
        installation_id: int | None = None,
    ) -> Grant:
        ...

    def installations(self) -> list[dict[str, object]]:
        """Accounts this credential can act for, as ``{id, login, type, ...}`` dicts.

        A delegated user token acts as exactly one person, so the list is empty
        and ``installation_id`` is meaningless. A GitHub App may be installed on
        several accounts — a founder's personal account *and* the company org —
        and each installation mints its own tokens.
        """
        return []

    def mint(
        self,
        scope: TokenScope,
        *,
        lifetime_seconds: int = 300,
        repositories: tuple[str, ...] = (),
        reason: str = "",
        installation_id: int | None = None,
    ) -> Grant:
        if SCOPE_RANK[scope] > SCOPE_RANK[self.max_scope]:
            raise CredentialError(
                f"backend '{self.name}' may not issue scope '{scope}' "
                f"(ceiling '{self.max_scope}')"
            )
        if not reason:
            raise CredentialError("every grant must carry a reason for the audit ledger")
        # Reuse a live grant for the same scope and repository set. Minting per
        # call made a 108-repository sweep request 108 installation tokens in a
        # row, which GitHub throttles; the lifetime cap (axiom 5) is unchanged —
        # the same grant simply serves more than one request before it expires.
        key = (scope, tuple(repositories), installation_id)
        live = self._live.get(key)
        if live is not None and not live.expired and live.seconds_remaining > self.reuse_floor_seconds:
            return live
        lifetime = min(lifetime_seconds, self.max_lifetime_seconds)
        grant = self._mint(scope, lifetime, repositories, reason, installation_id)
        self._live[key] = grant
        # Axiom 5: higher risk must not be able to buy a longer life.
        cap = datetime.now(timezone.utc) + timedelta(seconds=lifetime)
        if grant.expires_at > cap:
            grant.expires_at = cap
        return grant

    def describe(self) -> dict[str, str]:
        """Non-secret description for the audit ledger and the UI."""
        return {"backend": self.name, "max_scope": str(self.max_scope)}

    def health_check(self) -> tuple[bool, str]:
        """Return ``(ok, message)`` without exposing credential material."""
        return True, "not implemented"
