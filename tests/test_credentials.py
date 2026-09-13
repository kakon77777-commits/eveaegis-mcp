"""Axiom 1 & 5 — the credential broker is the only holder of secret material."""

from __future__ import annotations

import json
import pickle
from datetime import datetime, timedelta, timezone

import pytest

from eveaegis.credentials.base import (
    CredentialBroker,
    CredentialError,
    Grant,
    GrantExpired,
    TokenScope,
)
from eveaegis.credentials.gh_cli import GhCliBroker
from eveaegis.credentials.github_app import GitHubAppBroker

SECRET = "ghs_supersecrettokenvalue"


def make_grant(**overrides: object) -> Grant:
    defaults = dict(
        scope=TokenScope.READ_METADATA,
        expires_at=datetime.now(timezone.utc) + timedelta(seconds=60),
        backend="test",
        credential_type="test_token",
        reason="unit test",
        _secret=SECRET,
    )
    defaults.update(overrides)
    return Grant(**defaults)  # type: ignore[arg-type]


class TestGrantSecrecy:
    def test_repr_and_str_redact_the_secret(self) -> None:
        grant = make_grant()
        assert SECRET not in repr(grant)
        assert SECRET not in str(grant)
        assert "REDACTED" in repr(grant)

    def test_pickling_drops_the_secret(self) -> None:
        """A grant must not survive serialization with its credential intact."""
        restored = pickle.loads(pickle.dumps(make_grant()))
        with pytest.raises(CredentialError):
            restored.authorization_header()

    def test_format_string_does_not_leak(self) -> None:
        assert SECRET not in f"{make_grant()}"

    def test_header_carries_the_secret(self) -> None:
        assert make_grant().authorization_header()["Authorization"] == f"Bearer {SECRET}"

    def test_revoke_makes_the_grant_unusable(self) -> None:
        grant = make_grant()
        grant.revoke()
        assert grant.expired
        with pytest.raises(GrantExpired):
            grant.authorization_header()


class TestGrantExpiry:
    def test_expired_grant_refuses_to_authorize(self) -> None:
        grant = make_grant(expires_at=datetime.now(timezone.utc) - timedelta(seconds=1))
        with pytest.raises(GrantExpired):
            grant.authorization_header()

    def test_repository_allowlist(self) -> None:
        scoped = make_grant(repositories=("owner/a",))
        assert scoped.covers("owner/a")
        assert not scoped.covers("owner/b")
        # An empty allowlist means account-wide, not "nothing".
        assert make_grant().covers("owner/anything")


class NoisyBroker(CredentialBroker):
    """Backend that tries to hand out a longer-lived grant than it was asked for."""

    name = "noisy"
    max_scope = TokenScope.ADMIN

    def _mint(self, scope, lifetime_seconds, repositories, reason, installation_id=None):  # type: ignore[no-untyped-def]
        return Grant(
            scope=scope,
            expires_at=datetime.now(timezone.utc) + timedelta(days=30),
            backend=self.name,
            credential_type="over_eager",
            reason=reason,
            _secret=SECRET,
        )


class TinyBroker(NoisyBroker):
    name = "tiny"
    max_scope = TokenScope.READ_CONTENT


class TestBrokerInvariants:
    def test_lifetime_is_capped_by_the_broker(self) -> None:
        """Axiom 5 — a backend cannot buy itself a longer life than policy allows."""
        broker = NoisyBroker(max_lifetime_seconds=120)
        grant = broker.mint(TokenScope.READ_METADATA, lifetime_seconds=600, reason="test")
        assert grant.seconds_remaining <= 120

    def test_scope_ceiling_is_enforced(self) -> None:
        broker = TinyBroker()
        with pytest.raises(CredentialError, match="may not issue scope"):
            broker.mint(TokenScope.ADMIN, reason="test")

    def test_reason_is_mandatory(self) -> None:
        """Every grant has to be explainable in the audit ledger."""
        with pytest.raises(CredentialError, match="reason"):
            NoisyBroker().mint(TokenScope.READ_METADATA, reason="")

    def test_describe_never_contains_secret_material(self) -> None:
        description = json.dumps(NoisyBroker().describe())
        assert SECRET not in description


class TestBackendCeilings:
    def test_gh_cli_cannot_issue_content_writes(self) -> None:
        """The gh backend holds a long-lived token, so it is capped at metadata."""
        with pytest.raises(CredentialError):
            GhCliBroker().mint(TokenScope.WRITE_CONTENT_DIRECT, reason="test")

    def test_github_app_refuses_when_unconfigured(self) -> None:
        broker = GitHubAppBroker(app_id=None, private_key_path=None, installation_id=None)
        ok, message = broker.health_check()
        assert not ok
        assert "not configured" in message


class TestGrantReuse:
    def test_live_grant_is_reused_for_same_scope(self) -> None:
        """A sweep must not mint one token per repository."""
        broker = NoisyBroker(max_lifetime_seconds=300)
        a = broker.mint(TokenScope.READ_METADATA, reason="sweep")
        b = broker.mint(TokenScope.READ_METADATA, reason="sweep")
        assert a is b

    def test_different_scope_or_repositories_get_their_own_grant(self) -> None:
        broker = NoisyBroker(max_lifetime_seconds=300)
        a = broker.mint(TokenScope.READ_METADATA, reason="x")
        b = broker.mint(TokenScope.READ_CONTENT, reason="x")
        c = broker.mint(TokenScope.READ_METADATA, repositories=("o/r",), reason="x")
        assert len({id(a), id(b), id(c)}) == 3

    def test_expired_or_nearly_expired_grant_is_replaced(self) -> None:
        broker = NoisyBroker(max_lifetime_seconds=300)
        a = broker.mint(TokenScope.READ_METADATA, reason="x")
        a.expires_at = datetime.now(timezone.utc) + timedelta(seconds=5)  # under the reuse floor
        b = broker.mint(TokenScope.READ_METADATA, reason="x")
        assert b is not a
        assert b.seconds_remaining > 100

    def test_lifetime_cap_still_applies_to_reused_grants(self) -> None:
        """Axiom 5 is untouched: reuse never extends a grant's life."""
        broker = NoisyBroker(max_lifetime_seconds=120)
        a = broker.mint(TokenScope.READ_METADATA, lifetime_seconds=999, reason="x")
        b = broker.mint(TokenScope.READ_METADATA, lifetime_seconds=999, reason="x")
        assert b is a and a.seconds_remaining <= 120
