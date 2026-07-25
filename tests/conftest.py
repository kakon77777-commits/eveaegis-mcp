"""Shared fixtures. Nothing here touches the network or the real credential store."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from eveaegis.config import AnalysisConfig, Config, GovernanceConfig
from eveaegis.credentials.base import CredentialBroker, Grant, TokenScope
from eveaegis.db import init_db


class FakeBroker(CredentialBroker):
    """Issues grants carrying an obviously-fake secret, so tests never need `gh`."""

    name = "fake"
    max_scope = TokenScope.ADMIN

    def __init__(self, *, max_lifetime_seconds: int = 300) -> None:
        super().__init__(max_lifetime_seconds=max_lifetime_seconds)
        self.mint_calls: list[tuple[TokenScope, str]] = []

    def _mint(
        self,
        scope: TokenScope,
        lifetime_seconds: int,
        repositories: tuple[str, ...],
        reason: str,
    ) -> Grant:
        self.mint_calls.append((scope, reason))
        return Grant(
            scope=scope,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
            backend=self.name,
            credential_type="fake_token",
            reason=reason,
            repositories=repositories,
            _secret="not-a-real-token",
        )


@pytest.fixture
def db_path(tmp_path: Path) -> Path:
    return tmp_path / "eveaegis.db"


@pytest.fixture
def conn(db_path: Path) -> sqlite3.Connection:
    connection = init_db(db_path)
    yield connection
    connection.close()


@pytest.fixture
def config(tmp_path: Path) -> Config:
    # Everything lands in tmp_path so a test run never touches the real workspace.
    return Config(
        database_path=str(tmp_path / "eveaegis.db"),
        analysis=AnalysisConfig(workspace_dir=str(tmp_path / "workspace")),
        governance=GovernanceConfig(tenant_id="test-tenant", tenant_name="Test", read_only=True),
    )


@pytest.fixture
def core(config: Config):
    from eveaegis.core import GovernanceCore

    c = GovernanceCore(config, broker=FakeBroker())
    yield c
    c.close()
