"""Core wiring: bootstrap, the read-only gate, and workspace isolation (§21)."""

from __future__ import annotations

import pytest

from eveaegis.core import GovernanceCore
from eveaegis.credentials import TokenScope
from eveaegis.db import loads
from eveaegis.taxonomy import PermissionLevel


def test_bootstrap_creates_tenant_and_principals(core: GovernanceCore) -> None:
    tenant = core.tenant()
    assert tenant.id == "test-tenant"

    rows = {r["id"]: r for r in core.conn.execute("SELECT * FROM principals")}
    assert set(rows) == {"human:owner", "agent:local"}
    # The agent principal starts at the bottom of the ladder, not the top.
    assert rows["agent:local"]["max_permission_level"] == str(PermissionLevel.L0_INVENTORY)
    assert rows["human:owner"]["max_permission_level"] == str(PermissionLevel.L5_BREAK_GLASS)
    assert loads(rows["agent:local"]["roles"]) == ["AGENT"]


def test_bootstrap_is_idempotent(core: GovernanceCore) -> None:
    core._bootstrap_tenant()
    count = core.conn.execute("SELECT COUNT(*) AS n FROM principals").fetchone()["n"]
    assert count == 2


def test_read_only_mode_refuses_write_scopes(core: GovernanceCore) -> None:
    """A coarse gate in front of the policy engine — config alone can stop writes."""
    assert core.cfg.governance.read_only is True
    for scope in (
        TokenScope.WRITE_METADATA,
        TokenScope.WRITE_CONTENT_PR,
        TokenScope.WRITE_CONTENT_DIRECT,
        TokenScope.ADMIN,
    ):
        with pytest.raises(PermissionError, match="read_only"):
            core.client(scope, reason="test")


def test_read_scopes_are_allowed_in_read_only_mode(core: GovernanceCore) -> None:
    for scope in (TokenScope.READ_METADATA, TokenScope.READ_CONTENT):
        client = core.client(scope, reason="test")
        assert client.scope == scope
        client.close()


def test_client_credential_description_carries_no_secret(core: GovernanceCore) -> None:
    client = core.client(TokenScope.READ_METADATA, reason="test")
    description = client.credential_description
    assert "not-a-real-token" not in str(description)
    assert description["scope"] == str(TokenScope.READ_METADATA)
    client.close()


def test_workspace_is_isolated_per_repository(core: GovernanceCore) -> None:
    a = core.workspace_for("github:1:2")
    b = core.workspace_for("github:1:3")
    assert a != b
    assert a.is_dir() and b.is_dir()
    assert a.parent.name == core.tenant_id
