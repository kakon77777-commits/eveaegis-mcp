"""Governance core — the wiring every other module receives.

One object owns the database connection, the audit ledger and the credential
broker. Modules (inventory, provenance, classification, policy, MCP) take a
:class:`GovernanceCore` and never construct credentials themselves.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from pathlib import Path

from .audit import AuditLedger
from .config import Config, load_config
from .credentials import CredentialBroker, TokenScope, build_broker
from .db import dumps, init_db
from .githubapi import GitHubClient
from .models import Tenant
from .taxonomy import ActorType, PermissionLevel, Role, TenantType

#: Characters that are legal in an identifier but not in a Windows path component.
_ILLEGAL_PATH_CHARS = ':*?"<>|/\\'


def slugify_id(identifier: str) -> str:
    """Make an identifier safe as a single path component on every platform."""
    return "".join("_" if ch in _ILLEGAL_PATH_CHARS else ch for ch in identifier)


class GovernanceCore:
    def __init__(
        self,
        config: Config | None = None,
        *,
        conn: sqlite3.Connection | None = None,
        broker: CredentialBroker | None = None,
    ) -> None:
        self.cfg = config or load_config()
        self.conn = conn or init_db(self.cfg.db_path)
        self.ledger = AuditLedger(self.conn)
        self.broker = broker or build_broker(self.cfg.credentials, api_base=self.cfg.github.api_base)
        self._bootstrap_tenant()

    # -- bootstrap --------------------------------------------------------

    def _bootstrap_tenant(self) -> None:
        """Ensure the configured tenant and its two default principals exist."""
        g = self.cfg.governance
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO tenants (id, name, type, owners, policy_profile, created_at)
            VALUES (?,?,?,?,?,?)
            ON CONFLICT(id) DO UPDATE SET name=excluded.name, type=excluded.type
            """,
            (g.tenant_id, g.tenant_name, g.tenant_type, dumps([]), "default", now),
        )
        defaults = [
            ("human:owner", "Portfolio owner", ActorType.HUMAN, [Role.OWNER], PermissionLevel.L5_BREAK_GLASS),
            ("agent:local", "Local AI agent", ActorType.AGENT, [Role.AGENT], PermissionLevel.L0_INVENTORY),
        ]
        for pid, name, atype, roles, ceiling in defaults:
            self.conn.execute(
                """
                INSERT INTO principals
                    (id, tenant_id, display_name, actor_type, roles, max_permission_level,
                     trust_level, created_at)
                VALUES (?,?,?,?,?,?,?,?)
                ON CONFLICT(id) DO NOTHING
                """,
                (
                    pid,
                    g.tenant_id,
                    name,
                    str(atype),
                    dumps([str(r) for r in roles]),
                    str(ceiling),
                    "standard",
                    now,
                ),
            )
        self.conn.commit()

    # -- accessors --------------------------------------------------------

    @property
    def tenant_id(self) -> str:
        return self.cfg.governance.tenant_id

    def tenant(self) -> Tenant:
        row = self.conn.execute("SELECT * FROM tenants WHERE id = ?", (self.tenant_id,)).fetchone()
        return Tenant(
            id=row["id"],
            name=row["name"],
            type=TenantType(row["type"]),
            policy_profile=row["policy_profile"],
        )

    def client(
        self,
        scope: TokenScope = TokenScope.READ_METADATA,
        *,
        reason: str = "governance read",
        installation_id: int | None = None,
    ) -> GitHubClient:
        """Build a GitHub client bound to the broker.

        Read-only mode (the Phase 0 default) refuses to hand out a write scope at
        all, independent of any policy decision — a second, coarser gate in front
        of the policy engine.
        """
        if self.cfg.governance.read_only and scope not in (
            TokenScope.READ_METADATA,
            TokenScope.READ_CONTENT,
        ):
            raise PermissionError(
                f"governance.read_only is set; refusing to mint scope '{scope}'"
            )
        return GitHubClient(
            self.broker, self.cfg.github, scope=scope, reason=reason, installation_id=installation_id
        )

    def installation_for(self, full_name: str) -> int | None:
        """The App installation that covers a repository, by its owner login.

        ``None`` when the owner is not in ``github_installations`` yet, or under a
        user token where installations do not exist — the broker then uses its
        default, which is the right behaviour for a single-account setup.
        """
        owner = full_name.split("/", 1)[0].lower()
        row = self.conn.execute(
            "SELECT installation_id FROM github_installations WHERE tenant_id = ? AND lower(account_login) = ?",
            (self.tenant_id, owner),
        ).fetchone()
        return int(row["installation_id"]) if row and row["installation_id"] else None

    def client_for(
        self,
        full_name: str,
        scope: TokenScope = TokenScope.READ_METADATA,
        *,
        reason: str = "governance read",
    ) -> GitHubClient:
        """A client minted for whichever installation owns ``full_name``."""
        return self.client(scope, reason=reason, installation_id=self.installation_for(full_name))

    def workspace_for(self, repository_id: str) -> Path:
        """§21 — isolated per-repository analysis directory.

        Repository ids look like ``github:278690751:1300241499``; ``:`` is illegal
        in Windows paths, so ids are slugified. The mapping stays injective because
        only characters that cannot appear in an id's meaningful part are folded.
        """
        path = self.cfg.workspace_path / self.tenant_id / slugify_id(repository_id)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "GovernanceCore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
