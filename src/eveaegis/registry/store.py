"""Canonical Repository Registry — declarations and proposals.

Recovery Index (2026-09-13) §5 asks for the governance registry and the company
migration registry to be *one* table rather than two that drift. This module is
that merge, with one boundary kept sharp:

* ``repositories``            — facts EveAegis observed (inventory, provenance,
                                classification). Machine-written.
* ``registry_declarations``   — what a human declared about ownership: class,
                                target owner, canonical, product, family. Human-
                                written only, through the CLI or a CSV import.
* ``registry_proposals``      — what an agent *suggests* for those same fields,
                                append-only, with confidence and rationale.

``Machine Proposal ≠ Authoritative Governance State`` is not a slogan here; it is
which table a value is allowed to land in.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable

from pydantic import BaseModel, Field, field_validator

from ..core import GovernanceCore
from ..db import dumps, loads

ASSET_CLASSES = ("A", "B", "C", "D")
CANONICAL_STATES = ("true", "false", "undeclared")
TRANSFER_STATES = ("pending", "transferred", "archived", "stays")

#: Columns a human may declare. Everything else in the registry is a fact.
DECLARABLE: tuple[str, ...] = (
    "display_name",
    "asset_class",
    "target_owner",
    "canonical",
    "product",
    "transfer_status",
    "project_family",
    "superseded_by",
    "dependencies",
    "capabilities",
    "website",
    "mcp_endpoint",
    "mcp_status",
    "maintainer",
    "notes",
)


class Declaration(BaseModel):
    repository_id: str
    display_name: str | None = None
    asset_class: str | None = None
    target_owner: str | None = None
    canonical: str = "undeclared"
    product: str | None = None
    transfer_status: str = "pending"
    project_family: str | None = None
    superseded_by: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    website: str | None = None
    mcp_endpoint: str | None = None
    mcp_status: str | None = None
    maintainer: str | None = None
    notes: str | None = None
    declared_by: str = "human:owner"
    declared_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    @field_validator("asset_class")
    @classmethod
    def _class(cls, v: str | None) -> str | None:
        if v is None or v == "":
            return None
        v = v.strip().upper()
        if v not in ASSET_CLASSES:
            raise ValueError(f"class must be one of {ASSET_CLASSES}, got {v!r}")
        return v

    @field_validator("canonical")
    @classmethod
    def _canonical(cls, v: str) -> str:
        v = (v or "undeclared").strip().lower()
        if v in ("yes", "y", "1"):
            v = "true"
        if v in ("no", "n", "0"):
            v = "false"
        if v not in CANONICAL_STATES:
            raise ValueError(f"canonical must be one of {CANONICAL_STATES}, got {v!r}")
        return v

    @field_validator("transfer_status")
    @classmethod
    def _transfer(cls, v: str) -> str:
        v = (v or "pending").strip().lower()
        if v not in TRANSFER_STATES:
            raise ValueError(f"transfer_status must be one of {TRANSFER_STATES}, got {v!r}")
        return v


class Proposal(BaseModel):
    repository_id: str
    field: str
    value: str | None
    confidence: float
    rationale: str
    proposed_by: str = "agent:local"


class RegistryStore:
    def __init__(self, core: GovernanceCore) -> None:
        self.core = core
        self.conn: sqlite3.Connection = core.conn

    # -- declarations (human) ---------------------------------------------

    def declare(self, decl: Declaration, *, initiated_by: str = "human:owner") -> None:
        """Upsert a human declaration and record it. Never called by an agent path."""
        before = self.declaration(decl.repository_id)
        self.conn.execute(
            """
            INSERT INTO registry_declarations
                (repository_id, display_name, asset_class, target_owner, canonical, product,
                 transfer_status, project_family, superseded_by, dependencies, capabilities,
                 website, mcp_endpoint, mcp_status, maintainer, notes, declared_by, declared_at)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(repository_id) DO UPDATE SET
                display_name=excluded.display_name, asset_class=excluded.asset_class,
                target_owner=excluded.target_owner, canonical=excluded.canonical,
                product=excluded.product, transfer_status=excluded.transfer_status,
                project_family=excluded.project_family, superseded_by=excluded.superseded_by,
                dependencies=excluded.dependencies, capabilities=excluded.capabilities,
                website=excluded.website, mcp_endpoint=excluded.mcp_endpoint,
                mcp_status=excluded.mcp_status, maintainer=excluded.maintainer,
                notes=excluded.notes, declared_by=excluded.declared_by,
                declared_at=excluded.declared_at
            """,
            (
                decl.repository_id, decl.display_name, decl.asset_class, decl.target_owner,
                decl.canonical, decl.product, decl.transfer_status, decl.project_family,
                decl.superseded_by, dumps(decl.dependencies), dumps(decl.capabilities),
                decl.website, decl.mcp_endpoint, decl.mcp_status, decl.maintainer, decl.notes,
                decl.declared_by, decl.declared_at.isoformat(),
            ),
        )
        self.conn.commit()
        self.core.ledger.record(
            "registry_declared",
            actor=decl.declared_by,
            initiated_by=initiated_by,
            tenant=self.core.tenant_id,
            targets=[self._full_name(decl.repository_id) or decl.repository_id],
            detail={
                "before": before.model_dump(mode="json", exclude={"declared_at"}) if before else None,
                "after": decl.model_dump(mode="json", exclude={"declared_at"}),
            },
        )

    def declaration(self, repository_id: str) -> Declaration | None:
        row = self.conn.execute(
            "SELECT * FROM registry_declarations WHERE repository_id = ?", (repository_id,)
        ).fetchone()
        return self._row_to_declaration(row) if row else None

    def declarations(self) -> dict[str, Declaration]:
        return {
            r["repository_id"]: self._row_to_declaration(r)
            for r in self.conn.execute("SELECT * FROM registry_declarations")
        }

    # -- proposals (agent, append-only) -----------------------------------

    def propose(self, proposals: Iterable[Proposal]) -> int:
        now = datetime.now(timezone.utc).isoformat()
        n = 0
        for p in proposals:
            self.conn.execute(
                """
                INSERT INTO registry_proposals
                    (id, repository_id, field, value, confidence, rationale, proposed_by, proposed_at)
                VALUES (?,?,?,?,?,?,?,?)
                """,
                (
                    f"rpp_{uuid.uuid4().hex[:12]}", p.repository_id, p.field, p.value,
                    float(p.confidence), p.rationale, p.proposed_by, now,
                ),
            )
            n += 1
        self.conn.commit()
        if n:
            self.core.ledger.record(
                "registry_proposals_recorded",
                actor="agent:local",
                tenant=self.core.tenant_id,
                detail={"count": n, "note": "proposals only; no declaration changed"},
            )
        return n

    def latest_proposals(self, field: str) -> dict[str, Proposal]:
        """Most recent proposal per repository for one field."""
        out: dict[str, Proposal] = {}
        for r in self.conn.execute(
            "SELECT * FROM registry_proposals WHERE field = ? ORDER BY proposed_at ASC", (field,)
        ):
            out[r["repository_id"]] = Proposal(
                repository_id=r["repository_id"], field=r["field"], value=r["value"],
                confidence=r["confidence"], rationale=r["rationale"], proposed_by=r["proposed_by"],
            )
        return out

    # -- helpers ----------------------------------------------------------

    def _full_name(self, repository_id: str) -> str | None:
        row = self.conn.execute(
            "SELECT full_name FROM repositories WHERE id = ?", (repository_id,)
        ).fetchone()
        return row["full_name"] if row else None

    @staticmethod
    def _row_to_declaration(row: sqlite3.Row) -> Declaration:
        d: dict[str, Any] = {k: row[k] for k in row.keys()}
        d["dependencies"] = loads(row["dependencies"], [])
        d["capabilities"] = loads(row["capabilities"], [])
        d["declared_at"] = datetime.fromisoformat(row["declared_at"])
        return Declaration(**d)
