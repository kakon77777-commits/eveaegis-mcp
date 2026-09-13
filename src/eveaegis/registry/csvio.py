"""Registry ⇄ CSV, in the shape of ``repository_registry_template.csv``.

The export is the single merged registry the Recovery Index §5 asks for: every fact
column from EveAegis, every declaration column from a human, and — appended after
the template's own columns — the agent's latest proposal for class and family with
its confidence and rationale. The ``class`` column stays empty until a human fills
it; ``proposed_class`` is where the machine's opinion lives.

The import reads the same file back. It only ever touches declaration columns:
facts are EveAegis's to observe, and a spreadsheet edit to ``lifecycle`` or
``origin`` is ignored on purpose rather than silently overwriting a verdict.
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core import GovernanceCore
from ..db import loads
from .store import DECLARABLE, Declaration, RegistryStore

#: Exactly the template's header order (Recovery Index §5 / Migration Strategy §6).
TEMPLATE_COLUMNS: tuple[str, ...] = (
    "repository_id", "full_name", "display_name", "description", "current_owner",
    "target_owner", "class", "category", "lifecycle", "maturity", "criticality", "origin",
    "canonical", "visibility", "product", "license", "transfer_status", "project_family",
    "superseded_by", "dependencies", "capabilities", "topics", "primary_language", "website",
    "mcp_endpoint", "mcp_status", "maintainer", "agent_access", "updated_at", "notes",
)

#: Appended after the template: machine opinion, clearly labelled as such.
PROPOSAL_COLUMNS: tuple[str, ...] = (
    "proposed_class", "class_confidence", "class_rationale", "proposed_family",
    "proposed_mode", "mixed_score", "mixed_reasons",
    "origin_confidence", "review_status", "is_fork", "is_archived", "pushed_at", "size_mb",
)

#: CSV header -> declaration field. ``class`` is a Python keyword, hence the rename.
_CSV_TO_DECL = {"class": "asset_class"}


def _join(values: Any) -> str:
    return "; ".join(str(v) for v in (values or []))


def _split(value: str | None) -> list[str]:
    return [v.strip() for v in (value or "").replace(",", ";").split(";") if v.strip()]


def export_rows(core: GovernanceCore) -> list[dict[str, Any]]:
    store = RegistryStore(core)
    decls = store.declarations()
    p_class = store.latest_proposals("asset_class")
    p_family = store.latest_proposals("project_family")
    p_mode = store.latest_proposals("migration_mode")

    rows = core.conn.execute(
        """
        SELECT r.*, o.origin_type, o.origin_confidence, o.review_status
        FROM repositories r
        LEFT JOIN origin_profiles o ON o.repository_id = r.id
        WHERE r.tenant_id = ? AND r.missing_since IS NULL
        ORDER BY r.is_fork, r.full_name
        """,
        (core.tenant_id,),
    ).fetchall()

    out: list[dict[str, Any]] = []
    for r in rows:
        d = decls.get(r["id"]) or Declaration(repository_id=r["id"])
        pc = p_class.get(r["id"])
        pf = p_family.get(r["id"])
        pm = p_mode.get(r["id"])
        out.append(
            {
                "repository_id": r["id"],
                "full_name": r["full_name"],
                "display_name": d.display_name or "",
                "description": r["description"] or "",
                "current_owner": r["full_name"].split("/")[0],
                "target_owner": d.target_owner or "",
                "class": d.asset_class or "",
                "category": r["category"],
                "lifecycle": r["lifecycle"],
                "maturity": r["maturity"],
                "criticality": r["criticality"],
                "origin": r["origin_type"] or "",
                "canonical": d.canonical,
                "visibility": r["visibility"],
                "product": d.product or "",
                "license": r["license_spdx"] or "",
                "transfer_status": d.transfer_status,
                "project_family": d.project_family or "",
                "superseded_by": d.superseded_by or "",
                "dependencies": _join(d.dependencies),
                "capabilities": _join(d.capabilities),
                "topics": _join(loads(r["topics"], [])),
                "primary_language": r["primary_language"] or "",
                "website": d.website or r["homepage"] or "",
                "mcp_endpoint": d.mcp_endpoint or "",
                "mcp_status": d.mcp_status or "",
                "maintainer": d.maintainer or "",
                "agent_access": r["agent_access"],
                "updated_at": r["synced_at"],
                "notes": d.notes or "",
                # --- appended, machine opinion ---
                "proposed_class": pc.value if pc else "",
                "class_confidence": f"{pc.confidence:.2f}" if pc else "",
                "class_rationale": pc.rationale if pc else "",
                "proposed_family": pf.value if pf else "",
                "proposed_mode": pm.value if pm else "",
                "mixed_score": f"{max(0.0, pm.confidence - 0.4):.2f}" if pm else "",
                "mixed_reasons": pm.rationale if pm else "",
                "origin_confidence": f"{r['origin_confidence']:.2f}" if r["origin_confidence"] is not None else "",
                "review_status": r["review_status"] or "",
                "is_fork": int(r["is_fork"]),
                "is_archived": int(r["is_archived"]),
                "pushed_at": (r["pushed_at"] or "")[:10],
                "size_mb": round((r["size_kb"] or 0) / 1024, 1),
            }
        )
    return out


def export_csv(core: GovernanceCore, path: Path) -> int:
    rows = export_rows(core)
    path.parent.mkdir(parents=True, exist_ok=True)
    # utf-8-sig so Excel on Windows opens the CJK descriptions correctly.
    with io.open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[*TEMPLATE_COLUMNS, *PROPOSAL_COLUMNS])
        w.writeheader()
        w.writerows(rows)
    core.ledger.record(
        "registry_exported",
        actor="agent:local",
        tenant=core.tenant_id,
        detail={"path": str(path), "rows": len(rows)},
    )
    return len(rows)


def import_csv(core: GovernanceCore, path: Path, *, declared_by: str = "human:owner") -> dict[str, Any]:
    """Apply the declaration columns of an edited registry CSV.

    A row is applied only if at least one declarable column is non-empty *and*
    differs from what is stored; fact columns are ignored by construction.
    """
    store = RegistryStore(core)
    known = {
        r["id"]: r["full_name"]
        for r in core.conn.execute("SELECT id, full_name FROM repositories WHERE tenant_id = ?", (core.tenant_id,))
    }
    applied: list[str] = []
    skipped = 0
    errors: list[str] = []

    with io.open(path, "r", encoding="utf-8-sig", newline="") as f:
        for row in csv.DictReader(f):
            rid = (row.get("repository_id") or "").strip()
            if rid not in known:
                errors.append(f"unknown repository_id {rid!r} (full_name {row.get('full_name')!r})")
                continue
            current = store.declaration(rid) or Declaration(repository_id=rid)
            fields: dict[str, Any] = {}
            for col in DECLARABLE:
                header = next((h for h, fld in _CSV_TO_DECL.items() if fld == col), col)
                raw = row.get(header)
                if raw is None:
                    continue
                raw = raw.strip()
                if col in ("dependencies", "capabilities"):
                    val: Any = _split(raw)
                elif col in ("canonical", "transfer_status"):
                    val = raw or getattr(current, col)
                else:
                    val = raw or None
                fields[col] = val
            # `website` in the export falls back to GitHub's homepage; do not
            # re-declare a fallback as if a human typed it.
            homepage = core.conn.execute(
                "SELECT homepage FROM repositories WHERE id = ?", (rid,)
            ).fetchone()["homepage"]
            if fields.get("website") and fields["website"] == (homepage or "") and not current.website:
                fields["website"] = None
            try:
                candidate = Declaration(repository_id=rid, declared_by=declared_by, **fields)
            except ValueError as exc:
                errors.append(f"{known[rid]}: {exc}")
                continue
            if candidate.model_dump(exclude={"declared_at", "declared_by"}) == current.model_dump(
                exclude={"declared_at", "declared_by"}
            ):
                skipped += 1
                continue
            store.declare(candidate, initiated_by=declared_by)
            applied.append(known[rid])

    core.ledger.record(
        "registry_imported",
        actor=declared_by,
        initiated_by=declared_by,
        tenant=core.tenant_id,
        targets=applied[:50],
        detail={"path": str(path), "applied": len(applied), "unchanged": skipped, "errors": errors[:20],
                "imported_at": datetime.now(timezone.utc).isoformat()},
    )
    return {"applied": applied, "unchanged": skipped, "errors": errors}
