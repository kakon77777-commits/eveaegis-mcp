"""Read-only inventory views (§19.1 Portfolio Overview, §19.2 Repository Matrix).

These functions never call GitHub and never write. They project the catalog into
the three shapes the management UI and the MCP inventory toolset (§13.1) consume.

The reports are deliberately blunt about ignorance. A repository with no origin
profile is counted under *unknown origin*, not quietly assumed original — the
overview is the first place axiom 4 becomes visible to a human.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from ..core import GovernanceCore
from ..db import loads
from ..taxonomy import Category, Lifecycle

#: License verdicts that a human still has to look at (§10, §19.1).
LICENSE_REVIEW_STATUSES: tuple[str, ...] = ("REVIEW_REQUIRED", "INCOMPATIBLE", "UNKNOWN")


def _count(conn: sqlite3.Connection, sql: str, params: tuple[Any, ...]) -> int:
    return int(conn.execute(sql, params).fetchone()[0])


def _group(conn: sqlite3.Connection, column: str, tenant_id: str) -> dict[str, int]:
    rows = conn.execute(
        f"SELECT {column} AS k, COUNT(*) AS n FROM repositories WHERE tenant_id = ? AND missing_since IS NULL GROUP BY {column}",
        (tenant_id,),
    ).fetchall()
    return {str(r["k"]): int(r["n"]) for r in rows}


def portfolio_summary(core: GovernanceCore) -> dict[str, Any]:
    """§19.1 Portfolio Overview counters, plus the breakdowns behind them."""
    conn = core.conn
    tenant = core.tenant_id
    lifecycle_counts = _group(conn, "lifecycle", tenant)
    category_counts = _group(conn, "category", tenant)

    repositories = _count(conn, "SELECT COUNT(*) FROM repositories WHERE tenant_id = ? AND missing_since IS NULL", (tenant,))

    # A repository counts as "unknown origin" both when Phase 2 has not run at all
    # and when it ran and honestly concluded UNKNOWN.
    unknown_origin = _count(
        conn,
        """
        SELECT COUNT(*) FROM repositories r
        LEFT JOIN origin_profiles o ON o.id = r.origin_profile_id
        WHERE r.tenant_id = ? AND r.missing_since IS NULL AND (o.id IS NULL OR o.origin_type = 'UNKNOWN')
        """,
        (tenant,),
    )
    placeholders = ", ".join("?" for _ in LICENSE_REVIEW_STATUSES)
    license_review_required = _count(
        conn,
        f"""
        SELECT COUNT(*) FROM repositories r
        JOIN license_profiles l ON l.repository_id = r.id
        WHERE r.tenant_id = ? AND r.missing_since IS NULL AND l.compatibility_status IN ({placeholders})
        """,
        (tenant, *LICENSE_REVIEW_STATUSES),
    )
    unclassified = _count(
        conn,
        "SELECT COUNT(*) FROM repositories WHERE tenant_id = ? AND missing_since IS NULL "
        "AND (category = 'UNKNOWN' OR lifecycle = 'UNKNOWN')",
        (tenant,),
    )

    return {
        "tenant": tenant,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "companies": _count(conn, "SELECT COUNT(*) FROM tenants", ()),
        "accounts": _count(
            conn, "SELECT COUNT(*) FROM github_installations WHERE tenant_id = ?", (tenant,)
        ),
        "organizations": _count(
            conn,
            "SELECT COUNT(*) FROM github_installations "
            "WHERE tenant_id = ? AND account_type = 'organization'",
            (tenant,),
        ),
        "repositories": repositories,
        "active": lifecycle_counts.get(str(Lifecycle.ACTIVE), 0),
        "experimental": lifecycle_counts.get(str(Lifecycle.EXPERIMENTAL), 0),
        "maintenance": lifecycle_counts.get(str(Lifecycle.MAINTENANCE), 0),
        "archived": lifecycle_counts.get(str(Lifecycle.ARCHIVED), 0),
        "forks": _count(
            conn, "SELECT COUNT(*) FROM repositories WHERE tenant_id = ? AND missing_since IS NULL AND is_fork = 1", (tenant,)
        ),
        "mirrors": category_counts.get(str(Category.MIRROR), 0),
        "unknown_origin": unknown_origin,
        "license_review_required": license_review_required,
        "unclassified": unclassified,
        "missing": _count(
            conn,
            "SELECT COUNT(*) FROM repositories WHERE tenant_id = ? AND missing_since IS NOT NULL",
            (tenant,),
        ),
        # Supporting detail — the raw distributions the headline numbers came from.
        "lifecycle_counts": lifecycle_counts,
        "category_counts": category_counts,
        "visibility_counts": _group(conn, "visibility", tenant),
        "archived_flag": _count(
            conn,
            "SELECT COUNT(*) FROM repositories WHERE tenant_id = ? AND missing_since IS NULL AND is_archived = 1",
            (tenant,),
        ),
        "snapshots": _count(
            conn,
            "SELECT COUNT(*) FROM repository_snapshots s "
            "JOIN repositories r ON r.id = s.repository_id WHERE r.tenant_id = ?",
            (tenant,),
        ),
        "languages": _language_totals(conn, tenant),
    }


def _language_totals(conn: sqlite3.Connection, tenant_id: str) -> dict[str, int]:
    """Repository counts per language, primary language first, then anything seen."""
    totals: dict[str, int] = {}
    for row in conn.execute(
        "SELECT languages FROM repositories WHERE tenant_id = ? AND missing_since IS NULL", (tenant_id,)
    ):
        for name in loads(row["languages"], {}) or {}:
            totals[name] = totals.get(name, 0) + 1
    return dict(sorted(totals.items(), key=lambda kv: (-kv[1], kv[0])))


def unclassified_report(core: GovernanceCore) -> list[dict[str, Any]]:
    """Everything still waiting on a human or on Phase 3, with the evidence at hand.

    ``missing`` names the specific columns that are still ``UNKNOWN`` so the caller
    can queue work, rather than presenting one undifferentiated pile.
    """
    rows = core.conn.execute(
        """
        SELECT * FROM repositories
        WHERE tenant_id = ?
          AND (category = 'UNKNOWN' OR lifecycle = 'UNKNOWN' OR maturity = 'UNKNOWN')
        ORDER BY pushed_at DESC NULLS LAST, full_name ASC
        """,
        (core.tenant_id,),
    ).fetchall()

    report: list[dict[str, Any]] = []
    for row in rows:
        missing = [c for c in ("category", "lifecycle", "maturity") if row[c] == "UNKNOWN"]
        report.append(
            {
                "id": row["id"],
                "full_name": row["full_name"],
                "missing": missing,
                "description": row["description"],
                "topics": loads(row["topics"], []),
                "primary_language": row["primary_language"],
                "visibility": row["visibility"],
                "is_fork": bool(row["is_fork"]),
                "is_archived": bool(row["is_archived"]),
                "stargazers": row["stargazers"],
                "pushed_at": row["pushed_at"],
                "has_readme": _has_snapshot(core.conn, row["id"], "readme"),
            }
        )
    return report


def _has_snapshot(conn: sqlite3.Connection, repository_id: str, kind: str) -> bool:
    return (
        conn.execute(
            "SELECT 1 FROM repository_snapshots WHERE repository_id = ? AND kind = ? LIMIT 1",
            (repository_id, kind),
        ).fetchone()
        is not None
    )


def repository_matrix(core: GovernanceCore) -> list[dict[str, Any]]:
    """§19.2 Repository Matrix rows.

    ``risk`` is populated from ``criticality``: until the risk engine (§16) runs,
    criticality is the only standing risk statement the catalog holds, and inventing
    a second one would be a confident label without evidence.
    """
    rows = core.conn.execute(
        """
        SELECT r.*,
               o.origin_type        AS origin_type,
               o.contribution_band  AS contribution_band,
               o.review_status      AS review_status,
               o.public_label       AS public_label
        FROM repositories r
        LEFT JOIN origin_profiles o ON o.id = r.origin_profile_id
        WHERE r.tenant_id = ?
        ORDER BY r.pushed_at DESC NULLS LAST, r.full_name ASC
        """,
        (core.tenant_id,),
    ).fetchall()

    return [
        {
            "id": row["id"],
            "repo": row["full_name"],
            "category": row["category"],
            "lifecycle": row["lifecycle"],
            "origin": row["origin_type"] or "UNKNOWN",
            "contribution": row["contribution_band"] or "UNKNOWN",
            "risk": row["criticality"],
            "agent_mode": row["agent_access"],
            "visibility": row["visibility"],
            "is_fork": bool(row["is_fork"]),
            "is_archived": bool(row["is_archived"]),
            "primary_language": row["primary_language"],
            "review_status": row["review_status"] or "UNREVIEWED",
            "public_label": row["public_label"],
            "pushed_at": row["pushed_at"],
        }
        for row in rows
    ]
