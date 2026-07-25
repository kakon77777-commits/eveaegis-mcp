"""SQLite persistence (§20 storage model).

Deliberately plain ``sqlite3``: the governance core needs exact control over the
append-only audit table and over what an agent-facing connection is allowed to do,
which an ORM would only obscure. Schema changes go through :data:`MIGRATIONS`.

Two connection flavours exist:

* :func:`connect` — full read/write, used by the governance core itself.
* :func:`connect_readonly` — URI-mode ``mode=ro`` handle handed to analysis code, so
  a bug in an analyzer cannot mutate the ledger.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

SCHEMA_VERSION = 2

MIGRATIONS: dict[int, str] = {
    1: """
    -- §4 multi-tenant model -------------------------------------------------
    CREATE TABLE IF NOT EXISTS tenants (
        id             TEXT PRIMARY KEY,
        name           TEXT NOT NULL,
        type           TEXT NOT NULL,
        owners         TEXT NOT NULL DEFAULT '[]',
        policy_profile TEXT NOT NULL DEFAULT 'default',
        created_at     TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS principals (
        id                   TEXT PRIMARY KEY,
        tenant_id            TEXT NOT NULL REFERENCES tenants(id),
        display_name         TEXT NOT NULL,
        actor_type           TEXT NOT NULL,
        roles                TEXT NOT NULL DEFAULT '[]',
        max_permission_level TEXT NOT NULL DEFAULT 'L0_INVENTORY',
        trust_level          TEXT NOT NULL DEFAULT 'standard',
        created_at           TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS github_installations (
        id                    TEXT PRIMARY KEY,
        tenant_id             TEXT NOT NULL REFERENCES tenants(id),
        account_login         TEXT NOT NULL,
        account_type          TEXT NOT NULL,
        installation_id       INTEGER,
        allowed_repositories  TEXT NOT NULL DEFAULT 'selected',
        permission_snapshot   TEXT NOT NULL DEFAULT '{}',
        credential_backend    TEXT NOT NULL DEFAULT 'gh_cli',
        created_at            TEXT NOT NULL,
        UNIQUE (tenant_id, account_login)
    );

    -- §4.2 repository asset --------------------------------------------------
    CREATE TABLE IF NOT EXISTS repositories (
        id                   TEXT PRIMARY KEY,
        tenant_id            TEXT NOT NULL REFERENCES tenants(id),
        installation_id      TEXT REFERENCES github_installations(id),
        full_name            TEXT NOT NULL,
        github_repository_id INTEGER NOT NULL,
        visibility           TEXT NOT NULL DEFAULT 'public',
        default_branch       TEXT NOT NULL DEFAULT 'main',
        description          TEXT,
        homepage             TEXT,
        topics               TEXT NOT NULL DEFAULT '[]',
        primary_language     TEXT,
        languages            TEXT NOT NULL DEFAULT '{}',
        license_spdx         TEXT,
        is_archived          INTEGER NOT NULL DEFAULT 0,
        is_fork              INTEGER NOT NULL DEFAULT 0,
        parent_full_name     TEXT,
        source_full_name     TEXT,
        template_full_name   TEXT,
        size_kb              INTEGER NOT NULL DEFAULT 0,
        stargazers           INTEGER NOT NULL DEFAULT 0,
        open_issues          INTEGER NOT NULL DEFAULT 0,
        pushed_at            TEXT,
        created_at           TEXT,
        updated_at           TEXT,
        lifecycle            TEXT NOT NULL DEFAULT 'UNKNOWN',
        category             TEXT NOT NULL DEFAULT 'UNKNOWN',
        maturity             TEXT NOT NULL DEFAULT 'UNKNOWN',
        criticality          TEXT NOT NULL DEFAULT 'LOW',
        agent_access         TEXT NOT NULL DEFAULT 'READ_ONLY',
        origin_profile_id    TEXT,
        policy_profile       TEXT NOT NULL DEFAULT 'default',
        synced_at            TEXT NOT NULL,
        UNIQUE (tenant_id, full_name)
    );
    CREATE INDEX IF NOT EXISTS idx_repositories_tenant ON repositories(tenant_id);
    CREATE INDEX IF NOT EXISTS idx_repositories_lifecycle ON repositories(lifecycle);
    CREATE INDEX IF NOT EXISTS idx_repositories_fork ON repositories(is_fork);

    -- point-in-time raw payloads, so re-analysis never needs to re-hit the API
    CREATE TABLE IF NOT EXISTS repository_snapshots (
        id            TEXT PRIMARY KEY,
        repository_id TEXT NOT NULL REFERENCES repositories(id),
        taken_at      TEXT NOT NULL,
        kind          TEXT NOT NULL,
        payload       TEXT NOT NULL,
        payload_hash  TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_snapshots_repo ON repository_snapshots(repository_id, kind);

    -- §5 classification ------------------------------------------------------
    CREATE TABLE IF NOT EXISTS classifications (
        id            TEXT PRIMARY KEY,
        repository_id TEXT NOT NULL REFERENCES repositories(id),
        category      TEXT NOT NULL,
        lifecycle     TEXT NOT NULL,
        maturity      TEXT NOT NULL,
        criticality   TEXT NOT NULL,
        agent_access  TEXT NOT NULL,
        confidence    REAL NOT NULL DEFAULT 0.0,
        signals       TEXT NOT NULL DEFAULT '{}',
        rationale     TEXT NOT NULL DEFAULT '[]',
        created_at    TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_classifications_repo ON classifications(repository_id);

    -- §20.1 origin profile ---------------------------------------------------
    CREATE TABLE IF NOT EXISTS origin_profiles (
        id                    TEXT PRIMARY KEY,
        repository_id         TEXT NOT NULL REFERENCES repositories(id),
        origin_type           TEXT NOT NULL,
        origin_confidence     REAL NOT NULL,
        matched_rule          TEXT,
        upstream_retained_min REAL,
        upstream_retained_max REAL,
        local_contribution_min REAL,
        local_contribution_max REAL,
        transformation_score  REAL,
        contribution_band     TEXT,
        contribution_confidence TEXT,
        license_status        TEXT NOT NULL DEFAULT 'UNKNOWN',
        public_label          TEXT,
        public_attribution    TEXT,
        public_originality_claim TEXT NOT NULL DEFAULT 'none',
        review_status         TEXT NOT NULL DEFAULT 'UNREVIEWED',
        reviewed_by           TEXT,
        evidence              TEXT NOT NULL DEFAULT '[]',
        per_dimension         TEXT NOT NULL DEFAULT '{}',
        created_at            TEXT NOT NULL,
        updated_at            TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_origin_repo ON origin_profiles(repository_id);
    CREATE INDEX IF NOT EXISTS idx_origin_review ON origin_profiles(review_status);

    CREATE TABLE IF NOT EXISTS upstream_candidates (
        id                TEXT PRIMARY KEY,
        origin_profile_id TEXT NOT NULL REFERENCES origin_profiles(id),
        full_name         TEXT NOT NULL,
        discovered_via    TEXT NOT NULL,
        similarity        TEXT NOT NULL DEFAULT '{}',
        shared_root_commit INTEGER NOT NULL DEFAULT 0,
        merge_base        TEXT,
        confidence        REAL NOT NULL DEFAULT 0.0,
        notes             TEXT
    );

    CREATE TABLE IF NOT EXISTS component_profiles (
        id                TEXT PRIMARY KEY,
        origin_profile_id TEXT NOT NULL REFERENCES origin_profiles(id),
        path              TEXT NOT NULL,
        component_class   TEXT NOT NULL,
        bytes             INTEGER NOT NULL DEFAULT 0,
        files             INTEGER NOT NULL DEFAULT 0,
        reason            TEXT
    );

    CREATE TABLE IF NOT EXISTS license_profiles (
        id                   TEXT PRIMARY KEY,
        repository_id        TEXT NOT NULL REFERENCES repositories(id),
        repository_license   TEXT,
        embedded_sources     TEXT NOT NULL DEFAULT '[]',
        dependencies         TEXT NOT NULL DEFAULT '[]',
        assets               TEXT NOT NULL DEFAULT '[]',
        compatibility_status TEXT NOT NULL DEFAULT 'UNKNOWN',
        created_at           TEXT NOT NULL
    );

    -- §11-§12 policy ---------------------------------------------------------
    CREATE TABLE IF NOT EXISTS policy_bindings (
        id             TEXT PRIMARY KEY,
        tenant_id      TEXT NOT NULL REFERENCES tenants(id),
        scope_kind     TEXT NOT NULL,
        scope_value    TEXT NOT NULL,
        policy_profile TEXT NOT NULL,
        created_at     TEXT NOT NULL
    );

    -- §14-§17 requests, plans, approvals -------------------------------------
    CREATE TABLE IF NOT EXISTS change_requests (
        id                TEXT PRIMARY KEY,
        tenant_id         TEXT NOT NULL,
        actor_id          TEXT NOT NULL,
        actor_type        TEXT NOT NULL,
        principal         TEXT NOT NULL,
        tool              TEXT NOT NULL,
        targets           TEXT NOT NULL DEFAULT '[]',
        parameters        TEXT NOT NULL DEFAULT '{}',
        reason            TEXT,
        dry_run           INTEGER NOT NULL DEFAULT 1,
        requested_level   TEXT NOT NULL,
        decision          TEXT,
        risk              TEXT,
        constraints       TEXT NOT NULL DEFAULT '{}',
        matched_policies  TEXT NOT NULL DEFAULT '[]',
        created_at        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS change_plans (
        id                TEXT PRIMARY KEY,
        request_id        TEXT NOT NULL,
        tenant_id         TEXT NOT NULL,
        actor_id          TEXT NOT NULL,
        state             TEXT NOT NULL,
        targets           TEXT NOT NULL DEFAULT '[]',
        summary           TEXT NOT NULL DEFAULT '{}',
        risk_level        TEXT NOT NULL DEFAULT 'LOW',
        risk_reasons      TEXT NOT NULL DEFAULT '[]',
        approval_required INTEGER NOT NULL DEFAULT 1,
        approved_by       TEXT NOT NULL DEFAULT '[]',
        created_at        TEXT NOT NULL,
        expires_at        TEXT
    );

    CREATE TABLE IF NOT EXISTS approvals (
        id          TEXT PRIMARY KEY,
        plan_id     TEXT NOT NULL REFERENCES change_plans(id),
        approver    TEXT NOT NULL,
        decision    TEXT NOT NULL,
        comment     TEXT,
        created_at  TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS execution_events (
        id          TEXT PRIMARY KEY,
        plan_id     TEXT NOT NULL REFERENCES change_plans(id),
        repository  TEXT NOT NULL,
        change_type TEXT NOT NULL,
        result      TEXT NOT NULL,
        detail      TEXT NOT NULL DEFAULT '{}',
        created_at  TEXT NOT NULL
    );

    -- §18 append-only, hash-chained audit ledger ------------------------------
    CREATE TABLE IF NOT EXISTS audit_events (
        sequence        INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id        TEXT NOT NULL UNIQUE,
        request_id      TEXT,
        plan_id         TEXT,
        actor           TEXT NOT NULL,
        initiated_by    TEXT,
        tenant          TEXT,
        action          TEXT NOT NULL,
        targets         TEXT NOT NULL DEFAULT '[]',
        policy_decision TEXT,
        approved_by     TEXT NOT NULL DEFAULT '[]',
        credential_type TEXT,
        credential_scope TEXT,
        before_hash     TEXT,
        after_hash      TEXT,
        result          TEXT NOT NULL,
        detail          TEXT NOT NULL DEFAULT '{}',
        timestamp       TEXT NOT NULL,
        prev_event_hash TEXT,
        event_hash      TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_events(action);
    CREATE INDEX IF NOT EXISTS idx_audit_actor ON audit_events(actor);

    -- immutability guards: the ledger is append-only even for the core itself
    CREATE TRIGGER IF NOT EXISTS audit_events_no_update
    BEFORE UPDATE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit_events is append-only');
    END;

    CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
    BEFORE DELETE ON audit_events
    BEGIN
        SELECT RAISE(ABORT, 'audit_events is append-only');
    END;
    """,
    2: """
    -- Which taxonomy produced a verdict, and when. Previously only recoverable by
    -- digging through the `signals` JSON blob, which made it unqueryable.
    ALTER TABLE classifications ADD COLUMN taxonomy_profile TEXT NOT NULL DEFAULT 'evemisslab-v1';
    CREATE INDEX IF NOT EXISTS idx_classifications_recent
        ON classifications(repository_id, created_at DESC);
    """,
}


def connect(path: str | Path, *, readonly: bool = False) -> sqlite3.Connection:
    """Open the governance database, creating parent directories as needed."""
    p = Path(path)
    if readonly:
        conn = sqlite3.connect(f"file:{p.as_posix()}?mode=ro", uri=True)
    else:
        p.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(p)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    if not readonly:
        conn.execute("PRAGMA journal_mode = WAL")
    return conn


def connect_readonly(path: str | Path) -> sqlite3.Connection:
    """Handle for analysis code. Cannot mutate anything, by construction."""
    return connect(path, readonly=True)


def migrate(conn: sqlite3.Connection) -> int:
    """Apply pending migrations; returns the resulting schema version."""
    current = conn.execute("PRAGMA user_version").fetchone()[0]
    for version in sorted(MIGRATIONS):
        if version > current:
            conn.executescript(MIGRATIONS[version])
            conn.execute(f"PRAGMA user_version = {version}")
            current = version
    conn.commit()
    return current


def init_db(path: str | Path) -> sqlite3.Connection:
    conn = connect(path)
    migrate(conn)
    return conn


# --------------------------------------------------------------------------
# small helpers — JSON columns and datetimes are handled in exactly one place
# --------------------------------------------------------------------------

def dumps(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, default=_json_default)


def loads(value: str | None, default: Any = None) -> Any:
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def _json_default(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    return str(obj)


def iso(value: datetime | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def upsert(
    conn: sqlite3.Connection,
    table: str,
    row: dict[str, Any],
    keys: Iterable[str],
    *,
    skip_update: Iterable[str] = (),
) -> None:
    """INSERT … ON CONFLICT(keys) DO UPDATE for every non-key column.

    ``skip_update`` names columns that are written on insert but never on update —
    the governance overlay uses this so a re-sync cannot erase a classification.
    """
    cols = list(row)
    key_list = list(keys)
    protected = set(skip_update)
    updates = [c for c in cols if c not in key_list and c not in protected]
    placeholders = ", ".join("?" for _ in cols)
    sql = f"INSERT INTO {table} ({', '.join(cols)}) VALUES ({placeholders})"
    if updates:
        assignments = ", ".join(f"{c}=excluded.{c}" for c in updates)
        sql += f" ON CONFLICT({', '.join(key_list)}) DO UPDATE SET {assignments}"
    else:
        sql += f" ON CONFLICT({', '.join(key_list)}) DO NOTHING"
    conn.execute(sql, [row[c] for c in cols])
