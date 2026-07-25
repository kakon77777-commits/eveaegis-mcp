"""Phase 1 Inventory — build the unified asset catalog (§24 Phase 1, §4.2, §20, §27).

This module answers exactly one question: *what repositories exist, and what does
GitHub itself say about them?* It deliberately stops there. Deciding what a
repository **is** (§5 classification) or where it **came from** (§6 provenance) is
the job of Phases 2/3, and inventory must never pre-empt that judgement.

Two invariants make a re-sync safe to run at any time:

* **The governance overlay is write-once.** ``lifecycle``, ``category``,
  ``maturity``, ``criticality``, ``agent_access``, ``origin_profile_id`` and
  ``policy_profile`` are seeded when a repository is first discovered and are then
  never touched by inventory again. A nightly sync must not be able to erase a
  human's classification.
* **Only unambiguous GitHub facts become labels.** ``archived == true`` is the one
  signal GitHub states outright, so it may seed ``Lifecycle.ARCHIVED``. Everything
  else stays ``UNKNOWN`` and waits for the classifier (axiom 4).

Raw payloads land in ``repository_snapshots`` so Phase 2 can re-analyse without
re-hitting the API. That table is a *change log*: a payload whose content hash
matches the previous snapshot for the same (repository, kind) is not written again.
"""

from __future__ import annotations

import sqlite3
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterator

from pydantic import BaseModel

from ..audit import content_hash
from ..core import GovernanceCore
from ..credentials import TokenScope
from ..db import dumps, iso, loads, upsert
from ..githubapi import GitHubClient
from ..models import GitHubInstallation, RepositoryAsset
from ..taxonomy import (
    AgentAccess,
    Category,
    Criticality,
    Lifecycle,
    Maturity,
    Visibility,
)

#: Columns owned by Phases 2/3. Inventory seeds them once and never writes them again.
GOVERNANCE_OVERLAY_COLUMNS: tuple[str, ...] = (
    "lifecycle",
    "category",
    "maturity",
    "criticality",
    "agent_access",
    "origin_profile_id",
    "policy_profile",
)

#: Payload keys GitHub only populates on the single-repository endpoint. When a cheap
#: list payload omits them we keep whatever a previous detailed fetch stored, rather
#: than overwriting a known value with NULL.
DETAIL_ONLY_KEYS: tuple[str, ...] = ("parent", "source", "template_repository", "topics")


class InventoryResult(BaseModel):
    """Outcome of one :meth:`InventorySync.sync_repositories` run."""

    accounts: int = 0
    repositories: int = 0
    created: int = 0
    updated: int = 0
    snapshots: int = 0
    errors: list[str] = []
    duration_seconds: float = 0.0


# --------------------------------------------------------------------------
# identity (§27)
# --------------------------------------------------------------------------

def repository_id(payload: dict[str, Any]) -> str:
    """``github:{owner_id}:{repo_id}`` — the §27 catalog identifier.

    Numeric GitHub ids are used rather than ``full_name`` because both the owner
    login and the repository name are renameable, while the ids are not.
    """
    owner_id = (payload.get("owner") or {}).get("id")
    repo_id = payload.get("id")
    if owner_id is None or repo_id is None:
        raise ValueError(f"repository payload lacks owner.id/id: {payload.get('full_name')!r}")
    return f"github:{owner_id}:{repo_id}"


def account_id(payload: dict[str, Any]) -> str:
    """``github:{account_id}`` — same scheme, one segment shorter."""
    ident = payload.get("id")
    if ident is None:
        raise ValueError(f"account payload lacks id: {payload.get('login')!r}")
    return f"github:{ident}"


def _visibility(payload: dict[str, Any]) -> str:
    """Prefer the explicit ``visibility`` field, fall back to the ``private`` flag."""
    raw = payload.get("visibility")
    if raw in tuple(Visibility):
        return str(raw)
    return str(Visibility.PRIVATE if payload.get("private") else Visibility.PUBLIC)


def row_to_asset(row: sqlite3.Row) -> RepositoryAsset:
    """Rehydrate a ``repositories`` row. Datetime strings are coerced by pydantic."""
    return RepositoryAsset(
        id=row["id"],
        tenant_id=row["tenant_id"],
        installation_id=row["installation_id"],
        full_name=row["full_name"],
        github_repository_id=row["github_repository_id"],
        visibility=Visibility(row["visibility"]),
        default_branch=row["default_branch"],
        description=row["description"],
        homepage=row["homepage"],
        topics=loads(row["topics"], []),
        primary_language=row["primary_language"],
        languages=loads(row["languages"], {}),
        license_spdx=row["license_spdx"],
        is_archived=bool(row["is_archived"]),
        is_fork=bool(row["is_fork"]),
        parent_full_name=row["parent_full_name"],
        source_full_name=row["source_full_name"],
        template_full_name=row["template_full_name"],
        size_kb=row["size_kb"],
        stargazers=row["stargazers"],
        open_issues=row["open_issues"],
        pushed_at=row["pushed_at"],
        created_at=row["created_at"],
        updated_at=row["updated_at"],
        lifecycle=Lifecycle(row["lifecycle"]),
        category=Category(row["category"]),
        maturity=Maturity(row["maturity"]),
        criticality=Criticality(row["criticality"]),
        agent_access=AgentAccess(row["agent_access"]),
        origin_profile_id=row["origin_profile_id"],
        policy_profile=row["policy_profile"],
        synced_at=row["synced_at"],
    )


# --------------------------------------------------------------------------
# the sync itself
# --------------------------------------------------------------------------

class InventorySync:
    """Reads GitHub, writes the catalog. Holds no credential of its own (axiom 1)."""

    def __init__(self, core: GovernanceCore) -> None:
        self.core = core

    # -- public API -------------------------------------------------------

    def sync_accounts(self) -> list[GitHubInstallation]:
        """Persist the authenticated user and every organization it can see."""
        errors: list[str] = []
        with self.core.client(TokenScope.READ_METADATA, reason="inventory account sync") as gh:
            installations = self._sync_accounts(gh, errors, credential=gh.credential_description)
        return installations

    def sync_repositories(
        self,
        *,
        include_readme: bool = True,
        include_languages: bool = True,
        limit: int | None = None,
    ) -> InventoryResult:
        """Full portfolio sweep: accounts, then every repository they own.

        ``include_readme``/``include_languages`` each cost one extra API call per
        repository, so they are switches rather than always-on behaviour (§29 asks
        the system to stay usable at 100+ repositories).
        """
        started = time.monotonic()
        result = InventoryResult()

        # Axiom 5: ask for the narrowest scope that satisfies the request. README
        # bodies are content; everything else here is metadata.
        scope = TokenScope.READ_CONTENT if include_readme else TokenScope.READ_METADATA

        with self.core.client(scope, reason="phase 1 inventory sync") as gh:
            credential = gh.credential_description
            self.core.ledger.record(
                "inventory_sync_started",
                tenant=self.core.tenant_id,
                credential_type=credential.get("credential_type") or credential.get("backend"),
                credential_scope=credential.get("scope"),
                result="STARTED",
                detail={
                    "include_readme": include_readme,
                    "include_languages": include_languages,
                    "limit": limit,
                },
            )

            installations = self._sync_accounts(gh, result.errors, credential=credential)
            result.accounts = len(installations)

            seen: set[str] = set()
            for payload, installation in self._iter_repository_payloads(
                gh, installations, result.errors, credential
            ):
                full_name = payload.get("full_name") or ""
                if full_name in seen:
                    continue  # an org repo can surface twice if affiliations overlap
                seen.add(full_name)
                if limit is not None and result.repositories >= limit:
                    break
                try:
                    outcome = self._ingest(
                        gh,
                        payload,
                        installation_id=installation.id if installation else None,
                        include_readme=include_readme,
                        include_languages=include_languages,
                    )
                except Exception as exc:  # one bad repo must not end the sweep
                    self._record_error(full_name or "<unknown>", exc, result.errors, credential)
                    continue
                result.repositories += 1
                result.created += outcome["created"]
                result.updated += outcome["updated"]
                result.snapshots += outcome["snapshots"]

            result.duration_seconds = round(time.monotonic() - started, 3)
            self.core.ledger.record(
                "inventory_sync_completed",
                tenant=self.core.tenant_id,
                credential_type=credential.get("credential_type") or credential.get("backend"),
                credential_scope=credential.get("scope"),
                result="PARTIAL" if result.errors else "COMPLETED",
                detail={
                    **result.model_dump(exclude={"errors"}),
                    "error_count": len(result.errors),
                    "api_requests": getattr(gh, "request_count", None),
                },
            )
        return result

    def refresh_repository(self, full_name: str) -> RepositoryAsset:
        """Re-read one repository from the detailed endpoint and re-persist it.

        Unlike a sweep this always uses ``GET /repos/{full_name}``, which is the only
        endpoint that fills in ``parent``/``source``/``template_repository`` — the
        fields Phase 2 needs to tell a fork from an original.
        """
        with self.core.client(TokenScope.READ_CONTENT, reason=f"inventory refresh {full_name}") as gh:
            credential = gh.credential_description
            payload = gh.repo(full_name)
            owner_login = (payload.get("owner") or {}).get("login", "")
            installation = self._installation_for(owner_login)
            self._ingest(
                gh,
                payload,
                installation_id=installation.id if installation else None,
                include_readme=True,
                include_languages=True,
            )
            self.core.ledger.record(
                "inventory_repository_refreshed",
                tenant=self.core.tenant_id,
                targets=[payload.get("full_name") or full_name],
                credential_type=credential.get("credential_type") or credential.get("backend"),
                credential_scope=credential.get("scope"),
                detail={"repository_id": repository_id(payload)},
            )
        asset = self.load_repository(payload.get("full_name") or full_name)
        if asset is None:  # pragma: no cover - only reachable if the write vanished
            raise RuntimeError(f"repository {full_name} was not persisted")
        return asset

    def load_repository(self, full_name: str) -> RepositoryAsset | None:
        row = self.core.conn.execute(
            "SELECT * FROM repositories WHERE tenant_id = ? AND full_name = ?",
            (self.core.tenant_id, full_name),
        ).fetchone()
        return row_to_asset(row) if row else None

    def list_repositories(self, *, only_unclassified: bool = False) -> list[RepositoryAsset]:
        """All catalog entries, newest push first.

        ``only_unclassified`` is the §19.1 "Unclassified" bucket: anything whose
        category or lifecycle is still ``UNKNOWN``, i.e. still waiting for Phase 3.
        """
        sql = "SELECT * FROM repositories WHERE tenant_id = ?"
        if only_unclassified:
            sql += " AND (category = 'UNKNOWN' OR lifecycle = 'UNKNOWN')"
        sql += " ORDER BY pushed_at DESC NULLS LAST, full_name ASC"
        rows = self.core.conn.execute(sql, (self.core.tenant_id,)).fetchall()
        return [row_to_asset(r) for r in rows]

    # -- accounts ---------------------------------------------------------

    def _sync_accounts(
        self,
        gh: GitHubClient,
        errors: list[str],
        *,
        credential: dict[str, str],
    ) -> list[GitHubInstallation]:
        accounts: list[tuple[dict[str, Any], str]] = []
        try:
            accounts.append((gh.viewer(), "user"))
        except Exception as exc:
            self._record_error("<viewer>", exc, errors, credential)
            return []
        try:
            accounts.extend((org, "organization") for org in gh.orgs())
        except Exception as exc:
            # A gh CLI token without `read:org` still yields a usable personal sweep.
            self._record_error("<orgs>", exc, errors, credential)

        now = datetime.now(timezone.utc).isoformat()
        installations: list[GitHubInstallation] = []
        for payload, kind in accounts:
            install = GitHubInstallation(
                id=account_id(payload),
                tenant_id=self.core.tenant_id,
                account_login=payload["login"],
                account_type=kind,
                # NULL until the GitHub App path exists; the gh CLI token is a
                # delegated user token, not an installation.
                installation_id=None,
                # A delegated user token is account-wide by construction.
                allowed_repositories="all",
                credential_backend=str(credential.get("backend", "gh_cli")),
            )
            upsert(
                self.core.conn,
                "github_installations",
                {
                    "id": install.id,
                    "tenant_id": install.tenant_id,
                    "account_login": install.account_login,
                    "account_type": install.account_type,
                    "installation_id": install.installation_id,
                    "allowed_repositories": install.allowed_repositories,
                    "permission_snapshot": dumps(install.permission_snapshot),
                    "credential_backend": install.credential_backend,
                    "created_at": now,
                },
                keys=("tenant_id", "account_login"),
            )
            installations.append(install)
        self.core.conn.commit()
        return installations

    def _installation_for(self, login: str) -> GitHubInstallation | None:
        row = self.core.conn.execute(
            "SELECT * FROM github_installations WHERE tenant_id = ? AND lower(account_login) = ?",
            (self.core.tenant_id, login.lower()),
        ).fetchone()
        if row is None:
            return None
        return GitHubInstallation(
            id=row["id"],
            tenant_id=row["tenant_id"],
            account_login=row["account_login"],
            account_type=row["account_type"],
            installation_id=row["installation_id"],
            allowed_repositories=row["allowed_repositories"],
            permission_snapshot=loads(row["permission_snapshot"], {}),
            credential_backend=row["credential_backend"],
        )

    # -- repository payload sources ---------------------------------------

    def _iter_repository_payloads(
        self,
        gh: GitHubClient,
        installations: list[GitHubInstallation],
        errors: list[str],
        credential: dict[str, str],
    ) -> Iterator[tuple[dict[str, Any], GitHubInstallation | None]]:
        """Yield ``(payload, owning installation)`` for every reachable repository.

        Each source is isolated: an org that denies listing costs that org only.
        """
        for install in installations:
            try:
                if install.account_type == "user":
                    stream = gh.user_repos(affiliation="owner")
                else:
                    stream = gh.org_repos(install.account_login)
                for payload in stream:
                    yield payload, install
            except Exception as exc:
                self._record_error(install.account_login, exc, errors, credential)

    # -- persistence ------------------------------------------------------

    def _ingest(
        self,
        gh: GitHubClient,
        payload: dict[str, Any],
        *,
        installation_id: str | None,
        include_readme: bool,
        include_languages: bool,
    ) -> dict[str, int]:
        rid = repository_id(payload)
        full_name = payload["full_name"]
        conn = self.core.conn

        existing = self._reconcile_identity(rid, full_name)

        # parent/source only exist on the detailed endpoint, so pay for it exactly
        # where it matters: forks. Everything else is already in the list payload.
        if payload.get("fork") and "parent" not in payload:
            payload = gh.repo(full_name)

        languages: dict[str, int] | None = None
        if include_languages:
            languages = gh.languages(full_name)

        row = self._repository_row(
            payload,
            rid=rid,
            installation_id=installation_id,
            languages=languages,
            existing=existing,
        )
        upsert(conn, "repositories", row, keys=("tenant_id", "full_name"))

        snapshots = 0
        snapshots += int(self._write_snapshot(rid, "repository", payload))
        if languages is not None:
            snapshots += int(self._write_snapshot(rid, "languages", languages))
        if include_readme:
            readme = gh.readme(full_name)
            if readme is not None:
                snapshots += int(self._write_snapshot(rid, "readme", readme))

        conn.commit()
        return {
            "created": 0 if existing else 1,
            "updated": 1 if existing else 0,
            "snapshots": snapshots,
        }

    def _reconcile_identity(self, rid: str, full_name: str) -> sqlite3.Row | None:
        """Locate the existing row, healing a rename before the upsert runs.

        ``id`` is stable but ``full_name`` is the conflict key, so a renamed
        repository would otherwise arrive as a second row and collide on the primary
        key. Renaming the stored row first keeps the identity — and every snapshot
        hanging off it — intact.
        """
        conn = self.core.conn
        by_id = conn.execute("SELECT * FROM repositories WHERE id = ?", (rid,)).fetchone()
        by_name = conn.execute(
            "SELECT * FROM repositories WHERE tenant_id = ? AND full_name = ?",
            (self.core.tenant_id, full_name),
        ).fetchone()

        if by_id is not None and by_id["full_name"] != full_name:
            if by_name is not None:
                raise ValueError(
                    f"full_name {full_name!r} is already held by {by_name['id']}; "
                    f"cannot rename {rid}"
                )
            conn.execute("UPDATE repositories SET full_name = ? WHERE id = ?", (full_name, rid))
            return conn.execute("SELECT * FROM repositories WHERE id = ?", (rid,)).fetchone()

        if by_id is None and by_name is not None:
            # Same name, different GitHub id: the original was deleted and recreated.
            # Rewriting the primary key would orphan its snapshots, so stop and report.
            raise ValueError(
                f"{full_name} exists under id {by_name['id']} but GitHub now reports {rid}"
            )
        return by_id

    def _repository_row(
        self,
        payload: dict[str, Any],
        *,
        rid: str,
        installation_id: str | None,
        languages: dict[str, int] | None,
        existing: sqlite3.Row | None,
    ) -> dict[str, Any]:
        license_spdx = (payload.get("license") or {}).get("spdx_id")

        row: dict[str, Any] = {
            "id": rid,
            "tenant_id": self.core.tenant_id,
            "installation_id": installation_id,
            "full_name": payload["full_name"],
            "github_repository_id": int(payload["id"]),
            "visibility": _visibility(payload),
            "default_branch": payload.get("default_branch") or "main",
            "description": payload.get("description"),
            "homepage": payload.get("homepage") or None,
            "primary_language": payload.get("language"),
            # NOASSERTION is kept verbatim: it means "a license file exists but GitHub
            # could not name it", which is a different fact from "no license".
            "license_spdx": license_spdx,
            "is_archived": 1 if payload.get("archived") else 0,
            "is_fork": 1 if payload.get("fork") else 0,
            "size_kb": int(payload.get("size") or 0),
            "stargazers": int(payload.get("stargazers_count") or 0),
            "open_issues": int(payload.get("open_issues_count") or 0),
            "pushed_at": iso(payload.get("pushed_at")),
            "created_at": iso(payload.get("created_at")),
            "updated_at": iso(payload.get("updated_at")),
            "synced_at": datetime.now(timezone.utc).isoformat(),
        }

        # Languages cost an API call; when they were not fetched, keep what we have.
        if languages is not None:
            row["languages"] = dumps(languages)
        elif existing is not None:
            row["languages"] = existing["languages"]

        # Same rule for the detail-only fields: absent from a payload means "not
        # observed", never "cleared".
        for key, column in (
            ("topics", "topics"),
            ("parent", "parent_full_name"),
            ("source", "source_full_name"),
            ("template_repository", "template_full_name"),
        ):
            if key in payload:
                value = payload.get(key)
                row[column] = dumps(value or []) if key == "topics" else (value or {}).get("full_name")
            elif existing is not None:
                row[column] = existing[column]

        if existing is None:
            # First sighting: seed the overlay. `archived` is the only label GitHub
            # states outright, so it is the only one inventory dares to infer (axiom 4).
            row["lifecycle"] = str(
                Lifecycle.ARCHIVED if payload.get("archived") else Lifecycle.UNKNOWN
            )
            row["category"] = str(Category.UNKNOWN)
            row["maturity"] = str(Maturity.UNKNOWN)
            row["criticality"] = str(Criticality.LOW)
            row["agent_access"] = str(AgentAccess.READ_ONLY)
            row["policy_profile"] = "default"
        # else: every overlay column is intentionally absent from `row`, so the
        # generated ON CONFLICT DO UPDATE cannot touch a human's classification.

        return row

    def _write_snapshot(self, rid: str, kind: str, payload: Any) -> bool:
        """Append a raw payload unless it is byte-identical to the previous one."""
        digest = content_hash(payload)
        latest = self.core.conn.execute(
            "SELECT payload_hash FROM repository_snapshots "
            "WHERE repository_id = ? AND kind = ? ORDER BY rowid DESC LIMIT 1",
            (rid, kind),
        ).fetchone()
        if latest is not None and latest["payload_hash"] == digest:
            return False
        self.core.conn.execute(
            "INSERT INTO repository_snapshots (id, repository_id, taken_at, kind, payload, payload_hash) "
            "VALUES (?,?,?,?,?,?)",
            (
                f"snap_{uuid.uuid4().hex[:16]}",
                rid,
                datetime.now(timezone.utc).isoformat(),
                kind,
                dumps(payload),
                digest,
            ),
        )
        return True

    # -- errors -----------------------------------------------------------

    def _record_error(
        self,
        target: str,
        exc: Exception,
        errors: list[str],
        credential: dict[str, str],
    ) -> None:
        """Collect a per-target failure and give it its own ledger entry.

        Successful upserts stay silent — 55 repositories would otherwise bury the
        ledger under noise — but a failure is exactly the thing a human needs to see.
        """
        message = f"{target}: {type(exc).__name__}: {exc}"
        errors.append(message)
        self.core.ledger.record(
            "inventory_repository_error",
            tenant=self.core.tenant_id,
            targets=[target],
            credential_type=credential.get("credential_type") or credential.get("backend"),
            credential_scope=credential.get("scope"),
            result="FAILED",
            detail={"target": target, "error": f"{type(exc).__name__}: {exc}"},
        )
