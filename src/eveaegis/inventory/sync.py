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
  human's classification. The single exception is spelled out below.
* **Only unambiguous GitHub facts become labels.** ``archived == true`` is the one
  signal GitHub states outright, so it may seed ``Lifecycle.ARCHIVED`` — and may
  also promote a *still-undecided* ``UNKNOWN`` lifecycle later, since a repository
  archived after its first sync would otherwise stay unlabelled forever. It never
  overwrites a lifecycle anyone actually decided. Everything else waits for the
  classifier (axiom 4).

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
from ..githubapi import GitHubClient, GitHubError, NotFound
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
    #: Repositories a complete sweep no longer saw. Empty after a partial sweep.
    missing: list[str] = []
    duration_seconds: float = 0.0


# --------------------------------------------------------------------------
# identity (§27)
# --------------------------------------------------------------------------

def repository_id(payload: dict[str, Any]) -> str:
    """``github:{owner_id}:{repo_id}`` — the §27 catalog identifier.

    Numeric GitHub ids are used rather than ``full_name`` because the owner login and
    the repository name are both renameable. Note the limit of that reasoning: the
    *owner* can change too, when a repository is transferred between accounts, so
    this string is a **surrogate recording where a repository was first seen**, not a
    stable identity. The stable identity is ``github_repository_id`` alone, which is
    what :meth:`InventorySync._reconcile_identity` matches on.
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
        #: Installation-mode listing, fetched once during account discovery and
        #: reused by the repository sweep. ``None`` means "not fetched yet".
        self._installation_repo_cache: list[dict[str, Any]] | None = None

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
        include_tree: bool = True,
        limit: int | None = None,
    ) -> InventoryResult:
        """Full portfolio sweep: accounts, then every repository they own.

        ``include_readme``/``include_languages``/``include_tree`` each cost one extra
        API call per repository, so they are switches rather than always-on behaviour
        (§29 asks the system to stay usable at 100+ repositories). All three default
        to on because Phases 2 and 3 read the resulting snapshots offline — a sync
        that skips them makes the classifier guess from topics alone.
        """
        started = time.monotonic()
        result = InventoryResult()

        # Axiom 5: ask for the narrowest scope that satisfies the request. README
        # bodies are content; everything else here is metadata.
        scope = (
            TokenScope.READ_CONTENT
            if (include_readme or include_tree)
            else TokenScope.READ_METADATA
        )

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
                    "include_tree": include_tree,
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
                        include_tree=include_tree,
                    )
                except Exception as exc:  # one bad repo must not end the sweep
                    self._record_error(full_name or "<unknown>", exc, result.errors, credential)
                    continue
                result.repositories += 1
                result.created += outcome["created"]
                result.updated += outcome["updated"]
                result.snapshots += outcome["snapshots"]

            # Only a complete, error-free sweep is evidence of absence. A partial
            # sweep (limit set, or a listing that failed) says nothing about the
            # repositories it never reached, so it must not mark anything missing.
            if limit is None and not result.errors:
                result.missing = self._reconcile_presence(seen)

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
        with self.core.client_for(full_name, TokenScope.READ_CONTENT, reason=f"inventory refresh {full_name}") as gh:
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
                include_tree=True,
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
        sql = "SELECT * FROM repositories WHERE tenant_id = ? AND missing_since IS NULL"
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
        if gh.identity_mode == "installation":
            accounts = self._installation_accounts(gh, errors, credential)
        else:
            accounts = self._user_accounts(gh, errors, credential)
        if not accounts:
            return []

        now = datetime.now(timezone.utc).isoformat()
        installations: list[GitHubInstallation] = []
        for payload, kind in accounts:
            # Under an App each account is its own installation with its own grant
            # of permissions; the discovery step stamps both onto the payload.
            install = GitHubInstallation(
                id=account_id(payload),
                tenant_id=self.core.tenant_id,
                account_login=payload["login"],
                account_type=kind,
                installation_id=payload.get("_installation_id")
                if gh.identity_mode == "installation"
                else None,
                allowed_repositories=str(payload.get("_repository_selection") or "all"),
                permission_snapshot=dict(payload.get("_permissions") or {}),
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

    def _user_accounts(
        self, gh: GitHubClient, errors: list[str], credential: dict[str, str]
    ) -> list[tuple[dict[str, Any], str]]:
        """Discovery for a delegated user token: the person, then their orgs."""
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
        return accounts

    def _installation_accounts(
        self, gh: GitHubClient, errors: list[str], credential: dict[str, str]
    ) -> list[tuple[dict[str, Any], str]]:
        """Discovery for an App installation token.

        An installation token acts as the *App*, not as a person, so every
        ``/user*`` endpoint answers 403. The accounts an installation covers are
        therefore derived from the owners of the repositories it can reach — which
        is also more honest than asking for org membership: it reports the accounts
        the App was actually granted, not the accounts the human belongs to.
        """
        # The App is the authority on where it is installed. One listing per
        # installation; the personal account and the company org are separate
        # installations with separate tokens, and a sweep must reach both.
        try:
            installs = self.core.broker.installations()
        except Exception as exc:
            self._record_error("<installations>", exc, errors, credential)
            installs = []
        if not installs and self.core.cfg.credentials.installation_id:
            installs = [{"id": int(self.core.cfg.credentials.installation_id), "login": None, "type": None}]

        seen: dict[str, tuple[dict[str, Any], str]] = {}
        all_repos: list[dict[str, Any]] = []
        allowed = {a.lower() for a in self.core.cfg.governance.accounts}
        for inst in installs:
            inst_id = int(inst["id"])
            login = str(inst.get("login") or "")
            # A public App can be installed by anyone on their own account. That
            # installation is real, but it is not ours to govern: skip it loudly.
            if allowed and login.lower() not in allowed:
                self.core.ledger.record(
                    "inventory_installation_ignored",
                    tenant=self.core.tenant_id,
                    detail={"installation_id": inst_id, "account": login,
                            "reason": "account not in governance.accounts"},
                )
                continue
            try:
                with self.core.client(TokenScope.READ_METADATA, reason="installation discovery",
                                      installation_id=inst_id) as igh:
                    repos = list(igh.installation_repos())
            except Exception as exc:
                self._record_error(f"<installation {inst_id}>", exc, errors, credential)
                continue
            for repo in repos:
                repo["_installation_id"] = inst_id
                all_repos.append(repo)
                owner = repo.get("owner") or {}
                login = owner.get("login")
                if not login or login in seen:
                    continue
                kind = "organization" if owner.get("type") == "Organization" else "user"
                payload = dict(owner)
                payload["_installation_id"] = inst_id
                payload["_repository_selection"] = inst.get("repository_selection")
                payload["_permissions"] = inst.get("permissions") or {}
                seen[login] = (payload, kind)
            # An installation with zero repositories (a brand-new org) is still an
            # account under governance: record it from the installation itself.
            if inst.get("login") and inst["login"] not in seen:
                payload = {"id": inst.get("account_id") or inst_id, "login": inst["login"],
                           "_installation_id": inst_id,
                           "_repository_selection": inst.get("repository_selection"),
                           "_permissions": inst.get("permissions") or {}}
                kind = "organization" if inst.get("type") == "Organization" else "user"
                seen[inst["login"]] = (payload, kind)
        # Cache so the repository sweep does not pay for the same listings twice.
        self._installation_repo_cache = all_repos
        return list(seen.values())

    def _reconcile_presence(self, seen: set[str]) -> list[str]:
        """Mark rows the sweep did not see, and clear ones that came back.

        Rows are never deleted: a repository's governance history is the reason
        the catalog exists, and GitHub itself keeps deleted repositories restorable
        for 90 days, so absence is a state, not an erasure.
        """
        conn = self.core.conn
        now = datetime.now(timezone.utc).isoformat()
        seen_lower = {name.lower() for name in seen}
        newly_missing: list[str] = []
        for row in conn.execute(
            "SELECT full_name, missing_since FROM repositories WHERE tenant_id = ?",
            (self.core.tenant_id,),
        ).fetchall():
            present = row["full_name"].lower() in seen_lower
            if not present and row["missing_since"] is None:
                conn.execute(
                    "UPDATE repositories SET missing_since = ? WHERE tenant_id = ? AND full_name = ?",
                    (now, self.core.tenant_id, row["full_name"]),
                )
                newly_missing.append(row["full_name"])
            elif present and row["missing_since"] is not None:
                conn.execute(
                    "UPDATE repositories SET missing_since = NULL WHERE tenant_id = ? AND full_name = ?",
                    (self.core.tenant_id, row["full_name"]),
                )
                self.core.ledger.record(
                    "inventory_repository_reappeared",
                    tenant=self.core.tenant_id,
                    targets=[row["full_name"]],
                    detail={"was_missing_since": row["missing_since"]},
                )
        if newly_missing:
            self.core.ledger.record(
                "inventory_repositories_missing",
                tenant=self.core.tenant_id,
                targets=newly_missing,
                detail={"count": len(newly_missing), "note": "rows retained; governance history preserved"},
            )
        conn.commit()
        return newly_missing

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

        Under an App installation there is only one source — ``/installation/
        repositories`` already spans every account the installation covers — so the
        listing fetched during account discovery is reused rather than re-requested.
        """
        if gh.identity_mode == "installation":
            by_login = {i.account_login.lower(): i for i in installations}
            repos = getattr(self, "_installation_repo_cache", None)
            if repos is None:
                try:
                    repos = list(gh.installation_repos())
                except Exception as exc:
                    self._record_error("<installation>", exc, errors, credential)
                    return
            for payload in repos:
                login = ((payload.get("owner") or {}).get("login") or "").lower()
                yield payload, by_login.get(login)
            return

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
        include_tree: bool = True,
    ) -> dict[str, int]:
        rid = repository_id(payload)
        full_name = payload["full_name"]
        conn = self.core.conn

        existing = self._reconcile_identity(rid, full_name, int(payload["id"]))
        if existing is not None:
            # Reconciliation may have matched a row filed under an earlier owner. Every
            # snapshot and profile hangs off *that* surrogate id, so the rest of this
            # ingest must use it rather than the id derived from today's owner.
            rid = existing["id"]

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
        # `id` is insert-only: a transferred repository keeps the surrogate its history
        # hangs off, even though today's owner would derive a different one.
        upsert(conn, "repositories", row, keys=("tenant_id", "full_name"), skip_update=("id",))

        snapshots = 0
        snapshots += int(self._write_snapshot(rid, "repository", payload))
        if languages is not None:
            snapshots += int(self._write_snapshot(rid, "languages", languages))
        if include_readme:
            readme = gh.readme(full_name)
            if readme is not None:
                snapshots += int(self._write_snapshot(rid, "readme", readme))
        if include_tree:
            tree = self._fetch_tree(gh, payload)
            if tree is not None:
                snapshots += int(self._write_snapshot(rid, "tree", tree))

        conn.commit()
        return {
            "created": 0 if existing else 1,
            "updated": 1 if existing else 0,
            "snapshots": snapshots,
        }

    #: Cap on stored tree entries. A handful of repositories carry tens of thousands
    #: of paths (vendored trees, generated sites); the file markers classification
    #: and provenance care about all live near the root anyway.
    MAX_TREE_ENTRIES = 5000

    def _fetch_tree(self, gh: GitHubClient, payload: dict[str, Any]) -> dict[str, Any] | None:
        """Root tree listing, stored so Phase 2/3 can reason about paths offline.

        Without this, the file-marker evidence family has nothing to read and every
        repository without obvious topics falls through to UNKNOWN. Empty
        repositories legitimately have no tree — that is not an error.
        """
        ref = payload.get("default_branch") or "HEAD"
        try:
            entries = gh.tree(payload["full_name"], ref, recursive=True)
        except NotFound:
            return None
        except GitHubError as exc:
            # 409 "Git Repository is empty" and similar: the repository exists and
            # must still be inventoried — it simply has no tree to snapshot. Only a
            # tree fetch failed here, not the repository.
            if exc.status in (409, 422):
                return None
            raise
        if not entries:
            return None
        return {
            "ref": ref,
            "truncated": len(entries) > self.MAX_TREE_ENTRIES,
            "tree": [
                {"path": e.get("path"), "type": e.get("type"), "size": e.get("size", 0)}
                for e in entries[: self.MAX_TREE_ENTRIES]
            ],
        }

    def _reconcile_identity(
        self, rid: str, full_name: str, github_repository_id: int
    ) -> sqlite3.Row | None:
        """Locate the existing row, healing a rename *or a transfer* before the upsert.

        Three identifiers are in play and only one of them is actually stable:

        * ``full_name`` changes on rename **and** on transfer;
        * ``id`` is ``github:{owner_id}:{repo_id}``, so it changes on transfer too —
          the §27 scheme used numeric ids because names are renameable, but ownership
          is just as mutable;
        * ``github_repository_id`` survives both. It is the real identity.

        So the lookup is by numeric repository id, and the stored ``id`` is treated as
        an opaque surrogate that merely records where the repository was first seen.
        Rewriting it on transfer would orphan every snapshot, origin profile and
        classification hanging off it — which is exactly the governance history a
        personal-to-company move must not silently destroy.
        """
        conn = self.core.conn
        by_repo = conn.execute(
            "SELECT * FROM repositories WHERE tenant_id = ? AND github_repository_id = ?",
            (self.core.tenant_id, github_repository_id),
        ).fetchone()
        by_name = conn.execute(
            "SELECT * FROM repositories WHERE tenant_id = ? AND full_name = ?",
            (self.core.tenant_id, full_name),
        ).fetchone()

        if by_repo is not None and by_repo["full_name"] != full_name:
            if by_name is not None and by_name["id"] != by_repo["id"]:
                raise ValueError(
                    f"full_name {full_name!r} is already held by {by_name['id']}; "
                    f"cannot move {by_repo['id']}"
                )
            moved = by_repo["id"] != rid  # owner changed, not just the name
            conn.execute(
                "UPDATE repositories SET full_name = ? WHERE id = ?", (full_name, by_repo["id"])
            )
            self.core.ledger.record(
                "inventory_repository_moved" if moved else "inventory_repository_renamed",
                tenant=self.core.tenant_id,
                targets=[full_name],
                detail={
                    "from": by_repo["full_name"],
                    "to": full_name,
                    "surrogate_id": by_repo["id"],
                    "github_repository_id": github_repository_id,
                    "note": "governance history preserved under the original surrogate id",
                },
            )
            return conn.execute(
                "SELECT * FROM repositories WHERE id = ?", (by_repo["id"],)
            ).fetchone()

        if by_repo is None and by_name is not None:
            # Same name, different GitHub repository: the original was deleted and
            # recreated. Rewriting the primary key would orphan its snapshots, so stop
            # and report rather than silently repointing the history at a new project.
            raise ValueError(
                f"{full_name} exists under id {by_name['id']} but GitHub now reports "
                f"repository id {github_repository_id}"
            )
        return by_repo

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
            row["criticality"] = str(Criticality.UNKNOWN)
            row["agent_access"] = str(AgentAccess.READ_ONLY)
            row["policy_profile"] = "default"
        elif payload.get("archived") and existing["lifecycle"] == str(Lifecycle.UNKNOWN):
            # Narrow exception to write-once: a repository archived *after* its first
            # sync would otherwise stay UNKNOWN forever. Only ever promotes from
            # UNKNOWN, so a human's or the classifier's verdict is still untouchable.
            row["lifecycle"] = str(Lifecycle.ARCHIVED)
        # Otherwise every overlay column is intentionally absent from `row`, so the
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
