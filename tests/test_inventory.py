"""Phase 1 Inventory tests.

Everything here runs against the temporary SQLite file from ``conftest`` and a fake
GitHub client. No network, no ``gh`` CLI, no credential material: the sync is handed
its client, which is the point — it never reaches for a credential itself (axiom 1).
"""

from __future__ import annotations

from typing import Any, Iterator

import pytest

from eveaegis.core import GovernanceCore
from eveaegis.inventory import (
    InventorySync,
    portfolio_summary,
    repository_id,
    repository_matrix,
    unclassified_report,
)
from eveaegis.taxonomy import AgentAccess, Category, Criticality, Lifecycle, Maturity


# --------------------------------------------------------------------------
# fakes
# --------------------------------------------------------------------------

def repo_payload(
    *,
    owner_id: int = 100,
    owner_login: str = "octo",
    repo_id: int = 200,
    name: str = "alpha",
    **overrides: Any,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "id": repo_id,
        "name": name,
        "full_name": f"{owner_login}/{name}",
        "owner": {"id": owner_id, "login": owner_login, "type": "User"},
        "private": False,
        "visibility": "public",
        "default_branch": "main",
        "description": f"{name} description",
        "homepage": None,
        "topics": ["governance"],
        "language": "Python",
        "license": {"spdx_id": "Apache-2.0"},
        "archived": False,
        "fork": False,
        "size": 1234,
        "stargazers_count": 3,
        "open_issues_count": 1,
        "pushed_at": "2026-07-20T00:00:00Z",
        "created_at": "2025-01-01T00:00:00Z",
        "updated_at": "2026-07-20T00:00:00Z",
    }
    payload.update(overrides)
    return payload


class FakeGitHubClient:
    """Implements only the surface :class:`InventorySync` is allowed to use."""

    def __init__(
        self,
        *,
        viewer: dict[str, Any] | None = None,
        orgs: list[dict[str, Any]] | None = None,
        user_repos: list[dict[str, Any]] | None = None,
        org_repos: dict[str, list[dict[str, Any]]] | None = None,
        languages: dict[str, dict[str, int]] | None = None,
        readmes: dict[str, str | None] | None = None,
        fail_on: dict[str, Exception] | None = None,
    ) -> None:
        self._viewer = viewer or {"id": 100, "login": "octo"}
        self._orgs = orgs or []
        self._user_repos = user_repos or []
        self._org_repos = org_repos or {}
        self._languages = languages or {}
        self._readmes = readmes or {}
        self._fail_on = fail_on or {}
        self.request_count = 0
        self.closed = False

    # -- context manager --------------------------------------------------

    def __enter__(self) -> "FakeGitHubClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.closed = True

    def close(self) -> None:
        self.closed = True

    # -- surface ----------------------------------------------------------

    @property
    def credential_description(self) -> dict[str, str]:
        return {"backend": "fake", "credential_type": "fake_token", "scope": "read_content"}

    def _boom(self, key: str) -> None:
        exc = self._fail_on.get(key)
        if exc is not None:
            raise exc

    def viewer(self) -> dict[str, Any]:
        self.request_count += 1
        self._boom("viewer")
        return self._viewer

    def orgs(self) -> list[dict[str, Any]]:
        self.request_count += 1
        self._boom("orgs")
        return self._orgs

    def user_repos(self, affiliation: str = "owner") -> Iterator[dict[str, Any]]:
        self.request_count += 1
        self._boom("user_repos")
        return iter(self._user_repos)

    def org_repos(self, org: str) -> Iterator[dict[str, Any]]:
        self.request_count += 1
        self._boom(f"org_repos:{org}")
        return iter(self._org_repos.get(org, []))

    def repo(self, full_name: str) -> dict[str, Any]:
        self.request_count += 1
        self._boom(f"repo:{full_name}")
        for payload in [*self._user_repos, *[p for v in self._org_repos.values() for p in v]]:
            if payload["full_name"] == full_name:
                return payload
        raise KeyError(full_name)

    def languages(self, full_name: str) -> dict[str, int]:
        self.request_count += 1
        self._boom(f"languages:{full_name}")
        return self._languages.get(full_name, {})

    def readme(self, full_name: str) -> str | None:
        self.request_count += 1
        self._boom(f"readme:{full_name}")
        return self._readmes.get(full_name)


# --------------------------------------------------------------------------
# wiring (the ``core`` fixture comes from conftest)
# --------------------------------------------------------------------------

def bind(core: GovernanceCore, client: FakeGitHubClient) -> FakeGitHubClient:
    """Replace the credentialled client factory with a fake, keeping the signature."""
    core.client = lambda *a, **k: client  # type: ignore[method-assign]
    return client


# --------------------------------------------------------------------------
# id scheme (§27)
# --------------------------------------------------------------------------

def test_repository_id_uses_owner_and_repo_numeric_ids() -> None:
    payload = repo_payload(owner_id=278690751, repo_id=1300241499, name="FELRA")
    assert repository_id(payload) == "github:278690751:1300241499"


def test_repository_id_rejects_payload_without_ids() -> None:
    with pytest.raises(ValueError):
        repository_id({"full_name": "octo/alpha", "owner": {}})


def test_account_row_records_gh_cli_backend_with_null_installation(core: GovernanceCore) -> None:
    bind(core, FakeGitHubClient(orgs=[{"id": 300, "login": "evemisslab"}]))
    installs = InventorySync(core).sync_accounts()

    assert [i.account_type for i in installs] == ["user", "organization"]
    row = core.conn.execute(
        "SELECT * FROM github_installations WHERE account_login = 'evemisslab'"
    ).fetchone()
    assert row["id"] == "github:300"
    assert row["installation_id"] is None
    assert row["credential_backend"] == "fake"


# --------------------------------------------------------------------------
# upsert idempotency
# --------------------------------------------------------------------------

def test_sync_is_idempotent(core: GovernanceCore) -> None:
    client = bind(
        core,
        FakeGitHubClient(
            user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta")],
            languages={"octo/alpha": {"Python": 900}},
            readmes={"octo/alpha": "# alpha"},
        ),
    )
    sync = InventorySync(core)

    first = sync.sync_repositories()
    assert (first.repositories, first.created, first.updated) == (2, 2, 0)
    assert first.errors == []
    assert first.accounts == 1
    assert first.duration_seconds >= 0.0

    second = sync.sync_repositories()
    assert (second.repositories, second.created, second.updated) == (2, 0, 2)

    assert core.conn.execute("SELECT COUNT(*) FROM repositories").fetchone()[0] == 2
    asset = sync.load_repository("octo/alpha")
    assert asset is not None
    assert asset.id == "github:100:200"
    assert asset.languages == {"Python": 900}
    assert asset.topics == ["governance"]
    assert asset.license_spdx == "Apache-2.0"
    assert client.closed is True


def test_limit_and_optional_calls_are_respected(core: GovernanceCore) -> None:
    client = bind(
        core,
        FakeGitHubClient(user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta")]),
    )
    result = InventorySync(core).sync_repositories(
        include_readme=False, include_languages=False, limit=1
    )
    assert result.repositories == 1
    # viewer + orgs + user_repos + nothing per repository
    assert client.request_count == 3


def test_archived_repo_seeds_archived_lifecycle_only(core: GovernanceCore) -> None:
    bind(
        core,
        FakeGitHubClient(
            user_repos=[
                repo_payload(archived=True),
                repo_payload(repo_id=201, name="beta"),
            ]
        ),
    )
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)

    archived = sync.load_repository("octo/alpha")
    plain = sync.load_repository("octo/beta")
    assert archived is not None and plain is not None
    assert archived.lifecycle is Lifecycle.ARCHIVED
    assert archived.is_archived is True
    # Nothing else is inferred: absence of evidence stays UNKNOWN (axiom 4).
    assert archived.category is Category.UNKNOWN
    assert archived.maturity is Maturity.UNKNOWN
    assert plain.lifecycle is Lifecycle.UNKNOWN


# --------------------------------------------------------------------------
# governance overlay preservation (§5 belongs to Phases 2/3)
# --------------------------------------------------------------------------

def test_resync_never_overwrites_governance_overlay(core: GovernanceCore) -> None:
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)

    core.conn.execute(
        """
        UPDATE repositories SET lifecycle=?, category=?, maturity=?, criticality=?,
                                agent_access=?, origin_profile_id=?, policy_profile=?
        WHERE full_name = 'octo/alpha'
        """,
        (
            str(Lifecycle.ACTIVE),
            str(Category.RESEARCH),
            str(Maturity.STABLE),
            str(Criticality.HIGH),
            str(AgentAccess.PR_ONLY),
            "origin_manual_1",
            "core-research",
        ),
    )
    core.conn.commit()

    # Metadata genuinely changed upstream; the classification did not.
    client._user_repos = [repo_payload(description="renamed description", stargazers_count=99)]
    sync.sync_repositories(include_readme=False, include_languages=False)

    asset = sync.load_repository("octo/alpha")
    assert asset is not None
    assert asset.description == "renamed description"
    assert asset.stargazers == 99
    assert asset.lifecycle is Lifecycle.ACTIVE
    assert asset.category is Category.RESEARCH
    assert asset.maturity is Maturity.STABLE
    assert asset.criticality is Criticality.HIGH
    assert asset.agent_access is AgentAccess.PR_ONLY
    assert asset.origin_profile_id == "origin_manual_1"
    assert asset.policy_profile == "core-research"


def test_archiving_promotes_an_undecided_lifecycle(core: GovernanceCore) -> None:
    """The narrow exception to write-once: UNKNOWN may become ARCHIVED."""
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)
    assert sync.load_repository("octo/alpha").lifecycle is Lifecycle.UNKNOWN  # type: ignore[union-attr]

    client._user_repos = [repo_payload(archived=True)]
    sync.sync_repositories(include_readme=False, include_languages=False)

    asset = sync.load_repository("octo/alpha")
    assert asset is not None
    assert asset.is_archived is True
    assert asset.lifecycle is Lifecycle.ARCHIVED


def test_archiving_never_overwrites_a_decided_lifecycle(core: GovernanceCore) -> None:
    """The exception only ever promotes from UNKNOWN — a real verdict is untouchable."""
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)

    core.conn.execute(
        "UPDATE repositories SET lifecycle = ? WHERE full_name = ?",
        (str(Lifecycle.MAINTENANCE), "octo/alpha"),
    )
    core.conn.commit()

    client._user_repos = [repo_payload(archived=True)]
    sync.sync_repositories(include_readme=False, include_languages=False)

    asset = sync.load_repository("octo/alpha")
    assert asset is not None
    assert asset.is_archived is True  # the observable fact still updates
    assert asset.lifecycle is Lifecycle.MAINTENANCE  # the human's label survives


def test_omitted_optional_data_is_preserved_not_cleared(core: GovernanceCore) -> None:
    client = bind(
        core,
        FakeGitHubClient(user_repos=[repo_payload()], languages={"octo/alpha": {"Python": 10}}),
    )
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False)
    sync.sync_repositories(include_readme=False, include_languages=False)

    asset = sync.load_repository("octo/alpha")
    assert asset is not None
    assert asset.languages == {"Python": 10}


# --------------------------------------------------------------------------
# snapshots are a change log, not a duplicate log
# --------------------------------------------------------------------------

def _snapshot_counts(core: GovernanceCore) -> dict[str, int]:
    rows = core.conn.execute(
        "SELECT kind, COUNT(*) AS n FROM repository_snapshots GROUP BY kind"
    ).fetchall()
    return {r["kind"]: r["n"] for r in rows}


def test_snapshots_dedupe_by_content_hash(core: GovernanceCore) -> None:
    client = bind(
        core,
        FakeGitHubClient(
            user_repos=[repo_payload()],
            languages={"octo/alpha": {"Python": 10}},
            readmes={"octo/alpha": "# alpha"},
        ),
    )
    sync = InventorySync(core)

    first = sync.sync_repositories()
    assert first.snapshots == 3
    assert _snapshot_counts(core) == {"repository": 1, "languages": 1, "readme": 1}

    second = sync.sync_repositories()
    assert second.snapshots == 0
    assert _snapshot_counts(core) == {"repository": 1, "languages": 1, "readme": 1}

    # Only the README moves; only the README gets a new row.
    client._readmes["octo/alpha"] = "# alpha, revised"
    third = sync.sync_repositories()
    assert third.snapshots == 1
    assert _snapshot_counts(core) == {"repository": 1, "languages": 1, "readme": 2}


def test_missing_readme_writes_no_snapshot(core: GovernanceCore) -> None:
    bind(core, FakeGitHubClient(user_repos=[repo_payload()], readmes={}))
    result = InventorySync(core).sync_repositories(include_languages=False)
    assert result.errors == []
    assert "readme" not in _snapshot_counts(core)


# --------------------------------------------------------------------------
# resilience (§29 "manage at least 100 repositories")
# --------------------------------------------------------------------------

def test_single_repo_failure_does_not_abort_the_sweep(core: GovernanceCore) -> None:
    bind(
        core,
        FakeGitHubClient(
            user_repos=[
                repo_payload(),
                repo_payload(repo_id=201, name="beta"),
                repo_payload(repo_id=202, name="gamma"),
            ],
            fail_on={"languages:octo/beta": RuntimeError("404 empty repository")},
        ),
    )
    sync = InventorySync(core)
    result = sync.sync_repositories(include_readme=False)

    assert result.repositories == 2
    assert len(result.errors) == 1
    assert "octo/beta" in result.errors[0]
    assert sync.load_repository("octo/gamma") is not None

    actions = [
        r["action"]
        for r in core.conn.execute("SELECT action FROM audit_events ORDER BY sequence").fetchall()
    ]
    assert actions == [
        "inventory_sync_started",
        "inventory_repository_error",
        "inventory_sync_completed",
    ]


def test_failed_org_listing_still_yields_personal_repos(core: GovernanceCore) -> None:
    bind(
        core,
        FakeGitHubClient(
            orgs=[{"id": 300, "login": "evemisslab"}],
            user_repos=[repo_payload()],
            fail_on={"org_repos:evemisslab": RuntimeError("403 not a member")},
        ),
    )
    result = InventorySync(core).sync_repositories(include_readme=False, include_languages=False)
    assert result.accounts == 2
    assert result.repositories == 1
    assert len(result.errors) == 1


def test_audit_events_carry_credential_facts_and_counts(core: GovernanceCore) -> None:
    bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    InventorySync(core).sync_repositories(include_readme=False, include_languages=False)

    row = core.conn.execute(
        "SELECT * FROM audit_events WHERE action = 'inventory_sync_completed'"
    ).fetchone()
    assert row["credential_type"] == "fake_token"
    assert row["credential_scope"] == "read_content"
    assert '"repositories":1' in row["detail"].replace(" ", "")
    ok, message = core.ledger.verify()
    assert ok, message


# --------------------------------------------------------------------------
# identity healing
# --------------------------------------------------------------------------

def test_rename_keeps_id_and_snapshot_history(core: GovernanceCore) -> None:
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()], readmes={"octo/alpha": "x"}))
    sync = InventorySync(core)
    sync.sync_repositories(include_languages=False)

    client._user_repos = [repo_payload(name="alpha-renamed")]
    client._readmes = {"octo/alpha-renamed": "x"}
    result = sync.sync_repositories(include_languages=False)

    assert result.errors == []
    assert core.conn.execute("SELECT COUNT(*) FROM repositories").fetchone()[0] == 1
    asset = sync.load_repository("octo/alpha-renamed")
    assert asset is not None and asset.id == "github:100:200"
    # The README is unchanged, so the dedupe still holds across the rename.
    assert _snapshot_counts(core)["readme"] == 1


def test_recreated_repository_is_reported_not_silently_repointed(core: GovernanceCore) -> None:
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)

    client._user_repos = [repo_payload(repo_id=999)]  # same name, new GitHub id
    result = sync.sync_repositories(include_readme=False, include_languages=False)

    assert result.repositories == 0
    assert len(result.errors) == 1
    assert "github:100:999" in result.errors[0]


# --------------------------------------------------------------------------
# forks pull the detailed payload (§6 needs parent/source)
# --------------------------------------------------------------------------

def test_fork_resolves_parent_and_source(core: GovernanceCore) -> None:
    fork = repo_payload(
        repo_id=400,
        name="tandem-browser",
        fork=True,
        parent={"full_name": "upstream/tandem-browser"},
        source={"full_name": "root/tandem-browser"},
    )
    bind(core, FakeGitHubClient(user_repos=[fork]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)

    asset = sync.load_repository("octo/tandem-browser")
    assert asset is not None
    assert asset.is_fork is True
    assert asset.parent_full_name == "upstream/tandem-browser"
    assert asset.source_full_name == "root/tandem-browser"


def test_fork_without_parent_in_list_payload_pays_for_the_detail_call(
    core: GovernanceCore,
) -> None:
    """List endpoints omit parent/source; a fork is worth one extra call, others are not."""
    listed = repo_payload(repo_id=400, name="tandem-browser", fork=True)
    detailed = {**listed, "parent": {"full_name": "upstream/tandem-browser"}}

    detail_calls: list[str] = []
    client = bind(core, FakeGitHubClient(user_repos=[listed, repo_payload()]))

    def fake_repo(full_name: str) -> dict[str, Any]:
        detail_calls.append(full_name)
        return detailed

    client.repo = fake_repo  # type: ignore[method-assign]

    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False)

    fork_asset = sync.load_repository("octo/tandem-browser")
    plain_asset = sync.load_repository("octo/alpha")
    assert fork_asset is not None and plain_asset is not None
    assert fork_asset.parent_full_name == "upstream/tandem-browser"
    assert plain_asset.parent_full_name is None
    # Exactly one detail call, for the fork only — non-forks stay at zero extra calls.
    assert detail_calls == ["octo/tandem-browser"]


def test_refresh_repository_returns_the_persisted_asset(core: GovernanceCore) -> None:
    bind(
        core,
        FakeGitHubClient(
            user_repos=[repo_payload()],
            languages={"octo/alpha": {"Python": 5}},
            readmes={"octo/alpha": "# alpha"},
        ),
    )
    sync = InventorySync(core)
    sync.sync_accounts()
    asset = sync.refresh_repository("octo/alpha")

    assert asset.id == "github:100:200"
    assert asset.installation_id == "github:100"
    assert asset.languages == {"Python": 5}
    actions = {
        r["action"] for r in core.conn.execute("SELECT action FROM audit_events").fetchall()
    }
    assert "inventory_repository_refreshed" in actions


# --------------------------------------------------------------------------
# reports (§19.1, §19.2)
# --------------------------------------------------------------------------

def test_reports_reflect_the_catalog(core: GovernanceCore) -> None:
    bind(
        core,
        FakeGitHubClient(
            orgs=[{"id": 300, "login": "evemisslab"}],
            user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta", archived=True)],
            org_repos={
                "evemisslab": [
                    repo_payload(
                        owner_id=300,
                        owner_login="evemisslab",
                        repo_id=500,
                        name="gamma",
                        fork=True,
                        parent={"full_name": "upstream/gamma"},
                    )
                ]
            },
            languages={"octo/alpha": {"Python": 10, "HTML": 2}},
        ),
    )
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False)

    summary = portfolio_summary(core)
    assert summary["repositories"] == 3
    assert summary["accounts"] == 2
    assert summary["organizations"] == 1
    assert summary["archived"] == 1
    assert summary["forks"] == 1
    assert summary["unclassified"] == 3
    # Phase 2 has not run, so every repository is honestly "unknown origin".
    assert summary["unknown_origin"] == 3
    assert summary["license_review_required"] == 0
    assert summary["languages"] == {"HTML": 1, "Python": 1}

    matrix = repository_matrix(core)
    assert len(matrix) == 3
    row = next(r for r in matrix if r["repo"] == "octo/alpha")
    assert row["origin"] == "UNKNOWN"
    assert row["contribution"] == "UNKNOWN"
    assert row["agent_mode"] == "READ_ONLY"
    assert row["review_status"] == "UNREVIEWED"

    unclassified = unclassified_report(core)
    assert len(unclassified) == 3
    alpha = next(r for r in unclassified if r["full_name"] == "octo/alpha")
    assert alpha["missing"] == ["category", "lifecycle", "maturity"]
    assert alpha["topics"] == ["governance"]
    beta = next(r for r in unclassified if r["full_name"] == "octo/beta")
    assert beta["missing"] == ["category", "maturity"]  # lifecycle was seeded ARCHIVED

    assert [a.full_name for a in sync.list_repositories(only_unclassified=True)] == [
        a.full_name for a in sync.list_repositories()
    ]
