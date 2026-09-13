"""Phase 1 Inventory tests.

Everything here runs against the temporary SQLite file from ``conftest`` and a fake
GitHub client. No network, no ``gh`` CLI, no credential material: the sync is handed
its client, which is the point — it never reaches for a credential itself (axiom 1).
"""

from __future__ import annotations

from typing import Any, Iterator

import pytest

from eveaegis.core import GovernanceCore
from eveaegis.db import loads
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
        trees: dict[str, list[dict[str, Any]]] | None = None,
        fail_on: dict[str, Exception] | None = None,
        identity_mode: str = "user",
        installation_repos: list[dict[str, Any]] | None = None,
    ) -> None:
        self._viewer = viewer or {"id": 100, "login": "octo"}
        self._orgs = orgs or []
        self._user_repos = user_repos or []
        self._org_repos = org_repos or {}
        self._languages = languages or {}
        self._readmes = readmes or {}
        self._trees = trees or {}
        self._fail_on = fail_on or {}
        self._identity_mode = identity_mode
        self._installation_repos = installation_repos or []
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

    @property
    def identity_mode(self) -> str:
        return self._identity_mode

    def installation_repos(self) -> Iterator[dict[str, Any]]:
        """App-token discovery: one listing spanning every covered account."""
        self.request_count += 1
        self._boom("installation_repos")
        return iter(self._installation_repos)

    def user_repos_forbidden(self) -> None:
        """Installation tokens get 403 on every /user* endpoint. Mirror that."""
        raise RuntimeError("Resource not accessible by integration")

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

    def tree(self, full_name: str, ref: str, *, recursive: bool = True) -> list[dict[str, Any]]:
        self.request_count += 1
        self._boom(f"tree:{full_name}")
        return self._trees.get(full_name, [])


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
        include_readme=False, include_languages=False, include_tree=False, limit=1
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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)
    assert sync.load_repository("octo/alpha").lifecycle is Lifecycle.UNKNOWN  # type: ignore[union-attr]

    client._user_repos = [repo_payload(archived=True)]
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

    asset = sync.load_repository("octo/alpha")
    assert asset is not None
    assert asset.is_archived is True
    assert asset.lifecycle is Lifecycle.ARCHIVED


def test_archiving_never_overwrites_a_decided_lifecycle(core: GovernanceCore) -> None:
    """The exception only ever promotes from UNKNOWN — a real verdict is untouchable."""
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

    core.conn.execute(
        "UPDATE repositories SET lifecycle = ? WHERE full_name = ?",
        (str(Lifecycle.MAINTENANCE), "octo/alpha"),
    )
    core.conn.commit()

    client._user_repos = [repo_payload(archived=True)]
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    result = InventorySync(core).sync_repositories(include_languages=False, include_tree=False)
    assert result.errors == []
    assert "readme" not in _snapshot_counts(core)


def test_tree_snapshot_is_stored_for_offline_path_evidence(core: GovernanceCore) -> None:
    """Phases 2/3 read paths from here; without it, file markers see nothing."""
    entries = [
        {"path": "pyproject.toml", "type": "blob", "size": 400},
        {"path": "src", "type": "tree", "size": 0},
        {"path": "src/app.py", "type": "blob", "size": 1200},
    ]
    bind(core, FakeGitHubClient(user_repos=[repo_payload()], trees={"octo/alpha": entries}))
    InventorySync(core).sync_repositories(include_readme=False, include_languages=False)

    row = core.conn.execute(
        "SELECT payload FROM repository_snapshots WHERE kind = 'tree'"
    ).fetchone()
    assert row is not None
    payload = loads(row["payload"])
    assert payload["ref"] == "main"
    assert payload["truncated"] is False
    assert [e["path"] for e in payload["tree"]] == [e["path"] for e in entries]


def test_tree_snapshot_is_capped_and_flagged(core: GovernanceCore) -> None:
    """A vendored monster tree must not blow up the snapshot table silently."""
    entries = [{"path": f"f{i}.txt", "type": "blob", "size": 1} for i in range(6000)]
    bind(core, FakeGitHubClient(user_repos=[repo_payload()], trees={"octo/alpha": entries}))
    InventorySync(core).sync_repositories(include_readme=False, include_languages=False)

    payload = loads(
        core.conn.execute(
            "SELECT payload FROM repository_snapshots WHERE kind = 'tree'"
        ).fetchone()["payload"]
    )
    assert payload["truncated"] is True
    assert len(payload["tree"]) == InventorySync.MAX_TREE_ENTRIES


def test_empty_repository_tree_is_not_an_error(core: GovernanceCore) -> None:
    bind(core, FakeGitHubClient(user_repos=[repo_payload()], trees={}))
    result = InventorySync(core).sync_repositories(include_readme=False, include_languages=False)
    assert result.errors == []
    assert "tree" not in _snapshot_counts(core)


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
    result = InventorySync(core).sync_repositories(include_readme=False, include_languages=False, include_tree=False)
    assert result.accounts == 2
    assert result.repositories == 1
    assert len(result.errors) == 1


def test_audit_events_carry_credential_facts_and_counts(core: GovernanceCore) -> None:
    bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    InventorySync(core).sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    sync.sync_repositories(include_languages=False, include_tree=False)

    client._user_repos = [repo_payload(name="alpha-renamed")]
    client._readmes = {"octo/alpha-renamed": "x"}
    result = sync.sync_repositories(include_languages=False, include_tree=False)

    assert result.errors == []
    assert core.conn.execute("SELECT COUNT(*) FROM repositories").fetchone()[0] == 1
    asset = sync.load_repository("octo/alpha-renamed")
    assert asset is not None and asset.id == "github:100:200"
    # The README is unchanged, so the dedupe still holds across the rename.
    assert _snapshot_counts(core)["readme"] == 1


def test_recreated_repository_is_reported_not_silently_repointed(core: GovernanceCore) -> None:
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

    client._user_repos = [repo_payload(repo_id=999)]  # same name, new GitHub id
    result = sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

    assert result.repositories == 0
    assert len(result.errors) == 1
    # Identity is now the numeric repository id, so that is what the error names.
    assert "999" in result.errors[0]
    assert "github:100:200" in result.errors[0]


# --------------------------------------------------------------------------
# transfer between accounts (§4 personal/company separation)
# --------------------------------------------------------------------------

def test_transfer_between_accounts_preserves_governance_history(
    core: GovernanceCore,
) -> None:
    """Moving a repository personal -> org must not reset what is known about it.

    The surrogate id embeds the owner, so a transfer changes both the id and the
    full_name and would otherwise look like a brand-new repository — silently, since
    the delete-and-recreate guard only fires when the *name* is reused. Everything
    downstream (snapshots, origin profile, classification) hangs off the surrogate,
    so a fresh row would strand the whole governance history on a dead one.
    """
    client = bind(core, FakeGitHubClient(user_repos=[repo_payload()]))
    sync = InventorySync(core)
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

    original = sync.load_repository("octo/alpha")
    assert original is not None
    surrogate = original.id

    # A human graded it before the move.
    core.conn.execute(
        "UPDATE repositories SET criticality = ?, category = ? WHERE id = ?",
        (str(Criticality.HIGH), str(Category.RESEARCH), surrogate),
    )
    core.conn.commit()

    # Same repository, new owner: repo_id unchanged, owner_id and full_name changed.
    client._user_repos = [repo_payload(owner_id=777, owner_login="evemisslab")]
    result = sync.sync_repositories(
        include_readme=False, include_languages=False, include_tree=False
    )

    assert result.errors == []
    assert result.created == 0 and result.updated == 1

    rows = core.conn.execute("SELECT id, full_name FROM repositories").fetchall()
    assert len(rows) == 1, "a transfer must not produce a second row"
    assert rows[0]["id"] == surrogate, "the surrogate id must survive the move"
    assert rows[0]["full_name"] == "evemisslab/alpha"

    moved = sync.load_repository("evemisslab/alpha")
    assert moved is not None
    assert moved.criticality is Criticality.HIGH
    assert moved.category is Category.RESEARCH

    actions = [e.action for e in core.ledger.recent(20)]
    assert "inventory_repository_moved" in actions


def test_transfer_snapshots_stay_attached(core: GovernanceCore) -> None:
    """Snapshots must keep landing on the same surrogate after a move."""
    client = bind(
        core,
        FakeGitHubClient(user_repos=[repo_payload()], readmes={"octo/alpha": "# alpha"}),
    )
    sync = InventorySync(core)
    sync.sync_repositories(include_languages=False, include_tree=False)
    surrogate = sync.load_repository("octo/alpha").id  # type: ignore[union-attr]

    client._user_repos = [repo_payload(owner_id=777, owner_login="evemisslab")]
    client._readmes = {"evemisslab/alpha": "# alpha, after the move"}
    sync.sync_repositories(include_languages=False, include_tree=False)

    owners = {
        r["repository_id"]
        for r in core.conn.execute("SELECT DISTINCT repository_id FROM repository_snapshots")
    }
    assert owners == {surrogate}


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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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
    sync.sync_repositories(include_readme=False, include_languages=False, include_tree=False)

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


# --------------------------------------------------------------------------
# GitHub App installation discovery
# --------------------------------------------------------------------------

class TestInstallationModeDiscovery:
    """An installation token acts as the App, not as a person.

    Every ``/user*`` endpoint answers 403 "Resource not accessible by integration",
    so the user-shaped discovery path cannot work at all under a GitHub App — the
    sweep would report zero repositories rather than fail loudly.
    """

    @staticmethod
    def _client(**kw: Any) -> FakeGitHubClient:
        return FakeGitHubClient(
            identity_mode="installation",
            fail_on={
                "viewer": RuntimeError("403 Resource not accessible by integration"),
                "orgs": RuntimeError("403 Resource not accessible by integration"),
                "user_repos": RuntimeError("403 Resource not accessible by integration"),
            },
            **kw,
        )

    @staticmethod
    def _one_installation(core: GovernanceCore, installation_id: int = 153) -> None:
        """The App reports where it is installed; the fake broker must too."""
        core.broker.installations = lambda: [  # type: ignore[method-assign]
            {"id": installation_id, "login": "octo", "type": "User", "account_id": 100,
             "repository_selection": "all", "permissions": {"metadata": "read"}}
        ]

    def test_installation_sweep_never_touches_user_endpoints(
        self, core: GovernanceCore
    ) -> None:
        self._one_installation(core)
        bind(core, self._client(installation_repos=[repo_payload()]))
        result = InventorySync(core).sync_repositories(
            include_readme=False, include_languages=False, include_tree=False
        )
        assert result.errors == []
        assert result.repositories == 1

    def test_accounts_are_derived_from_the_repositories_granted(
        self, core: GovernanceCore
    ) -> None:
        """Not from org membership: report what the App was granted, not who he is."""
        self._one_installation(core)
        bind(
            core,
            self._client(
                installation_repos=[
                    repo_payload(),
                    repo_payload(
                        owner_id=900,
                        owner_login="evemisslab",
                        repo_id=901,
                        name="company-thing",
                        owner={"id": 900, "login": "evemisslab", "type": "Organization"},
                    ),
                ]
            ),
        )
        installs = InventorySync(core).sync_accounts()
        assert {i.account_login for i in installs} == {"octo", "evemisslab"}
        assert {i.account_type for i in installs} == {"user", "organization"}
        # The installation id is recorded now, unlike the delegated-token path.
        rows = core.conn.execute("SELECT DISTINCT installation_id FROM github_installations")
        assert {r["installation_id"] for r in rows} == {153}

    def test_the_listing_is_fetched_once_not_per_account(
        self, core: GovernanceCore
    ) -> None:
        """One listing per installation; the sweep reuses it instead of re-paying."""
        self._one_installation(core)
        client = bind(
            core,
            self._client(
                installation_repos=[
                    repo_payload(),
                    repo_payload(
                        owner_id=900,
                        owner_login="evemisslab",
                        repo_id=901,
                        name="company-thing",
                        owner={"id": 900, "login": "evemisslab", "type": "Organization"},
                    ),
                ]
            ),
        )
        InventorySync(core).sync_repositories(
            include_readme=False, include_languages=False, include_tree=False
        )
        assert client.request_count == 1

    def test_installation_failure_is_reported_not_silently_empty(
        self, core: GovernanceCore
    ) -> None:
        self._one_installation(core)
        bind(
            core,
            FakeGitHubClient(
                identity_mode="installation",
                fail_on={"installation_repos": RuntimeError("App suspended")},
            ),
        )
        result = InventorySync(core).sync_repositories(
            include_readme=False, include_languages=False, include_tree=False
        )
        assert result.repositories == 0
        assert any("App suspended" in e for e in result.errors)


# --------------------------------------------------------------------------
# presence: a repository that disappears from GitHub
# --------------------------------------------------------------------------

class TestPresenceReconciliation:
    """Rows are never deleted; absence is a state. Only a complete sweep can assert it."""

    @staticmethod
    def _sweep(sync: InventorySync, **kw: Any):
        return sync.sync_repositories(
            include_readme=False, include_languages=False, include_tree=False, **kw
        )

    def test_vanished_repository_is_marked_not_deleted(self, core: GovernanceCore) -> None:
        client = bind(core, FakeGitHubClient(user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta")]))
        sync = InventorySync(core)
        self._sweep(sync)

        client._user_repos = [repo_payload()]  # beta was deleted on GitHub
        result = self._sweep(sync)

        assert result.missing == ["octo/beta"]
        row = core.conn.execute("SELECT missing_since FROM repositories WHERE full_name='octo/beta'").fetchone()
        assert row is not None, "the row must survive"
        assert row["missing_since"] is not None
        assert core.conn.execute("SELECT COUNT(*) n FROM repositories").fetchone()["n"] == 2
        assert any(a.action == "inventory_repositories_missing" for a in core.ledger.recent(5))

    def test_present_views_exclude_missing_rows(self, core: GovernanceCore) -> None:
        client = bind(core, FakeGitHubClient(user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta")]))
        sync = InventorySync(core)
        self._sweep(sync)
        client._user_repos = [repo_payload()]
        self._sweep(sync)

        assert {r.full_name for r in sync.list_repositories()} == {"octo/alpha"}
        summary = portfolio_summary(core)
        assert summary["repositories"] == 1
        assert summary["missing"] == 1

    def test_reappearance_clears_the_mark(self, core: GovernanceCore) -> None:
        """GitHub restores deleted repositories within 90 days; so do we."""
        client = bind(core, FakeGitHubClient(user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta")]))
        sync = InventorySync(core)
        self._sweep(sync)
        client._user_repos = [repo_payload()]
        self._sweep(sync)
        client._user_repos = [repo_payload(), repo_payload(repo_id=201, name="beta")]
        result = self._sweep(sync)

        assert result.missing == []
        row = core.conn.execute("SELECT missing_since FROM repositories WHERE full_name='octo/beta'").fetchone()
        assert row["missing_since"] is None
        assert any(a.action == "inventory_repository_reappeared" for a in core.ledger.recent(5))

    def test_partial_sweep_never_asserts_absence(self, core: GovernanceCore) -> None:
        """`limit` reaches only some repositories; the rest are unobserved, not gone."""
        client = bind(core, FakeGitHubClient(user_repos=[repo_payload(), repo_payload(repo_id=201, name="beta")]))
        sync = InventorySync(core)
        self._sweep(sync)

        result = self._sweep(sync, limit=1)
        assert result.missing == []
        assert core.conn.execute("SELECT COUNT(*) n FROM repositories WHERE missing_since IS NOT NULL").fetchone()["n"] == 0

    def test_a_failed_listing_never_asserts_absence(self, core: GovernanceCore) -> None:
        """An org whose listing errored contributed nothing; its repos are not missing."""
        client = bind(
            core,
            FakeGitHubClient(
                orgs=[{"id": 300, "login": "evemisslab"}],
                user_repos=[repo_payload()],
                org_repos={"evemisslab": [repo_payload(owner_id=300, owner_login="evemisslab", repo_id=301, name="corp")]},
            ),
        )
        sync = InventorySync(core)
        self._sweep(sync)
        assert core.conn.execute("SELECT COUNT(*) n FROM repositories").fetchone()["n"] == 2

        client._fail_on = {"org_repos:evemisslab": RuntimeError("403")}
        result = self._sweep(sync)
        assert result.errors  # the failure is reported
        assert result.missing == []  # and nothing is declared gone
        assert core.conn.execute("SELECT COUNT(*) n FROM repositories WHERE missing_since IS NOT NULL").fetchone()["n"] == 0


def test_two_installations_are_both_swept(core: GovernanceCore) -> None:
    """Personal account + company org: two installations, two listings, one catalog."""
    core.broker.installations = lambda: [  # type: ignore[method-assign]
        {"id": 1, "login": "octo", "type": "User", "account_id": 100, "repository_selection": "all", "permissions": {}},
        {"id": 2, "login": "EveMissLab", "type": "Organization", "account_id": 900, "repository_selection": "all", "permissions": {"contents": "write"}},
    ]
    personal = repo_payload()
    company = repo_payload(owner_id=900, owner_login="EveMissLab", repo_id=901, name="corp",
                           owner={"id": 900, "login": "EveMissLab", "type": "Organization"})
    listings = {1: [personal], 2: [company]}

    class PerInstallationClient(FakeGitHubClient):
        def __init__(self, installation_id: int | None) -> None:
            super().__init__(identity_mode="installation", installation_repos=listings.get(installation_id or 0, []))

    core.client = lambda *a, **k: PerInstallationClient(k.get("installation_id"))  # type: ignore[method-assign]
    result = InventorySync(core).sync_repositories(include_readme=False, include_languages=False, include_tree=False)

    assert result.errors == []
    assert result.repositories == 2
    rows = {r["account_login"]: r for r in core.conn.execute("SELECT * FROM github_installations")}
    assert rows["octo"]["installation_id"] == 1
    assert rows["EveMissLab"]["installation_id"] == 2
    assert rows["EveMissLab"]["account_type"] == "organization"
    assert core.installation_for("EveMissLab/corp") == 2
    assert core.installation_for("octo/alpha") == 1


def test_an_empty_new_org_is_still_recorded(core: GovernanceCore) -> None:
    """A brand-new org has no repositories yet but is already an account under governance."""
    core.broker.installations = lambda: [  # type: ignore[method-assign]
        {"id": 1, "login": "octo", "type": "User", "account_id": 100, "repository_selection": "all", "permissions": {}},
        {"id": 2, "login": "EveMissLab", "type": "Organization", "account_id": 900, "repository_selection": "all", "permissions": {}},
    ]
    core.client = lambda *a, **k: FakeGitHubClient(  # type: ignore[method-assign]
        identity_mode="installation", installation_repos=[repo_payload()] if k.get("installation_id") == 1 else []
    )
    InventorySync(core).sync_repositories(include_readme=False, include_languages=False, include_tree=False)
    rows = {r["account_login"]: r for r in core.conn.execute("SELECT * FROM github_installations")}
    assert "EveMissLab" in rows and rows["EveMissLab"]["installation_id"] == 2


def test_foreign_installation_is_ignored_not_swept(core: GovernanceCore) -> None:
    """A public App can be installed by strangers; their repos must never enter the catalog."""
    core.cfg.governance.accounts = ["octo"]
    core.broker.installations = lambda: [  # type: ignore[method-assign]
        {"id": 1, "login": "octo", "type": "User", "account_id": 100, "repository_selection": "all", "permissions": {}},
        {"id": 99, "login": "stranger", "type": "User", "account_id": 555, "repository_selection": "all", "permissions": {}},
    ]
    listings = {1: [repo_payload()], 99: [repo_payload(owner_id=555, owner_login="stranger", repo_id=556, name="theirs")]}
    core.client = lambda *a, **k: FakeGitHubClient(  # type: ignore[method-assign]
        identity_mode="installation", installation_repos=listings.get(k.get("installation_id") or 0, [])
    )
    result = InventorySync(core).sync_repositories(include_readme=False, include_languages=False, include_tree=False)
    assert result.repositories == 1
    assert {r["full_name"] for r in core.conn.execute("SELECT full_name FROM repositories")} == {"octo/alpha"}
    assert "stranger" not in {r["account_login"] for r in core.conn.execute("SELECT account_login FROM github_installations")}
    assert any(e.action == "inventory_installation_ignored" for e in core.ledger.recent(10))
