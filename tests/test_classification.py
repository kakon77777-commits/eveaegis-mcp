"""§5 classification — labels, and the honesty of the labels.

The interesting assertions here are the negative ones: that thin evidence lands on
``UNKNOWN`` instead of a plausible guess, that a year of silence never becomes
``ARCHIVED`` on its own, and that agent access is capped by provenance rather than
by how confident the classifier feels.
"""

from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest

from eveaegis.classification import Classifier, collect_signals
from eveaegis.config import Config, GovernanceConfig
from eveaegis.core import GovernanceCore
from eveaegis.db import dumps
from eveaegis.taxonomy import (
    AGENT_ACCESS_RANK,
    AgentAccess,
    Category,
    Criticality,
    Lifecycle,
    Maturity,
    OriginType,
)

from conftest import FakeBroker  # pytest puts tests/ on sys.path (rootdir conftest)

TENANT = "test-tenant"


@pytest.fixture
def core(tmp_path: Path):
    cfg = Config(
        database_path=str(tmp_path / f"{uuid.uuid4().hex}.db"),
        governance=GovernanceConfig(tenant_id=TENANT, tenant_name="Test", read_only=True),
    )
    c = GovernanceCore(cfg, broker=FakeBroker())
    yield c
    c.close()


def days_ago(days: int) -> str:
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


def add_repo(
    core: GovernanceCore,
    full_name: str,
    *,
    description: str = "",
    topics: list[str] | None = None,
    homepage: str | None = None,
    language: str | None = None,
    visibility: str = "public",
    archived: bool = False,
    fork: bool = False,
    parent: str | None = None,
    pushed_days_ago: int | None = 10,
    size_kb: int = 500,
    stars: int = 0,
    open_issues: int = 0,
) -> str:
    repo_id = f"repo_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    core.conn.execute(
        """
        INSERT INTO repositories
            (id, tenant_id, full_name, github_repository_id, visibility, default_branch,
             description, homepage, topics, primary_language, languages, license_spdx,
             is_archived, is_fork, parent_full_name, size_kb, stargazers, open_issues,
             pushed_at, created_at, updated_at, synced_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            repo_id, TENANT, full_name, abs(hash(full_name)) % 10**8, visibility, "main",
            description, homepage, dumps(topics or []), language, dumps({}), "MIT",
            int(archived), int(fork), parent, size_kb, stars, open_issues,
            (days_ago(pushed_days_ago) if pushed_days_ago is not None else None),
            days_ago(900), now, now,
        ),
    )
    core.conn.commit()
    return repo_id


def add_snapshot(core: GovernanceCore, repo_id: str, kind: str, payload: Any) -> None:
    core.conn.execute(
        "INSERT INTO repository_snapshots (id, repository_id, taken_at, kind, payload, payload_hash) "
        "VALUES (?,?,?,?,?,?)",
        (
            f"snap_{uuid.uuid4().hex[:10]}", repo_id,
            datetime.now(timezone.utc).isoformat(), kind,
            payload if isinstance(payload, str) else dumps(payload), "sha256:test",
        ),
    )
    core.conn.commit()


def add_tree(core: GovernanceCore, repo_id: str, paths: list[str]) -> None:
    add_snapshot(core, repo_id, "tree", {"tree": [{"path": p} for p in paths]})


def add_origin(
    core: GovernanceCore,
    repo_id: str,
    origin_type: OriginType,
    *,
    confidence: float = 0.9,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    core.conn.execute(
        """
        INSERT INTO origin_profiles
            (id, repository_id, origin_type, origin_confidence, license_status,
             review_status, created_at, updated_at)
        VALUES (?,?,?,?,?,?,?,?)
        """,
        (
            f"org_{uuid.uuid4().hex[:10]}", repo_id, str(origin_type), confidence,
            "CLEAR", "REVIEWED", now, now,
        ),
    )
    core.conn.commit()


# --------------------------------------------------------------------------
# ambiguity → UNKNOWN
# --------------------------------------------------------------------------

class TestAmbiguityStaysUnknown:
    def test_a_bare_repository_is_unknown_on_every_inferred_axis(
        self, core: GovernanceCore
    ) -> None:
        """No topics, no description, no files, no releases. Nothing is knowable."""
        add_repo(core, "acme/thing")
        result = Classifier(core).classify("acme/thing")
        assert result.category == Category.UNKNOWN
        assert result.maturity == Maturity.UNKNOWN
        assert result.criticality == Criticality.LOW  # least-privilege default
        assert result.agent_access == AgentAccess.READ_ONLY
        assert any("UNKNOWN" in line for line in result.rationale)

    def test_two_equally_supported_categories_do_not_produce_a_winner(
        self, core: GovernanceCore
    ) -> None:
        """One topic each for two categories: a coin flip is not a classification."""
        repo = add_repo(core, "acme/hybrid", topics=["game", "dataset"])
        result = Classifier(core).classify("acme/hybrid")
        assert result.category == Category.UNKNOWN
        assert any("too close to separate" in line for line in result.rationale)

    def test_a_lone_keyword_is_a_hint_not_a_conclusion(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/notes", description="A handbook of things")
        result = Classifier(core).classify("acme/notes")
        by_axis = result.signals["confidence_by_axis"]
        if result.category != Category.UNKNOWN:
            assert by_axis["category"] <= 0.70, "a single prose keyword must not read as certain"

    def test_missing_push_date_leaves_lifecycle_unknown(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/nodate", pushed_days_ago=None)
        result = Classifier(core).classify("acme/nodate")
        assert result.lifecycle == Lifecycle.UNKNOWN
        assert result.agent_access == AgentAccess.READ_ONLY


# --------------------------------------------------------------------------
# §5.2 lifecycle
# --------------------------------------------------------------------------

class TestLifecycle:
    def test_archived_repository_is_archived(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/old", archived=True, pushed_days_ago=800)
        result = Classifier(core).classify("acme/old")
        assert result.lifecycle == Lifecycle.ARCHIVED
        assert result.category == Category.ARCHIVE
        assert result.maturity == Maturity.LEGACY
        assert result.agent_access == AgentAccess.READ_ONLY

    def test_recent_push_is_active(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/live", pushed_days_ago=3)
        result = Classifier(core).classify("acme/live")
        assert result.lifecycle == Lifecycle.ACTIVE

    def test_mid_range_silence_is_maintenance(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/quiet", pushed_days_ago=200)
        assert Classifier(core).classify("acme/quiet").lifecycle == Lifecycle.MAINTENANCE

    def test_long_silence_never_becomes_archived_on_its_own(
        self, core: GovernanceCore
    ) -> None:
        """Archiving is a human act (§12, §25). Silence is evidence, not consent."""
        add_repo(core, "acme/dormant", pushed_days_ago=900)
        result = Classifier(core).classify("acme/dormant")
        assert result.lifecycle != Lifecycle.ARCHIVED
        assert result.lifecycle in (
            Lifecycle.EXPERIMENTAL, Lifecycle.REFERENCE, Lifecycle.IDEA
        )
        assert any("never inferred as ARCHIVED" in r or "not archived automatically" in r
                   for r in result.rationale)

    def test_superseded_marker_in_readme_wins_over_recency(
        self, core: GovernanceCore
    ) -> None:
        repo = add_repo(core, "acme/older-tool", pushed_days_ago=5)
        add_snapshot(core, repo, "readme", "# Older Tool\n\nThis project is superseded by acme/newer-tool.")
        result = Classifier(core).classify("acme/older-tool")
        assert result.lifecycle == Lifecycle.SUPERSEDED
        assert result.agent_access == AgentAccess.READ_ONLY


# --------------------------------------------------------------------------
# §5.5 agent access — capped by provenance
# --------------------------------------------------------------------------

class TestAgentAccessCapping:
    def test_no_origin_profile_caps_at_read_only(self, core: GovernanceCore) -> None:
        """Phase 2 has not run. 'Not analysed' is not 'safe to write'."""
        repo = add_repo(core, "acme/app", topics=["desktop-app"], pushed_days_ago=5)
        add_tree(core, repo, ["package.json", "src/index.ts"])
        result = Classifier(core).classify("acme/app")
        assert result.agent_access == AgentAccess.READ_ONLY
        assert any("no origin profile" in r for r in result.rationale)

    def test_mirror_origin_caps_at_read_only(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/mirrored", topics=["library"], pushed_days_ago=5)
        add_origin(core, repo, OriginType.MIRROR)
        result = Classifier(core).classify("acme/mirrored")
        assert result.agent_access == AgentAccess.READ_ONLY

    def test_fork_origin_caps_at_pr_only(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/patched", topics=["library"], pushed_days_ago=5)
        add_origin(core, repo, OriginType.GITHUB_FORK)
        result = Classifier(core).classify("acme/patched")
        assert result.agent_access == AgentAccess.PR_ONLY

    def test_original_origin_still_stops_at_the_classifier_ceiling(
        self, core: GovernanceCore
    ) -> None:
        """§12 would allow controlled_code_write; the classifier never proposes it."""
        repo = add_repo(core, "acme/ours", topics=["library"], pushed_days_ago=5)
        add_origin(core, repo, OriginType.ORIGINAL)
        result = Classifier(core).classify("acme/ours")
        assert result.agent_access == AgentAccess.PR_ONLY
        assert (
            AGENT_ACCESS_RANK[result.agent_access]
            < AGENT_ACCESS_RANK[AgentAccess.CONTROLLED_WRITE]
        )

    def test_low_confidence_origin_is_not_a_basis_for_access(
        self, core: GovernanceCore
    ) -> None:
        repo = add_repo(core, "acme/maybe-ours", topics=["library"], pushed_days_ago=5)
        add_origin(core, repo, OriginType.ORIGINAL, confidence=0.2)
        result = Classifier(core).classify("acme/maybe-ours")
        assert result.agent_access == AgentAccess.READ_ONLY

    def test_a_github_fork_is_read_only_regardless_of_origin_analysis(
        self, core: GovernanceCore
    ) -> None:
        repo = add_repo(
            core, "acme/upstream-copy", fork=True, parent="upstream/project",
            topics=["library"], pushed_days_ago=5,
        )
        add_origin(core, repo, OriginType.ORIGINAL)  # deliberately contradictory
        result = Classifier(core).classify("acme/upstream-copy")
        assert result.category == Category.FORK
        assert result.agent_access == AgentAccess.READ_ONLY


# --------------------------------------------------------------------------
# rationale & confidence
# --------------------------------------------------------------------------

class TestRationale:
    def test_every_axis_contributes_a_rationale_line(self, core: GovernanceCore) -> None:
        repo = add_repo(
            core, "acme/portal", topics=["website"], homepage="https://acme.example",
            pushed_days_ago=2, language="HTML",
        )
        add_tree(core, repo, ["index.html", "style.css"])
        add_origin(core, repo, OriginType.ORIGINAL)
        result = Classifier(core).classify("acme/portal")
        prefixes = {line.split("=", 1)[0] for line in result.rationale}
        assert {"category", "lifecycle", "maturity", "criticality", "agent_access"} <= prefixes

    def test_non_unknown_verdicts_always_carry_a_rationale(
        self, core: GovernanceCore
    ) -> None:
        for i, topics in enumerate(
            [["website"], ["dataset"], ["chrome-extension"], ["mcp-server"], ["game"]]
        ):
            repo = add_repo(core, f"acme/sample-{i}", topics=topics, pushed_days_ago=5)
            add_origin(core, repo, OriginType.ORIGINAL)
        for result in Classifier(core).classify_all():
            for axis, value in (
                ("category", result.category),
                ("lifecycle", result.lifecycle),
                ("maturity", result.maturity),
            ):
                if str(value) != "UNKNOWN":
                    assert any(
                        line.startswith(f"{axis}={value}") for line in result.rationale
                    ), f"{axis}={value} has no rationale line"

    def test_agreement_across_families_beats_a_single_signal(
        self, core: GovernanceCore
    ) -> None:
        weak = add_repo(core, "acme/weak", description="a small library", pushed_days_ago=5)
        strong = add_repo(
            core, "acme/strong", topics=["library", "sdk"],
            description="reusable component library", pushed_days_ago=5,
        )
        add_tree(core, strong, ["pyproject.toml", "src/strong/__init__.py"])
        classifier = Classifier(core)
        weak_result = classifier.classify("acme/weak")
        strong_result = classifier.classify("acme/strong")
        assert (
            strong_result.signals["confidence_by_axis"]["category"]
            > weak_result.signals["confidence_by_axis"]["category"]
        )
        assert strong_result.category == Category.LIBRARY

    def test_confidence_never_reaches_certainty(self, core: GovernanceCore) -> None:
        repo = add_repo(
            core, "acme/everything", topics=["library", "sdk", "package"],
            description="library sdk package toolkit", pushed_days_ago=1,
        )
        add_tree(core, repo, ["pyproject.toml", "setup.py"])
        result = Classifier(core).classify("acme/everything")
        assert result.confidence < 1.0
        assert result.signals["confidence_by_axis"]["category"] <= 0.95


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

class TestPersistence:
    def test_save_and_load_round_trip(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/keep", topics=["website"], pushed_days_ago=3)
        add_origin(core, repo, OriginType.ORIGINAL)
        classifier = Classifier(core)
        result = classifier.classify("acme/keep")
        classifier.save(result)
        loaded = classifier.load(repo)
        assert loaded is not None
        assert (loaded.category, loaded.lifecycle, loaded.agent_access) == (
            result.category, result.lifecycle, result.agent_access
        )
        assert loaded.rationale == result.rationale

    def test_apply_to_repository_updates_the_governance_overlay(
        self, core: GovernanceCore
    ) -> None:
        repo = add_repo(core, "acme/apply", topics=["website"], pushed_days_ago=3)
        add_origin(core, repo, OriginType.ORIGINAL)
        classifier = Classifier(core)
        result = classifier.classify("acme/apply")
        classifier.save(result, apply_to_repository=True)
        row = core.conn.execute(
            "SELECT lifecycle, category, agent_access FROM repositories WHERE id = ?", (repo,)
        ).fetchone()
        assert row["category"] == str(result.category)
        assert row["agent_access"] == str(result.agent_access)

    def test_proposal_only_leaves_the_repository_untouched(
        self, core: GovernanceCore
    ) -> None:
        """A proposal is not an application (axiom 3)."""
        repo = add_repo(core, "acme/propose", topics=["website"], pushed_days_ago=3)
        classifier = Classifier(core)
        classifier.save(classifier.classify("acme/propose"), apply_to_repository=False)
        row = core.conn.execute(
            "SELECT category FROM repositories WHERE id = ?", (repo,)
        ).fetchone()
        assert row["category"] == "UNKNOWN"
        assert classifier.load(repo) is not None

    def test_saving_writes_an_audit_event(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/audited", topics=["website"], pushed_days_ago=3)
        classifier = Classifier(core)
        before = core.ledger.count()
        classifier.save(classifier.classify("acme/audited"))
        assert core.ledger.count() == before + 1
        ok, message = core.ledger.verify()
        assert ok, message

    def test_classify_missing_repository_raises(self, core: GovernanceCore) -> None:
        with pytest.raises(LookupError):
            Classifier(core).classify("acme/not-inventoried")


# --------------------------------------------------------------------------
# §13.3 detectors
# --------------------------------------------------------------------------

class TestDetectors:
    def test_archive_candidates_are_proposals_with_evidence(
        self, core: GovernanceCore
    ) -> None:
        add_repo(core, "acme/forgotten", pushed_days_ago=900)
        add_repo(core, "acme/busy", pushed_days_ago=2)
        add_repo(core, "acme/already", pushed_days_ago=900, archived=True)
        candidates = Classifier(core).detect_archive_candidates()
        names = {c["full_name"] for c in candidates}
        assert "acme/forgotten" in names
        assert "acme/busy" not in names
        assert "acme/already" not in names
        for candidate in candidates:
            assert candidate["reasons"]
            assert candidate["recommendation"] == "HUMAN_REVIEW"

    def test_popular_dormant_repositories_are_not_proposed(
        self, core: GovernanceCore
    ) -> None:
        add_repo(core, "acme/beloved", pushed_days_ago=900, stars=400)
        assert Classifier(core).detect_archive_candidates() == []

    def test_superseded_marker_is_detected_with_its_successor(
        self, core: GovernanceCore
    ) -> None:
        old = add_repo(core, "acme/widget-maker", pushed_days_ago=500)
        add_repo(core, "acme/widget-maker-2", pushed_days_ago=5)
        add_snapshot(
            core, old, "readme",
            {"content": base64.b64encode(
                b"# widget-maker\n\nDeprecated in favor of acme/widget-maker-2."
            ).decode(), "encoding": "base64"},
        )
        found = Classifier(core).detect_superseded_projects()
        entry = next(f for f in found if f["full_name"] == "acme/widget-maker")
        assert entry["evidence"]
        assert entry["successor"] == "acme/widget-maker-2"
        assert entry["confidence"] > 0.5

    def test_naming_overlap_alone_is_a_weak_hint(self, core: GovernanceCore) -> None:
        add_repo(core, "acme/data-pipeline", pushed_days_ago=700)
        add_repo(core, "acme/data-pipeline-next", pushed_days_ago=3)
        found = Classifier(core).detect_superseded_projects()
        hits = {f["full_name"]: f for f in found}
        if "acme/data-pipeline" in hits:
            assert hits["acme/data-pipeline"]["confidence"] < 0.7
            assert hits["acme/data-pipeline"]["recommendation"] == "HUMAN_REVIEW"

    def test_detectors_survive_an_empty_portfolio(self, core: GovernanceCore) -> None:
        classifier = Classifier(core)
        assert classifier.detect_archive_candidates() == []
        assert classifier.detect_superseded_projects() == []
        assert classifier.classify_all() == []


# --------------------------------------------------------------------------
# signal collection
# --------------------------------------------------------------------------

class TestSignals:
    def test_base64_readme_snapshots_are_decoded(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/encoded")
        add_snapshot(
            core, repo, "readme",
            {"content": base64.b64encode("# Hello 世界".encode()).decode(), "encoding": "base64"},
        )
        row = core.conn.execute("SELECT * FROM repositories WHERE id = ?", (repo,)).fetchone()
        sig = collect_signals(core.conn, row)
        assert "Hello 世界" in sig.readme_text

    def test_file_markers_are_found_at_any_depth(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/nested")
        add_tree(core, repo, ["docs/mkdocs.yml", "src/app/manifest.json", "Dockerfile"])
        row = core.conn.execute("SELECT * FROM repositories WHERE id = ?", (repo,)).fetchone()
        sig = collect_signals(core.conn, row)
        assert sig.has_file("mkdocs.yml")
        assert sig.has_file("manifest.json")
        assert sig.has_file("dockerfile")
        assert not sig.has_file("pyproject.toml")

    def test_absent_snapshots_do_not_fabricate_evidence(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/thin")
        row = core.conn.execute("SELECT * FROM repositories WHERE id = ?", (repo,)).fetchone()
        sig = collect_signals(core.conn, row)
        assert sig.paths == frozenset()
        assert sig.has_tree_snapshot is False
        assert sig.has_file("package.json") is False  # absence of proof, not proof of absence
        assert sig.release_count is None

    def test_malformed_snapshot_payloads_are_ignored(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/broken")
        add_snapshot(core, repo, "tree", "{not json at all")
        row = core.conn.execute("SELECT * FROM repositories WHERE id = ?", (repo,)).fetchone()
        sig = collect_signals(core.conn, row)  # must not raise
        assert sig.full_name == "acme/broken"

    def test_version_hint_prefers_the_release_tag(self, core: GovernanceCore) -> None:
        repo = add_repo(core, "acme/versioned", description="see v0.2.0 notes")
        add_snapshot(core, repo, "releases", [{"tag_name": "v1.4.0"}, {"tag_name": "v1.3.0"}])
        row = core.conn.execute("SELECT * FROM repositories WHERE id = ?", (repo,)).fetchone()
        sig = collect_signals(core.conn, row)
        assert sig.version_hint() == (1, 4, 0)
        assert sig.release_count == 2
