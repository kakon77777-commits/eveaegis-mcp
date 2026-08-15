"""Tests for the Origin & Provenance Engine (§6-§10, §21-§23).

Every test here runs offline against synthetic fixtures. The properties under test
are the ones §29 lists as acceptance criteria for source analysis:

* official forks are identified correctly;
* dependencies are never mistaken for upstream sources;
* generated and vendored content can be separated;
* an unknown origin never carries an automatic originality claim;
* every verdict carries evidence and a confidence.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from eveaegis.config import AnalysisConfig, Config
from eveaegis.core import GovernanceCore
from eveaegis.credentials.base import CredentialBroker, Grant, TokenScope
from eveaegis.db import init_db
from eveaegis.models import (
    ContributionEstimate,
    Evidence,
    OriginProfile,
    PublicLabel,
    UpstreamCandidate,
)
from eveaegis.provenance import (
    ORIGINALITY_CLAIM_THRESHOLD,
    ProvenanceEngine,
    ProvenanceError,
    classify_paths,
    estimate_contribution,
    evaluate_rules,
    jaccard,
    load_rules,
    minhash_signature,
    render_report,
    token_similarity,
    winnow_fingerprints,
)
from eveaegis.provenance.components import ComponentSummary
from eveaegis.provenance.contribution import upstream_retention_from_components
from eveaegis.provenance.engine import _public_label, RepositoryEvidenceBundle
from eveaegis.provenance.fingerprint import (
    blob_similarity,
    commit_similarity,
    normalize_text,
    normalized_text_hash,
    overlap_coefficient,
    shingles,
    tokenize,
)
from eveaegis.provenance.gitlocal import (
    FORBIDDEN_COMMANDS,
    RepositoryExecutionRefused,
    assert_safe,
    run_git,
)
from eveaegis.provenance.rules import (
    SIGNAL_TIERS,
    OriginRule,
    RuleError,
    _condition_holds,
    sort_rules,
)
from eveaegis.taxonomy import (
    NO_AUTOMATIC_ORIGINALITY_CLAIM,
    ComponentClass,
    ContributionBand,
    EvidenceKind,
    LicenseStatus,
    OriginType,
    ReviewStatus,
)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
RULES_PATH = PROJECT_ROOT / "config" / "policies" / "origin_rules.yaml"


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture(scope="session")
def rules() -> list[OriginRule]:
    return load_rules(RULES_PATH)


class _NullBroker(CredentialBroker):
    """A broker that never mints anything. Tests must not reach the network."""

    name = "test-null"
    max_scope = TokenScope.READ_CONTENT

    def _mint(self, scope, lifetime_seconds, repositories, reason) -> Grant:  # noqa: ANN001
        raise AssertionError("a unit test attempted to mint a GitHub credential")


@pytest.fixture()
def core(tmp_path: Path) -> GovernanceCore:
    cfg = Config()
    cfg.database_path = str(tmp_path / "test.db")
    cfg.analysis.workspace_dir = str(tmp_path / "workspace")
    cfg.governance.policy_dir = str(PROJECT_ROOT / "config" / "policies")
    governance = GovernanceCore(cfg, conn=init_db(tmp_path / "test.db"), broker=_NullBroker())
    yield governance
    governance.close()


@pytest.fixture()
def engine(core: GovernanceCore) -> ProvenanceEngine:
    return ProvenanceEngine(core)


def _register_repository(core: GovernanceCore, repository_id: str, full_name: str) -> None:
    core.conn.execute(
        """
        INSERT INTO repositories
            (id, tenant_id, full_name, github_repository_id, visibility, default_branch, synced_at)
        VALUES (?,?,?,?,?,?,?)
        """,
        (repository_id, core.tenant_id, full_name, 1, "public", "main", datetime.now(timezone.utc).isoformat()),
    )
    core.conn.commit()


# --------------------------------------------------------------------------
# §7.1 similarity primitives
# --------------------------------------------------------------------------

def test_minhash_identical_sets_are_one() -> None:
    items = {f"token-{i}" for i in range(400)}
    a = minhash_signature(items, permutations=128)
    b = minhash_signature(set(items), permutations=128)
    assert len(a) == 128
    assert jaccard(a, b) == 1.0


def test_minhash_disjoint_sets_are_zero() -> None:
    a = minhash_signature({f"alpha-{i}" for i in range(400)}, permutations=128)
    b = minhash_signature({f"omega-{i}" for i in range(400)}, permutations=128)
    assert jaccard(a, b) == pytest.approx(0.0, abs=0.02)


def test_minhash_estimates_true_jaccard() -> None:
    a = {f"s{i}" for i in range(1000)}
    b = {f"s{i}" for i in range(500, 1500)}
    exact = jaccard(a, b)
    estimate = jaccard(
        minhash_signature(a, permutations=256), minhash_signature(b, permutations=256)
    )
    assert exact == pytest.approx(1 / 3, abs=0.01)
    assert estimate == pytest.approx(exact, abs=0.08)


def test_minhash_empty_input_is_not_similar() -> None:
    assert minhash_signature([]) == ()
    assert jaccard(minhash_signature([]), minhash_signature({"a"})) == 0.0
    assert jaccard(set(), set()) == 0.0


def test_jaccard_rejects_mismatched_signature_lengths() -> None:
    with pytest.raises(ValueError):
        jaccard(minhash_signature({"a", "b"}, permutations=32), minhash_signature({"a"}, permutations=64))


def test_overlap_coefficient_uses_min_not_union() -> None:
    """§7.1: a small fork inside a huge upstream must read as high similarity."""
    fork = {f"c{i}" for i in range(40)}
    upstream = fork | {f"u{i}" for i in range(4000)}
    assert overlap_coefficient(fork, upstream) == 1.0
    assert jaccard(fork, upstream) < 0.02


def test_commit_and_blob_similarity_are_overlap_coefficients() -> None:
    a, b = {"x", "y", "z"}, {"y", "z", "w", "q"}
    assert commit_similarity(a, b) == pytest.approx(2 / 3)
    assert blob_similarity(a, b) == pytest.approx(2 / 3)
    assert commit_similarity(set(), b) == 0.0


def test_winnowing_finds_a_shared_passage() -> None:
    passage = "the quick brown fox jumps over the lazy dog and keeps running onwards"
    a = winnow_fingerprints("prefix material " + passage + " suffix material", k=6, window=4)
    b = winnow_fingerprints("entirely different opening " + passage, k=6, window=4)
    assert {fp.hash for fp in a} & {fp.hash for fp in b}
    assert all(fp.position >= 0 for fp in a)


def test_winnowing_is_deterministic_and_disjoint_for_unrelated_text() -> None:
    a = winnow_fingerprints("alpha beta gamma delta epsilon zeta eta theta", k=5, window=4)
    assert a == winnow_fingerprints("alpha beta gamma delta epsilon zeta eta theta", k=5, window=4)
    b = winnow_fingerprints("mnemonic ratchet vestibule quorum syzygy plinth", k=5, window=4)
    assert not ({fp.hash for fp in a} & {fp.hash for fp in b})


def test_normalized_hash_ignores_formatting() -> None:
    assert normalized_text_hash("def  f():\r\n\treturn 1\n") == normalized_text_hash("def f():\n  return 1")
    assert normalized_text_hash("a") != normalized_text_hash("b")
    assert normalize_text("  A\tB  ") == "a b"


def test_token_similarity_bounds() -> None:
    source = "def add(a, b):\n    return a + b\n" * 20
    assert token_similarity(source, source) == 1.0
    assert token_similarity(source, "SELECT name FROM users WHERE id = 7") < 0.1
    assert shingles(tokenize("a b c d e f"), 3)


# --------------------------------------------------------------------------
# §9 component classification
# --------------------------------------------------------------------------

def _sample_tree() -> list[dict[str, object]]:
    entries = [
        {"path": "README.md", "type": "blob", "size": 4000},
        {"path": "LICENSE", "type": "blob", "size": 1000},
        {"path": "package.json", "type": "blob", "size": 800},
        {"path": "package-lock.json", "type": "blob", "size": 400_000},
        {"path": "src/app.ts", "type": "blob", "size": 6000},
        {"path": "src/store.ts", "type": "blob", "size": 3000},
        {"path": "tests/test_app.ts", "type": "blob", "size": 2000},
        {"path": "docs/guide.md", "type": "blob", "size": 5000},
        {"path": "assets/logo.png", "type": "blob", "size": 90_000},
        {"path": "dist/bundle.min.js", "type": "blob", "size": 700_000},
        {"path": "vendor/core/engine.c", "type": "blob", "size": 12_000},
        {"path": "vendor/core/LICENSE", "type": "blob", "size": 35_000},
        {"path": "src", "type": "tree"},
    ]
    entries.extend(
        {"path": f"node_modules/left-pad-{i}/index.js", "type": "blob", "size": 1500}
        for i in range(300)
    )
    return entries


def test_dependencies_and_build_output_leave_the_denominator() -> None:
    """§9.1 — the single most important correctness property in the module."""
    summary = classify_paths(_sample_tree(), config=AnalysisConfig())
    assert summary.total_files == 312
    assert summary.dependency_files == 300
    assert summary.vendored_files == 2
    # dist/bundle.min.js and package-lock.json
    assert summary.generated_files == 2
    assert summary.effective_files == 8
    assert summary.effective_file_ratio < 0.03

    effective = set(summary.effective_paths())
    assert not any(p.startswith(("node_modules/", "vendor/", "dist/")) for p in effective)
    assert "package-lock.json" not in effective
    assert {"src/app.ts", "src/store.ts", "tests/test_app.ts", "docs/guide.md"} <= effective


def test_unclassified_content_defaults_to_unknown_not_original() -> None:
    """Axiom 4 at file granularity: not-excluded is not the same as authored."""
    summary = classify_paths([("src/main.py", 100)])
    assert summary.files[0].component_class is ComponentClass.UNKNOWN
    promoted = classify_paths([("src/main.py", 100)], default_class=ComponentClass.ORIGINAL)
    assert promoted.files[0].component_class is ComponentClass.ORIGINAL


def test_nested_and_configured_exclusions_are_honoured() -> None:
    summary = classify_paths(
        [
            ("web/node_modules/pkg/a.js", 10),
            ("services/api/vendor/lib/b.go", 10),
            ("frontend/dist/app.js", 10),
            ("custom_cache/thing.txt", 10),
        ],
        config=AnalysisConfig(excluded_dirs=["custom_cache"]),
    )
    classes = {f.path: f.component_class for f in summary.files}
    assert classes["web/node_modules/pkg/a.js"] is ComponentClass.DEPENDENCY
    assert classes["services/api/vendor/lib/b.go"] is ComponentClass.VENDORED
    assert classes["frontend/dist/app.js"] is ComponentClass.GENERATED
    assert classes["custom_cache/thing.txt"] is ComponentClass.GENERATED
    assert summary.effective_files == 0


def test_embedded_license_inside_vendor_is_still_recorded() -> None:
    """A licence in vendor/ is the §10 signal most easily lost with the exclusion."""
    summary = classify_paths(_sample_tree())
    assert "vendor/core/LICENSE" in summary.embedded_license_files
    assert "LICENSE" in summary.license_files
    assert "package.json" in summary.dependency_manifests
    assert "package-lock.json" in summary.lock_files


def test_manifest_inside_node_modules_is_not_our_manifest() -> None:
    summary = classify_paths([("node_modules/x/package.json", 10), ("package.json", 10)])
    assert summary.dependency_manifests == ["package.json"]


def test_component_profiles_group_instead_of_exploding() -> None:
    profiles = classify_paths(_sample_tree()).to_profiles()
    assert len(profiles) < 15
    node_modules = next(p for p in profiles if p.path == "node_modules")
    assert node_modules.component_class is ComponentClass.DEPENDENCY
    assert node_modules.files == 300


# --------------------------------------------------------------------------
# §7.3 rule language and §7.2 precedence
# --------------------------------------------------------------------------

def test_shipped_rule_file_is_complete(rules: list[OriginRule]) -> None:
    ids = {rule.id for rule in rules}
    assert {
        "native-github-fork",
        "detached-fork-shared-history",
        "mirror-detection",
        "template-derived",
        "original",
        "original-with-dependencies",
        "plugin-or-extension",
        "generated-scaffold",
        "vendor-snapshot",
        "unknown-origin",
    } <= ids
    assert all(rule.signal_tier in SIGNAL_TIERS for rule in rules)
    assert any(rule.origin_type is OriginType.UNKNOWN for rule in rules)


def test_condition_operators() -> None:
    facts = {"a": 0.42, "b": True, "c": "MIT", "n": 3}
    assert _condition_holds(facts, "a", ">=0.30")
    assert not _condition_holds(facts, "a", ">=0.50")
    assert _condition_holds(facts, "n", "<=3")
    assert _condition_holds(facts, "b", True)
    assert not _condition_holds(facts, "b", False)
    assert _condition_holds(facts, "c", "MIT")
    assert _condition_holds(facts, "c", ["MIT", "Apache-2.0"])
    assert _condition_holds(facts, "c", "in: MIT, ISC")
    assert _condition_holds(facts, "c", "!=GPL-3.0")
    assert _condition_holds(facts, "missing", None)


def test_missing_fact_never_satisfies_a_condition() -> None:
    """Absence must never be read as false or zero (§29)."""
    assert not _condition_holds({}, "similarity.commit", ">=0.30")
    assert not _condition_holds({}, "github.fork", False)
    assert not _condition_holds({}, "candidates.count", 0)


def test_official_fork_metadata_wins_over_every_weaker_signal(rules: list[OriginRule]) -> None:
    """§7.2 — a weaker rung may never override a stronger one."""
    facts = {
        "analysis.completed": True,
        "github.fork": True,
        "github.parent.exists": True,
        "github.template.exists": False,
        "attribution.detected": True,
        "attribution.upstream_count": 3,
        "attribution.explicit_fork_statement": True,
        "similarity.token": 0.95,
        "candidates.count": 3,
        "tree.effective_files": 400,
        "tree.has_dependency_manifest": True,
        "tree.vendored_ratio": 0.9,
        "tree.effective_ratio": 0.05,
    }
    result = evaluate_rules(rules, facts)
    assert result.origin_type is OriginType.GITHUB_FORK
    assert result.matched_rule_id == "native-github-fork"
    assert result.matched.signal_tier == "fork_metadata"
    # The weaker rules still matched — they are recorded as dissent, not discarded.
    assert {r.id for r in result.dissenting} >= {"declared-fork-in-documentation"}
    assert all(r.tier_rank >= result.matched.tier_rank for r in result.all_matches)


def test_commit_ancestry_beats_attribution_and_token_similarity(rules: list[OriginRule]) -> None:
    facts = {
        "analysis.completed": True,
        "github.fork": False,
        "github.template.exists": False,
        "similarity.commit": 0.55,
        "similarity.token": 0.99,
        "common_root_commit": True,
        "attribution.detected": True,
        "attribution.upstream_count": 2,
        "attribution.explicit_fork_statement": True,
        "candidates.count": 1,
        "tree.effective_files": 120,
        "tree.has_dependency_manifest": True,
    }
    result = evaluate_rules(rules, facts)
    assert result.origin_type is OriginType.DETACHED_FORK
    assert result.matched.signal_tier == "commit_ancestry"


def test_corroboration_adds_only_a_small_bonus() -> None:
    strong = OriginRule(
        id="strong", when={"x": True}, origin_type=OriginType.DETACHED_FORK,
        confidence=0.70, signal_tier="commit_ancestry",
    )
    weak = OriginRule(
        id="weak", when={"y": True}, origin_type=OriginType.DETACHED_FORK,
        confidence=0.99, signal_tier="token_similarity",
    )
    result = evaluate_rules([strong, weak], {"x": True, "y": True})
    assert result.matched_rule_id == "strong"
    assert result.confidence == pytest.approx(0.72)
    assert [r.id for r in result.corroborating] == ["weak"]


def test_no_match_stays_unknown() -> None:
    rule = OriginRule(id="r", when={"x": True}, origin_type=OriginType.ORIGINAL, confidence=1.0)
    result = evaluate_rules([rule], {"x": False})
    assert result.matched is None
    assert result.origin_type is OriginType.UNKNOWN
    assert result.confidence == 0.0


def test_rules_sort_strongest_tier_first(rules: list[OriginRule]) -> None:
    ordered = sort_rules(rules)
    ranks = [rule.tier_rank for rule in ordered]
    assert ranks == sorted(ranks)


def test_malformed_rule_files_are_rejected(tmp_path: Path) -> None:
    bad = tmp_path / "origin_rules.yaml"
    bad.write_text("rules:\n  - id: x\n    when: {a: true}\n    result: {origin_type: NOPE}\n", "utf-8")
    with pytest.raises(RuleError):
        load_rules(bad)
    bad.write_text("rules:\n  - id: x\n    when: {}\n    result: {origin_type: ORIGINAL}\n", "utf-8")
    with pytest.raises(RuleError):
        load_rules(bad)
    bad.write_text(
        "rules:\n  - id: x\n    signal_tier: vibes\n    when: {a: true}\n"
        "    result: {origin_type: ORIGINAL}\n",
        "utf-8",
    )
    with pytest.raises(RuleError):
        load_rules(bad)


def test_dependency_manifests_do_not_imply_upstream(rules: list[OriginRule]) -> None:
    """§9.1 — a project with dependencies is still an original project."""
    facts = {
        "analysis.completed": True,
        "github.fork": False,
        "github.template.exists": False,
        "candidates.count": 0,
        "attribution.explicit_fork_statement": False,
        "tree.has_dependency_manifest": True,
        "tree.effective_files": 60,
        "tree.dependency_files": 12000,
        "tree.dependency_ratio": 0.99,
    }
    result = evaluate_rules(rules, facts)
    assert result.origin_type is OriginType.ORIGINAL_WITH_DEPENDENCIES


# --------------------------------------------------------------------------
# §8 contribution ranges
# --------------------------------------------------------------------------

def _summary(effective_files: int = 100, effective_bytes: int = 100_000) -> ComponentSummary:
    summary = ComponentSummary()
    summary.total_files = effective_files
    summary.total_bytes = effective_bytes
    summary.effective_files = effective_files
    summary.effective_bytes = effective_bytes
    summary.files_by_dimension = {}
    return summary


@pytest.mark.parametrize(
    "retained_files,retained_bytes,measurement",
    [
        (0.0, 0.0, "blob_exact"),
        (1.0, 1.0, "blob_exact"),
        (0.5, 0.9, "shallow"),
        (0.97, 0.02, "commit_graph"),
        (0.33, None, "token"),
    ],
)
def test_contribution_ranges_stay_inside_zero_one(
    retained_files: float, retained_bytes: float | None, measurement: str
) -> None:
    estimate = estimate_contribution(
        _summary(),
        origin_type=OriginType.GITHUB_FORK,
        origin_confidence=1.0,
        upstream_retained=retained_files,
        upstream_retained_bytes=retained_bytes,
        measurement=measurement,
    )
    for low, high in (
        (estimate.upstream_retained_min, estimate.upstream_retained_max),
        (estimate.local_contribution_min, estimate.local_contribution_max),
    ):
        assert low is not None and high is not None
        assert 0.0 <= low <= high <= 1.0


def test_contribution_is_never_a_single_number() -> None:
    """§8.1 — the public answer is a band plus an interval, never a bare score."""
    estimate = estimate_contribution(
        _summary(),
        origin_type=OriginType.GITHUB_FORK,
        origin_confidence=1.0,
        upstream_retained=0.30,
        upstream_retained_bytes=0.40,
        measurement="blob_exact",
    )
    assert estimate.local_contribution_min < estimate.local_contribution_max
    assert estimate.band is not ContributionBand.UNKNOWN
    assert estimate.confidence is not None


def test_unmeasured_upstream_is_reported_as_unknown_not_as_full_originality() -> None:
    estimate = estimate_contribution(
        _summary(),
        origin_type=OriginType.DETACHED_FORK,
        origin_confidence=0.95,
        upstream_retained=None,
        measurement="shallow",
    )
    assert estimate.local_contribution_min is None
    assert estimate.local_contribution_max is None
    assert estimate.band is ContributionBand.UNKNOWN


def test_self_contained_repository_still_gets_a_range_not_a_hundred_percent() -> None:
    estimate = estimate_contribution(
        _summary(),
        origin_type=OriginType.ORIGINAL,
        origin_confidence=0.88,
        measurement="shallow",
    )
    assert estimate.local_contribution_min == pytest.approx(0.80)
    assert estimate.local_contribution_max == pytest.approx(1.0)
    assert estimate.band is ContributionBand.NEARLY_FULL


def test_empty_effective_content_refuses_to_conclude() -> None:
    estimate = estimate_contribution(
        ComponentSummary(), origin_type=OriginType.VENDOR_SNAPSHOT, origin_confidence=0.7
    )
    assert estimate.band is ContributionBand.UNKNOWN
    assert estimate.local_contribution_min is None


def test_vendored_repository_is_not_mostly_upstream() -> None:
    """The §9.1 headline case, end to end through the estimator."""
    summary = classify_paths(_sample_tree(), config=AnalysisConfig())
    # 3 of the 8 effective files match upstream — 300 node_modules files must not
    # drag this toward "almost entirely upstream".
    estimate = estimate_contribution(
        summary,
        origin_type=OriginType.GITHUB_FORK,
        origin_confidence=1.0,
        upstream_retained=3 / summary.effective_files,
        measurement="blob_exact",
    )
    assert estimate.upstream_retained_max < 0.50
    assert estimate.local_contribution_min > 0.50


def test_out_of_range_inputs_are_clamped_not_propagated() -> None:
    estimate = estimate_contribution(
        _summary(),
        origin_type=OriginType.GITHUB_FORK,
        origin_confidence=1.0,
        upstream_retained=1.4,
        upstream_modified_ratio=4.0,
        measurement="blob_exact",
    )
    assert estimate.upstream_retained_max == 1.0
    assert estimate.transformation_score == 1.0


def test_invalid_interval_raises_rather_than_publishes() -> None:
    from eveaegis.provenance.contribution import _assert_invariants

    with pytest.raises(ValueError):
        _assert_invariants(
            ContributionEstimate(local_contribution_min=0.8, local_contribution_max=0.2)
        )
    with pytest.raises(ValueError):
        # A half-open interval would render as a single number downstream (§8.1).
        _assert_invariants(ContributionEstimate(upstream_retained_min=0.3))


def test_retention_from_components_requires_a_comparison() -> None:
    summary = _summary()
    assert upstream_retention_from_components(summary) is None
    summary.files_by_class[ComponentClass.UPSTREAM_UNMODIFIED] = 40
    summary.bytes_by_class[ComponentClass.UPSTREAM_UNMODIFIED] = 40_000
    by_files, by_bytes = upstream_retention_from_components(summary)
    assert by_files == pytest.approx(0.4)
    assert by_bytes == pytest.approx(0.4)


# --------------------------------------------------------------------------
# Axiom 4 — no automatic originality claim
# --------------------------------------------------------------------------

def _bundle(license_status: LicenseStatus = LicenseStatus.CLEAR) -> RepositoryEvidenceBundle:
    bundle = RepositoryEvidenceBundle("owner/repo", "repo_1", {"id": 1})
    bundle.summary = _summary()
    bundle.license_status = license_status
    return bundle


@pytest.mark.parametrize("origin_type", sorted(NO_AUTOMATIC_ORIGINALITY_CLAIM, key=str))
def test_forbidden_origin_types_never_claim_originality(origin_type: OriginType) -> None:
    """Axiom 4, exhaustively over every forbidden origin type."""
    label, review = _public_label(
        origin_type=origin_type,
        confidence=1.0,
        bundle=_bundle(),
        contribution=ContributionEstimate(
            local_contribution_min=0.95, local_contribution_max=1.0, band=ContributionBand.NEARLY_FULL
        ),
    )
    assert label.originality_claim == "none"
    assert review is ReviewStatus.NEEDS_REVIEW


def test_low_confidence_never_claims_originality() -> None:
    label, review = _public_label(
        origin_type=OriginType.ORIGINAL,
        confidence=ORIGINALITY_CLAIM_THRESHOLD - 0.01,
        bundle=_bundle(),
        contribution=ContributionEstimate(band=ContributionBand.NEARLY_FULL),
    )
    assert label.originality_claim == "none"
    assert review is ReviewStatus.NEEDS_REVIEW


def test_confident_original_may_claim_and_carries_no_attribution() -> None:
    label, review = _public_label(
        origin_type=OriginType.ORIGINAL,
        confidence=0.88,
        bundle=_bundle(),
        contribution=ContributionEstimate(band=ContributionBand.NEARLY_FULL),
    )
    assert label.originality_claim == "original"
    assert label.attribution is None
    assert review is ReviewStatus.UNREVIEWED


def test_measurement_can_veto_an_origin_based_claim() -> None:
    """An "original" verdict whose measured contribution is minimal defers to a human."""
    label, review = _public_label(
        origin_type=OriginType.ORIGINAL,
        confidence=0.95,
        bundle=_bundle(),
        contribution=ContributionEstimate(band=ContributionBand.LIMITED),
    )
    assert label.originality_claim == "none"
    assert review is ReviewStatus.NEEDS_REVIEW


def test_license_concern_escalates_to_legal_review() -> None:
    label, review = _public_label(
        origin_type=OriginType.ORIGINAL,
        confidence=0.95,
        bundle=_bundle(LicenseStatus.COPYLEFT_TRIGGERED),
        contribution=ContributionEstimate(band=ContributionBand.NEARLY_FULL),
    )
    assert label.originality_claim == "original"
    assert review is ReviewStatus.LEGAL_REVIEW_REQUESTED


def test_unknown_origin_public_label_is_conservative() -> None:
    bundle = _bundle()
    bundle.candidates.append(
        UpstreamCandidate(
            full_name="upstream/example", discovered_via="github_fork_parent", confidence=1.0
        )
    )
    label, review = _public_label(
        origin_type=OriginType.UNKNOWN,
        confidence=0.0,
        bundle=bundle,
        contribution=ContributionEstimate(),
    )
    assert label.originality_claim == "none"
    assert label.label == "Origin under review"
    assert label.attribution == "Based on upstream/example"
    assert review is ReviewStatus.NEEDS_REVIEW


# --------------------------------------------------------------------------
# §21 no repository code execution
# --------------------------------------------------------------------------

def test_execution_permission_is_refused_before_any_git_runs(tmp_path: Path) -> None:
    unsafe = AnalysisConfig(allow_repository_code_execution=True)
    with pytest.raises(RepositoryExecutionRefused):
        assert_safe(unsafe)
    with pytest.raises(RepositoryExecutionRefused):
        run_git(["status"], config=unsafe, workspace=tmp_path)


def test_build_tools_are_refused_even_with_a_safe_config(tmp_path: Path) -> None:
    safe = AnalysisConfig()
    for command in ("npm", "pip", "make", "docker", "bash"):
        assert command in FORBIDDEN_COMMANDS
        with pytest.raises(RepositoryExecutionRefused):
            run_git([command, "install"], config=safe, workspace=tmp_path)


def test_hardened_git_disables_hooks_and_exotic_transports(tmp_path: Path) -> None:
    from eveaegis.provenance.gitlocal import _hardening_flags, _safe_env

    flags = " ".join(_hardening_flags(tmp_path))
    assert "core.hooksPath=" in flags
    assert "protocol.ext.allow=never" in flags
    assert "protocol.file.allow=never" in flags
    env = _safe_env()
    assert env["GIT_TERMINAL_PROMPT"] == "0"
    assert "GIT_ASKPASS" not in env


# --------------------------------------------------------------------------
# engine wiring: facts, persistence, review queue, report
# --------------------------------------------------------------------------

def test_engine_loads_the_shipped_rules(engine: ProvenanceEngine) -> None:
    assert engine.rules
    assert any(rule.id == "native-github-fork" for rule in engine.rules)


def test_build_facts_omits_what_was_not_measured(engine: ProvenanceEngine) -> None:
    bundle = RepositoryEvidenceBundle(
        "owner/repo",
        "repo_1",
        {"id": 1, "fork": False, "default_branch": "main", "size": 120, "topics": []},
    )
    bundle.summary = classify_paths(_sample_tree(), config=AnalysisConfig())
    facts = engine.build_facts(bundle)

    assert facts["analysis.completed"] is True
    assert facts["github.fork"] is False
    assert facts["tree.effective_files"] == 8
    assert facts["tree.has_dependency_manifest"] is True
    # Nothing was compared, so no similarity fact may exist at all.
    for key in ("similarity.commit", "similarity.blob", "common_root_commit", "upstream_retained"):
        assert key not in facts


def test_a_build_dependency_does_not_make_a_project_a_plugin(engine: ProvenanceEngine) -> None:
    """§9.1 regression: `vite-plugin-svgr` in devDependencies is a dependency."""
    from eveaegis.provenance.engine import _plugin_signature

    bundle = RepositoryEvidenceBundle("owner/webapp", "repo_3", {"id": 3, "topics": []})
    bundle.manifests["package.json"] = (
        '{"name": "storyforge", "keywords": ["fiction"], '
        '"devDependencies": {"vite-plugin-svgr": "^4.0.0", "eslint-plugin-react": "^7.0.0"}}'
    )
    assert _plugin_signature(bundle) is False

    bundle.manifests["package.json"] = '{"name": "eslint-plugin-eveaegis", "version": "1.0.0"}'
    assert _plugin_signature(bundle) is True

    bundle.manifests = {"manifest.json": '{"manifest_version": 3, "name": "Exporter"}'}
    assert _plugin_signature(bundle) is True


def test_crediting_a_source_is_not_descending_from_it(rules: list[OriginRule]) -> None:
    """A NOTICE credit plus near-zero structural overlap is not a derivation."""
    facts = {
        "analysis.completed": True,
        "github.fork": False,
        "github.template.exists": False,
        "attribution.detected": True,
        "attribution.upstream_count": 1,
        "attribution.explicit_fork_statement": False,
        "candidates.count": 1,
        "similarity.path": 0.04,
        "tree.effective_files": 80,
        "tree.has_dependency_manifest": True,
    }
    result = evaluate_rules(rules, facts)
    assert result.matched_rule_id == "original-with-credited-sources"
    assert result.origin_type is OriginType.ORIGINAL_WITH_DEPENDENCIES
    # Below the claim threshold on purpose: informative verdict, no public claim.
    assert result.confidence < ORIGINALITY_CLAIM_THRESHOLD
    assert result.requires_review

    # Raise the structural overlap and the rule must stop firing.
    result_similar = evaluate_rules(rules, {**facts, "similarity.path": 0.85})
    assert result_similar.matched_rule_id != "original-with-credited-sources"


def test_verdict_without_evidence_is_forced_to_unknown(engine: ProvenanceEngine) -> None:
    """§29 — every verdict carries evidence; one that does not is UNKNOWN."""
    bundle = RepositoryEvidenceBundle("owner/empty", "repo_2", {"id": 2, "fork": False})
    facts = engine.build_facts(bundle)
    evaluation = evaluate_rules(engine.rules, facts)
    profile = engine._build_profile(bundle, facts, evaluation)
    assert profile.origin_type is OriginType.UNKNOWN
    assert profile.origin_confidence == 0.0
    assert profile.public.originality_claim == "none"
    assert profile.review_status is ReviewStatus.NEEDS_REVIEW


def test_save_refuses_when_the_repository_is_not_in_the_inventory(
    engine: ProvenanceEngine,
) -> None:
    profile = OriginProfile(id="orp_missing", repository_id="repo_missing")
    with pytest.raises(ProvenanceError):
        engine.save(profile)


def test_save_load_and_review_queue_round_trip(core: GovernanceCore, engine: ProvenanceEngine) -> None:
    _register_repository(core, "repo_9", "owner/forked")
    profile = OriginProfile(
        id="orp_repo_9",
        repository_id="repo_9",
        origin_type=OriginType.GITHUB_FORK,
        origin_confidence=1.0,
        matched_rule="native-github-fork",
        evidence=[
            Evidence(
                kind=EvidenceKind.GITHUB_METADATA,
                key="github.parent",
                value="upstream/example",
                weight=1.0,
                supports=[OriginType.GITHUB_FORK],
            )
        ],
        contribution=ContributionEstimate(
            upstream_retained_min=0.30,
            upstream_retained_max=0.45,
            local_contribution_min=0.55,
            local_contribution_max=0.70,
            band=ContributionBand.SUBSTANTIAL,
        ),
        components=classify_paths(_sample_tree()).to_profiles(),
        license_status=LicenseStatus.REVIEW_REQUIRED,
        public=PublicLabel(
            label="Fork of an upstream project",
            attribution="Based on upstream/example",
            originality_claim="none",
        ),
        review_status=ReviewStatus.NEEDS_REVIEW,
    )
    profile.upstream_candidates.append(
        UpstreamCandidate(
            full_name="upstream/example", discovered_via="github_fork_parent", confidence=1.0
        )
    )
    engine.save(profile)
    engine.save(profile)  # idempotent: re-analysis must not duplicate child rows

    loaded = engine.load("repo_9")
    assert loaded is not None
    assert loaded.origin_type is OriginType.GITHUB_FORK
    assert loaded.public.originality_claim == "none"
    assert [c.full_name for c in loaded.upstream_candidates] == ["upstream/example"]
    assert any(c.component_class is ComponentClass.DEPENDENCY for c in loaded.components)

    queue = engine.review_queue()
    assert len(queue) == 1
    entry = queue[0]
    assert entry["full_name"] == "owner/forked"
    assert "axiom 4" in " ".join(entry["reasons"])
    assert any("license" in reason for reason in entry["reasons"])

    linked = core.conn.execute("SELECT origin_profile_id FROM repositories WHERE id='repo_9'").fetchone()
    assert linked["origin_profile_id"] == "orp_repo_9"


def test_report_states_the_axiom_when_no_claim_is_made() -> None:
    profile = OriginProfile(
        id="orp_x",
        repository_id="repo_x",
        origin_type=OriginType.DETACHED_FORK,
        origin_confidence=0.95,
        matched_rule="detached-fork-shared-history",
        evidence=[
            Evidence(
                kind=EvidenceKind.GIT_METADATA,
                key="similarity.commit",
                value="0.550 against upstream/example",
                weight=0.9,
            )
        ],
        public=PublicLabel(label="Modified upstream project", originality_claim="none"),
        review_status=ReviewStatus.NEEDS_REVIEW,
    )
    report = render_report("owner/repo", profile)
    assert "Origin & Provenance Report" in report
    assert "detached-fork-shared-history" in report
    assert "Axiom 4" in report
    assert "not a legal conclusion" in report
    assert "similarity.commit" in report


def test_analysis_never_opens_a_writable_scope(core: GovernanceCore) -> None:
    """The engine is a read-only consumer; read_only mode must still permit it."""
    assert core.cfg.governance.read_only is True
    with pytest.raises(PermissionError):
        core.client(TokenScope.WRITE_METADATA, reason="should be refused")


class TestLicenceProseIsNotAnEmbeddedLicence:
    """A page *about* licensing governs no code and must not trigger legal review.

    Caught on the live portfolio: an ``ai/governance/license.md`` page (an AI-rights
    declaration, entirely the author's own writing) sent two flagship repositories to
    LEGAL_REVIEW_REQUIRED because the detector treated any non-root licence file as
    embedded third-party material.
    """

    @staticmethod
    def _paths(paths: list[str]):
        from eveaegis.provenance.components import classify_paths

        return classify_paths([{"path": p, "type": "blob", "size": 100} for p in paths])

    def test_licence_prose_with_no_adjacent_code_is_not_embedded(self) -> None:
        summary = self._paths(
            ["README.md", "LICENSE", "src/main.py", "ai/governance/license.md"]
        )
        assert summary.embedded_license_files == []
        # Ruled out, not discarded — a human can still see what was considered.
        assert summary.documentary_license_files == ["ai/governance/license.md"]

    def test_licence_beside_code_is_still_embedded(self) -> None:
        summary = self._paths(
            ["LICENSE", "packages/upstream-lib/LICENSE", "packages/upstream-lib/index.ts"]
        )
        assert summary.embedded_license_files == ["packages/upstream-lib/LICENSE"]

    def test_vendored_licence_is_kept_even_without_detected_code(self) -> None:
        """Inside vendor/ the signal stands on its own — that is where copyleft hides."""
        summary = self._paths(["LICENSE", "vendor/core/LICENSE"])
        assert summary.embedded_license_files == ["vendor/core/LICENSE"]

    def test_root_licence_is_never_embedded(self) -> None:
        summary = self._paths(["LICENSE", "src/main.py"])
        assert summary.embedded_license_files == []
        assert summary.license_files == ["LICENSE"]


class TestRefusingToClaimIsNotTheSameAsNeedingAHuman:
    """A settled fork makes no claim *and* needs no decision.

    On the live portfolio every one of 16 forks sat in NEEDS_REVIEW at confidence
    1.00, saying the same thing GitHub already says. At 100 forks that is a queue
    nobody reads — and a queue nobody reads means nothing ever becomes publishable,
    because publishing requires human review. Human review is for cases that need
    judgement: the engine is unsure, or a claim is on the table.
    """

    def test_fork_from_github_metadata_is_settled_not_pending(self) -> None:
        label, review = _public_label(
            origin_type=OriginType.GITHUB_FORK,
            confidence=1.0,
            bundle=_bundle(),
            contribution=ContributionEstimate(band=ContributionBand.LIMITED),
            signal_tier="fork_metadata",
        )
        assert label.originality_claim == "none"   # axiom 4 still holds
        assert review is ReviewStatus.UNREVIEWED   # but nothing is pending

    def test_settled_forks_drop_out_of_the_review_queue(self) -> None:
        """The queue already filters correctly; only the status assignment was wrong."""
        _, review = _public_label(
            origin_type=OriginType.GITHUB_FORK,
            confidence=1.0,
            bundle=_bundle(),
            contribution=ContributionEstimate(band=ContributionBand.LIMITED),
            signal_tier="fork_metadata",
        )
        # review_queue() selects NEEDS_REVIEW / LEGAL_REVIEW_REQUESTED, plus UNREVIEWED
        # rows that carry a public claim. A settled fork matches none of those.
        assert review not in {ReviewStatus.NEEDS_REVIEW, ReviewStatus.LEGAL_REVIEW_REQUESTED}

    def test_an_inferred_fork_still_needs_a_human(self) -> None:
        """Detached forks rest on our inference, not on GitHub's own assertion."""
        _, review = _public_label(
            origin_type=OriginType.DETACHED_FORK,
            confidence=0.95,
            bundle=_bundle(),
            contribution=ContributionEstimate(band=ContributionBand.MIXED),
            signal_tier="commit_ancestry",
        )
        assert review is ReviewStatus.NEEDS_REVIEW

    def test_unknown_origin_is_never_settled(self) -> None:
        """Whatever tier it claims, "we could not tell" is the definition of pending."""
        _, review = _public_label(
            origin_type=OriginType.UNKNOWN,
            confidence=1.0,
            bundle=_bundle(),
            contribution=ContributionEstimate(),
            signal_tier="fork_metadata",
        )
        assert review is ReviewStatus.NEEDS_REVIEW

    def test_upstreams_licence_structure_is_not_our_review_task(self) -> None:
        """An untouched fork inherits upstream's vendoring, not a legal task.

        Eight of the sixteen live forks were flagged because the *upstream* project
        vendors third-party code with licence files. That is the upstream's own
        arrangement; assigning it to whoever forked them misattributes whose question
        it is.
        """
        label, review = _public_label(
            origin_type=OriginType.GITHUB_FORK,
            confidence=1.0,
            bundle=_bundle(LicenseStatus.REVIEW_REQUIRED),
            contribution=ContributionEstimate(band=ContributionBand.LIMITED),
            signal_tier="fork_metadata",
        )
        assert label.originality_claim == "none"
        assert review is ReviewStatus.UNREVIEWED

    def test_licence_becomes_ours_once_we_make_it_our_own_version(self) -> None:
        """fork -> study -> own version is exactly when the question transfers."""
        _, review = _public_label(
            origin_type=OriginType.DETACHED_FORK,
            confidence=0.95,
            bundle=_bundle(LicenseStatus.COPYLEFT_TRIGGERED),
            contribution=ContributionEstimate(band=ContributionBand.SUBSTANTIAL),
            signal_tier="commit_ancestry",
        )
        assert review is ReviewStatus.LEGAL_REVIEW_REQUESTED

    def test_licence_hold_on_our_own_project_still_reaches_a_human(self) -> None:
        _, review = _public_label(
            origin_type=OriginType.ORIGINAL_WITH_DEPENDENCIES,
            confidence=0.95,
            bundle=_bundle(LicenseStatus.COPYLEFT_TRIGGERED),
            contribution=ContributionEstimate(band=ContributionBand.NEARLY_FULL),
            signal_tier="structural",
        )
        assert review is ReviewStatus.LEGAL_REVIEW_REQUESTED
