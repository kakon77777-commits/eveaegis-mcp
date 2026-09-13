"""Repository classifier (§5, §13.3, §24 Phase 3).

Maps :class:`~eveaegis.classification.signals.RepositorySignals` onto the five
governance axes of §5 — category, lifecycle, maturity, criticality and agent
access — together with a confidence and a human-readable rationale.

Three rules shape every decision here:

1. **Ambiguity is a verdict.** When the evidence does not separate two categories,
   the answer is ``UNKNOWN``. A guess that looks like a conclusion is worse than
   an honest gap, because downstream policy treats a confident label as a licence
   to act (§29 "every verdict carries evidence and confidence").
2. **Confidence is reported honestly.** A single keyword match is ~0.45, not 0.9.
   The confidence formula rewards *independent* evidence families agreeing, not
   the same word appearing in three places.
3. **Agent access is the minimum of what classification suggests and what the
   origin type permits** (§12). A missing origin profile caps access at
   ``READ_ONLY``: "not analysed yet" must never read as "safe to write".

The vocabulary lives in ``config/taxonomy/<profile>.yaml`` so tuning the portfolio
never requires touching this file.
"""

from __future__ import annotations

import re
import sqlite3
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from ..config import PROJECT_ROOT
from ..core import GovernanceCore
from ..db import dumps, loads
from ..models import ClassificationResult
from ..taxonomy import (
    AGENT_ACCESS_RANK,
    CRITICALITY_EVIDENCE_RANK,
    AgentAccess,
    Category,
    Criticality,
    Lifecycle,
    Maturity,
    OriginType,
)
from .signals import RepositorySignals, collect_signals, load_repository_row

#: Classification escalates along the *evidence* ordering: UNKNOWN is the floor and
#: every step above it must be justified by an observation. The risk engine uses a
#: different ordering on purpose — see :data:`eveaegis.taxonomy.CRITICALITY_RISK_RANK`.
_CRITICALITY_RANK = CRITICALITY_EVIDENCE_RANK


class TaxonomyProfile:
    """The tunable vocabulary, loaded from ``config/taxonomy/<profile>.yaml``."""

    def __init__(self, data: Mapping[str, Any], *, source: Path | None = None) -> None:
        self.data = dict(data)
        self.source = source

    @classmethod
    def load(cls, profile: str = "evemisslab-v1", *, root: Path | None = None) -> "TaxonomyProfile":
        base = (root or PROJECT_ROOT) / "config" / "taxonomy"
        path = base / f"{profile}.yaml"
        if not path.is_file():
            # Fail *soft* on vocabulary, not on safety: with no keyword map every
            # repository simply lands on UNKNOWN, which is the safe verdict anyway.
            return cls({}, source=None)
        return cls(yaml.safe_load(path.read_text("utf-8")) or {}, source=path)

    def section(self, name: str, default: Any = None) -> Any:
        value = self.data.get(name)
        return default if value is None else value

    def weight(self, family: str) -> float:
        return float(self.section("weights", {}).get(family, 0.0))

    def threshold(self, name: str, default: float) -> float:
        return float(self.section("thresholds", {}).get(name, default))


class Classifier:
    """§13.3 Classification toolset, minus the MCP wrapper."""

    def __init__(self, core: GovernanceCore) -> None:
        self.core = core
        self.conn: sqlite3.Connection = core.conn
        self.profile = TaxonomyProfile.load(core.cfg.governance.taxonomy_profile)

    # -- public API -------------------------------------------------------

    def classify(self, full_name: str) -> ClassificationResult:
        """Classify one repository. Raises ``LookupError`` if it is not inventoried."""
        row = load_repository_row(self.conn, full_name, tenant_id=self.core.tenant_id)
        if row is None:
            row = load_repository_row(self.conn, full_name)
        if row is None:
            raise LookupError(f"repository '{full_name}' is not in the inventory")
        return self._classify_row(row)

    def classify_all(self, *, limit: int | None = None) -> list[ClassificationResult]:
        """Classify every inventoried repository in the tenant. Does not persist."""
        sql = "SELECT * FROM repositories WHERE tenant_id = ? AND missing_since IS NULL ORDER BY full_name"
        if limit is not None:
            sql += f" LIMIT {int(limit)}"
        rows = self.conn.execute(sql, (self.core.tenant_id,)).fetchall()
        return [self._classify_row(row) for row in rows]

    def save(self, result: ClassificationResult, *, apply_to_repository: bool = True) -> None:
        """Persist the verdict.

        ``apply_to_repository=False`` records the proposal only — the governance
        overlay on ``repositories`` stays untouched, which is what a dry-run or an
        unapproved agent proposal must do (axiom 3).
        """
        now = datetime.now(timezone.utc).isoformat()
        self.conn.execute(
            """
            INSERT INTO classifications
                (id, repository_id, category, lifecycle, maturity, criticality,
                 agent_access, confidence, signals, rationale, created_at, taxonomy_profile)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                f"cls_{uuid.uuid4().hex[:16]}",
                result.repository_id,
                str(result.category),
                str(result.lifecycle),
                str(result.maturity),
                str(result.criticality),
                str(result.agent_access),
                float(result.confidence),
                dumps(result.signals),
                dumps(result.rationale),
                now,
                result.taxonomy_profile,
            ),
        )
        if apply_to_repository:
            self.conn.execute(
                """
                UPDATE repositories
                   SET category = ?, lifecycle = ?, maturity = ?, criticality = ?,
                       agent_access = ?
                 WHERE id = ?
                """,
                (
                    str(result.category),
                    str(result.lifecycle),
                    str(result.maturity),
                    str(result.criticality),
                    str(result.agent_access),
                    result.repository_id,
                ),
            )
        self.conn.commit()
        self.core.ledger.record(
            "classification_saved",
            actor="system:classifier",
            tenant=self.core.tenant_id,
            targets=[result.repository_id],
            detail={
                "category": str(result.category),
                "lifecycle": str(result.lifecycle),
                "maturity": str(result.maturity),
                "criticality": str(result.criticality),
                "agent_access": str(result.agent_access),
                "confidence": round(result.confidence, 3),
                "applied_to_repository": apply_to_repository,
            },
        )

    def load(self, repository_id: str) -> ClassificationResult | None:
        """Most recent stored verdict for a repository, or ``None``."""
        row = self.conn.execute(
            "SELECT * FROM classifications WHERE repository_id = ? "
            "ORDER BY created_at DESC, rowid DESC LIMIT 1",
            (repository_id,),
        ).fetchone()
        if row is None:
            return None
        return ClassificationResult(
            repository_id=row["repository_id"],
            category=Category(row["category"]),
            lifecycle=Lifecycle(row["lifecycle"]),
            maturity=Maturity(row["maturity"]),
            criticality=Criticality(row["criticality"]),
            agent_access=AgentAccess(row["agent_access"]),
            confidence=float(row["confidence"]),
            signals=loads(row["signals"], {}) or {},
            rationale=loads(row["rationale"], []) or [],
            taxonomy_profile=row["taxonomy_profile"],
            classified_at=datetime.fromisoformat(row["created_at"]),
        )

    # -- §13.3 detectors --------------------------------------------------

    def detect_archive_candidates(self) -> list[dict]:
        """Repositories that *a human might* want to archive.

        Never a decision — §12 forbids ``archive_without_review`` even for unknown
        origin, and §25 rules out autonomous archiving entirely. This produces a
        review queue with its evidence attached.
        """
        stale_days = int(self.profile.threshold("archive_candidate_days", 540))
        max_stars = int(self.profile.threshold("archive_candidate_max_stars", 3))
        out: list[dict] = []
        for row in self.conn.execute(
            "SELECT * FROM repositories WHERE tenant_id = ? AND missing_since IS NULL ORDER BY full_name",
            (self.core.tenant_id,),
        ).fetchall():
            sig = collect_signals(self.conn, row)
            if sig.is_archived:
                continue  # already archived; nothing to propose
            if sig.days_since_push is None:
                continue  # no push date means no evidence of staleness
            reasons: list[str] = []
            if sig.days_since_push < stale_days:
                continue
            reasons.append(f"no push for {sig.days_since_push} days (threshold {stale_days})")
            if sig.stargazers > max_stars:
                continue  # visible community interest — not an autonomous call
            reasons.append(f"only {sig.stargazers} stars")
            if sig.open_issues:
                reasons.append(f"but {sig.open_issues} open issues remain — review before archiving")
            if sig.release_count:
                reasons.append(f"but {sig.release_count} releases exist — may still be depended on")
            confidence = 0.6 if not (sig.open_issues or sig.release_count) else 0.35
            out.append(
                {
                    "repository_id": sig.repository_id,
                    "full_name": sig.full_name,
                    "days_since_push": sig.days_since_push,
                    "stargazers": sig.stargazers,
                    "open_issues": sig.open_issues,
                    "reasons": reasons,
                    "confidence": confidence,
                    "recommendation": "HUMAN_REVIEW",
                }
            )
        return out

    def detect_superseded_projects(self) -> list[dict]:
        """§13.3 — find repositories a successor has replaced.

        Two independent signals: an explicit README marker ("superseded by",
        "moved to", "deprecated", "replaced by"), and naming overlap between a
        dormant repository and a more recently pushed sibling in the same tenant.
        A marker naming a concrete successor is strong; naming overlap alone is a
        hint that needs a human.
        """
        markers = [str(m).lower() for m in self.profile.section("superseded_markers", [])]
        deprecated = [str(m).lower() for m in self.profile.section("deprecated_markers", [])]
        overlap_threshold = self.profile.threshold("superseded_name_overlap", 0.60)

        rows = self.conn.execute(
            "SELECT * FROM repositories WHERE tenant_id = ? AND missing_since IS NULL ORDER BY full_name",
            (self.core.tenant_id,),
        ).fetchall()
        sigs = [collect_signals(self.conn, row) for row in rows]
        by_name = {s.full_name: s for s in sigs}

        out: list[dict] = []
        for sig in sigs:
            haystack = f"{sig.description}\n{sig.readme_text}".lower()
            evidence: list[str] = []
            successor: str | None = None
            confidence = 0.0

            for marker in markers:
                if marker and marker in haystack:
                    evidence.append(f"README/description contains '{marker}'")
                    successor = successor or _successor_from_text(haystack, marker, by_name)
                    confidence = max(confidence, 0.75 if successor else 0.55)
            if not evidence:
                for marker in deprecated:
                    if marker and marker in haystack:
                        evidence.append(f"deprecation marker '{marker}'")
                        # "deprecated" alone says end-of-life, not *superseded by X*.
                        confidence = max(confidence, 0.45)

            overlap_match = self._naming_overlap(sig, sigs, overlap_threshold)
            if overlap_match is not None:
                other, score = overlap_match
                evidence.append(
                    f"name overlap {score:.2f} with '{other.full_name}', "
                    f"which was pushed more recently"
                )
                successor = successor or other.full_name
                confidence = max(confidence, 0.40 if not markers else min(0.85, confidence + 0.15))

            if not evidence:
                continue
            out.append(
                {
                    "repository_id": sig.repository_id,
                    "full_name": sig.full_name,
                    "successor": successor,
                    "evidence": evidence,
                    "confidence": round(confidence, 2),
                    "recommendation": "HUMAN_REVIEW",
                }
            )
        return out

    def _naming_overlap(
        self,
        sig: RepositorySignals,
        others: Iterable[RepositorySignals],
        threshold: float,
    ) -> tuple[RepositorySignals, float] | None:
        """Best-scoring sibling whose name overlaps and which is *newer*."""
        tokens = sig.name_tokens()
        if not tokens or sig.days_since_push is None:
            return None
        best: tuple[RepositorySignals, float] | None = None
        for other in others:
            if other.full_name == sig.full_name or other.days_since_push is None:
                continue
            if other.days_since_push >= sig.days_since_push:
                continue  # a successor must be more recent than what it replaced
            other_tokens = other.name_tokens()
            if not other_tokens:
                continue
            score = len(tokens & other_tokens) / len(tokens | other_tokens)
            if score >= threshold and (best is None or score > best[1]):
                best = (other, score)
        return best

    # -- classification core ----------------------------------------------

    def _classify_row(self, row: sqlite3.Row) -> ClassificationResult:
        sig = collect_signals(self.conn, row)
        origin = self._origin_profile(sig.repository_id)
        rationale: list[str] = []

        category, cat_conf = self._category(sig, rationale)
        lifecycle, life_conf = self._lifecycle(sig, category, rationale)
        maturity, mat_conf = self._maturity(sig, lifecycle, rationale)
        criticality, crit_conf = self._criticality(sig, lifecycle, rationale)
        access = self._agent_access(sig, category, lifecycle, criticality, origin, rationale)

        confidence = round((cat_conf + life_conf + mat_conf + crit_conf) / 4.0, 3)
        signals = sig.to_dict()
        signals["confidence_by_axis"] = {
            "category": round(cat_conf, 3),
            "lifecycle": round(life_conf, 3),
            "maturity": round(mat_conf, 3),
            "criticality": round(crit_conf, 3),
        }
        signals["origin_type"] = str(origin["origin_type"]) if origin else None

        return ClassificationResult(
            repository_id=sig.repository_id,
            taxonomy_profile=self.core.cfg.governance.taxonomy_profile,
            category=category,
            lifecycle=lifecycle,
            maturity=maturity,
            criticality=criticality,
            agent_access=access,
            confidence=confidence,
            signals=signals,
            rationale=rationale,
        )

    # -- §5.1 category ----------------------------------------------------

    def _category(self, sig: RepositorySignals, rationale: list[str]) -> tuple[Category, float]:
        # Structural facts short-circuit the scoring: a GitHub fork *is* a fork,
        # no amount of prose changes that.
        if sig.is_fork:
            rationale.append(
                f"category=FORK: GitHub reports is_fork=true"
                + (f" (parent {sig.parent_full_name})" if sig.parent_full_name else "")
            )
            return Category.FORK, 0.95
        if sig.is_archived:
            rationale.append("category=ARCHIVE: repository is archived on GitHub")
            return Category.ARCHIVE, 0.90

        scores: dict[Category, float] = defaultdict(float)
        families: dict[Category, set[str]] = defaultdict(set)
        hits: dict[Category, list[str]] = defaultdict(list)

        def add(cat: Category, family: str, note: str) -> None:
            scores[cat] += self.profile.weight(family)
            families[cat].add(family)
            hits[cat].append(note)

        topic_map = self.profile.section("topic_category", {}) or {}
        for topic in sig.topics:
            name = topic_map.get(topic)
            if name and _is_category(name):
                add(Category(name), "topic", f"topic '{topic}'")

        file_map = self.profile.section("file_category", {}) or {}
        for marker, cats in file_map.items():
            if sig.has_file(str(marker)):
                for name in _as_list(cats):
                    if _is_category(name):
                        add(Category(name), "file_marker", f"file '{marker}'")

        lang_map = self.profile.section("language_category", {}) or {}
        if sig.primary_language:
            for name in _as_list(lang_map.get(sig.primary_language, [])):
                if _is_category(name):
                    add(Category(name), "language", f"primary language {sig.primary_language}")

        keyword_map = self.profile.section("category_keywords", {}) or {}
        name_text = sig.name.replace("-", " ").replace("_", " ").lower()
        desc_text = sig.description.lower()
        readme_text = sig.readme_text[:2000].lower()
        for name, keywords in keyword_map.items():
            if not _is_category(name):
                continue
            cat = Category(name)
            for kw in _as_list(keywords):
                needle = str(kw).lower()
                if needle in name_text:
                    add(cat, "name", f"name contains '{needle}'")
                elif needle in desc_text:
                    add(cat, "description", f"description contains '{needle}'")
                elif needle in readme_text:
                    add(cat, "readme", f"README contains '{needle}'")

        if sig.has_pages or (sig.has_homepage and sig.has_file("index.html")):
            add(Category.WEBSITE, "homepage", "repository publishes a site")

        if not scores:
            rationale.append(
                "category=UNKNOWN: no topic, file marker, keyword or language evidence"
            )
            return Category.UNKNOWN, 0.0

        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        winner, top = ranked[0]
        runner_up = ranked[1][1] if len(ranked) > 1 else 0.0
        margin = top - runner_up

        if top < self.profile.threshold("min_category_score", 0.30):
            rationale.append(
                f"category=UNKNOWN: strongest candidate {winner} scored {top:.2f}, "
                f"below the {self.profile.threshold('min_category_score', 0.30):.2f} floor"
            )
            return Category.UNKNOWN, 0.0
        if margin < self.profile.threshold("min_category_margin", 0.10):
            rationale.append(
                f"category=UNKNOWN: {winner} ({top:.2f}) and {ranked[1][0]} "
                f"({runner_up:.2f}) are too close to separate"
            )
            return Category.UNKNOWN, 0.0

        confidence = _confidence(len(families[winner]), margin)
        rationale.append(
            f"category={winner} (score {top:.2f}, margin {margin:.2f}, "
            f"{len(families[winner])} evidence families): " + "; ".join(hits[winner][:4])
        )
        return winner, confidence

    # -- §5.2 lifecycle ---------------------------------------------------

    def _lifecycle(
        self,
        sig: RepositorySignals,
        category: Category,
        rationale: list[str],
    ) -> tuple[Lifecycle, float]:
        if sig.is_archived:
            rationale.append("lifecycle=ARCHIVED: GitHub archived flag is set")
            return Lifecycle.ARCHIVED, 0.98

        haystack = f"{sig.description}\n{sig.readme_text[:3000]}".lower()
        for marker in self.profile.section("superseded_markers", []) or []:
            if str(marker).lower() in haystack:
                rationale.append(f"lifecycle=SUPERSEDED: README/description says '{marker}'")
                return Lifecycle.SUPERSEDED, 0.70

        days = sig.days_since_push
        if days is None:
            rationale.append("lifecycle=UNKNOWN: no pushed_at timestamp in the inventory")
            return Lifecycle.UNKNOWN, 0.0

        active = int(self.profile.threshold("active_days", 90))
        maintenance = int(self.profile.threshold("maintenance_days", 365))
        idea_size = int(self.profile.threshold("idea_max_size_kb", 40))

        if days <= active:
            rationale.append(f"lifecycle=ACTIVE: pushed {days} days ago (<= {active})")
            return Lifecycle.ACTIVE, 0.80 if days <= 30 else 0.65
        if days <= maintenance:
            rationale.append(
                f"lifecycle=MAINTENANCE: last push {days} days ago, inside the "
                f"{maintenance}-day maintenance window"
            )
            return Lifecycle.MAINTENANCE, 0.55

        # Past a year of silence. Deliberately NOT ARCHIVED — archiving is a human
        # act (§12 unknown-origin-policy denies archive_without_review, §25).
        if sig.release_count or sig.stargazers >= 5 or category in (
            Category.DOCUMENTATION,
            Category.DATASET,
            Category.REFERENCE,
        ):
            rationale.append(
                f"lifecycle=REFERENCE: silent for {days} days but has releases/stars or is "
                f"reference-shaped material; not archived automatically"
            )
            return Lifecycle.REFERENCE, 0.50
        if sig.size_kb <= idea_size and not sig.has_readme_snapshot:
            rationale.append(
                f"lifecycle=IDEA: silent for {days} days, only {sig.size_kb} KB and no README"
            )
            return Lifecycle.IDEA, 0.45
        rationale.append(
            f"lifecycle=EXPERIMENTAL: silent for {days} days with no releases and few stars; "
            f"never inferred as ARCHIVED without a human decision"
        )
        return Lifecycle.EXPERIMENTAL, 0.50

    # -- §5.3 maturity ----------------------------------------------------

    def _maturity(
        self,
        sig: RepositorySignals,
        lifecycle: Lifecycle,
        rationale: list[str],
    ) -> tuple[Maturity, float]:
        if lifecycle == Lifecycle.ARCHIVED:
            rationale.append("maturity=LEGACY: repository is archived")
            return Maturity.LEGACY, 0.85

        keywords = self.profile.section("maturity_keywords", {}) or {}
        haystack = f"{sig.name} {sig.description} {' '.join(sig.topics)} {sig.readme_text[:1500]}".lower()
        prose_hit: tuple[Maturity, str] | None = None
        for name, words in keywords.items():
            if not _is_maturity(name):
                continue
            for word in _as_list(words):
                if str(word).lower() in haystack:
                    prose_hit = (Maturity(name), str(word))
                    break
            if prose_hit:
                break

        version = sig.version_hint()
        if version is not None:
            major, minor, _patch = version
            if major >= 1:
                deployed = bool(sig.has_pages or sig.has_homepage)
                verdict = Maturity.PRODUCTION if deployed else Maturity.STABLE
                rationale.append(
                    f"maturity={verdict}: version {major}.{minor} >= 1.0"
                    + (" and the project advertises a live homepage" if deployed else "")
                )
                return verdict, 0.70 if sig.latest_release_tag else 0.55
            if minor >= 5:
                rationale.append(f"maturity=BETA: version 0.{minor} is past the 0.5 mark")
                return Maturity.BETA, 0.55
            rationale.append(f"maturity=ALPHA: version 0.{minor} is early")
            return Maturity.ALPHA, 0.50

        if prose_hit is not None:
            verdict, word = prose_hit
            rationale.append(f"maturity={verdict}: text mentions '{word}' (prose evidence only)")
            return verdict, 0.45

        rationale.append(
            "maturity=UNKNOWN: no release tag, no version string and no maturity wording"
        )
        return Maturity.UNKNOWN, 0.0

    # -- §5.4 criticality -------------------------------------------------

    def _criticality(
        self,
        sig: RepositorySignals,
        lifecycle: Lifecycle,
        rationale: list[str],
    ) -> tuple[Criticality, float]:
        hints = self.profile.section("criticality_hints", {}) or {}
        # Start from UNKNOWN, not LOW: "we found no signal" is a different claim from
        # "this is genuinely low stakes", and the risk engine treats them differently.
        verdict = Criticality.UNKNOWN
        notes: list[str] = []
        confidence = 0.20

        def raise_to(level: Criticality, note: str, conf: float) -> None:
            nonlocal verdict, confidence
            if _CRITICALITY_RANK[level] > _CRITICALITY_RANK[verdict]:
                verdict = level
                confidence = conf
            notes.append(note)

        name_lower = sig.full_name.lower()
        for entry in _as_list(hints.get("critical_repositories", [])):
            if str(entry).lower() in name_lower:
                raise_to(Criticality.CRITICAL, f"listed as a critical repository ('{entry}')", 0.90)
        for entry in _as_list(hints.get("high_repositories", [])):
            if str(entry).lower() in name_lower:
                raise_to(Criticality.HIGH, f"listed as a high-criticality repository ('{entry}')", 0.85)
        for kw in _as_list(hints.get("high_name_keywords", [])):
            if str(kw).lower() in sig.name.lower():
                raise_to(Criticality.HIGH, f"name contains flagship keyword '{kw}'", 0.60)
        for topic in sig.topics:
            if topic in {str(t).lower() for t in _as_list(hints.get("critical_topics", []))}:
                raise_to(Criticality.CRITICAL, f"topic '{topic}' marks it critical", 0.75)
            if topic in {str(t).lower() for t in _as_list(hints.get("high_topics", []))}:
                raise_to(Criticality.HIGH, f"topic '{topic}' marks it high", 0.65)

        stars_high = int(hints.get("high_min_stars", 25) or 25)
        stars_critical = int(hints.get("critical_min_stars", 200) or 200)
        if sig.stargazers >= stars_critical:
            raise_to(Criticality.CRITICAL, f"{sig.stargazers} stars — widely depended on", 0.80)
        elif sig.stargazers >= stars_high:
            raise_to(Criticality.HIGH, f"{sig.stargazers} stars", 0.70)

        if hints.get("medium_when_public_and_active", True):
            if sig.is_public and sig.has_homepage and lifecycle == Lifecycle.ACTIVE:
                raise_to(
                    Criticality.MEDIUM,
                    "public, actively pushed and advertises a homepage — breakage is visible",
                    0.55,
                )

        if lifecycle in (Lifecycle.ARCHIVED, Lifecycle.SUPERSEDED) and verdict != Criticality.LOW:
            # A retired asset cannot be load-bearing, whatever its name suggests. This
            # is a genuine observation, so it resolves UNKNOWN to LOW rather than
            # leaving it ungraded.
            notes.append(f"resolved to LOW from {verdict} because lifecycle is {lifecycle}")
            verdict, confidence = Criticality.LOW, 0.60

        if notes:
            rationale.append(f"criticality={verdict}: " + "; ".join(notes[:4]))
        else:
            rationale.append(
                "criticality=UNKNOWN: no criticality signal found; not graded, which the "
                "risk engine treats as more dangerous than a graded LOW, not less"
            )
        return verdict, confidence

    # -- §5.5 agent access ------------------------------------------------

    def _agent_access(
        self,
        sig: RepositorySignals,
        category: Category,
        lifecycle: Lifecycle,
        criticality: Criticality,
        origin: Mapping[str, Any] | None,
        rationale: list[str],
    ) -> AgentAccess:
        cfg = self.profile.section("agent_access", {}) or {}

        proposed = _access(cfg.get("max_proposed"), AgentAccess.PR_ONLY)
        why = [f"classification proposes at most {proposed}"]

        if lifecycle in {
            _lifecycle_name(x) for x in _as_list(cfg.get("frozen_lifecycles", []))
        }:
            proposed = _min_access(proposed, _access(cfg.get("frozen_cap"), AgentAccess.READ_ONLY))
            why.append(f"lifecycle {lifecycle} freezes the repository")
        if category in {_category_name(x) for x in _as_list(cfg.get("foreign_categories", []))}:
            proposed = _min_access(proposed, _access(cfg.get("foreign_cap"), AgentAccess.READ_ONLY))
            why.append(f"category {category} is somebody else's code")
        if lifecycle == Lifecycle.UNKNOWN:
            proposed = _min_access(
                proposed, _access(cfg.get("unknown_lifecycle_cap"), AgentAccess.READ_ONLY)
            )
            why.append("lifecycle is UNKNOWN — nothing is understood about this repository yet")
        if criticality == Criticality.CRITICAL:
            proposed = _min_access(proposed, _access(cfg.get("critical_cap"), AgentAccess.PR_ONLY))
            why.append("criticality CRITICAL forbids autonomous direct writes")

        # Origin cap (§12). This is the half of the decision the classifier does
        # not get to argue with.
        if origin is None:
            cap = _access(cfg.get("no_origin_profile_cap"), AgentAccess.READ_ONLY)
            why.append("no origin profile exists yet — 'not analysed' is not 'safe'")
        else:
            origin_type = str(origin.get("origin_type") or OriginType.UNKNOWN)
            caps = cfg.get("origin_caps", {}) or {}
            cap = _access(caps.get(origin_type), AgentAccess.READ_ONLY)
            why.append(f"origin {origin_type} caps access at {cap}")
            confidence = float(origin.get("origin_confidence") or 0.0)
            floor = float(cfg.get("low_confidence_threshold", 0.50) or 0.50)
            if confidence < floor:
                cap = _min_access(cap, _access(cfg.get("low_confidence_cap"), AgentAccess.READ_ONLY))
                why.append(f"origin confidence {confidence:.2f} < {floor:.2f}")

        effective = _min_access(proposed, cap)
        rationale.append(f"agent_access={effective}: " + "; ".join(why))
        return effective

    # -- helpers ----------------------------------------------------------

    def _origin_profile(self, repository_id: str) -> Mapping[str, Any] | None:
        """Read Phase 2's verdict defensively — the table may not be populated yet."""
        if not repository_id:
            return None
        try:
            row = self.conn.execute(
                "SELECT origin_type, origin_confidence, license_status, review_status "
                "FROM origin_profiles WHERE repository_id = ? "
                "ORDER BY updated_at DESC LIMIT 1",
                (repository_id,),
            ).fetchone()
        except sqlite3.Error:
            return None
        if row is None:
            return None
        return {k: row[k] for k in row.keys()}


# --------------------------------------------------------------------------
# module-level helpers
# --------------------------------------------------------------------------

#: ``owner/name`` or a GitHub URL, as written in a superseded notice.
_REPO_REF = re.compile(r"(?:github\.com/)?([A-Za-z0-9._-]+/[A-Za-z0-9._-]+)")


def _successor_from_text(
    haystack: str,
    marker: str,
    known: Mapping[str, RepositorySignals],
) -> str | None:
    """Pull the successor repository out of the sentence containing ``marker``.

    Only a name that exists in the same tenant is returned. A README can point
    anywhere; a governance verdict should not invent a repository that the
    inventory has never seen.
    """
    index = haystack.find(marker)
    if index < 0:
        return None
    window = haystack[index : index + 240]
    lowered = {name.lower(): name for name in known}
    for match in _REPO_REF.finditer(window):
        candidate = match.group(1).strip(".,;:)")
        if candidate.lower() in lowered:
            return lowered[candidate.lower()]
        # Bare "name" references: resolve against the tail of a known full name.
        tail = candidate.split("/")[-1].lower()
        for lower_name, original in lowered.items():
            if lower_name.split("/")[-1] == tail and tail:
                return original
    return None


def _confidence(family_count: int, margin: float) -> float:
    """Honest confidence: independent agreement counts, repetition does not.

    One evidence family with no separation lands around 0.45 — a keyword match is
    a hint, not a conclusion. Reaching 0.9 requires three families and a clear
    margin over the runner-up.
    """
    base = 0.25 + 0.20 * min(family_count, 3)
    separation = 0.20 * min(margin / 0.50, 1.0)
    return round(min(0.95, base + separation), 3)


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def _is_category(name: Any) -> bool:
    return isinstance(name, str) and name in Category.__members__


def _is_maturity(name: Any) -> bool:
    return isinstance(name, str) and name in Maturity.__members__


def _category_name(value: Any) -> Category | None:
    return Category(value) if _is_category(value) else None


def _lifecycle_name(value: Any) -> Lifecycle | None:
    return Lifecycle(value) if isinstance(value, str) and value in Lifecycle.__members__ else None


def _access(value: Any, default: AgentAccess) -> AgentAccess:
    if isinstance(value, AgentAccess):
        return value
    if isinstance(value, str) and value in AgentAccess.__members__:
        return AgentAccess(value)
    return default


def _min_access(a: AgentAccess, b: AgentAccess) -> AgentAccess:
    return a if AGENT_ACCESS_RANK[a] <= AGENT_ACCESS_RANK[b] else b
