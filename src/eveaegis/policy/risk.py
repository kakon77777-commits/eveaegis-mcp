"""§15 risk assessment.

Risk is a *score of the blast radius*, not a probability. It rises with how much
authority the tool needs, how many repositories are in scope, how load-bearing and
how public those repositories are, how uncertain their provenance is, whether a
licence question is open, and whether the action can be undone at all.

The score exists to drive axiom 5 — ``Risk↑ ⇒ scope↓ ∧ lifetime↓ ∧ approval↑`` —
so every contribution is spelled out in the returned reason list. A risk level
without reasons would be an unfalsifiable number, and §29 requires evidence behind
every verdict.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping, Sequence

from ..models import ActionRequest, OriginProfile, RepositoryAsset
from ..taxonomy import (
    RISK_RANK,
    CRITICALITY_RISK_RANK,
    Criticality,
    LicenseStatus,
    OriginType,
    RiskLevel,
    Visibility,
)
from .rules import PolicySet

#: Origin types where somebody else's work is materially present. Writing to these
#: is riskier than writing to something we wrote (§12 fork-policy / mirror-policy).
FORK_FAMILY: frozenset[OriginType] = frozenset(
    {
        OriginType.GITHUB_FORK,
        OriginType.DETACHED_FORK,
        OriginType.DERIVATIVE_PROJECT,
        OriginType.UPSTREAM_IMPORT,
        OriginType.MIRROR,
        OriginType.VENDOR_SNAPSHOT,
        OriginType.MULTI_SOURCE_COMPOSITE,
    }
)

#: §10 verdicts that mean a human has not yet cleared the licence question.
LICENSE_REVIEW_STATES: frozenset[LicenseStatus] = frozenset(
    {
        LicenseStatus.REVIEW_REQUIRED,
        LicenseStatus.INCOMPATIBLE,
        LicenseStatus.COPYLEFT_TRIGGERED,
    }
)


def assess_risk(
    request: ActionRequest,
    repos: Mapping[str, RepositoryAsset] | Sequence[RepositoryAsset],
    origin_profiles: Mapping[str, OriginProfile] | Sequence[OriginProfile],
    cfg: PolicySet,
) -> tuple[RiskLevel, list[str]]:
    """Score one request.

    ``repos`` is keyed by ``owner/name`` (the shape §14 targets use);
    ``origin_profiles`` is keyed by repository id (the shape §20.1 stores). Both
    accept a plain sequence too and are indexed here.

    Both may be partial: a target with no repository row is *more* risky, not less,
    because the engine is being asked to act on something it has never inventoried.
    """
    repo_map = _index(repos, lambda r: r.full_name)
    origin_map = _index(origin_profiles, lambda o: o.repository_id)

    level = cfg.level_for(request.tool)
    score = 0.0
    reasons: list[str] = []

    def add(points: float, reason: str) -> None:
        nonlocal score
        if points <= 0:
            return
        score += points
        reasons.append(f"+{points:g} {reason}")

    add(cfg.risk_weight("level", str(level)), f"tool '{request.tool}' requires {level}")

    # -- breadth ----------------------------------------------------------
    target_count = len(request.targets)
    band_score = 0.0
    for band in cfg.risk.get("target_bands", []) or []:
        if target_count >= int(band.get("min_targets", 0)):
            band_score = max(band_score, float(band.get("score", 0)))
    add(band_score, f"{target_count} targets in one request")

    # -- irreversibility --------------------------------------------------
    if request.tool in cfg.irreversible_tools:
        add(
            cfg.risk_weight("irreversible_action", default=4.0),
            f"'{request.tool}' cannot be undone by re-running the opposite tool",
        )
    if not request.dry_run:
        add(cfg.risk_weight("not_dry_run", default=1.0), "dry_run is disabled")

    # -- per-target attributes --------------------------------------------
    worst_criticality = Criticality.LOW
    public_seen = False
    unknown_origin_seen = False
    fork_family_seen = False
    missing_origin_seen = False
    license_hold_seen = False
    unknown_target_seen = False

    for target in request.targets:
        repo = repo_map.get(target)
        if repo is None:
            unknown_target_seen = True
            continue
        if _crit_rank(repo.criticality) > _crit_rank(worst_criticality):
            worst_criticality = repo.criticality
        if repo.visibility == Visibility.PUBLIC:
            public_seen = True
        profile = origin_map.get(repo.id)
        if profile is None:
            missing_origin_seen = True
        else:
            if profile.origin_type == OriginType.UNKNOWN:
                unknown_origin_seen = True
            elif profile.origin_type in FORK_FAMILY:
                fork_family_seen = True
            if profile.license_status in LICENSE_REVIEW_STATES:
                license_hold_seen = True

    if worst_criticality != Criticality.LOW:
        add(
            cfg.risk_weight("criticality", str(worst_criticality)),
            f"most critical target is {worst_criticality}",
        )
    if public_seen:
        add(cfg.risk_weight("public_repository", default=1.0), "at least one target is public")
    if unknown_origin_seen:
        add(cfg.risk_weight("unknown_origin", default=3.0), "a target has UNKNOWN origin")
    if fork_family_seen:
        add(
            cfg.risk_weight("fork_family_origin", default=2.0),
            "a target is a fork/mirror/derivative — upstream work is present",
        )
    if missing_origin_seen:
        add(
            cfg.risk_weight("no_origin_profile", default=2.0),
            "a target has no origin profile — provenance has not been analysed",
        )
    if license_hold_seen:
        add(
            cfg.risk_weight("license_review_required", default=2.0),
            "a target has an unresolved licence question",
        )
    if unknown_target_seen:
        add(
            cfg.risk_weight("unknown_target", default=2.0),
            "a target is not in the inventory at all",
        )

    level_out = _level_for_score(score, cfg)
    if not reasons:
        reasons.append("no risk factors: read-only tool, no targets at stake")
    reasons.insert(0, f"risk score {score:g} => {level_out}")
    return level_out, reasons


def _level_for_score(score: float, cfg: PolicySet) -> RiskLevel:
    thresholds = cfg.risk.get("thresholds", {}) or {}
    critical = float(thresholds.get("CRITICAL", 10))
    high = float(thresholds.get("HIGH", 6))
    medium = float(thresholds.get("MEDIUM", 3))
    if score >= critical:
        return RiskLevel.CRITICAL
    if score >= high:
        return RiskLevel.HIGH
    if score >= medium:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def escalate(current: RiskLevel, floor: RiskLevel) -> RiskLevel:
    """Raise ``current`` to at least ``floor``. Risk only ever moves up."""
    return current if RISK_RANK[current] >= RISK_RANK[floor] else floor


def _crit_rank(value: Criticality) -> int:
    """Risk ordering, where UNKNOWN outranks MEDIUM.

    Deliberately *not* the classifier's evidence ordering: an ungraded repository
    is unexamined, not safe. Ranking UNKNOWN at the bottom here would make "nobody
    ever classified it" the cheapest thing in the portfolio to write to.
    """
    return CRITICALITY_RISK_RANK[value]


def _index(items: Any, key: Any) -> Mapping[str, Any]:
    if isinstance(items, Mapping):
        return items
    if isinstance(items, Iterable):
        return {key(item): item for item in items}
    return {}


__all__ = ["FORK_FAMILY", "LICENSE_REVIEW_STATES", "assess_risk", "escalate"]
