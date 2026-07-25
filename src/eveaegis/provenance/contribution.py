"""Contribution estimation (§8 原創貢獻模型).

§8.1 is the rule this module exists to obey: *a single score is never the answer*.
Everything here produces an interval plus a confidence label, and the public surface
gets a :class:`~eveaegis.taxonomy.ContributionBand`, never a bare percentage.

Where the interval comes from
-----------------------------
Two independent denominators are computed over the *effective* content only
(§9 exclusions already applied by :mod:`.components`): file count and byte count.
They disagree — a repository with one 4 000-line generated-looking data file and
forty small modules gets very different answers — and that disagreement is real
measurement uncertainty, so it becomes the width of the interval rather than being
averaged into a false point estimate. A method-dependent margin widens it further:
exact blob matching is tight, shallow metadata-only inference is deliberately wide.

Where it refuses to answer
--------------------------
If no upstream retention could be measured for a repository that *has* an upstream,
the range stays ``None`` and the band stays ``UNKNOWN``. An unmeasured fork is not a
100%-original project.
"""

from __future__ import annotations

from typing import Mapping

from ..models import ContributionEstimate
from ..taxonomy import (
    ComponentClass,
    Confidence,
    ContributionBand,
    ContributionDimension,
    OriginType,
    band_for,
    confidence_for,
)
from .components import ComponentSummary

#: §8.4 default weights. Only used to summarise dimensions for humans; §8.4 is
#: explicit that a single LOC ratio must not stand in for them, so they never
#: replace the measured range.
DEFAULT_DIMENSION_WEIGHTS: dict[str, float] = {
    ContributionDimension.CODE: 0.25,
    ContributionDimension.ARCHITECTURE: 0.20,
    ContributionDimension.TESTS: 0.10,
    ContributionDimension.DOCUMENTATION: 0.10,
    ContributionDimension.UI_UX: 0.10,
    ContributionDimension.DATA_MODEL: 0.10,
    ContributionDimension.DEPLOYMENT: 0.05,
    ContributionDimension.RESEARCH: 0.10,
}

#: Half-width added to the interval, by how the retention figure was obtained.
MEASUREMENT_MARGIN: dict[str, float] = {
    "blob_exact": 0.05,      # byte-identical blob sets from a real clone
    "commit_graph": 0.10,    # commit overlap only; content may have diverged
    "token": 0.15,           # fingerprint similarity, no history
    "shallow": 0.20,         # metadata and tree shape only
}

#: A shallow scan cannot rule out uncredited copying, so an "original" repository is
#: never credited with a hard 100%. The floor is what the engine is willing to
#: assert with tree-level evidence alone; the ceiling stays at 1.0 because nothing
#: observed contradicts full authorship either.
SHALLOW_ORIGINAL_FLOOR = 0.80
DEEP_ORIGINAL_FLOOR = 0.90

#: Origin types whose local contribution is bounded by a known external base.
_UPSTREAM_BEARING: frozenset[OriginType] = frozenset(
    {
        OriginType.GITHUB_FORK,
        OriginType.DETACHED_FORK,
        OriginType.MIRROR,
        OriginType.UPSTREAM_IMPORT,
        OriginType.DERIVATIVE_PROJECT,
        OriginType.MULTI_SOURCE_COMPOSITE,
        OriginType.VENDOR_SNAPSHOT,
        OriginType.TEMPLATE_DERIVED,
        OriginType.GENERATED_PROJECT,
    }
)

_SELF_CONTAINED: frozenset[OriginType] = frozenset(
    {
        OriginType.ORIGINAL,
        OriginType.ORIGINAL_WITH_DEPENDENCIES,
        OriginType.PLUGIN_OR_EXTENSION,
    }
)


def _clamp(value: float, low: float = 0.0, high: float = 1.0) -> float:
    return max(low, min(high, value))


def _interval(centre: float, margin: float) -> tuple[float, float]:
    return _clamp(centre - margin), _clamp(centre + margin)


def _certainty(
    origin_confidence: float,
    measurement: str,
    effective_files: int,
) -> float:
    """How much to trust the interval itself (§8.2 C_origin folded with sample size).

    A confident origin verdict measured over eleven files is still a weak estimate;
    both factors have to be present.
    """
    method_factor = {"blob_exact": 1.0, "commit_graph": 0.85, "token": 0.7, "shallow": 0.6}.get(
        measurement, 0.5
    )
    if effective_files >= 200:
        sample_factor = 1.0
    elif effective_files >= 50:
        sample_factor = 0.9
    elif effective_files >= 10:
        sample_factor = 0.75
    elif effective_files > 0:
        sample_factor = 0.6
    else:
        sample_factor = 0.0
    return _clamp(origin_confidence * method_factor * sample_factor)


def _per_dimension(
    summary: ComponentSummary,
    local_midpoint: float | None,
    weights: Mapping[str, float] | None,
) -> dict[str, float]:
    """Local contribution per §8.3 dimension.

    Without a per-file upstream map the only honest statement is "this dimension
    exists and carries the repository-wide local share", so each present dimension
    reports the aggregate midpoint scaled by nothing — the *distribution* of work is
    reported separately as ``share`` so a reader cannot mistake presence for effort.
    """
    if local_midpoint is None or not summary.files_by_dimension:
        return {}
    weight_map = dict(weights or DEFAULT_DIMENSION_WEIGHTS)
    total = sum(summary.files_by_dimension.values()) or 1
    result: dict[str, float] = {}
    for dimension, count in sorted(summary.files_by_dimension.items(), key=lambda kv: -kv[1]):
        key = str(dimension)
        result[key] = round(local_midpoint, 4)
        result[f"{key}.share"] = round(count / total, 4)
        if key in weight_map:
            result[f"{key}.weight"] = weight_map[key]
    return result


def estimate_contribution(
    summary: ComponentSummary,
    *,
    origin_type: OriginType = OriginType.UNKNOWN,
    origin_confidence: float = 0.0,
    upstream_retained: float | None = None,
    upstream_retained_bytes: float | None = None,
    upstream_modified_ratio: float | None = None,
    measurement: str = "shallow",
    weights: Mapping[str, float] | None = None,
) -> ContributionEstimate:
    """Produce the §8.2 metrics as intervals.

    ``upstream_retained`` is the fraction of *effective* files that still match the
    upstream byte-for-byte (or by whatever method ``measurement`` names);
    ``upstream_retained_bytes`` is the same fraction computed over bytes. Passing
    both is what gives the interval its width. ``None`` for both means retention was
    not measured, which is reported as unknown rather than guessed.
    """
    estimate = ContributionEstimate()
    margin = MEASUREMENT_MARGIN.get(measurement, 0.20)
    certainty = _certainty(origin_confidence, measurement, summary.effective_files)

    if summary.effective_files == 0:
        # Nothing survived the §9.2 exclusions: a pure vendor dump or an empty repo.
        # Reporting "0% local" would be a conclusion; reporting nothing is the fact.
        estimate.band = ContributionBand.UNKNOWN
        estimate.confidence = Confidence.LOW
        estimate.per_dimension = {
            "note": 0.0,
            "effective_content_files": 0.0,
            "total_files": float(summary.total_files),
        }
        return estimate

    local_midpoint: float | None = None

    if upstream_retained is not None or upstream_retained_bytes is not None:
        observations = [v for v in (upstream_retained, upstream_retained_bytes) if v is not None]
        low_observation, high_observation = min(observations), max(observations)
        retained_min = _clamp(low_observation - margin)
        retained_max = _clamp(high_observation + margin)
        estimate.upstream_retained_min = round(retained_min, 4)
        estimate.upstream_retained_max = round(retained_max, 4)
        # Local contribution is the complement of retention, so the *widest*
        # retention bound produces the *narrowest* local bound and vice versa.
        estimate.local_contribution_min = round(_clamp(1.0 - retained_max), 4)
        estimate.local_contribution_max = round(_clamp(1.0 - retained_min), 4)
        local_midpoint = (estimate.local_contribution_min + estimate.local_contribution_max) / 2

    elif origin_type in _SELF_CONTAINED:
        # No upstream was found, and the origin rules positively concluded the
        # repository stands on its own. The floor encodes what tree-level evidence
        # can actually support (see SHALLOW_ORIGINAL_FLOOR).
        floor = DEEP_ORIGINAL_FLOOR if measurement != "shallow" else SHALLOW_ORIGINAL_FLOOR
        estimate.upstream_retained_min = 0.0
        estimate.upstream_retained_max = round(1.0 - floor, 4)
        estimate.local_contribution_min = floor
        estimate.local_contribution_max = 1.0
        local_midpoint = (floor + 1.0) / 2

    elif origin_type in _UPSTREAM_BEARING:
        # An upstream exists but nothing measured how much of it survives. §8.1
        # forbids inventing a number here; the interval stays open.
        estimate.per_dimension = {"note.unmeasured_upstream": 1.0}

    if local_midpoint is not None:
        estimate.band = band_for(local_midpoint)
    else:
        estimate.band = ContributionBand.UNKNOWN

    if upstream_modified_ratio is not None:
        # §8.2 轉化深度: of the upstream content still present, how much was reworked.
        estimate.transformation_score = round(_clamp(upstream_modified_ratio), 4)
    elif origin_type in _SELF_CONTAINED and local_midpoint is not None:
        estimate.transformation_score = None  # nothing to transform without an upstream

    estimate.confidence = confidence_for(certainty)
    dimensions = _per_dimension(summary, local_midpoint, weights)
    estimate.per_dimension = {**estimate.per_dimension, **dimensions}

    _assert_invariants(estimate)
    return estimate


def _assert_invariants(estimate: ContributionEstimate) -> None:
    """Fail loudly rather than publish an impossible range."""
    pairs = (
        (estimate.upstream_retained_min, estimate.upstream_retained_max, "upstream_retained"),
        (estimate.local_contribution_min, estimate.local_contribution_max, "local_contribution"),
    )
    for low, high, name in pairs:
        if low is None and high is None:
            continue
        if low is None or high is None:
            raise ValueError(f"{name} interval is half-open; both bounds must be set or neither")
        if not 0.0 <= low <= high <= 1.0:
            raise ValueError(f"{name} interval [{low}, {high}] is not a valid subinterval of [0,1]")
    if estimate.transformation_score is not None and not 0.0 <= estimate.transformation_score <= 1.0:
        raise ValueError(f"transformation_score {estimate.transformation_score} outside [0,1]")


def describe(estimate: ContributionEstimate) -> str:
    """The §8.5 display form. Three lines, band first, never a bare percentage."""
    if estimate.local_contribution_min is None or estimate.local_contribution_max is None:
        return (
            f"Original contribution: {estimate.band.value.title().replace('_', ' ')}\n"
            f"Estimated range: not measured\n"
            f"Confidence: {estimate.confidence.value.title()}"
        )
    low = int(round(estimate.local_contribution_min * 100))
    high = int(round(estimate.local_contribution_max * 100))
    return (
        f"Original contribution: {estimate.band.value.title().replace('_', ' ')}\n"
        f"Estimated range: {low}-{high}%\n"
        f"Confidence: {estimate.confidence.value.title()}"
    )


def upstream_retention_from_components(summary: ComponentSummary) -> tuple[float, float] | None:
    """Retention implied by per-file classes, when a deep pass has assigned them.

    Returns ``(by_files, by_bytes)`` over effective content, or ``None`` when no file
    carries an UPSTREAM_* class — i.e. when nothing was actually compared.
    """
    upstream_classes = {ComponentClass.UPSTREAM_MODIFIED, ComponentClass.UPSTREAM_UNMODIFIED}
    upstream_files = sum(summary.files_by_class.get(c, 0) for c in upstream_classes)
    upstream_bytes = sum(summary.bytes_by_class.get(c, 0) for c in upstream_classes)
    if upstream_files == 0:
        return None
    by_files = upstream_files / summary.effective_files if summary.effective_files else 0.0
    by_bytes = upstream_bytes / summary.effective_bytes if summary.effective_bytes else by_files
    return _clamp(by_files), _clamp(by_bytes)
