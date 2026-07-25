"""Origin & Provenance Engine (§6-§10, §21-§23) — Phase 2 of the MVP (§24).

Answers §6.1: where did this repository come from, does it have an upstream, how
much of that upstream survives, what did we actually contribute, and what may be
said about it in public.

The public surface is deliberately small:

* :class:`ProvenanceEngine` — the orchestrator other modules call.
* :mod:`.rules` — the §7.3 YAML rule language and the §7.2 precedence ladder.
* :mod:`.fingerprint` — §7.1 similarity primitives, pure Python.
* :mod:`.components` — §9 dependency / upstream / vendored separation.
* :mod:`.contribution` — §8 contribution *ranges*, never a single score.
* :mod:`.gitlocal` — §21 isolated, non-executing git access.
"""

from __future__ import annotations

from .components import ComponentSummary, classify_paths
from .contribution import estimate_contribution
from .engine import ORIGINALITY_CLAIM_THRESHOLD, ProvenanceEngine, ProvenanceError, render_report
from .fingerprint import (
    blob_similarity,
    commit_similarity,
    jaccard,
    minhash_signature,
    normalized_text_hash,
    overlap_coefficient,
    token_similarity,
    winnow_fingerprints,
)
from .rules import OriginRule, RuleEvaluation, evaluate_rules, load_rules

__all__ = [
    "ORIGINALITY_CLAIM_THRESHOLD",
    "ComponentSummary",
    "OriginRule",
    "ProvenanceEngine",
    "ProvenanceError",
    "RuleEvaluation",
    "blob_similarity",
    "classify_paths",
    "commit_similarity",
    "estimate_contribution",
    "evaluate_rules",
    "jaccard",
    "load_rules",
    "minhash_signature",
    "normalized_text_hash",
    "overlap_coefficient",
    "render_report",
    "token_similarity",
    "winnow_fingerprints",
]
