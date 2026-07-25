"""Declarative origin rules (§7.2 precedence, §7.3 rule format).

The verdict logic lives in ``config/policies/origin_rules.yaml``, not here. That is
a governance requirement, not a style preference: a portfolio owner must be able to
read, diff and review the rule that labelled their repository a fork without reading
Python, and a rule change must show up in version control as a policy change.

This module contributes exactly two things Python is better at than YAML:

1. A tiny, total condition language over a **flat fact dictionary** — no nesting, no
   expressions, no callables. Facts are produced once by the engine (§22 steps 1-11)
   and every rule sees the same dictionary.
2. Enforcement of the §7.2 precedence ladder::

       official GitHub fork metadata
       > shared commit ancestry
       > exact blob history
       > explicit attribution
       > normalized token similarity
       > AST similarity
       > semantic similarity

   A rule declares which rung it stands on via ``signal_tier``. A weaker rung can
   never override a stronger one; it may only *add confidence* when it agrees, and
   is recorded as a dissent when it disagrees.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

import yaml

from ..taxonomy import OriginType

#: §7.2, strongest first. ``structural`` and ``fallback`` sit below every evidential
#: rung: they are shape heuristics (scaffolds, vendor dumps) and the catch-all.
SIGNAL_TIERS: tuple[str, ...] = (
    "fork_metadata",
    "commit_ancestry",
    "blob_history",
    "attribution",
    "token_similarity",
    "ast_similarity",
    "semantic_similarity",
    "structural",
    "fallback",
)

TIER_RANK: dict[str, int] = {tier: index for index, tier in enumerate(SIGNAL_TIERS)}

#: How much an agreeing weaker rule may add. Kept small on purpose — corroboration
#: is not independent evidence, and stacking it is how systems talk themselves into
#: false confidence.
CORROBORATION_BONUS = 0.02
MAX_CORROBORATION = 0.06

_OPERATOR_RE = re.compile(r"^\s*(>=|<=|!=|==|>|<)\s*(.+?)\s*$")
_IN_RE = re.compile(r"^\s*in:\s*(.+?)\s*$")

DEFAULT_RULES_FILENAME = "origin_rules.yaml"


class RuleError(ValueError):
    """Malformed rule file. Raised at load time so a bad policy never runs."""


# --------------------------------------------------------------------------
# rule model
# --------------------------------------------------------------------------

@dataclass(slots=True, frozen=True)
class OriginRule:
    """One §7.3 rule: a set of conditions and the verdict they justify."""

    id: str
    when: Mapping[str, Any]
    origin_type: OriginType
    confidence: float
    signal_tier: str = "fallback"
    description: str = ""
    requires_review: bool = False
    public_label: str | None = None

    @property
    def tier_rank(self) -> int:
        return TIER_RANK[self.signal_tier]

    def matches(self, facts: Mapping[str, Any]) -> bool:
        return all(_condition_holds(facts, key, expected) for key, expected in self.when.items())

    def unmet(self, facts: Mapping[str, Any]) -> list[str]:
        """Conditions that failed — the material for a "why not" explanation."""
        return [
            f"{key} {_render(expected)} (actual: {facts.get(key, '<absent>')!r})"
            for key, expected in self.when.items()
            if not _condition_holds(facts, key, expected)
        ]


@dataclass(slots=True)
class RuleEvaluation:
    """Outcome of evaluating the whole rule set against one fact dictionary."""

    matched: OriginRule | None = None
    origin_type: OriginType = OriginType.UNKNOWN
    confidence: float = 0.0
    corroborating: list[OriginRule] = field(default_factory=list)
    dissenting: list[OriginRule] = field(default_factory=list)
    all_matches: list[OriginRule] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def matched_rule_id(self) -> str | None:
        return self.matched.id if self.matched else None

    @property
    def requires_review(self) -> bool:
        return bool(self.matched and self.matched.requires_review)


# --------------------------------------------------------------------------
# condition language
# --------------------------------------------------------------------------

def _coerce(raw: str) -> Any:
    lowered = raw.strip().strip("'\"")
    if lowered.lower() in {"true", "false"}:
        return lowered.lower() == "true"
    if lowered.lower() in {"null", "none", "~"}:
        return None
    try:
        return int(lowered)
    except ValueError:
        pass
    try:
        return float(lowered)
    except ValueError:
        return lowered


def _numeric(value: Any) -> float | None:
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _condition_holds(facts: Mapping[str, Any], key: str, expected: Any) -> bool:
    """Evaluate one condition. A missing fact always fails.

    "Absent" is never quietly treated as zero or false: §29 requires that a verdict
    without evidence stays UNKNOWN, and a rule firing on missing data is precisely
    how that requirement gets violated. Rules that genuinely want "absent" must say
    so with the explicit ``==null`` form.
    """
    present = key in facts
    actual = facts.get(key)

    # list ⇒ membership, matching the readable YAML form `key: [A, B]`
    if isinstance(expected, (list, tuple)):
        return present and actual in list(expected)

    if isinstance(expected, str):
        membership = _IN_RE.match(expected)
        if membership:
            options = [_coerce(part) for part in membership.group(1).split(",")]
            return present and actual in options

        operator_match = _OPERATOR_RE.match(expected)
        if operator_match:
            operator, raw = operator_match.groups()
            target = _coerce(raw)
            if operator == "==":
                return present and actual == target
            if operator == "!=":
                return present and actual != target
            left, right = _numeric(actual), _numeric(target)
            if left is None or right is None:
                return False
            return {
                ">=": left >= right,
                "<=": left <= right,
                ">": left > right,
                "<": left < right,
            }[operator]

    if expected is None:
        # Explicit "fact is absent or null" — the only way to assert absence.
        return not present or actual is None

    if isinstance(expected, bool):
        return present and bool(actual) is expected

    return present and actual == expected


def _render(expected: Any) -> str:
    if isinstance(expected, (list, tuple)):
        return f"in {list(expected)}"
    if isinstance(expected, str) and (_OPERATOR_RE.match(expected) or _IN_RE.match(expected)):
        return expected
    return f"== {expected!r}"


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def _parse_rule(raw: Mapping[str, Any], index: int) -> OriginRule:
    rule_id = raw.get("id")
    if not rule_id:
        raise RuleError(f"rule #{index} has no id")
    when = raw.get("when")
    if not isinstance(when, Mapping) or not when:
        raise RuleError(f"rule '{rule_id}' has no 'when' conditions")
    result = raw.get("result")
    if not isinstance(result, Mapping):
        raise RuleError(f"rule '{rule_id}' has no 'result'")

    try:
        origin_type = OriginType(str(result["origin_type"]))
    except KeyError as exc:
        raise RuleError(f"rule '{rule_id}' result has no origin_type") from exc
    except ValueError as exc:
        raise RuleError(f"rule '{rule_id}' names unknown origin_type {result['origin_type']!r}") from exc

    tier = str(raw.get("signal_tier", "fallback"))
    if tier not in TIER_RANK:
        raise RuleError(f"rule '{rule_id}' declares unknown signal_tier {tier!r}; expected one of {SIGNAL_TIERS}")

    confidence = float(result.get("confidence", 0.0))
    if not 0.0 <= confidence <= 1.0:
        raise RuleError(f"rule '{rule_id}' confidence {confidence} outside [0,1]")

    return OriginRule(
        id=str(rule_id),
        when=dict(when),
        origin_type=origin_type,
        confidence=confidence,
        signal_tier=tier,
        description=str(raw.get("description", "")),
        requires_review=bool(result.get("requires_review", False)),
        public_label=result.get("public_label"),
    )


def load_rules(path: str | Path | None = None) -> list[OriginRule]:
    """Load and validate the rule set, strongest signal tier first.

    ``path`` may be the YAML file itself or the policy directory holding
    ``origin_rules.yaml``.
    """
    if path is None:
        path = Path(__file__).resolve().parents[3] / "config" / "policies" / DEFAULT_RULES_FILENAME
    resolved = Path(path)
    if resolved.is_dir():
        resolved = resolved / DEFAULT_RULES_FILENAME
    if not resolved.is_file():
        raise RuleError(f"origin rule file not found: {resolved}")

    document = yaml.safe_load(resolved.read_text("utf-8")) or {}
    raw_rules = document.get("rules")
    if not isinstance(raw_rules, list) or not raw_rules:
        raise RuleError(f"{resolved} contains no 'rules' list")

    rules = [_parse_rule(raw, index) for index, raw in enumerate(raw_rules)]
    duplicates = {r.id for r in rules if sum(1 for other in rules if other.id == r.id) > 1}
    if duplicates:
        raise RuleError(f"duplicate rule ids: {sorted(duplicates)}")
    return sort_rules(rules)


def sort_rules(rules: Iterable[OriginRule]) -> list[OriginRule]:
    """Strongest tier first, then highest confidence — the §7.2 evaluation order."""
    return sorted(rules, key=lambda r: (r.tier_rank, -r.confidence, r.id))


# --------------------------------------------------------------------------
# evaluation
# --------------------------------------------------------------------------

def evaluate_rules(rules: Sequence[OriginRule], facts: Mapping[str, Any]) -> RuleEvaluation:
    """Apply the §7.2 precedence ladder to every matching rule.

    The winner is the highest-confidence rule on the *strongest* rung that matched.
    Weaker rules never change the verdict — they only nudge confidence when they
    agree, and are surfaced as dissent when they do not, so a reviewer can see the
    disagreement instead of it being averaged away.
    """
    evaluation = RuleEvaluation()
    matches = [rule for rule in sort_rules(rules) if rule.matches(facts)]
    evaluation.all_matches = matches
    if not matches:
        evaluation.notes.append("no rule matched; origin remains UNKNOWN")
        return evaluation

    winner = matches[0]
    evaluation.matched = winner
    evaluation.origin_type = winner.origin_type
    evaluation.confidence = winner.confidence

    for rule in matches[1:]:
        if rule.tier_rank < winner.tier_rank:  # pragma: no cover - sort_rules forbids it
            raise AssertionError("precedence violated: a weaker winner outranked a stronger match")
        if rule.origin_type == winner.origin_type:
            evaluation.corroborating.append(rule)
        else:
            evaluation.dissenting.append(rule)

    if evaluation.corroborating:
        bonus = min(MAX_CORROBORATION, CORROBORATION_BONUS * len(evaluation.corroborating))
        evaluation.confidence = min(1.0, evaluation.confidence + bonus)
        evaluation.notes.append(
            f"+{bonus:.2f} confidence from {len(evaluation.corroborating)} corroborating "
            f"lower-tier rule(s): {', '.join(r.id for r in evaluation.corroborating)}"
        )

    for rule in evaluation.dissenting:
        evaluation.notes.append(
            f"rule '{rule.id}' ({rule.signal_tier}) argued for {rule.origin_type}; "
            f"outranked by '{winner.id}' ({winner.signal_tier}) per §7.2"
        )
    return evaluation
