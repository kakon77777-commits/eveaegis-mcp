"""Policy vocabulary and rule loading (§11 RBAC/ABAC, §12 origin bindings, §13 tools).

Two things live here that the rest of the policy package treats as ground truth:

* :data:`TOOL_LEVELS` — every MCP tool named in §13.1-§13.7 with its §11.3
  permission level. A tool that is *not* in the map resolves to
  ``L5_BREAK_GLASS``. That default is the security property: adding a tool to the
  server without adding it here makes it unreachable, not unguarded. Never invert
  this into "unknown means L0".
* :class:`PolicyRule` — one declarative rule, used for both §11.2 ABAC rules and
  §12 origin bindings. Its :meth:`~PolicyRule.matches` fails closed as well: an
  attribute the engine could not resolve does not match, so a rule can never fire
  on evidence nobody has.

Rule data comes from ``config/policies/core.yaml`` and
``config/policies/origin_bindings.yaml``. ``origin_rules.yaml`` belongs to the
provenance engine and is deliberately not read here.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

import yaml

from ..taxonomy import PERMISSION_LEVEL_RANK, PermissionLevel

#: Fail-closed default for any tool the policy configuration does not name.
DEFAULT_TOOL_LEVEL: PermissionLevel = PermissionLevel.L5_BREAK_GLASS

#: §13.1-§13.7. Kept in code as well as in YAML so that a missing/edited config
#: file cannot silently downgrade a tool: the engine takes the *stricter* of the
#: two (see :meth:`PolicySet.level_for`).
TOOL_LEVELS: dict[str, PermissionLevel] = {
    # §13.1 Inventory
    "inventory_accounts": PermissionLevel.L0_INVENTORY,
    "inventory_repositories": PermissionLevel.L0_INVENTORY,
    "refresh_repository": PermissionLevel.L0_INVENTORY,
    "get_portfolio_summary": PermissionLevel.L0_INVENTORY,
    "find_unclassified_repositories": PermissionLevel.L0_INVENTORY,
    # §13.2 Provenance
    "analyze_repository_origin": PermissionLevel.L0_INVENTORY,
    "compare_repository_lineage": PermissionLevel.L0_INVENTORY,
    "find_candidate_upstreams": PermissionLevel.L0_INVENTORY,
    "estimate_local_contribution": PermissionLevel.L0_INVENTORY,
    "generate_provenance_report": PermissionLevel.L0_INVENTORY,
    "review_provenance_decision": PermissionLevel.L1_METADATA_WRITE,
    # §13.3 Classification
    "classify_repository": PermissionLevel.L0_INVENTORY,
    "classify_portfolio": PermissionLevel.L0_INVENTORY,
    "propose_lifecycle": PermissionLevel.L0_INVENTORY,
    "propose_repository_category": PermissionLevel.L0_INVENTORY,
    "detect_archive_candidates": PermissionLevel.L0_INVENTORY,
    "detect_superseded_projects": PermissionLevel.L0_INVENTORY,
    # §13.4 Governance
    "evaluate_action_policy": PermissionLevel.L0_INVENTORY,
    "create_change_plan": PermissionLevel.L0_INVENTORY,
    "preview_change_plan": PermissionLevel.L0_INVENTORY,
    "approve_change_plan": PermissionLevel.L4_REPOSITORY_ADMIN,
    "execute_approved_plan": PermissionLevel.L3_CONTROLLED_CODE_WRITE,
    "rollback_change_plan": PermissionLevel.L3_CONTROLLED_CODE_WRITE,
    # §13.5 Metadata
    "propose_repository_metadata": PermissionLevel.L1_METADATA_WRITE,
    "apply_repository_taxonomy": PermissionLevel.L1_METADATA_WRITE,
    "standardize_topics": PermissionLevel.L1_METADATA_WRITE,
    "standardize_descriptions": PermissionLevel.L1_METADATA_WRITE,
    "generate_project_catalog": PermissionLevel.L1_METADATA_WRITE,
    # §13.6 Documentation
    "propose_readme_update": PermissionLevel.L2_CONTENT_PROPOSAL,
    "create_documentation_branch": PermissionLevel.L2_CONTENT_PROPOSAL,
    "create_documentation_pr": PermissionLevel.L2_CONTENT_PROPOSAL,
    "add_origin_notice": PermissionLevel.L2_CONTENT_PROPOSAL,
    "add_superseded_notice": PermissionLevel.L2_CONTENT_PROPOSAL,
    # §13.7 Administration — not exposed to general agents.
    "archive_repository": PermissionLevel.L4_REPOSITORY_ADMIN,
    "transfer_repository": PermissionLevel.L4_REPOSITORY_ADMIN,
    "change_visibility": PermissionLevel.L4_REPOSITORY_ADMIN,
    "modify_ruleset": PermissionLevel.L4_REPOSITORY_ADMIN,
    "modify_collaborators": PermissionLevel.L4_REPOSITORY_ADMIN,
    "delete_repository": PermissionLevel.L5_BREAK_GLASS,
}

#: Anything above L0 touches state a human would notice. Used for the read-only
#: gate and for axiom 3 ("all writes form a plan first").
WRITE_LEVEL_FLOOR: PermissionLevel = PermissionLevel.L1_METADATA_WRITE


def is_write_level(level: PermissionLevel) -> bool:
    return PERMISSION_LEVEL_RANK[level] >= PERMISSION_LEVEL_RANK[WRITE_LEVEL_FLOOR]


@dataclass(frozen=True)
class PolicyRule:
    """One declarative rule — an §11.2 ABAC rule or an §12 origin binding.

    ``when`` maps an attribute name to the values that satisfy it. All entries
    must match. A ``None`` attribute never matches: a rule must not fire on
    evidence that was never gathered.
    """

    id: str
    when: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    allow: tuple[str, ...] = ()
    deny: tuple[str, ...] = ()
    require: tuple[str, ...] = ()
    deny_tools: tuple[str, ...] = ()
    max_level: PermissionLevel | None = None
    require_approval: bool = False
    description: str = ""
    source: str = ""

    def matches(self, attributes: Mapping[str, Any]) -> bool:
        for key, allowed in self.when.items():
            value = attributes.get(key)
            if value is None:
                return False
            if isinstance(value, (list, tuple, set, frozenset)):
                if not {str(v) for v in value} & set(allowed):
                    return False
            elif str(value) not in allowed:
                return False
        return bool(self.when)  # a rule with no condition is a configuration error

    @classmethod
    def from_mapping(cls, data: Mapping[str, Any], *, source: str = "") -> "PolicyRule":
        when = {
            str(k): tuple(str(v) for v in _as_list(vals))
            for k, vals in (data.get("when") or {}).items()
        }
        return cls(
            id=str(data.get("id") or "unnamed-rule"),
            when=when,
            allow=tuple(str(v) for v in _as_list(data.get("allow"))),
            deny=tuple(str(v) for v in _as_list(data.get("deny"))),
            require=tuple(str(v) for v in _as_list(data.get("require"))),
            deny_tools=tuple(str(v) for v in _as_list(data.get("deny_tools"))),
            max_level=_level(data.get("max_level")),
            require_approval=bool(data.get("require_approval", False)),
            description=str(data.get("description") or ""),
            source=source,
        )


@dataclass(frozen=True)
class PolicySet:
    """Everything :class:`~eveaegis.policy.engine.PolicyEngine` needs, already parsed."""

    role_max_level: Mapping[str, PermissionLevel]
    unknown_role_level: PermissionLevel
    abac_rules: tuple[PolicyRule, ...]
    origin_rules: tuple[PolicyRule, ...]
    origin_fallbacks: Mapping[str, str]
    default_origin_policy_id: str
    capabilities: Mapping[str, tuple[str, ...]]
    requirement_descriptions: Mapping[str, str]
    tool_levels: Mapping[str, PermissionLevel]
    originality_claim_tools: frozenset[str]
    irreversible_tools: frozenset[str]
    attribution_safe_tools: frozenset[str]
    risk: Mapping[str, Any]
    token: Mapping[str, Any]
    constraints: Mapping[str, Any]
    sources: tuple[str, ...] = ()

    # -- lookups ----------------------------------------------------------

    def level_for(self, tool: str) -> PermissionLevel:
        """Permission level for a tool, taking the **stricter** of code and config.

        Config may tighten a tool but never loosen it, and an unnamed tool lands on
        ``L5_BREAK_GLASS``. There is no configuration edit that opens a hole here.
        """
        builtin = TOOL_LEVELS.get(tool)
        configured = self.tool_levels.get(tool)
        candidates = [lvl for lvl in (builtin, configured) if lvl is not None]
        if not candidates:
            return DEFAULT_TOOL_LEVEL
        return max(candidates, key=lambda lvl: PERMISSION_LEVEL_RANK[lvl])

    def is_known_tool(self, tool: str) -> bool:
        return tool in TOOL_LEVELS or tool in self.tool_levels

    def tools_for_capability(self, capability: str) -> tuple[str, ...]:
        return self.capabilities.get(capability, ())

    def origin_rule_for(self, origin_type: str) -> PolicyRule | None:
        """§12 binding for an origin type, following the declared fallbacks."""
        for rule in self.origin_rules:
            if origin_type in rule.when.get("origin_type", ()):
                return rule
        mapped = self.origin_fallbacks.get(origin_type)
        target = mapped or self.default_origin_policy_id
        for rule in self.origin_rules:
            if rule.id == target:
                return rule
        return None

    def risk_weight(self, *path: str, default: float = 0.0) -> float:
        node: Any = self.risk.get("weights", {})
        for key in path:
            if not isinstance(node, Mapping) or key not in node:
                return default
            node = node[key]
        try:
            return float(node)
        except (TypeError, ValueError):
            return default


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def load_policies(policy_dir: str | Path | None = None) -> PolicySet:
    """Read ``core.yaml`` + ``origin_bindings.yaml`` from ``policy_dir``.

    Missing files are tolerated — the built-in :data:`TOOL_LEVELS` and the
    fail-closed defaults still produce a usable, restrictive policy set. A policy
    engine that refused to start without config would be a denial-of-service on
    the read-only tools, which are the ones that need no policy at all.
    """
    base = Path(policy_dir) if policy_dir else Path("config/policies")
    core = _read_yaml(base / "core.yaml")
    bindings = _read_yaml(base / "origin_bindings.yaml")
    sources = tuple(
        str(p) for p in (base / "core.yaml", base / "origin_bindings.yaml") if p.is_file()
    )

    rbac = core.get("rbac") or {}
    role_max = {
        str(role): lvl
        for role, raw in (rbac.get("role_max_level") or {}).items()
        if (lvl := _level(raw)) is not None
    }

    abac = tuple(
        PolicyRule.from_mapping(rule, source="core.yaml")
        for rule in _as_list((core.get("abac") or {}).get("rules"))
        if isinstance(rule, Mapping)
    )
    origin = tuple(
        PolicyRule.from_mapping(rule, source="origin_bindings.yaml")
        for rule in _as_list(bindings.get("policies"))
        if isinstance(rule, Mapping)
    )

    tools = core.get("tools") or {}
    tool_levels = {
        str(name): lvl
        for name, raw in (tools.get("levels") or {}).items()
        if (lvl := _level(raw)) is not None
    }

    return PolicySet(
        role_max_level=role_max,
        unknown_role_level=_level(rbac.get("unknown_role_level")) or PermissionLevel.L0_INVENTORY,
        abac_rules=abac,
        origin_rules=origin,
        origin_fallbacks={
            str(k): str(v) for k, v in (bindings.get("fallback_bindings") or {}).items()
        },
        default_origin_policy_id=str(bindings.get("default_policy_id") or "unknown-origin-policy"),
        capabilities={
            str(k): tuple(str(t) for t in _as_list(v))
            for k, v in (bindings.get("capabilities") or {}).items()
        },
        requirement_descriptions={
            str(k): str(v) for k, v in (bindings.get("requirement_descriptions") or {}).items()
        },
        tool_levels=tool_levels,
        originality_claim_tools=frozenset(str(t) for t in _as_list(tools.get("originality_claim"))),
        irreversible_tools=frozenset(str(t) for t in _as_list(tools.get("irreversible"))),
        attribution_safe_tools=frozenset(str(t) for t in _as_list(tools.get("attribution_safe"))),
        risk=core.get("risk") or {},
        token=core.get("token") or {},
        constraints=core.get("constraints") or {},
        sources=sources,
    )


def _read_yaml(path: Path) -> Mapping[str, Any]:
    if not path.is_file():
        return {}
    data = yaml.safe_load(path.read_text("utf-8"))
    return data if isinstance(data, Mapping) else {}


def _level(value: Any) -> PermissionLevel | None:
    if isinstance(value, PermissionLevel):
        return value
    if isinstance(value, str) and value in PermissionLevel.__members__:
        return PermissionLevel(value)
    return None


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return list(value)
    return [value]


def min_level(*levels: PermissionLevel | None) -> PermissionLevel:
    """Lowest of the given levels; ``None`` entries are ignored."""
    present: Iterable[PermissionLevel] = [lvl for lvl in levels if lvl is not None]
    return min(present, key=lambda lvl: PERMISSION_LEVEL_RANK[lvl], default=PermissionLevel.L0_INVENTORY)
