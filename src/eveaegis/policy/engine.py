"""Policy decision point (§11, §12, §15) — where the five axioms of §3 are enforced.

Every MCP tool call passes through :meth:`PolicyEngine.evaluate` before anything
else happens. The engine is a pure function of (request, stored state, policy
config) plus one side effect: it writes a ``policy_decision`` event to the audit
ledger, so §29's "every write has a policy decision" is structurally true rather
than a convention.

Axioms, and where each is enforced below:

* **Axiom 2** ``Agent Capability ⊆ Policy Authorization ⊆ GitHub Installation
  Permission`` — :meth:`_ceiling`. The decision can never exceed the principal's
  own ``max_permission_level`` nor the repository's ``agent_access`` ceiling.
* **Axiom 3** inspect → plan → preview → approve → apply — :meth:`_needs_approval`.
  A write with ``dry_run=False`` and no APPROVED plan is ``REQUIRE_APPROVAL``.
* **Axiom 4** unknown provenance ⇒ no automatic public originality claim —
  :meth:`_originality_denials`. Hard ``DENY``, not a constraint.
* **Axiom 5** risk↑ ⇒ scope↓, lifetime↓, approval↑ — :meth:`_token_terms`.
* Axiom 1 is upstream of this module entirely: the engine names a scope and a
  lifetime, and the credential broker is the only thing that ever holds a token.

Ordering matters. A denial always wins over a constraint, and the read-only gate
is checked before anything that could be interpreted as a grant.
"""

from __future__ import annotations

import sqlite3
from typing import Any, Mapping

from ..core import GovernanceCore
from ..credentials.base import SCOPE_RANK, TokenScope
from ..db import loads
from ..models import ActionRequest, OriginProfile, PolicyDecision, Principal, RepositoryAsset
from ..taxonomy import (
    AGENT_ACCESS_CEILING,
    PERMISSION_LEVEL_RANK,
    RISK_RANK,
    ActorType,
    AgentAccess,
    Category,
    Criticality,
    Decision,
    Lifecycle,
    LicenseStatus,
    Maturity,
    OriginType,
    PermissionLevel,
    RiskLevel,
    Role,
    Visibility,
)
from .risk import assess_risk
from .rules import PolicyRule, PolicySet, is_write_level, load_policies, min_level


class _Trace:
    """Accumulator for the evaluation, so ``explain`` and ``evaluate`` agree exactly."""

    def __init__(self) -> None:
        self.lines: list[str] = []
        self.matched: list[str] = []
        self.reasons: list[str] = []
        self.denials: list[str] = []
        self.requirements: list[str] = []
        self.approval_reasons: list[str] = []

    def note(self, line: str) -> None:
        self.lines.append(line)

    def match(self, policy_id: str, line: str) -> None:
        if policy_id not in self.matched:
            self.matched.append(policy_id)
        self.lines.append(f"[{policy_id}] {line}")
        self.reasons.append(line)

    def deny(self, policy_id: str, line: str) -> None:
        self.match(policy_id, line)
        self.denials.append(line)

    def require_approval(self, policy_id: str, line: str) -> None:
        self.match(policy_id, line)
        self.approval_reasons.append(line)


class PolicyEngine:
    """§15 policy decision point."""

    def __init__(self, core: GovernanceCore) -> None:
        self.core = core
        self.conn: sqlite3.Connection = core.conn
        self.policies: PolicySet = load_policies(core.cfg.policy_path)

    # -- public API -------------------------------------------------------

    def required_level(self, tool: str) -> PermissionLevel:
        """§11.3 level a tool needs. Unknown tools fail closed to ``L5_BREAK_GLASS``."""
        return self.policies.level_for(tool)

    def evaluate(self, request: ActionRequest) -> PolicyDecision:
        """Decide one request and record the decision in the audit ledger (§18)."""
        decision, _trace = self._evaluate(request)
        self.core.ledger.record(
            "policy_decision",
            actor=request.actor.id,
            initiated_by=request.actor.principal,
            tenant=request.tenant_id,
            targets=list(request.targets),
            request_id=request.request_id,
            policy_decision=decision.decision,
            credential_scope=decision.token_scope,
            result=str(decision.decision),
            detail={
                "tool": request.tool,
                "risk": str(decision.risk),
                "matched_policies": decision.matched_policies,
                "reasons": decision.reasons,
                "constraints": decision.constraints,
                "token_lifetime_seconds": decision.token_lifetime_seconds,
                "dry_run": request.dry_run,
            },
        )
        return decision

    def explain(self, request: ActionRequest) -> str:
        """§19.4 — the human-readable trace behind a decision. Records nothing."""
        decision, trace = self._evaluate(request)
        header = [
            f"request  : {request.request_id}",
            f"actor    : {request.actor.id} (principal {request.actor.principal}, "
            f"{request.actor.type})",
            f"tool     : {request.tool} -> requires {self.required_level(request.tool)}",
            f"targets  : {', '.join(request.targets) if request.targets else '(none)'}",
            f"dry_run  : {request.dry_run}",
            "",
            "evaluation:",
        ]
        body = [f"  {i + 1}. {line}" for i, line in enumerate(trace.lines)]
        footer = [
            "",
            f"decision : {decision.decision}",
            f"risk     : {decision.risk}",
            f"token    : scope={decision.token_scope or 'none'} "
            f"lifetime={decision.token_lifetime_seconds}s",
            f"policies : {', '.join(decision.matched_policies)}",
        ]
        if decision.constraints:
            footer.append("constraints:")
            footer += [f"  - {k} = {v}" for k, v in sorted(decision.constraints.items())]
        return "\n".join(header + body + footer)

    # -- evaluation -------------------------------------------------------

    def _evaluate(self, request: ActionRequest) -> tuple[PolicyDecision, _Trace]:
        trace = _Trace()
        cfg = self.policies

        level = self.required_level(request.tool)
        if not cfg.is_known_tool(request.tool):
            trace.deny(
                "unknown-tool-fail-closed",
                f"tool '{request.tool}' is not in the §13 tool map; treated as "
                f"{PermissionLevel.L5_BREAK_GLASS} and refused",
            )
        else:
            trace.match("tool-level", f"tool '{request.tool}' requires {level}")

        principal = self._principal(request, trace)
        repos = self._repositories(request.targets, trace)
        origins = self._origin_profiles(repos)
        attributes = self._attributes(request, principal, repos, origins)
        trace.note(
            "attributes: "
            + ", ".join(f"{k}={_fmt(v)}" for k, v in sorted(attributes.items()))
        )

        # Axiom 5 input — needed before the token terms and before break-glass.
        risk, risk_reasons = assess_risk(request, repos, origins, cfg)
        for line in risk_reasons:
            trace.note(f"risk: {line}")
        trace.match("risk-assessment", f"risk assessed as {risk}")

        writes = is_write_level(level)

        # -- coarse gate: read-only mode --------------------------------
        if self.core.cfg.governance.read_only and writes:
            trace.deny(
                "governance-read-only",
                "governance.read_only is set; every write tool is refused regardless "
                "of role, repository policy or risk",
            )

        # -- axiom 2: ceilings ------------------------------------------
        ceiling, ceiling_notes = self._ceiling(principal, repos, attributes, trace)
        for note in ceiling_notes:
            trace.note(note)
        if PERMISSION_LEVEL_RANK[level] > PERMISSION_LEVEL_RANK[ceiling]:
            trace.deny(
                "axiom-2-capability-subset",
                f"tool needs {level} but the effective authorization ceiling is "
                f"{ceiling} (Agent Capability ⊆ Policy Authorization)",
            )

        # -- explicit tool denials from ABAC ----------------------------
        for rule in self._matching_abac(attributes):
            if request.tool in rule.deny_tools:
                trace.deny(rule.id, f"{rule.id} forbids tool '{request.tool}'")

        # -- axiom 4: originality claims --------------------------------
        self._originality_denials(request, repos, origins, trace)

        # -- §12 origin binding -----------------------------------------
        self._origin_bindings(request, repos, origins, trace)

        # -- axiom 3: plan before write ---------------------------------
        blocks_now, approval_policy = self._approval(request, level, attributes, risk, trace)

        # -- decide ------------------------------------------------------
        scope, lifetime, scope_notes = self._token_terms(level, risk, trace)
        for note in scope_notes:
            trace.note(note)

        constraints = self._constraints(request, level, risk, ceiling, approval_policy, trace)
        # An L0 read at LOW risk carries only informational constraints, so it is a
        # plain ALLOW; anything that writes, or that carries risk, is constrained.
        binding = approval_policy or writes or risk != RiskLevel.LOW
        decision_kind = self._decide(level, risk, trace, blocks_now, binding)

        if decision_kind == Decision.DENY:
            scope = None  # a denied request buys no credential at all

        if not trace.matched:  # a decision with no explanation is a bug
            trace.match("baseline", "no rule matched; baseline evaluation applied")
        if not trace.reasons:
            trace.reasons.append("no policy objected to this request")

        decision = PolicyDecision(
            request_id=request.request_id,
            decision=decision_kind,
            risk=risk,
            constraints=constraints,
            matched_policies=list(trace.matched),
            reasons=list(trace.reasons),
            token_scope=str(scope) if scope else None,
            token_lifetime_seconds=lifetime,
        )
        return decision, trace

    def _decide(
        self,
        level: PermissionLevel,
        risk: RiskLevel,
        trace: _Trace,
        approval_required: bool,
        binding_constraints: bool,
    ) -> Decision:
        if trace.denials:
            return Decision.DENY
        if level == PermissionLevel.L5_BREAK_GLASS:
            trace.match(
                "level-5-break-glass",
                "§11.3 Level 5 requires two-person approval, MFA and explicit targets",
            )
            return Decision.REQUIRE_BREAK_GLASS
        if risk == RiskLevel.CRITICAL:
            trace.match(
                "axiom-5-critical-risk",
                "CRITICAL risk escalates approval strength to break-glass",
            )
            return Decision.REQUIRE_BREAK_GLASS
        if approval_required:
            return Decision.REQUIRE_APPROVAL
        if binding_constraints:
            return Decision.ALLOW_WITH_CONSTRAINTS
        return Decision.ALLOW

    # -- axiom 2 ----------------------------------------------------------

    def _ceiling(
        self,
        principal: Principal,
        repos: Mapping[str, RepositoryAsset],
        attributes: Mapping[str, Any],
        trace: _Trace,
    ) -> tuple[PermissionLevel, list[str]]:
        """Lowest of: RBAC role ceiling, the principal's own ceiling, every target's
        ``agent_access`` ceiling, and every matching ABAC ``max_level``."""
        notes: list[str] = []
        cfg = self.policies

        role_levels = [cfg.role_max_level.get(str(role)) for role in principal.roles]
        role_ceiling = (
            min_level(*[lvl for lvl in role_levels if lvl is not None])
            if any(lvl is not None for lvl in role_levels)
            else cfg.unknown_role_level
        )
        notes.append(
            f"RBAC: roles {[str(r) for r in principal.roles] or '[]'} -> {role_ceiling}"
        )
        ceiling = min_level(role_ceiling, principal.max_permission_level)
        notes.append(f"principal ceiling: {principal.max_permission_level}")

        for full_name, repo in repos.items():
            repo_ceiling = AGENT_ACCESS_CEILING[repo.agent_access]
            notes.append(
                f"repository '{full_name}': agent_access {repo.agent_access} -> {repo_ceiling}"
            )
            ceiling = min_level(ceiling, repo_ceiling)

        for rule in self._matching_abac(attributes):
            if rule.max_level is not None:
                if PERMISSION_LEVEL_RANK[rule.max_level] < PERMISSION_LEVEL_RANK[ceiling]:
                    trace.match(
                        rule.id,
                        f"{rule.id} lowers the ceiling to {rule.max_level}"
                        + (f" — {rule.description.strip()}" if rule.description else ""),
                    )
                    ceiling = rule.max_level
                else:
                    trace.match(rule.id, f"{rule.id} matched (ceiling already {ceiling})")
            for requirement in rule.require:
                if requirement not in trace.requirements:
                    trace.requirements.append(requirement)
                    trace.match(rule.id, f"{rule.id} requires '{requirement}'")

        trace.match("axiom-2-ceiling", f"effective authorization ceiling is {ceiling}")
        return ceiling, notes

    # -- axiom 4 ----------------------------------------------------------

    def _originality_denials(
        self,
        request: ActionRequest,
        repos: Mapping[str, RepositoryAsset],
        origins: Mapping[str, OriginProfile],
        trace: _Trace,
    ) -> None:
        """UNKNOWN PROVENANCE ⇒ NO AUTOMATIC PUBLIC ORIGINALITY CLAIM."""
        claims = request.tool in self.policies.originality_claim_tools or bool(
            request.parameters.get("public_originality_claim")
        )
        if not claims:
            return
        trace.note(f"axiom 4: '{request.tool}' can publish an originality claim")
        for full_name, repo in repos.items():
            profile = origins.get(repo.id)
            if profile is None:
                trace.deny(
                    "axiom-4-unknown-origin",
                    f"'{full_name}' has no origin profile; an originality claim on "
                    f"unanalysed provenance is refused",
                )
                continue
            if profile.origin_type == OriginType.UNKNOWN:
                trace.deny(
                    "axiom-4-unknown-origin",
                    f"'{full_name}' has UNKNOWN origin; automatic originality claim refused",
                )
            elif profile.origin_type in _NO_CLAIM_ORIGINS:
                trace.deny(
                    "axiom-4-derived-origin",
                    f"'{full_name}' is {profile.origin_type}; upstream work is present, so "
                    f"an automatic originality claim is refused",
                )
        if not repos and request.targets:
            trace.deny(
                "axiom-4-unknown-origin",
                "targets are not inventoried, so their provenance is unknown by definition",
            )

    # -- §12 ---------------------------------------------------------------

    def _origin_bindings(
        self,
        request: ActionRequest,
        repos: Mapping[str, RepositoryAsset],
        origins: Mapping[str, OriginProfile],
        trace: _Trace,
    ) -> None:
        """Apply the §12 allow/deny/require lists per target."""
        cfg = self.policies
        for full_name, repo in repos.items():
            profile = origins.get(repo.id)
            origin_type = str(profile.origin_type) if profile else str(OriginType.UNKNOWN)
            rule = cfg.origin_rule_for(origin_type)
            if rule is None:
                trace.deny(
                    "origin-binding-missing",
                    f"no §12 binding covers origin type {origin_type} for '{full_name}'",
                )
                continue

            denied_tools = {
                tool for cap in rule.deny for tool in cfg.tools_for_capability(cap)
            }
            allowed_tools = {
                tool for cap in rule.allow for tool in cfg.tools_for_capability(cap)
            }
            if request.tool in denied_tools:
                trace.deny(
                    rule.id,
                    f"§12 {rule.id} denies '{request.tool}' on '{full_name}' "
                    f"(origin {origin_type})",
                )
                continue
            if is_write_level(cfg.level_for(request.tool)) and request.tool not in allowed_tools:
                trace.deny(
                    rule.id,
                    f"§12 {rule.id} does not allow '{request.tool}' on '{full_name}' "
                    f"(origin {origin_type}); allowed capabilities: "
                    f"{', '.join(rule.allow) or 'none'}",
                )
                continue
            trace.match(
                rule.id,
                f"§12 {rule.id} permits '{request.tool}' on '{full_name}' (origin {origin_type})",
            )
            for requirement in rule.require:
                if requirement not in trace.requirements:
                    trace.requirements.append(requirement)
                    trace.match(rule.id, f"§12 {rule.id} requires '{requirement}'")

    # -- axiom 3 ----------------------------------------------------------

    def _approval(
        self,
        request: ActionRequest,
        level: PermissionLevel,
        attributes: Mapping[str, Any],
        risk: RiskLevel,
        trace: _Trace,
    ) -> tuple[bool, bool]:
        """Returns ``(blocks_this_request, approval_required_before_apply)``.

        The two are different on purpose. A dry run does not need an approval *now*
        — it is the preview step — but the resulting plan still cannot be applied
        without one, and §15's ``constraints.approval_required`` is what tells the
        caller so. Collapsing them would let a preview advertise itself as free.
        """
        floor_raw = self.policies.constraints.get("approval_required_from_level")
        floor = (
            PermissionLevel(floor_raw)
            if isinstance(floor_raw, str) and floor_raw in PermissionLevel.__members__
            else PermissionLevel.L1_METADATA_WRITE
        )
        if PERMISSION_LEVEL_RANK[level] < PERMISSION_LEVEL_RANK[floor]:
            return False, False  # read-only tools never need an approval

        policy_required = False
        if self.core.cfg.governance.require_human_approval:
            trace.match(
                "governance-require-human-approval",
                "governance.require_human_approval is set: this change cannot be applied "
                "without a human",
            )
            policy_required = True
        for rule in self._matching_abac(attributes):
            if rule.require_approval:
                trace.match(rule.id, f"{rule.id} requires a human approval before apply")
                policy_required = True
        if RISK_RANK[risk] >= RISK_RANK[RiskLevel.HIGH]:
            trace.match(
                "axiom-5-high-risk-approval",
                f"{risk} risk raises approval strength (axiom 5)",
            )
            policy_required = True

        if request.dry_run:
            trace.match(
                "axiom-3-dry-run",
                "dry_run=true: this is the preview step of inspect → plan → preview → "
                "approve → apply, so nothing is applied yet",
            )
            return False, policy_required

        plan_state = self._plan_state(request)
        if plan_state == "APPROVED":
            trace.match(
                "axiom-3-approved-plan",
                f"plan '{request.parameters.get('plan_id')}' is APPROVED; the write may proceed",
            )
            return False, policy_required

        detail = f"plan state is {plan_state}" if plan_state else "no approved plan referenced"
        trace.require_approval(
            "axiom-3-plan-required",
            f"write with dry_run=false and {detail}: all writes form a plan first",
        )
        return True, True

    def _plan_state(self, request: ActionRequest) -> str | None:
        plan_id = request.parameters.get("plan_id")
        if not plan_id:
            return None
        try:
            row = self.conn.execute(
                "SELECT state FROM change_plans WHERE id = ?", (str(plan_id),)
            ).fetchone()
        except sqlite3.Error:
            return None
        return str(row["state"]) if row else None

    # -- axiom 5 ----------------------------------------------------------

    def _token_terms(
        self,
        level: PermissionLevel,
        risk: RiskLevel,
        trace: _Trace,
    ) -> tuple[TokenScope | None, int, list[str]]:
        """Risk↑ ⇒ scope↓ ∧ lifetime↓. Both caps are hard, never advisory."""
        token_cfg = self.policies.token or {}
        notes: list[str] = []

        scope_name = (token_cfg.get("scope_by_level") or {}).get(str(level))
        scope = _scope(scope_name) or TokenScope.READ_METADATA
        notes.append(f"scope for {level}: {scope}")

        cap_name = (token_cfg.get("scope_cap_by_risk") or {}).get(str(risk))
        cap = _scope(cap_name)
        if cap is not None and SCOPE_RANK[scope] > SCOPE_RANK[cap]:
            notes.append(f"{risk} risk caps the scope at {cap} (was {scope})")
            trace.match("axiom-5-scope-reduction", f"{risk} risk narrows token scope to {cap}")
            scope = cap

        lifetimes = token_cfg.get("lifetime_by_risk") or {}
        lifetime = int(lifetimes.get(str(risk), 300) or 300)
        broker_cap = int(self.core.cfg.credentials.max_token_lifetime_seconds or 600)
        if lifetime > broker_cap:
            lifetime = broker_cap
            notes.append(f"broker ceiling shortens the lifetime to {lifetime}s")
        notes.append(f"token lifetime for {risk} risk: {lifetime}s")
        if risk == RiskLevel.CRITICAL:
            lifetime = min(lifetime, 60)
            trace.match(
                "axiom-5-lifetime-reduction",
                f"CRITICAL risk shortens the token lifetime to {lifetime}s",
            )
        return scope, lifetime, notes

    # -- constraints ------------------------------------------------------

    def _constraints(
        self,
        request: ActionRequest,
        level: PermissionLevel,
        risk: RiskLevel,
        ceiling: PermissionLevel,
        approval_required: bool,
        trace: _Trace,
    ) -> dict[str, Any]:
        by_risk = self.policies.constraints.get("max_repositories_by_risk") or {}
        constraints: dict[str, Any] = {
            "max_repositories": int(by_risk.get(str(risk), 1) or 1),
            "metadata_only": PERMISSION_LEVEL_RANK[level]
            <= PERMISSION_LEVEL_RANK[PermissionLevel.L1_METADATA_WRITE],
            "direct_write": level == PermissionLevel.L3_CONTROLLED_CODE_WRITE
            and not self.core.cfg.governance.read_only,
            "approval_required": approval_required,
            "effective_ceiling": str(ceiling),
        }
        if PERMISSION_LEVEL_RANK[level] >= PERMISSION_LEVEL_RANK[
            PermissionLevel.L2_CONTENT_PROPOSAL
        ]:
            # §11.3 Level 3 constraints, applied from Level 2 upwards because a
            # documentation write is still a write.
            constraints["pull_request_required"] = True
            constraints["direct_push"] = False
        if level == PermissionLevel.L5_BREAK_GLASS:
            constraints["approvers_required"] = int(
                self.policies.constraints.get("break_glass_approvers", 2) or 2
            )
            constraints["explicit_targets_required"] = True
        if request.dry_run:
            constraints["dry_run"] = True
        if trace.requirements:
            # §12 `require:` entries (preserve_attribution, license_review). The
            # executor must be able to see these without parsing prose.
            constraints["requirements"] = list(trace.requirements)
            constraints["requirement_descriptions"] = {
                name: self.policies.requirement_descriptions.get(name, "")
                for name in trace.requirements
            }
        return constraints

    # -- state loading ----------------------------------------------------

    def _principal(self, request: ActionRequest, trace: _Trace) -> Principal:
        """Load the acting principal, or synthesise the most restrictive one.

        Only ``actor.id`` is looked up. ``actor.principal`` says *on whose behalf*
        the actor runs (§14) and must never be used as a fallback identity — an
        unregistered agent naming a human principal would otherwise inherit that
        human's ceiling, which is exactly the escalation axiom 2 forbids.
        """
        row = self.conn.execute(
            "SELECT * FROM principals WHERE id = ?", (request.actor.id,)
        ).fetchone()
        if row is not None:
            roles = [Role(r) for r in (loads(row["roles"], []) or []) if r in Role.__members__]
            return Principal(
                id=row["id"],
                tenant_id=row["tenant_id"],
                display_name=row["display_name"],
                actor_type=ActorType(row["actor_type"]),
                roles=roles,
                max_permission_level=PermissionLevel(row["max_permission_level"]),
                trust_level=row["trust_level"],
            )
        trace.match(
            "unregistered-principal",
            f"principal '{request.actor.id}' is not registered; treated as "
            f"{PermissionLevel.L0_INVENTORY} with no roles",
        )
        return Principal(
            id=request.actor.id,
            tenant_id=request.tenant_id,
            display_name=request.actor.id,
            actor_type=request.actor.type,
            roles=[],
            max_permission_level=PermissionLevel.L0_INVENTORY,
            trust_level="untrusted",
        )

    def _repositories(
        self, targets: list[str], trace: _Trace
    ) -> dict[str, RepositoryAsset]:
        out: dict[str, RepositoryAsset] = {}
        for target in targets:
            row = self.conn.execute(
                "SELECT * FROM repositories WHERE tenant_id = ? AND full_name = ?",
                (self.core.tenant_id, target),
            ).fetchone()
            if row is None:
                row = self.conn.execute(
                    "SELECT * FROM repositories WHERE full_name = ?", (target,)
                ).fetchone()
            if row is None:
                trace.match(
                    "unknown-target",
                    f"target '{target}' is not in the inventory; nothing is known about it",
                )
                continue
            out[target] = _repo_from_row(row)
        return out

    def _origin_profiles(
        self, repos: Mapping[str, RepositoryAsset]
    ) -> dict[str, OriginProfile]:
        """Read Phase 2 output defensively — the table may still be empty."""
        out: dict[str, OriginProfile] = {}
        for repo in repos.values():
            try:
                row = self.conn.execute(
                    "SELECT * FROM origin_profiles WHERE repository_id = ? "
                    "ORDER BY updated_at DESC LIMIT 1",
                    (repo.id,),
                ).fetchone()
            except sqlite3.Error:
                continue
            if row is None:
                continue
            out[repo.id] = OriginProfile(
                id=row["id"],
                repository_id=row["repository_id"],
                origin_type=_enum(OriginType, row["origin_type"], OriginType.UNKNOWN),
                origin_confidence=float(row["origin_confidence"] or 0.0),
                matched_rule=row["matched_rule"],
                license_status=_enum(
                    LicenseStatus, row["license_status"], LicenseStatus.UNKNOWN
                ),
            )
        return out

    def _attributes(
        self,
        request: ActionRequest,
        principal: Principal,
        repos: Mapping[str, RepositoryAsset],
        origins: Mapping[str, OriginProfile],
    ) -> dict[str, Any]:
        """§11.2 ABAC attribute set.

        Multi-target requests collapse to the *most restrictive* value on every
        axis: a batch is only as safe as its most dangerous member.
        """
        attrs: dict[str, Any] = {
            "tenant": request.tenant_id,
            "tool": request.tool,
            "actor_type": str(principal.actor_type),
            "role": [str(r) for r in principal.roles] or None,
            "trust_level": principal.trust_level,
        }
        if not repos:
            return attrs

        attrs["visibility"] = [str(r.visibility) for r in repos.values()]
        attrs["category"] = [str(r.category) for r in repos.values()]
        attrs["lifecycle"] = [str(r.lifecycle) for r in repos.values()]
        attrs["maturity"] = [str(r.maturity) for r in repos.values()]
        attrs["criticality"] = [str(r.criticality) for r in repos.values()]
        attrs["agent_access"] = [str(r.agent_access) for r in repos.values()]
        origin_types = [
            str(origins[r.id].origin_type) if r.id in origins else str(OriginType.UNKNOWN)
            for r in repos.values()
        ]
        attrs["origin_type"] = origin_types
        attrs["license_status"] = [
            str(origins[r.id].license_status) if r.id in origins else str(LicenseStatus.UNKNOWN)
            for r in repos.values()
        ]
        return attrs

    def _matching_abac(self, attributes: Mapping[str, Any]) -> list[PolicyRule]:
        return [rule for rule in self.policies.abac_rules if rule.matches(attributes)]


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

#: Origin types where somebody else's work is materially present, so an automatic
#: originality claim is never permitted (axiom 4). Mirrors
#: :data:`eveaegis.taxonomy.NO_AUTOMATIC_ORIGINALITY_CLAIM` minus UNKNOWN, which is
#: reported with its own, clearer reason string.
_NO_CLAIM_ORIGINS: frozenset[OriginType] = frozenset(
    {
        OriginType.GITHUB_FORK,
        OriginType.DETACHED_FORK,
        OriginType.MIRROR,
        OriginType.UPSTREAM_IMPORT,
        OriginType.DERIVATIVE_PROJECT,
        OriginType.MULTI_SOURCE_COMPOSITE,
        OriginType.VENDOR_SNAPSHOT,
    }
)


def _repo_from_row(row: sqlite3.Row) -> RepositoryAsset:
    return RepositoryAsset(
        id=row["id"],
        tenant_id=row["tenant_id"],
        installation_id=row["installation_id"],
        full_name=row["full_name"],
        github_repository_id=int(row["github_repository_id"] or 0),
        visibility=_enum(Visibility, row["visibility"], Visibility.PUBLIC),
        default_branch=row["default_branch"] or "main",
        description=row["description"],
        homepage=row["homepage"],
        topics=loads(row["topics"], []) or [],
        primary_language=row["primary_language"],
        languages=loads(row["languages"], {}) or {},
        license_spdx=row["license_spdx"],
        is_archived=bool(row["is_archived"]),
        is_fork=bool(row["is_fork"]),
        parent_full_name=row["parent_full_name"],
        source_full_name=row["source_full_name"],
        template_full_name=row["template_full_name"],
        size_kb=int(row["size_kb"] or 0),
        stargazers=int(row["stargazers"] or 0),
        open_issues=int(row["open_issues"] or 0),
        lifecycle=_enum(Lifecycle, row["lifecycle"], Lifecycle.UNKNOWN),
        category=_enum(Category, row["category"], Category.UNKNOWN),
        maturity=_enum(Maturity, row["maturity"], Maturity.UNKNOWN),
        criticality=_enum(Criticality, row["criticality"], Criticality.LOW),
        agent_access=_enum(AgentAccess, row["agent_access"], AgentAccess.READ_ONLY),
        origin_profile_id=row["origin_profile_id"],
        policy_profile=row["policy_profile"] or "default",
    )


def _enum(enum_cls: Any, value: Any, default: Any) -> Any:
    """Coerce a stored string into its enum, falling back to the safe member."""
    try:
        return enum_cls(value)
    except (ValueError, KeyError, TypeError):
        return default


def _scope(name: Any) -> TokenScope | None:
    if isinstance(name, TokenScope):
        return name
    if isinstance(name, str):
        try:
            return TokenScope(name)
        except ValueError:
            return None
    return None


def _fmt(value: Any) -> str:
    if isinstance(value, (list, tuple)):
        return "|".join(sorted({str(v) for v in value}))
    return str(value)
