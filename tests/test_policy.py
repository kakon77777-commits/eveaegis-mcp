"""§11-§12, §15 policy engine — and the axioms of §3 it is supposed to enforce.

Most of these are security tests: they assert that something is *refused*. When
one fails, the system is more permissive than the whitepaper allows, which is the
only kind of regression here that cannot be caught by looking at the happy path.
"""

from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from eveaegis.config import Config, CredentialConfig, GovernanceConfig
from eveaegis.core import GovernanceCore
from eveaegis.credentials.base import SCOPE_RANK, TokenScope
from eveaegis.db import dumps
from eveaegis.models import ActionRequest, Actor
from eveaegis.policy import TOOL_LEVELS, PolicyEngine, assess_risk, load_policies
from eveaegis.policy.rules import DEFAULT_TOOL_LEVEL, PolicyRule
from eveaegis.taxonomy import (
    CRITICALITY_EVIDENCE_RANK,
    CRITICALITY_RISK_RANK,
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
)

from conftest import FakeBroker  # pytest puts tests/ on sys.path (rootdir conftest)

TENANT = "test-tenant"


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

def _make_core(tmp_path: Path, **governance: Any) -> GovernanceCore:
    settings: dict[str, Any] = dict(
        tenant_id=TENANT,
        tenant_name="Test",
        read_only=True,
        require_human_approval=True,
    )
    settings.update(governance)
    cfg = Config(
        database_path=str(tmp_path / f"{uuid.uuid4().hex}.db"),
        credentials=CredentialConfig(max_token_lifetime_seconds=600),
        governance=GovernanceConfig(**settings),
    )
    return GovernanceCore(cfg, broker=FakeBroker())


@pytest.fixture
def writable_core(tmp_path: Path):
    """A core with the Phase 0 read-only brake released, so writes are reachable."""
    core = _make_core(tmp_path, read_only=False, require_human_approval=False)
    yield core
    core.close()


@pytest.fixture
def readonly_core(tmp_path: Path):
    core = _make_core(tmp_path, read_only=True)
    yield core
    core.close()


def add_repo(
    core: GovernanceCore,
    full_name: str,
    *,
    visibility: str = "public",
    lifecycle: Lifecycle = Lifecycle.ACTIVE,
    category: Category = Category.PRODUCT,
    maturity: Maturity = Maturity.STABLE,
    criticality: Criticality = Criticality.LOW,
    agent_access: AgentAccess = AgentAccess.CONTROLLED_WRITE,
    is_fork: bool = False,
) -> str:
    repo_id = f"repo_{uuid.uuid4().hex[:10]}"
    now = datetime.now(timezone.utc).isoformat()
    core.conn.execute(
        """
        INSERT INTO repositories
            (id, tenant_id, full_name, github_repository_id, visibility, default_branch,
             description, homepage, topics, primary_language, languages, license_spdx,
             is_archived, is_fork, size_kb, stargazers, open_issues, pushed_at,
             created_at, updated_at, lifecycle, category, maturity, criticality,
             agent_access, policy_profile, synced_at)
        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """,
        (
            repo_id, TENANT, full_name, abs(hash(full_name)) % 10**8, visibility, "main",
            "", None, dumps([]), "Python", dumps({}), "MIT",
            0, int(is_fork), 100, 0, 0, now,
            now, now, str(lifecycle), str(category), str(maturity), str(criticality),
            str(agent_access), "default", now,
        ),
    )
    core.conn.commit()
    return repo_id


def add_origin(
    core: GovernanceCore,
    repository_id: str,
    origin_type: OriginType,
    *,
    confidence: float = 0.9,
    license_status: LicenseStatus = LicenseStatus.CLEAR,
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
            f"org_{uuid.uuid4().hex[:10]}", repository_id, str(origin_type), confidence,
            str(license_status), "REVIEWED", now, now,
        ),
    )
    core.conn.commit()


def add_principal(
    core: GovernanceCore,
    principal_id: str,
    *,
    actor_type: ActorType = ActorType.AGENT,
    roles: list[Role] | None = None,
    max_level: PermissionLevel = PermissionLevel.L0_INVENTORY,
) -> None:
    core.conn.execute(
        """
        INSERT INTO principals
            (id, tenant_id, display_name, actor_type, roles, max_permission_level,
             trust_level, created_at)
        VALUES (?,?,?,?,?,?,?,?)
        ON CONFLICT(id) DO UPDATE SET
            roles = excluded.roles, max_permission_level = excluded.max_permission_level
        """,
        (
            principal_id, TENANT, principal_id, str(actor_type),
            dumps([str(r) for r in (roles or [Role.AGENT])]), str(max_level),
            "standard", datetime.now(timezone.utc).isoformat(),
        ),
    )
    core.conn.commit()


def make_request(
    tool: str,
    targets: list[str] | None = None,
    *,
    actor_id: str = "agent:local",
    actor_type: ActorType = ActorType.AGENT,
    principal: str = "human:owner",
    dry_run: bool = True,
    parameters: dict[str, Any] | None = None,
) -> ActionRequest:
    return ActionRequest(
        request_id=f"req_{uuid.uuid4().hex[:8]}",
        actor=Actor(type=actor_type, id=actor_id, principal=principal),
        tenant_id=TENANT,
        tool=tool,
        targets=targets or [],
        parameters=parameters or {},
        reason="unit test",
        dry_run=dry_run,
    )


# --------------------------------------------------------------------------
# §13 tool map — fail closed
# --------------------------------------------------------------------------

class TestFailClosed:
    def test_unknown_tool_resolves_to_break_glass(self, readonly_core: GovernanceCore) -> None:
        """The security property: an unmapped tool is not an unguarded tool."""
        engine = PolicyEngine(readonly_core)
        assert engine.required_level("totally_made_up_tool") == PermissionLevel.L5_BREAK_GLASS
        assert DEFAULT_TOOL_LEVEL == PermissionLevel.L5_BREAK_GLASS

    def test_unknown_tool_is_denied_not_merely_escalated(
        self, writable_core: GovernanceCore
    ) -> None:
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(make_request("exfiltrate_everything"))
        assert decision.decision == Decision.DENY
        assert "unknown-tool-fail-closed" in decision.matched_policies

    def test_every_whitepaper_tool_is_mapped(self) -> None:
        """§13.1-§13.7. If a name here is missing, the engine silently break-glasses it."""
        expected = {
            # §13.1
            "inventory_accounts", "inventory_repositories", "refresh_repository",
            "get_portfolio_summary", "find_unclassified_repositories",
            # §13.2
            "analyze_repository_origin", "compare_repository_lineage",
            "find_candidate_upstreams", "estimate_local_contribution",
            "generate_provenance_report", "review_provenance_decision",
            # §13.3
            "classify_repository", "classify_portfolio", "propose_lifecycle",
            "propose_repository_category", "detect_archive_candidates",
            "detect_superseded_projects",
            # §13.4
            "evaluate_action_policy", "create_change_plan", "preview_change_plan",
            "approve_change_plan", "execute_approved_plan", "rollback_change_plan",
            # §13.5
            "propose_repository_metadata", "apply_repository_taxonomy",
            "standardize_topics", "standardize_descriptions", "generate_project_catalog",
            # §13.6
            "propose_readme_update", "create_documentation_branch",
            "create_documentation_pr", "add_origin_notice", "add_superseded_notice",
            # §13.7
            "archive_repository", "transfer_repository", "change_visibility",
            "modify_ruleset", "modify_collaborators", "delete_repository",
        }
        assert expected <= set(TOOL_LEVELS)

    def test_config_may_tighten_a_tool_but_never_loosen_it(self, tmp_path: Path) -> None:
        policy_dir = tmp_path / "policies"
        policy_dir.mkdir()
        (policy_dir / "core.yaml").write_text(
            "tools:\n  levels:\n    delete_repository: L0_INVENTORY\n", "utf-8"
        )
        loosened = load_policies(policy_dir)
        assert loosened.level_for("delete_repository") == PermissionLevel.L5_BREAK_GLASS

    def test_missing_policy_files_do_not_open_a_hole(self, tmp_path: Path) -> None:
        empty = load_policies(tmp_path / "nothing-here")
        assert empty.level_for("delete_repository") == PermissionLevel.L5_BREAK_GLASS
        assert empty.level_for("who_knows") == PermissionLevel.L5_BREAK_GLASS


# --------------------------------------------------------------------------
# governance.read_only — the coarse gate in front of the policy engine
# --------------------------------------------------------------------------

class TestReadOnlyMode:
    def test_read_only_denies_every_write_tool(self, readonly_core: GovernanceCore) -> None:
        repo = add_repo(readonly_core, "acme/site")
        add_origin(readonly_core, repo, OriginType.ORIGINAL)
        engine = PolicyEngine(readonly_core)
        for tool in ("standardize_topics", "create_documentation_pr", "execute_approved_plan"):
            decision = engine.evaluate(make_request(tool, ["acme/site"]))
            assert decision.decision == Decision.DENY, tool
            assert "governance-read-only" in decision.matched_policies, tool

    def test_read_only_still_allows_inventory(self, readonly_core: GovernanceCore) -> None:
        add_repo(readonly_core, "acme/site")
        engine = PolicyEngine(readonly_core)
        decision = engine.evaluate(make_request("get_portfolio_summary", ["acme/site"]))
        assert decision.decision in (Decision.ALLOW, Decision.ALLOW_WITH_CONSTRAINTS)


# --------------------------------------------------------------------------
# Axiom 2 — capability ⊆ authorization
# --------------------------------------------------------------------------

class TestAxiom2Ceilings:
    def test_agent_cannot_exceed_its_ceiling_on_a_permissive_repository(
        self, writable_core: GovernanceCore
    ) -> None:
        """The repository says CONTROLLED_WRITE; the principal says L0. L0 wins."""
        repo = add_repo(
            writable_core, "acme/permissive", agent_access=AgentAccess.CONTROLLED_WRITE
        )
        add_origin(writable_core, repo, OriginType.ORIGINAL)
        add_principal(
            writable_core, "agent:weak", max_level=PermissionLevel.L0_INVENTORY
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request("create_documentation_pr", ["acme/permissive"], actor_id="agent:weak")
        )
        assert decision.decision == Decision.DENY
        assert "axiom-2-capability-subset" in decision.matched_policies
        assert decision.constraints["effective_ceiling"] == str(PermissionLevel.L0_INVENTORY)

    def test_repository_ceiling_binds_a_powerful_principal(
        self, writable_core: GovernanceCore
    ) -> None:
        """The mirror image: an OWNER is still bound by the repository's agent_access."""
        repo = add_repo(writable_core, "acme/frozen", agent_access=AgentAccess.READ_ONLY)
        add_origin(writable_core, repo, OriginType.ORIGINAL)
        add_principal(
            writable_core,
            "human:boss",
            actor_type=ActorType.HUMAN,
            roles=[Role.OWNER],
            max_level=PermissionLevel.L5_BREAK_GLASS,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "standardize_topics",
                ["acme/frozen"],
                actor_id="human:boss",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.decision == Decision.DENY
        assert "axiom-2-capability-subset" in decision.matched_policies

    def test_unregistered_principal_gets_the_lowest_ceiling(
        self, writable_core: GovernanceCore
    ) -> None:
        add_repo(writable_core, "acme/site")
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request("standardize_topics", ["acme/site"], actor_id="agent:ghost")
        )
        assert decision.decision == Decision.DENY
        assert "unregistered-principal" in decision.matched_policies

    def test_administration_tools_are_denied_to_agents(
        self, writable_core: GovernanceCore
    ) -> None:
        """§13.7 is 'not exposed to general agents' — enforced, not just documented."""
        repo = add_repo(writable_core, "acme/site", agent_access=AgentAccess.ADMIN_APPROVAL)
        add_origin(writable_core, repo, OriginType.ORIGINAL)
        add_principal(
            writable_core, "agent:strong", max_level=PermissionLevel.L4_REPOSITORY_ADMIN
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request("change_visibility", ["acme/site"], actor_id="agent:strong")
        )
        assert decision.decision == Decision.DENY
        assert "agent-write-ceiling" in decision.matched_policies


# --------------------------------------------------------------------------
# Axiom 3 — inspect → plan → preview → approve → apply
# --------------------------------------------------------------------------

class TestAxiom3Plans:
    def _setup(self, core: GovernanceCore) -> PolicyEngine:
        # HIGH criticality so an approval is genuinely required before apply, which
        # is what separates "blocked now" from "needs a human eventually".
        repo = add_repo(
            core, "acme/site", agent_access=AgentAccess.PR_ONLY, criticality=Criticality.HIGH
        )
        add_origin(core, repo, OriginType.ORIGINAL)
        add_principal(
            core,
            "human:writer",
            actor_type=ActorType.HUMAN,
            roles=[Role.DEVELOPER],
            max_level=PermissionLevel.L2_CONTENT_PROPOSAL,
        )
        return PolicyEngine(core)

    def test_write_without_a_plan_requires_approval(
        self, writable_core: GovernanceCore
    ) -> None:
        engine = self._setup(writable_core)
        decision = engine.evaluate(
            make_request(
                "create_documentation_pr",
                ["acme/site"],
                actor_id="human:writer",
                actor_type=ActorType.HUMAN,
                dry_run=False,
            )
        )
        assert decision.decision == Decision.REQUIRE_APPROVAL
        assert "axiom-3-plan-required" in decision.matched_policies

    def test_dry_run_is_the_preview_step_and_needs_no_approval_yet(
        self, writable_core: GovernanceCore
    ) -> None:
        engine = self._setup(writable_core)
        decision = engine.evaluate(
            make_request(
                "create_documentation_pr",
                ["acme/site"],
                actor_id="human:writer",
                actor_type=ActorType.HUMAN,
                dry_run=True,
            )
        )
        assert decision.decision == Decision.ALLOW_WITH_CONSTRAINTS
        # …but it must still say that applying the result needs a human.
        assert decision.constraints["approval_required"] is True

    def test_an_approved_plan_unblocks_the_write(self, writable_core: GovernanceCore) -> None:
        engine = self._setup(writable_core)
        now = datetime.now(timezone.utc).isoformat()
        writable_core.conn.execute(
            "INSERT INTO change_plans (id, request_id, tenant_id, actor_id, state, created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("plan_1", "req_1", TENANT, "human:writer", "APPROVED", now),
        )
        writable_core.conn.commit()
        decision = engine.evaluate(
            make_request(
                "create_documentation_pr",
                ["acme/site"],
                actor_id="human:writer",
                actor_type=ActorType.HUMAN,
                dry_run=False,
                parameters={"plan_id": "plan_1"},
            )
        )
        assert decision.decision == Decision.ALLOW_WITH_CONSTRAINTS
        assert "axiom-3-approved-plan" in decision.matched_policies

    def test_a_draft_plan_does_not_unblock_the_write(
        self, writable_core: GovernanceCore
    ) -> None:
        engine = self._setup(writable_core)
        now = datetime.now(timezone.utc).isoformat()
        writable_core.conn.execute(
            "INSERT INTO change_plans (id, request_id, tenant_id, actor_id, state, created_at) "
            "VALUES (?,?,?,?,?,?)",
            ("plan_2", "req_2", TENANT, "human:writer", "DRAFT", now),
        )
        writable_core.conn.commit()
        decision = engine.evaluate(
            make_request(
                "create_documentation_pr",
                ["acme/site"],
                actor_id="human:writer",
                actor_type=ActorType.HUMAN,
                dry_run=False,
                parameters={"plan_id": "plan_2"},
            )
        )
        assert decision.decision == Decision.REQUIRE_APPROVAL


# --------------------------------------------------------------------------
# Axiom 4 — unknown provenance ⇒ no automatic public originality claim
# --------------------------------------------------------------------------

class TestAxiom4Originality:
    def test_unknown_origin_denies_an_originality_claim(
        self, writable_core: GovernanceCore
    ) -> None:
        repo = add_repo(writable_core, "acme/mystery", agent_access=AgentAccess.METADATA_WRITE)
        add_origin(writable_core, repo, OriginType.UNKNOWN, confidence=0.1)
        add_principal(
            writable_core,
            "human:pm",
            actor_type=ActorType.HUMAN,
            roles=[Role.PORTFOLIO_MANAGER],
            max_level=PermissionLevel.L2_CONTENT_PROPOSAL,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "standardize_descriptions",
                ["acme/mystery"],
                actor_id="human:pm",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.decision == Decision.DENY
        assert "axiom-4-unknown-origin" in decision.matched_policies

    def test_missing_origin_profile_is_treated_as_unknown(
        self, writable_core: GovernanceCore
    ) -> None:
        """Phase 2 has not run. 'Not analysed' must not read as 'safe'."""
        add_repo(writable_core, "acme/unanalysed", agent_access=AgentAccess.METADATA_WRITE)
        add_principal(
            writable_core,
            "human:pm",
            actor_type=ActorType.HUMAN,
            roles=[Role.PORTFOLIO_MANAGER],
            max_level=PermissionLevel.L2_CONTENT_PROPOSAL,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "generate_project_catalog",
                ["acme/unanalysed"],
                actor_id="human:pm",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.decision == Decision.DENY
        assert "axiom-4-unknown-origin" in decision.matched_policies

    def test_fork_origin_denies_an_originality_claim(
        self, writable_core: GovernanceCore
    ) -> None:
        repo = add_repo(
            writable_core, "acme/forked", agent_access=AgentAccess.PR_ONLY, is_fork=True
        )
        add_origin(writable_core, repo, OriginType.GITHUB_FORK)
        add_principal(
            writable_core,
            "human:pm",
            actor_type=ActorType.HUMAN,
            roles=[Role.PORTFOLIO_MANAGER],
            max_level=PermissionLevel.L2_CONTENT_PROPOSAL,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "propose_repository_metadata",
                ["acme/forked"],
                actor_id="human:pm",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.decision == Decision.DENY
        assert any(p.startswith("axiom-4") for p in decision.matched_policies)

    def test_original_origin_permits_the_same_claim(
        self, writable_core: GovernanceCore
    ) -> None:
        """The control case: axiom 4 blocks unknown provenance, not all metadata."""
        repo = add_repo(writable_core, "acme/ours", agent_access=AgentAccess.METADATA_WRITE)
        add_origin(writable_core, repo, OriginType.ORIGINAL)
        add_principal(
            writable_core,
            "human:pm",
            actor_type=ActorType.HUMAN,
            roles=[Role.PORTFOLIO_MANAGER],
            max_level=PermissionLevel.L2_CONTENT_PROPOSAL,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "propose_repository_metadata",
                ["acme/ours"],
                actor_id="human:pm",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.decision == Decision.ALLOW_WITH_CONSTRAINTS
        assert "original-project-default" in decision.matched_policies


# --------------------------------------------------------------------------
# §12 origin bindings
# --------------------------------------------------------------------------

class TestOriginBindings:
    def test_mirror_policy_denies_autonomous_rewrite(
        self, writable_core: GovernanceCore
    ) -> None:
        repo = add_repo(writable_core, "acme/mirror", agent_access=AgentAccess.CONTROLLED_WRITE)
        add_origin(writable_core, repo, OriginType.MIRROR)
        add_principal(
            writable_core,
            "human:dev",
            actor_type=ActorType.HUMAN,
            roles=[Role.MAINTAINER],
            max_level=PermissionLevel.L3_CONTROLLED_CODE_WRITE,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "execute_approved_plan",
                ["acme/mirror"],
                actor_id="human:dev",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.decision == Decision.DENY
        assert "mirror-policy" in decision.matched_policies

    def test_fork_policy_attaches_its_requirements(
        self, writable_core: GovernanceCore
    ) -> None:
        repo = add_repo(writable_core, "acme/patched", agent_access=AgentAccess.PR_ONLY)
        add_origin(writable_core, repo, OriginType.DETACHED_FORK)
        add_principal(
            writable_core,
            "human:dev",
            actor_type=ActorType.HUMAN,
            roles=[Role.DEVELOPER],
            max_level=PermissionLevel.L2_CONTENT_PROPOSAL,
        )
        engine = PolicyEngine(writable_core)
        request = make_request(
            "create_documentation_pr",
            ["acme/patched"],
            actor_id="human:dev",
            actor_type=ActorType.HUMAN,
        )
        decision = engine.evaluate(request)
        assert "fork-policy" in decision.matched_policies
        # The executor must see the requirements as data, not only as prose.
        assert set(decision.constraints["requirements"]) >= {
            "preserve_attribution",
            "license_review",
        }
        joined = " ".join(decision.reasons)
        assert "preserve_attribution" in joined and "license_review" in joined


# --------------------------------------------------------------------------
# Axiom 5 — risk up, scope down, lifetime down, approval up
# --------------------------------------------------------------------------

class TestAxiom5RiskShortensCredentials:
    def test_risk_escalation_shortens_the_token_lifetime(
        self, writable_core: GovernanceCore
    ) -> None:
        low = add_repo(
            writable_core, "acme/low", criticality=Criticality.LOW,
            visibility="private", agent_access=AgentAccess.CONTROLLED_WRITE,
        )
        add_origin(writable_core, low, OriginType.ORIGINAL)
        high = add_repo(
            writable_core, "acme/high", criticality=Criticality.CRITICAL,
            agent_access=AgentAccess.CONTROLLED_WRITE,
        )
        add_origin(writable_core, high, OriginType.GITHUB_FORK)
        add_principal(
            writable_core,
            "human:dev",
            actor_type=ActorType.HUMAN,
            roles=[Role.MAINTAINER],
            max_level=PermissionLevel.L3_CONTROLLED_CODE_WRITE,
        )
        engine = PolicyEngine(writable_core)

        quiet = engine.evaluate(
            make_request(
                "get_portfolio_summary", ["acme/low"],
                actor_id="human:dev", actor_type=ActorType.HUMAN,
            )
        )
        loud = engine.evaluate(
            make_request(
                "execute_approved_plan", ["acme/high"],
                actor_id="human:dev", actor_type=ActorType.HUMAN,
            )
        )
        assert quiet.risk == RiskLevel.LOW
        assert loud.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert loud.token_lifetime_seconds < quiet.token_lifetime_seconds

    def test_critical_risk_caps_lifetime_at_sixty_seconds_and_demands_break_glass(
        self, writable_core: GovernanceCore
    ) -> None:
        for i in range(30):
            repo = add_repo(
                writable_core, f"acme/critical-{i}",
                criticality=Criticality.CRITICAL,
                agent_access=AgentAccess.BREAK_GLASS,
            )
            add_origin(writable_core, repo, OriginType.UNKNOWN, confidence=0.1)
        add_principal(
            writable_core,
            "human:boss",
            actor_type=ActorType.HUMAN,
            roles=[Role.OWNER],
            max_level=PermissionLevel.L5_BREAK_GLASS,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "archive_repository",
                [f"acme/critical-{i}" for i in range(30)],
                actor_id="human:boss",
                actor_type=ActorType.HUMAN,
            )
        )
        assert decision.risk == RiskLevel.CRITICAL
        assert decision.token_lifetime_seconds <= 60
        assert decision.decision in (Decision.DENY, Decision.REQUIRE_BREAK_GLASS)

    def test_high_risk_narrows_the_token_scope(self, writable_core: GovernanceCore) -> None:
        repo = add_repo(
            writable_core, "acme/risky", criticality=Criticality.HIGH,
            agent_access=AgentAccess.CONTROLLED_WRITE,
        )
        add_origin(writable_core, repo, OriginType.ORIGINAL, license_status=LicenseStatus.CLEAR)
        add_principal(
            writable_core,
            "human:dev",
            actor_type=ActorType.HUMAN,
            roles=[Role.MAINTAINER],
            max_level=PermissionLevel.L3_CONTROLLED_CODE_WRITE,
        )
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(
            make_request(
                "execute_approved_plan", ["acme/risky"],
                actor_id="human:dev", actor_type=ActorType.HUMAN,
            )
        )
        if decision.token_scope is not None:
            assert (
                SCOPE_RANK[TokenScope(decision.token_scope)]
                <= SCOPE_RANK[TokenScope.WRITE_CONTENT_DIRECT]
            )
        assert decision.risk in (RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL)

    def test_denied_requests_buy_no_credential(self, readonly_core: GovernanceCore) -> None:
        repo = add_repo(readonly_core, "acme/site")
        add_origin(readonly_core, repo, OriginType.ORIGINAL)
        engine = PolicyEngine(readonly_core)
        decision = engine.evaluate(make_request("standardize_topics", ["acme/site"]))
        assert decision.decision == Decision.DENY
        assert decision.token_scope is None


# --------------------------------------------------------------------------
# §15 decision shape and §18 audit
# --------------------------------------------------------------------------

class TestDecisionShape:
    @pytest.mark.parametrize(
        "tool, targets",
        [
            ("get_portfolio_summary", []),
            ("inventory_repositories", ["acme/site"]),
            ("standardize_topics", ["acme/site"]),
            ("delete_repository", ["acme/site"]),
            ("no_such_tool", ["acme/site"]),
            ("classify_repository", ["acme/missing-from-inventory"]),
        ],
    )
    def test_matched_policies_and_reasons_are_never_empty(
        self, writable_core: GovernanceCore, tool: str, targets: list[str]
    ) -> None:
        """A decision nobody can explain is a bug, whatever the verdict is."""
        repo = add_repo(writable_core, "acme/site")
        add_origin(writable_core, repo, OriginType.ORIGINAL)
        engine = PolicyEngine(writable_core)
        decision = engine.evaluate(make_request(tool, targets))
        assert decision.matched_policies, f"{tool} produced no matched policies"
        assert decision.reasons, f"{tool} produced no reasons"

    def test_every_evaluation_is_recorded_in_the_ledger(
        self, writable_core: GovernanceCore
    ) -> None:
        add_repo(writable_core, "acme/site")
        engine = PolicyEngine(writable_core)
        before = writable_core.ledger.count()
        request = make_request("get_portfolio_summary", ["acme/site"])
        decision = engine.evaluate(request)
        assert writable_core.ledger.count() == before + 1
        event = writable_core.ledger.recent(1)[0]
        assert event.action == "policy_decision"
        assert event.request_id == request.request_id
        assert event.policy_decision == decision.decision
        assert event.detail["matched_policies"] == decision.matched_policies
        ok, message = writable_core.ledger.verify()
        assert ok, message

    def test_explain_names_the_rules_that_fired(self, writable_core: GovernanceCore) -> None:
        repo = add_repo(writable_core, "acme/site", agent_access=AgentAccess.READ_ONLY)
        add_origin(writable_core, repo, OriginType.ORIGINAL)
        engine = PolicyEngine(writable_core)
        text = engine.explain(make_request("standardize_topics", ["acme/site"]))
        assert "decision :" in text and "risk     :" in text
        assert "acme/site" in text
        assert "axiom-2" in text

    def test_explain_does_not_write_to_the_ledger(self, writable_core: GovernanceCore) -> None:
        add_repo(writable_core, "acme/site")
        engine = PolicyEngine(writable_core)
        before = writable_core.ledger.count()
        engine.explain(make_request("get_portfolio_summary", ["acme/site"]))
        assert writable_core.ledger.count() == before


# --------------------------------------------------------------------------
# rules & risk units
# --------------------------------------------------------------------------

class TestRuleMatching:
    def test_a_rule_never_fires_on_an_unresolved_attribute(self) -> None:
        rule = PolicyRule(id="r", when={"origin_type": ("UNKNOWN",)})
        assert rule.matches({"origin_type": "UNKNOWN"})
        assert not rule.matches({})
        assert not rule.matches({"origin_type": None})

    def test_a_rule_with_no_condition_never_fires(self) -> None:
        assert not PolicyRule(id="empty").matches({"anything": "goes"})

    def test_list_attributes_match_on_intersection(self) -> None:
        """A batch is as dangerous as its most dangerous member."""
        rule = PolicyRule(id="r", when={"criticality": ("CRITICAL",)})
        assert rule.matches({"criticality": ["LOW", "CRITICAL"]})
        assert not rule.matches({"criticality": ["LOW", "MEDIUM"]})

    def test_origin_fallbacks_bind_types_section_12_does_not_name(self) -> None:
        cfg = load_policies("config/policies")
        rule = cfg.origin_rule_for(str(OriginType.VENDOR_SNAPSHOT))
        assert rule is not None and rule.id == "mirror-policy"
        assert cfg.origin_rule_for("SOMETHING_NEW") is not None


class TestRiskScoring:
    def test_risk_grows_with_target_count(self, writable_core: GovernanceCore) -> None:
        cfg = load_policies("config/policies")
        one = make_request("standardize_topics", ["a/b"])
        many = make_request("standardize_topics", [f"a/b{i}" for i in range(60)])
        low, _ = assess_risk(one, {}, {}, cfg)
        high, reasons = assess_risk(many, {}, {}, cfg)
        assert high != low
        assert any("targets" in r for r in reasons)

    def test_risk_reasons_are_always_present(self) -> None:
        cfg = load_policies("config/policies")
        level, reasons = assess_risk(make_request("get_portfolio_summary"), {}, {}, cfg)
        assert level == RiskLevel.LOW
        assert reasons


class TestUngradedCriticality:
    """§5.4 was extended with UNKNOWN; these pin down what that must mean.

    Two orderings exist on purpose. The classifier escalates along the *evidence*
    ordering, where UNKNOWN is the floor. The risk engine ranks along the *risk*
    ordering, where UNKNOWN sits above MEDIUM. Collapsing them back into one table
    would silently make "nobody ever classified it" the safest thing in the
    portfolio, so both directions are asserted here.
    """

    def test_the_two_orderings_disagree_on_purpose(self) -> None:
        assert CRITICALITY_EVIDENCE_RANK[Criticality.UNKNOWN] < CRITICALITY_EVIDENCE_RANK[
            Criticality.LOW
        ]
        assert CRITICALITY_RISK_RANK[Criticality.UNKNOWN] > CRITICALITY_RISK_RANK[
            Criticality.MEDIUM
        ]

    def test_ungraded_target_outranks_a_graded_low_one(
        self, writable_core: GovernanceCore
    ) -> None:
        cfg = load_policies("config/policies")
        add_repo(writable_core, "acme/graded", criticality=Criticality.LOW)
        add_repo(writable_core, "acme/ungraded", criticality=Criticality.UNKNOWN)
        repos = {r.full_name: r for r in _repos(writable_core)}

        _, graded_reasons = assess_risk(
            make_request("standardize_topics", ["acme/graded"]), repos, {}, cfg
        )
        _, ungraded_reasons = assess_risk(
            make_request("standardize_topics", ["acme/ungraded"]), repos, {}, cfg
        )
        assert _score(ungraded_reasons) > _score(graded_reasons)
        assert any("UNKNOWN" in r for r in ungraded_reasons)

    def test_ungraded_target_requires_human_approval(
        self, writable_core: GovernanceCore
    ) -> None:
        add_repo(writable_core, "acme/ungraded", criticality=Criticality.UNKNOWN)
        decision = PolicyEngine(writable_core).evaluate(
            make_request("standardize_topics", ["acme/ungraded"])
        )
        assert "ungraded-criticality-approval" in decision.matched_policies
        assert decision.constraints.get("approval_required") is True


def _score(reasons: list[str]) -> float:
    """Pull the numeric score back out of the first reason line."""
    head = reasons[0]
    return float(head.split("risk score ", 1)[1].split(" ", 1)[0])


def _repos(core: GovernanceCore) -> list[Any]:
    from eveaegis.inventory.sync import row_to_asset

    return [row_to_asset(r) for r in core.conn.execute("SELECT * FROM repositories")]
