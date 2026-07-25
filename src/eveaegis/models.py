"""Domain entities (§4 multi-tenant model, §6-§10 provenance, §14-§16 requests & plans).

These are the in-memory contracts every module speaks. Persistence lives in
:mod:`eveaegis.db`; nothing here knows about SQL.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .taxonomy import (
    ActorType,
    AgentAccess,
    Category,
    ComponentClass,
    Confidence,
    ContributionBand,
    Criticality,
    Decision,
    EvidenceKind,
    Lifecycle,
    LicenseStatus,
    Maturity,
    OriginType,
    PermissionLevel,
    PlanState,
    ReviewStatus,
    RiskLevel,
    Role,
    TenantType,
    Visibility,
)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


# --------------------------------------------------------------------------
# §4.2 Core entities
# --------------------------------------------------------------------------

class Tenant(Base):
    id: str
    name: str
    type: TenantType = TenantType.PERSONAL
    owners: list[str] = Field(default_factory=list)
    policy_profile: str = "default"


class Principal(Base):
    """A human or an agent. Agents are principals too — they just never hold secrets."""

    id: str
    tenant_id: str
    display_name: str
    actor_type: ActorType
    roles: list[Role] = Field(default_factory=list)
    #: Ceiling this principal can never exceed regardless of repository policy (axiom 2).
    max_permission_level: PermissionLevel = PermissionLevel.L0_INVENTORY
    trust_level: str = "standard"


class GitHubInstallation(Base):
    """§4.2 — one connected GitHub account/org, and what the credential layer may reach."""

    id: str
    tenant_id: str
    account_login: str
    account_type: str  # "user" | "organization"
    installation_id: int | None = None
    allowed_repositories: str = "selected"  # "selected" | "all"
    permission_snapshot: dict[str, str] = Field(default_factory=dict)
    credential_backend: str = "gh_cli"


class RepositoryAsset(Base):
    """§4.2 — the governed unit."""

    id: str
    tenant_id: str
    installation_id: str | None = None
    full_name: str
    github_repository_id: int
    visibility: Visibility = Visibility.PUBLIC
    default_branch: str = "main"
    description: str | None = None
    homepage: str | None = None
    topics: list[str] = Field(default_factory=list)
    primary_language: str | None = None
    languages: dict[str, int] = Field(default_factory=dict)
    license_spdx: str | None = None
    is_archived: bool = False
    is_fork: bool = False
    parent_full_name: str | None = None
    source_full_name: str | None = None
    template_full_name: str | None = None
    size_kb: int = 0
    stargazers: int = 0
    open_issues: int = 0
    pushed_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None

    # governance overlay, filled by later phases
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    category: Category = Category.UNKNOWN
    maturity: Maturity = Maturity.UNKNOWN
    criticality: Criticality = Criticality.LOW
    agent_access: AgentAccess = AgentAccess.READ_ONLY
    origin_profile_id: str | None = None
    policy_profile: str = "default"

    synced_at: datetime = Field(default_factory=utcnow)


# --------------------------------------------------------------------------
# §6-§8 Provenance
# --------------------------------------------------------------------------

class Evidence(Base):
    """One observable fact supporting or weakening an origin hypothesis.

    ``weight`` is the evidence's own strength in [0,1]; ``supports`` says which
    origin types it argues *for*. Nothing here is a conclusion.
    """

    kind: EvidenceKind
    key: str
    value: str
    weight: float = 0.0
    supports: list[OriginType] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)


class SimilarityVector(Base):
    """§7.1 — layered similarity S(A,B). ``None`` means "not computed", not "zero"."""

    commit: float | None = None
    blob: float | None = None
    text: float | None = None
    token: float | None = None
    ast: float | None = None
    semantic: float | None = None

    def strongest(self) -> tuple[str, float] | None:
        pairs = [(k, v) for k, v in self.model_dump().items() if v is not None]
        return max(pairs, key=lambda kv: kv[1]) if pairs else None


class UpstreamCandidate(Base):
    """A repository that might be an ancestor of the asset under analysis."""

    full_name: str
    discovered_via: str
    similarity: SimilarityVector = Field(default_factory=SimilarityVector)
    shared_root_commit: bool = False
    merge_base: str | None = None
    confidence: float = 0.0
    notes: str | None = None


class ComponentProfile(Base):
    """§9.3 — per-path classification so dependencies never inflate upstream retention."""

    path: str
    component_class: ComponentClass
    bytes: int = 0
    files: int = 0
    reason: str | None = None


class ContributionEstimate(Base):
    """§8.2 — ranges, never a single headline number."""

    upstream_retained_min: float | None = None
    upstream_retained_max: float | None = None
    local_contribution_min: float | None = None
    local_contribution_max: float | None = None
    transformation_score: float | None = None
    band: ContributionBand = ContributionBand.UNKNOWN
    confidence: Confidence = Confidence.LOW
    per_dimension: dict[str, float] = Field(default_factory=dict)


class PublicLabel(Base):
    """§23.2 — the conservative, outward-facing view."""

    label: str
    attribution: str | None = None
    originality_claim: str = "none"


class OriginProfile(Base):
    """§6/§20.1 — the full verdict for one repository, internal + public split."""

    id: str
    repository_id: str
    origin_type: OriginType = OriginType.UNKNOWN
    origin_confidence: float = 0.0
    matched_rule: str | None = None
    evidence: list[Evidence] = Field(default_factory=list)
    upstream_candidates: list[UpstreamCandidate] = Field(default_factory=list)
    components: list[ComponentProfile] = Field(default_factory=list)
    contribution: ContributionEstimate = Field(default_factory=ContributionEstimate)
    license_status: LicenseStatus = LicenseStatus.UNKNOWN
    public: PublicLabel | None = None
    review_status: ReviewStatus = ReviewStatus.UNREVIEWED
    reviewed_by: str | None = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)


class ClassificationResult(Base):
    """§5 — what the classifier concluded, and why."""

    repository_id: str
    category: Category = Category.UNKNOWN
    lifecycle: Lifecycle = Lifecycle.UNKNOWN
    maturity: Maturity = Maturity.UNKNOWN
    criticality: Criticality = Criticality.LOW
    agent_access: AgentAccess = AgentAccess.READ_ONLY
    confidence: float = 0.0
    signals: dict[str, Any] = Field(default_factory=dict)
    rationale: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------
# §14-§16 Requests, decisions, plans
# --------------------------------------------------------------------------

class Actor(Base):
    type: ActorType
    id: str
    principal: str


class ActionRequest(Base):
    """§14 — what an agent submits. Agents submit *requests*, never credentials."""

    request_id: str
    actor: Actor
    tenant_id: str
    tool: str
    targets: list[str] = Field(default_factory=list)
    parameters: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    dry_run: bool = True
    requested_level: PermissionLevel = PermissionLevel.L0_INVENTORY
    created_at: datetime = Field(default_factory=utcnow)


class PolicyDecision(Base):
    """§15 — the answer, with the constraints the executor must honour."""

    request_id: str
    decision: Decision
    risk: RiskLevel = RiskLevel.LOW
    constraints: dict[str, Any] = Field(default_factory=dict)
    matched_policies: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    token_scope: str | None = None
    token_lifetime_seconds: int = 300
    decided_at: datetime = Field(default_factory=utcnow)

    @property
    def permits_execution(self) -> bool:
        return self.decision in (Decision.ALLOW, Decision.ALLOW_WITH_CONSTRAINTS)


class Change(Base):
    """One reversible mutation against one repository."""

    type: str
    before: Any = None
    after: Any = None
    add: list[str] = Field(default_factory=list)
    remove: list[str] = Field(default_factory=list)


class TargetChanges(Base):
    repository: str
    changes: list[Change] = Field(default_factory=list)


class ChangePlan(Base):
    """§16 — inspect → plan → preview → approve → apply, materialised."""

    id: str
    request_id: str
    actor: str
    tenant: str
    state: PlanState = PlanState.DRAFT
    targets: list[TargetChanges] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)
    risk_level: RiskLevel = RiskLevel.LOW
    risk_reasons: list[str] = Field(default_factory=list)
    approval_required: bool = True
    approved_by: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=utcnow)
    expires_at: datetime | None = None


class AuditEvent(Base):
    """§18 — append-only, hash-chained."""

    event_id: str
    sequence: int = 0
    request_id: str | None = None
    plan_id: str | None = None
    actor: str = "system"
    initiated_by: str | None = None
    tenant: str | None = None
    action: str = ""
    targets: list[str] = Field(default_factory=list)
    policy_decision: Decision | None = None
    approved_by: list[str] = Field(default_factory=list)
    credential_type: str | None = None
    credential_scope: str | None = None
    before_hash: str | None = None
    after_hash: str | None = None
    result: str = "COMPLETED"
    detail: dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=utcnow)
    prev_event_hash: str | None = None
    event_hash: str | None = None
