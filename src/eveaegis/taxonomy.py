"""Controlled vocabularies from the whitepaper (§5, §6, §8, §9, §10, §11, §15, §17).

Every enum here is a *closed* vocabulary. The governance core refuses to persist a
value outside these sets, so downstream consumers (UI, MCP clients, public catalog)
can rely on the label space being stable.

Design rule inherited from the whitepaper: every vocabulary carries an explicit
``UNKNOWN`` member. Absence of evidence is a first-class state, never silently
coerced into a confident label (axiom 4).
"""

from __future__ import annotations

from enum import StrEnum


# --------------------------------------------------------------------------
# §5 Repository classification
# --------------------------------------------------------------------------

class Category(StrEnum):
    """§5.1 Project type."""

    PRODUCT = "PRODUCT"
    LIBRARY = "LIBRARY"
    RESEARCH = "RESEARCH"
    WEBSITE = "WEBSITE"
    SERVICE = "SERVICE"
    AGENT = "AGENT"
    DATASET = "DATASET"
    DOCUMENTATION = "DOCUMENTATION"
    GAME = "GAME"
    PLUGIN = "PLUGIN"
    PROTOTYPE = "PROTOTYPE"
    FORK = "FORK"
    MIRROR = "MIRROR"
    REFERENCE = "REFERENCE"
    ARCHIVE = "ARCHIVE"
    UNKNOWN = "UNKNOWN"


class Lifecycle(StrEnum):
    """§5.2 Lifecycle stage."""

    IDEA = "IDEA"
    EXPERIMENTAL = "EXPERIMENTAL"
    ACTIVE = "ACTIVE"
    MAINTENANCE = "MAINTENANCE"
    SUPERSEDED = "SUPERSEDED"
    ARCHIVED = "ARCHIVED"
    REFERENCE = "REFERENCE"
    UNKNOWN = "UNKNOWN"


class Maturity(StrEnum):
    """§5.3 Maturity."""

    CONCEPT = "CONCEPT"
    MVP = "MVP"
    ALPHA = "ALPHA"
    BETA = "BETA"
    STABLE = "STABLE"
    PRODUCTION = "PRODUCTION"
    LEGACY = "LEGACY"
    UNKNOWN = "UNKNOWN"


class Criticality(StrEnum):
    """§5.4 Criticality."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AgentAccess(StrEnum):
    """§5.5 Agent access mode — the *ceiling* an agent may reach on a repository."""

    READ_ONLY = "READ_ONLY"
    METADATA_WRITE = "METADATA_WRITE"
    PR_ONLY = "PR_ONLY"
    CONTROLLED_WRITE = "CONTROLLED_WRITE"
    ADMIN_APPROVAL = "ADMIN_APPROVAL"
    BREAK_GLASS = "BREAK_GLASS"


#: Ordering used by the policy engine to compare "how much power" a mode grants.
AGENT_ACCESS_RANK: dict[AgentAccess, int] = {
    AgentAccess.READ_ONLY: 0,
    AgentAccess.METADATA_WRITE: 1,
    AgentAccess.PR_ONLY: 2,
    AgentAccess.CONTROLLED_WRITE: 3,
    AgentAccess.ADMIN_APPROVAL: 4,
    AgentAccess.BREAK_GLASS: 5,
}


# --------------------------------------------------------------------------
# §6 Origin & provenance
# --------------------------------------------------------------------------

class OriginType(StrEnum):
    """§6.2 Where a repository came from."""

    ORIGINAL = "ORIGINAL"
    ORIGINAL_WITH_DEPENDENCIES = "ORIGINAL_WITH_DEPENDENCIES"
    GITHUB_FORK = "GITHUB_FORK"
    DETACHED_FORK = "DETACHED_FORK"
    MIRROR = "MIRROR"
    TEMPLATE_DERIVED = "TEMPLATE_DERIVED"
    UPSTREAM_IMPORT = "UPSTREAM_IMPORT"
    DERIVATIVE_PROJECT = "DERIVATIVE_PROJECT"
    PLUGIN_OR_EXTENSION = "PLUGIN_OR_EXTENSION"
    MULTI_SOURCE_COMPOSITE = "MULTI_SOURCE_COMPOSITE"
    VENDOR_SNAPSHOT = "VENDOR_SNAPSHOT"
    GENERATED_PROJECT = "GENERATED_PROJECT"
    UNKNOWN = "UNKNOWN"


#: Origin types that must never carry an automatic public originality claim (axiom 4).
NO_AUTOMATIC_ORIGINALITY_CLAIM: frozenset[OriginType] = frozenset(
    {
        OriginType.GITHUB_FORK,
        OriginType.DETACHED_FORK,
        OriginType.MIRROR,
        OriginType.UPSTREAM_IMPORT,
        OriginType.DERIVATIVE_PROJECT,
        OriginType.MULTI_SOURCE_COMPOSITE,
        OriginType.VENDOR_SNAPSHOT,
        OriginType.UNKNOWN,
    }
)


class EvidenceKind(StrEnum):
    """§6.3 Evidence families, ordered loosely by strength."""

    GITHUB_METADATA = "GITHUB_METADATA"
    GIT_METADATA = "GIT_METADATA"
    FILE_EVIDENCE = "FILE_EVIDENCE"
    CODE_EVIDENCE = "CODE_EVIDENCE"
    DOCUMENTARY_EVIDENCE = "DOCUMENTARY_EVIDENCE"
    DEPENDENCY_EVIDENCE = "DEPENDENCY_EVIDENCE"


class ReviewStatus(StrEnum):
    """Human-review state of a provenance decision (§19.3)."""

    UNREVIEWED = "UNREVIEWED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    REVIEWED = "REVIEWED"
    CORRECTED = "CORRECTED"
    MARKED_UNKNOWN = "MARKED_UNKNOWN"
    LEGAL_REVIEW_REQUESTED = "LEGAL_REVIEW_REQUESTED"


# --------------------------------------------------------------------------
# §8 Contribution model
# --------------------------------------------------------------------------

class ContributionDimension(StrEnum):
    """§8.3 Dimensions along which local contribution is estimated."""

    CODE = "CODE"
    ARCHITECTURE = "ARCHITECTURE"
    TESTS = "TESTS"
    DOCUMENTATION = "DOCUMENTATION"
    UI_UX = "UI_UX"
    DATA_MODEL = "DATA_MODEL"
    DEPLOYMENT = "DEPLOYMENT"
    RESEARCH = "RESEARCH"
    CONTENT = "CONTENT"
    ASSETS = "ASSETS"


class ContributionBand(StrEnum):
    """§8.5 Public-facing band. Never publish a bare percentage."""

    MINIMAL = "MINIMAL"
    LIMITED = "LIMITED"
    MIXED = "MIXED"
    SUBSTANTIAL = "SUBSTANTIAL"
    PREDOMINANT = "PREDOMINANT"
    NEARLY_FULL = "NEARLY_FULL"
    UNKNOWN = "UNKNOWN"


#: §8.5 band boundaries as half-open intervals on the *midpoint* of the estimate.
CONTRIBUTION_BANDS: tuple[tuple[ContributionBand, float, float], ...] = (
    (ContributionBand.MINIMAL, 0.00, 0.10),
    (ContributionBand.LIMITED, 0.10, 0.30),
    (ContributionBand.MIXED, 0.30, 0.50),
    (ContributionBand.SUBSTANTIAL, 0.50, 0.75),
    (ContributionBand.PREDOMINANT, 0.75, 0.90),
    (ContributionBand.NEARLY_FULL, 0.90, 1.01),
)


class Confidence(StrEnum):
    """Coarse confidence label shown to humans."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


def band_for(value: float) -> ContributionBand:
    """Map a [0,1] contribution estimate onto its public band."""
    for band, lo, hi in CONTRIBUTION_BANDS:
        if lo <= value < hi:
            return band
    return ContributionBand.UNKNOWN


def confidence_for(score: float) -> Confidence:
    """Map a [0,1] certainty onto the coarse label used in public output."""
    if score >= 0.85:
        return Confidence.HIGH
    if score >= 0.60:
        return Confidence.MEDIUM
    return Confidence.LOW


# --------------------------------------------------------------------------
# §9 Component classification
# --------------------------------------------------------------------------

class ComponentClass(StrEnum):
    """§9.3 What a file/directory *is*, so dependencies never masquerade as upstream."""

    ORIGINAL = "ORIGINAL"
    UPSTREAM_MODIFIED = "UPSTREAM_MODIFIED"
    UPSTREAM_UNMODIFIED = "UPSTREAM_UNMODIFIED"
    DEPENDENCY = "DEPENDENCY"
    VENDORED = "VENDORED"
    VENDORED_MODIFIED = "VENDORED_MODIFIED"
    GENERATED = "GENERATED"
    BINARY = "BINARY"
    ASSET = "ASSET"
    UNKNOWN = "UNKNOWN"


# --------------------------------------------------------------------------
# §10 License model
# --------------------------------------------------------------------------

class LicenseStatus(StrEnum):
    """§10 Compatibility verdict. Advisory only — never a legal conclusion (§25)."""

    CLEAR = "CLEAR"
    NOTICE_REQUIRED = "NOTICE_REQUIRED"
    ATTRIBUTION_REQUIRED = "ATTRIBUTION_REQUIRED"
    COPYLEFT_TRIGGERED = "COPYLEFT_TRIGGERED"
    INCOMPATIBLE = "INCOMPATIBLE"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    UNKNOWN = "UNKNOWN"


# --------------------------------------------------------------------------
# §11 Authorization
# --------------------------------------------------------------------------

class Role(StrEnum):
    """§11.1 RBAC roles."""

    OWNER = "OWNER"
    ADMIN = "ADMIN"
    PORTFOLIO_MANAGER = "PORTFOLIO_MANAGER"
    MAINTAINER = "MAINTAINER"
    DEVELOPER = "DEVELOPER"
    REVIEWER = "REVIEWER"
    AGENT = "AGENT"
    VIEWER = "VIEWER"


class PermissionLevel(StrEnum):
    """§11.3 Capability tiers, from inventory reads to break-glass."""

    L0_INVENTORY = "L0_INVENTORY"
    L1_METADATA_WRITE = "L1_METADATA_WRITE"
    L2_CONTENT_PROPOSAL = "L2_CONTENT_PROPOSAL"
    L3_CONTROLLED_CODE_WRITE = "L3_CONTROLLED_CODE_WRITE"
    L4_REPOSITORY_ADMIN = "L4_REPOSITORY_ADMIN"
    L5_BREAK_GLASS = "L5_BREAK_GLASS"


PERMISSION_LEVEL_RANK: dict[PermissionLevel, int] = {
    PermissionLevel.L0_INVENTORY: 0,
    PermissionLevel.L1_METADATA_WRITE: 1,
    PermissionLevel.L2_CONTENT_PROPOSAL: 2,
    PermissionLevel.L3_CONTROLLED_CODE_WRITE: 3,
    PermissionLevel.L4_REPOSITORY_ADMIN: 4,
    PermissionLevel.L5_BREAK_GLASS: 5,
}

#: The highest permission level each agent-access mode may reach (§5.5 ↔ §11.3).
AGENT_ACCESS_CEILING: dict[AgentAccess, PermissionLevel] = {
    AgentAccess.READ_ONLY: PermissionLevel.L0_INVENTORY,
    AgentAccess.METADATA_WRITE: PermissionLevel.L1_METADATA_WRITE,
    AgentAccess.PR_ONLY: PermissionLevel.L2_CONTENT_PROPOSAL,
    AgentAccess.CONTROLLED_WRITE: PermissionLevel.L3_CONTROLLED_CODE_WRITE,
    AgentAccess.ADMIN_APPROVAL: PermissionLevel.L4_REPOSITORY_ADMIN,
    AgentAccess.BREAK_GLASS: PermissionLevel.L5_BREAK_GLASS,
}


# --------------------------------------------------------------------------
# §15 / §16 / §17 Decisions, risk, plans
# --------------------------------------------------------------------------

class Decision(StrEnum):
    """§15 Policy decision outcomes."""

    ALLOW = "ALLOW"
    ALLOW_WITH_CONSTRAINTS = "ALLOW_WITH_CONSTRAINTS"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"
    DENY = "DENY"
    REQUIRE_BREAK_GLASS = "REQUIRE_BREAK_GLASS"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


RISK_RANK: dict[RiskLevel, int] = {
    RiskLevel.LOW: 0,
    RiskLevel.MEDIUM: 1,
    RiskLevel.HIGH: 2,
    RiskLevel.CRITICAL: 3,
}


class PlanState(StrEnum):
    """§17 Approval workflow states, success path then failure path."""

    DRAFT = "DRAFT"
    ANALYZED = "ANALYZED"
    POLICY_CHECKED = "POLICY_CHECKED"
    PREVIEW_READY = "PREVIEW_READY"
    APPROVED = "APPROVED"
    EXECUTING = "EXECUTING"
    VERIFIED = "VERIFIED"
    COMPLETED = "COMPLETED"

    DENIED = "DENIED"
    PARTIALLY_FAILED = "PARTIALLY_FAILED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    EXPIRED = "EXPIRED"
    CANCELLED = "CANCELLED"


TERMINAL_PLAN_STATES: frozenset[PlanState] = frozenset(
    {
        PlanState.COMPLETED,
        PlanState.DENIED,
        PlanState.FAILED,
        PlanState.ROLLED_BACK,
        PlanState.EXPIRED,
        PlanState.CANCELLED,
    }
)


class TenantType(StrEnum):
    PERSONAL = "personal"
    COMPANY = "company"
    LABORATORY = "laboratory"
    CLIENT = "client"


class Visibility(StrEnum):
    PUBLIC = "public"
    PRIVATE = "private"
    INTERNAL = "internal"


class ActorType(StrEnum):
    HUMAN = "human"
    AGENT = "agent"
    SYSTEM = "system"
