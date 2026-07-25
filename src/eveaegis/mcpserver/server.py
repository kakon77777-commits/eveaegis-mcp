"""§13 MCP tool surface.

Deliberately *not* a GitHub API wrapper. Tools are high-level and semantic, and
every one of them is a governed action: policy is evaluated before the handler
runs and the outcome lands in the audit ledger (see :mod:`.guard`).

What v0.1 exposes, and what it does not:

* §13.1 Inventory, §13.2 Provenance, §13.3 Classification — exposed.
* §13.4 Governance — only ``evaluate_action_policy`` / ``explain_action_policy``.
  Plan/approve/execute belong to Phase 4-5 and are absent rather than stubbed, so
  an agent cannot discover a tool it must not have.
* §13.5 Metadata, §13.6 Documentation — read-only catalog generation only.
* §13.7 Administration — never exposed to a general agent.

Absence is the security boundary here. A tool that is not registered cannot be
called, whatever the policy file says.
"""

from __future__ import annotations

from typing import Any

from ..classification import Classifier
from ..config import Config, load_config
from ..core import GovernanceCore
from ..inventory import (
    InventorySync,
    portfolio_summary,
    repository_matrix,
    unclassified_report,
)
from ..provenance import ProvenanceEngine
from .guard import ToolDenied, ToolGuard, decision_payload

SERVER_NAME = "eveaegis"
SERVER_INSTRUCTIONS = """\
EveAegis governs a GitHub repository portfolio.

Read the inventory first, then provenance, then classification. Origin verdicts
carry evidence and a confidence; treat anything with review_status NEEDS_REVIEW as
unresolved and never restate it as fact. Never claim a repository is original work
on the basis of these tools alone — that decision is reserved for a human.

Every call is policy-checked and audited. A denial returns the policy decision;
do not retry it with different wording.
"""


def build_server(core: GovernanceCore | None = None, config: Config | None = None) -> Any:
    """Construct the FastMCP server. Imported lazily so the SDK stays optional."""
    try:
        from mcp.server.fastmcp import FastMCP
    except ModuleNotFoundError as exc:  # pragma: no cover - environment dependent
        raise RuntimeError(
            "the MCP SDK is not installed; run: pip install 'eveaegis[mcp]'"
        ) from exc

    core = core or GovernanceCore(config or load_config())
    guard = ToolGuard(core)
    mcp = FastMCP(SERVER_NAME, instructions=SERVER_INSTRUCTIONS)

    def _denied(exc: ToolDenied) -> dict[str, Any]:
        """Return the decision as data rather than raising — agents can reason on it."""
        return {"error": "policy_denied", "decision": decision_payload(exc.decision)}

    # -- §13.1 Inventory --------------------------------------------------

    @mcp.tool()
    def inventory_accounts() -> dict[str, Any]:
        """List the GitHub accounts and organizations under governance."""
        try:
            return guard.run(
                "inventory_accounts",
                lambda _d: {
                    "accounts": [
                        dict(row)
                        for row in core.conn.execute(
                            "SELECT account_login, account_type, allowed_repositories,"
                            " credential_backend FROM github_installations WHERE tenant_id = ?",
                            (core.tenant_id,),
                        )
                    ]
                },
                reason="list governed accounts",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def inventory_repositories(
        only_unclassified: bool = False, limit: int | None = None
    ) -> dict[str, Any]:
        """List governed repositories with their current governance overlay."""

        def handler(_d: Any) -> dict[str, Any]:
            repos = InventorySync(core).list_repositories(only_unclassified=only_unclassified)
            if limit:
                repos = repos[:limit]
            return {
                "count": len(repos),
                "repositories": [
                    {
                        "full_name": r.full_name,
                        "visibility": str(r.visibility),
                        "is_fork": r.is_fork,
                        "archived": r.is_archived,
                        "category": str(r.category),
                        "lifecycle": str(r.lifecycle),
                        "maturity": str(r.maturity),
                        "criticality": str(r.criticality),
                        "agent_access": str(r.agent_access),
                        "primary_language": r.primary_language,
                        "pushed_at": r.pushed_at.isoformat() if r.pushed_at else None,
                    }
                    for r in repos
                ],
            }

        try:
            return guard.run("inventory_repositories", handler, reason="list repositories")
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def refresh_repository(full_name: str) -> dict[str, Any]:
        """Re-read one repository from GitHub. Governance overlay is preserved."""
        try:
            return guard.run(
                "refresh_repository",
                lambda _d: InventorySync(core).refresh_repository(full_name).model_dump(mode="json"),
                targets=[full_name],
                reason="refresh single repository",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def get_portfolio_summary() -> dict[str, Any]:
        """§19.1 portfolio overview counts."""
        try:
            return guard.run(
                "get_portfolio_summary",
                lambda _d: portfolio_summary(core),
                reason="portfolio overview",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def find_unclassified_repositories() -> dict[str, Any]:
        """Repositories still lacking a category, lifecycle or origin verdict."""
        try:
            return guard.run(
                "find_unclassified_repositories",
                lambda _d: {"repositories": unclassified_report(core)},
                reason="find unclassified repositories",
            )
        except ToolDenied as exc:
            return _denied(exc)

    # -- §13.2 Provenance -------------------------------------------------

    @mcp.tool()
    def analyze_repository_origin(full_name: str, deep: bool = False) -> dict[str, Any]:
        """Determine where a repository came from, with evidence and confidence.

        ``deep=True`` additionally clones a bare mirror for commit and blob level
        comparison. Repository code is never executed.
        """

        def handler(_d: Any) -> dict[str, Any]:
            engine = ProvenanceEngine(core)
            profile = engine.analyze(full_name, deep=deep)
            engine.save(profile)
            return profile.model_dump(mode="json")

        try:
            return guard.run(
                "analyze_repository_origin",
                handler,
                targets=[full_name],
                parameters={"deep": deep},
                reason="origin analysis",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def find_candidate_upstreams(full_name: str) -> dict[str, Any]:
        """Candidate upstream repositories, each with how it was discovered."""

        def handler(_d: Any) -> dict[str, Any]:
            profile = ProvenanceEngine(core).analyze(full_name, deep=False)
            return {
                "full_name": full_name,
                "candidates": [c.model_dump(mode="json") for c in profile.upstream_candidates],
            }

        try:
            return guard.run(
                "find_candidate_upstreams",
                handler,
                targets=[full_name],
                reason="upstream discovery",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def estimate_local_contribution(full_name: str, deep: bool = False) -> dict[str, Any]:
        """Estimate local contribution as a *range* and a band, never a bare score."""

        def handler(_d: Any) -> dict[str, Any]:
            profile = ProvenanceEngine(core).analyze(full_name, deep=deep)
            return {
                "full_name": full_name,
                "origin_type": str(profile.origin_type),
                "contribution": profile.contribution.model_dump(mode="json"),
                "review_status": str(profile.review_status),
            }

        try:
            return guard.run(
                "estimate_local_contribution",
                handler,
                targets=[full_name],
                parameters={"deep": deep},
                reason="contribution estimate",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def generate_provenance_report(full_name: str) -> dict[str, Any]:
        """Human-readable evidence report for a provenance decision (§19.3)."""
        try:
            return guard.run(
                "generate_provenance_report",
                lambda _d: {"report": ProvenanceEngine(core).evidence_report(full_name)},
                targets=[full_name],
                reason="provenance report",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def list_provenance_review_queue() -> dict[str, Any]:
        """Origin verdicts a human still needs to confirm, correct or mark unknown."""
        try:
            return guard.run(
                "list_provenance_review_queue",
                lambda _d: {"queue": ProvenanceEngine(core).review_queue()},
                reason="provenance review queue",
            )
        except ToolDenied as exc:
            return _denied(exc)

    # -- §13.3 Classification ---------------------------------------------

    @mcp.tool()
    def classify_repository(full_name: str, apply: bool = False) -> dict[str, Any]:
        """Classify one repository. ``apply=False`` returns a proposal only."""

        def handler(_d: Any) -> dict[str, Any]:
            classifier = Classifier(core)
            result = classifier.classify(full_name)
            classifier.save(result, apply_to_repository=apply)
            return result.model_dump(mode="json")

        try:
            return guard.run(
                "classify_repository",
                handler,
                targets=[full_name],
                parameters={"apply": apply},
                dry_run=not apply,
                reason="classify repository",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def classify_portfolio(limit: int | None = None) -> dict[str, Any]:
        """Classify every governed repository and return the distribution."""

        def handler(_d: Any) -> dict[str, Any]:
            results = Classifier(core).classify_all(limit=limit)
            distribution: dict[str, dict[str, int]] = {}
            for field in ("category", "lifecycle", "maturity", "criticality", "agent_access"):
                counts: dict[str, int] = {}
                for r in results:
                    key = str(getattr(r, field))
                    counts[key] = counts.get(key, 0) + 1
                distribution[field] = dict(sorted(counts.items(), key=lambda kv: -kv[1]))
            return {"classified": len(results), "distribution": distribution}

        try:
            return guard.run("classify_portfolio", handler, reason="classify portfolio")
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def detect_archive_candidates() -> dict[str, Any]:
        """Repositories that look dormant enough to archive — a proposal, not an action."""
        try:
            return guard.run(
                "detect_archive_candidates",
                lambda _d: {"candidates": Classifier(core).detect_archive_candidates()},
                reason="archive candidate detection",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def detect_superseded_projects() -> dict[str, Any]:
        """Repositories whose documentation says they were replaced by something else."""
        try:
            return guard.run(
                "detect_superseded_projects",
                lambda _d: {"superseded": Classifier(core).detect_superseded_projects()},
                reason="superseded detection",
            )
        except ToolDenied as exc:
            return _denied(exc)

    # -- §13.4 Governance (evaluation only in v0.1) ------------------------

    @mcp.tool()
    def evaluate_action_policy(
        tool: str, targets: list[str] | None = None, dry_run: bool = True
    ) -> dict[str, Any]:
        """Ask what would happen if a given tool were called, without calling it."""
        request = guard.build_request(
            tool, targets=targets, reason="policy pre-flight", dry_run=dry_run
        )
        return decision_payload(guard.policy.evaluate(request))

    @mcp.tool()
    def explain_action_policy(
        tool: str, targets: list[str] | None = None, dry_run: bool = True
    ) -> dict[str, Any]:
        """Human-readable trace of which policy rules would fire, and why (§19.4)."""
        request = guard.build_request(
            tool, targets=targets, reason="policy explanation", dry_run=dry_run
        )
        return {"explanation": guard.policy.explain(request)}

    # -- §19.2 / §27 read-only catalog -------------------------------------

    @mcp.tool()
    def get_repository_matrix() -> dict[str, Any]:
        """§19.2 Repository Matrix rows: category, lifecycle, origin, contribution, risk."""
        try:
            return guard.run(
                "get_repository_matrix",
                lambda _d: {"rows": repository_matrix(core)},
                reason="repository matrix",
            )
        except ToolDenied as exc:
            return _denied(exc)

    @mcp.tool()
    def verify_audit_chain() -> dict[str, Any]:
        """Verify the audit ledger hash chain (§18)."""
        ok, message = core.ledger.verify()
        return {"ok": ok, "message": message, "events": core.ledger.count()}

    return mcp


def main() -> None:  # pragma: no cover - process entry point
    build_server().run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    main()
