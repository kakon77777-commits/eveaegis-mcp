"""The gate every MCP tool call passes through.

An MCP tool never talks to GitHub directly. It builds an :class:`ActionRequest`,
hands it to the policy engine, and only proceeds when the returned
:class:`PolicyDecision` permits execution — then the outcome is written to the
audit ledger. This is where axioms 2 and 3 become code:

    Agent Capability ⊆ Policy Authorization ⊆ GitHub Installation Permission
    Inspect → Plan → Preview → Approve → Apply
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Callable, TypeVar

from ..core import GovernanceCore
from ..models import Actor, ActionRequest, PolicyDecision
from ..policy import PolicyEngine
from ..taxonomy import ActorType, Decision

T = TypeVar("T")


class ToolDenied(PermissionError):
    """Raised when policy refuses a tool call. Carries the decision for the client."""

    def __init__(self, decision: PolicyDecision) -> None:
        reasons = "; ".join(decision.reasons) or "no reason recorded"
        super().__init__(f"{decision.decision}: {reasons}")
        self.decision = decision


class ToolGuard:
    def __init__(self, core: GovernanceCore, *, agent_id: str = "agent:local") -> None:
        self.core = core
        self.policy = PolicyEngine(core)
        self.agent_id = agent_id

    def build_request(
        self,
        tool: str,
        *,
        targets: list[str] | None = None,
        parameters: dict[str, Any] | None = None,
        reason: str = "",
        dry_run: bool = True,
    ) -> ActionRequest:
        now = datetime.now(timezone.utc)
        return ActionRequest(
            request_id=f"req_{now.strftime('%Y%m%d')}_{uuid.uuid4().hex[:8]}",
            actor=Actor(type=ActorType.AGENT, id=self.agent_id, principal=self.core.tenant_id),
            tenant_id=self.core.tenant_id,
            tool=tool,
            targets=targets or [],
            parameters=parameters or {},
            reason=reason,
            dry_run=dry_run,
            requested_level=self.policy.required_level(tool),
        )

    def run(
        self,
        tool: str,
        handler: Callable[[PolicyDecision], T],
        *,
        targets: list[str] | None = None,
        parameters: dict[str, Any] | None = None,
        reason: str = "",
        dry_run: bool = True,
    ) -> T:
        """Evaluate policy, execute on approval, and record the outcome either way."""
        request = self.build_request(
            tool, targets=targets, parameters=parameters, reason=reason, dry_run=dry_run
        )
        decision = self.policy.evaluate(request)

        if not decision.permits_execution:
            self.core.ledger.record(
                f"tool_denied:{tool}",
                actor=self.agent_id,
                tenant=self.core.tenant_id,
                targets=request.targets,
                request_id=request.request_id,
                policy_decision=decision.decision,
                result="DENIED",
                detail={"reasons": decision.reasons, "risk": str(decision.risk)},
            )
            raise ToolDenied(decision)

        try:
            result = handler(decision)
        except Exception as exc:
            self.core.ledger.record(
                f"tool_failed:{tool}",
                actor=self.agent_id,
                tenant=self.core.tenant_id,
                targets=request.targets,
                request_id=request.request_id,
                policy_decision=decision.decision,
                result="FAILED",
                detail={"error": f"{type(exc).__name__}: {exc}"},
            )
            raise

        self.core.ledger.record(
            f"tool_completed:{tool}",
            actor=self.agent_id,
            tenant=self.core.tenant_id,
            targets=request.targets,
            request_id=request.request_id,
            policy_decision=decision.decision,
            credential_type=self.core.broker.describe().get("credential_type"),
            credential_scope=decision.token_scope,
            result="COMPLETED",
            detail={"dry_run": dry_run},
        )
        return result


def decision_payload(decision: PolicyDecision) -> dict[str, Any]:
    """Serialize a decision for an MCP client — §15 shape."""
    return {
        "request_id": decision.request_id,
        "decision": str(decision.decision),
        "risk": str(decision.risk),
        "constraints": decision.constraints,
        "matched_policies": decision.matched_policies,
        "reasons": decision.reasons,
        "token_scope": decision.token_scope,
        "token_lifetime_seconds": decision.token_lifetime_seconds,
    }


__all__ = ["ToolGuard", "ToolDenied", "decision_payload", "Decision"]
