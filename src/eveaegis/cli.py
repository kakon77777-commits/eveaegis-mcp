"""``aegis`` — the human-facing side of the control plane.

The CLI is the *human* interface; the MCP server is the *agent* interface. Some
actions live only here on purpose: confirming a provenance verdict is a human
decision (§19.3), so no agent-callable tool exposes it.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import __version__
from .config import load_config
from .core import GovernanceCore
from .taxonomy import ReviewStatus

app = typer.Typer(
    name="aegis",
    help="EveAegis - AI-native GitHub portfolio governance control plane.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()

review_app = typer.Typer(help="Human review of provenance verdicts (sec. 19.3).", no_args_is_help=True)
audit_app = typer.Typer(help="Audit ledger inspection (sec. 18).", no_args_is_help=True)
app.add_typer(review_app, name="review")
app.add_typer(audit_app, name="audit")


def _core(config: Optional[str] = None) -> GovernanceCore:
    return GovernanceCore(load_config(config))


def _names(core: GovernanceCore) -> dict[str, str]:
    """Repository id -> owner/name. Tables show names; ids are for machines."""
    return {
        row["id"]: row["full_name"]
        for row in core.conn.execute(
            "SELECT id, full_name FROM repositories WHERE tenant_id = ?", (core.tenant_id,)
        )
    }


# --------------------------------------------------------------------------
# diagnostics
# --------------------------------------------------------------------------

@app.command()
def version() -> None:
    """Show the EveAegis version."""
    console.print(f"EveAegis {__version__}")


@app.command()
def doctor(config: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Check configuration, credentials, database and audit chain integrity."""
    cfg = load_config(config)
    console.print(f"[bold]config[/bold]      {cfg.source_path or '(defaults)'}")
    console.print(f"[bold]database[/bold]    {cfg.db_path}")
    console.print(f"[bold]tenant[/bold]      {cfg.governance.tenant_id}")
    console.print(
        f"[bold]mode[/bold]        {'read-only' if cfg.governance.read_only else 'READ-WRITE'}"
    )

    core = GovernanceCore(cfg)
    try:
        ok, message = core.broker.health_check()
        colour = "green" if ok else "red"
        console.print(f"[bold]credentials[/bold] [{colour}]{cfg.credentials.backend}: {message}[/]")
        for key, value in core.broker.describe().items():
            console.print(f"              {key}: {value}")

        repos = core.conn.execute("SELECT COUNT(*) AS n FROM repositories").fetchone()["n"]
        console.print(f"[bold]inventory[/bold]   {repos} repositories")

        chain_ok, chain_msg = core.ledger.verify()
        colour = "green" if chain_ok else "red"
        console.print(f"[bold]audit[/bold]       [{colour}]{chain_msg}[/]")
        if not chain_ok:
            raise typer.Exit(code=1)
    finally:
        core.close()


# --------------------------------------------------------------------------
# Phase 1 — inventory
# --------------------------------------------------------------------------

@app.command()
def sync(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    readme: bool = typer.Option(True, help="Fetch README text (one extra API call per repo)."),
    languages: bool = typer.Option(True, help="Fetch language breakdown."),
    tree: bool = typer.Option(True, help="Fetch the file tree (feeds path evidence)."),
    limit: Optional[int] = typer.Option(None, help="Stop after N repositories."),
) -> None:
    """Sync accounts and repositories into the asset inventory (Phase 1)."""
    from .inventory import InventorySync

    core = _core(config)
    try:
        result = InventorySync(core).sync_repositories(
            include_readme=readme, include_languages=languages, include_tree=tree, limit=limit
        )
        console.print(
            f"[green]synced[/green] {result.repositories} repositories across "
            f"{result.accounts} accounts in {result.duration_seconds:.1f}s "
            f"({result.created} new, {result.updated} updated, {result.snapshots} snapshots)"
        )
        for error in result.errors:
            console.print(f"  [yellow]![/yellow] {error}")
    finally:
        core.close()


@app.command()
def summary(config: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Portfolio overview (sec. 19.1)."""
    from .inventory import portfolio_summary

    core = _core(config)
    try:
        data = portfolio_summary(core)
        table = Table(show_header=False, box=None)
        for key, value in data.items():
            table.add_row(f"[bold]{key}[/bold]", str(value))
        console.print(table)
    finally:
        core.close()


@app.command()
def matrix(
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    limit: Optional[int] = typer.Option(None),
) -> None:
    """Repository Matrix (sec. 19.2)."""
    from .inventory import repository_matrix

    core = _core(config)
    try:
        rows = repository_matrix(core)
        if limit:
            rows = rows[:limit]
        table = Table(title=f"Repository Matrix ({len(rows)})")
        for column in (
            "Repo",
            "Category",
            "Lifecycle",
            "Origin",
            "Contribution",
            "Crit",
            "Agent",
            "Review",
        ):
            table.add_column(column, overflow="fold")
        for row in rows:
            # `repo` is owner/name; strip the owner, which is identical for every row
            # in a single-account tenant and just eats width.
            name = str(row.get("repo", "")).split("/", 1)[-1]
            table.add_row(
                name,
                str(row.get("category", "")),
                str(row.get("lifecycle", "")),
                str(row.get("origin", "")).replace("ORIGINAL_WITH_DEPENDENCIES", "ORIGINAL+DEPS"),
                str(row.get("contribution", "")),
                str(row.get("risk", "")),
                str(row.get("agent_mode", "")),
                str(row.get("review_status", "")),
            )
        console.print(table)
    finally:
        core.close()


# --------------------------------------------------------------------------
# Phase 2 — provenance
# --------------------------------------------------------------------------

@app.command()
def origin(
    repository: Optional[str] = typer.Argument(None, help="owner/name; omit with --all"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    all_repos: bool = typer.Option(False, "--all", help="Analyze every governed repository."),
    deep: bool = typer.Option(False, help="Clone a bare mirror for commit/blob evidence."),
    limit: Optional[int] = typer.Option(None),
    report: bool = typer.Option(False, help="Print the full evidence report."),
) -> None:
    """Determine where repositories came from (Phase 2)."""
    from .provenance import ProvenanceEngine

    if not repository and not all_repos:
        raise typer.BadParameter("give a repository or --all")

    core = _core(config)
    try:
        engine = ProvenanceEngine(core)
        if all_repos:
            profiles = engine.analyze_all(deep=deep, limit=limit)
        else:
            profile = engine.analyze(repository, deep=deep)  # type: ignore[arg-type]
            engine.save(profile)
            profiles = [profile]

        names = _names(core)
        table = Table(title=f"Origin verdicts ({len(profiles)})")
        for column in ("Repository", "Origin", "Conf", "Depth", "Contribution", "Review"):
            table.add_column(column, overflow="fold")
        for p in profiles:
            table.add_row(
                names.get(p.repository_id, p.repository_id),
                str(p.origin_type),
                f"{p.origin_confidence:.2f}",
                p.analysis_depth,
                str(p.contribution.band),
                str(p.review_status),
            )
        console.print(table)

        if report and repository:
            console.print(engine.evidence_report(repository))
    finally:
        core.close()


@review_app.command("list")
def review_list(config: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Origin verdicts awaiting a human decision."""
    from .provenance import ProvenanceEngine

    core = _core(config)
    try:
        queue = ProvenanceEngine(core).review_queue()
        if not queue:
            console.print("[green]review queue is empty[/green]")
            return
        table = Table(title=f"Provenance review queue ({len(queue)})")
        for column, style in (
            ("Repository", None),
            ("Origin", None),
            ("Conf", "right"),
            ("Why it needs a human", None),
        ):
            table.add_column(column, justify=style or "left", overflow="fold")
        for item in queue:
            table.add_row(
                str(item.get("full_name") or item.get("repository_id", "")),
                str(item.get("origin_type", "")),
                f"{float(item.get('confidence', 0.0)):.2f}",
                "; ".join(item.get("reasons", []))[:110],
            )
        console.print(table)
    finally:
        core.close()


@review_app.command("set")
def review_set(
    repository: str = typer.Argument(..., help="owner/name"),
    status: str = typer.Argument(..., help="confirm | correct | unknown | legal"),
    origin_type: Optional[str] = typer.Option(None, help="Required when status is 'correct'."),
    reviewer: str = typer.Option("human:owner", help="Who is making this call."),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Record a human provenance decision. Deliberately not available to agents."""
    mapping = {
        "confirm": ReviewStatus.REVIEWED,
        "correct": ReviewStatus.CORRECTED,
        "unknown": ReviewStatus.MARKED_UNKNOWN,
        "legal": ReviewStatus.LEGAL_REVIEW_REQUESTED,
    }
    if status not in mapping:
        raise typer.BadParameter(f"status must be one of {sorted(mapping)}")
    if status == "correct" and not origin_type:
        raise typer.BadParameter("--origin-type is required when correcting a verdict")

    core = _core(config)
    try:
        row = core.conn.execute(
            "SELECT id, origin_type FROM origin_profiles WHERE repository_id = ("
            "  SELECT id FROM repositories WHERE tenant_id = ? AND full_name = ?)"
            " ORDER BY updated_at DESC LIMIT 1",
            (core.tenant_id, repository),
        ).fetchone()
        if not row:
            console.print(f"[red]no origin profile for {repository}[/red] — run `aegis origin` first")
            raise typer.Exit(code=1)

        now = datetime.now(timezone.utc).isoformat()
        if origin_type:
            core.conn.execute(
                "UPDATE origin_profiles SET review_status=?, reviewed_by=?, origin_type=?,"
                " updated_at=? WHERE id=?",
                (str(mapping[status]), reviewer, origin_type, now, row["id"]),
            )
        else:
            core.conn.execute(
                "UPDATE origin_profiles SET review_status=?, reviewed_by=?, updated_at=?"
                " WHERE id=?",
                (str(mapping[status]), reviewer, now, row["id"]),
            )
        core.conn.commit()
        core.ledger.record(
            "provenance_review",
            actor=reviewer,
            initiated_by=reviewer,
            tenant=core.tenant_id,
            targets=[repository],
            detail={
                "status": str(mapping[status]),
                "origin_before": row["origin_type"],
                "origin_after": origin_type or row["origin_type"],
            },
        )
        console.print(f"[green]{repository}[/green] → {mapping[status]}")
    finally:
        core.close()


# --------------------------------------------------------------------------
# Phase 3 — classification & policy
# --------------------------------------------------------------------------

@app.command()
def classify(
    repository: Optional[str] = typer.Argument(None, help="owner/name; omit with --all"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    all_repos: bool = typer.Option(False, "--all"),
    apply: bool = typer.Option(False, help="Write results onto the repository overlay."),
    limit: Optional[int] = typer.Option(None),
) -> None:
    """Classify repositories by category, lifecycle, maturity, criticality (Phase 3)."""
    from .classification import Classifier

    if not repository and not all_repos:
        raise typer.BadParameter("give a repository or --all")

    core = _core(config)
    try:
        classifier = Classifier(core)
        results = (
            classifier.classify_all(limit=limit)
            if all_repos
            else [classifier.classify(repository)]  # type: ignore[arg-type]
        )
        for result in results:
            classifier.save(result, apply_to_repository=apply)

        names = _names(core)
        table = Table(title=f"Classification ({len(results)}{'  applied' if apply else '  proposal'})")
        for column in ("Repository", "Category", "Lifecycle", "Maturity", "Crit", "Agent", "Conf"):
            table.add_column(column, overflow="fold")
        for r in results:
            table.add_row(
                names.get(r.repository_id, r.repository_id),
                str(r.category),
                str(r.lifecycle),
                str(r.maturity),
                str(r.criticality),
                str(r.agent_access),
                f"{r.confidence:.2f}",
            )
        console.print(table)
    finally:
        core.close()


@app.command()
def policy(
    tool: str = typer.Argument(..., help="MCP tool name to evaluate."),
    target: list[str] = typer.Option([], "--target", "-t", help="Repository target; repeatable."),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
    write: bool = typer.Option(False, "--write", help="Evaluate as a real write, not a dry run."),
    explain: bool = typer.Option(False, help="Print the full rule trace."),
) -> None:
    """Ask the policy engine what would happen, without doing it."""
    from .mcpserver.guard import ToolGuard, decision_payload

    core = _core(config)
    try:
        guard = ToolGuard(core)
        request = guard.build_request(tool, targets=list(target), reason="cli pre-flight", dry_run=not write)
        decision = guard.policy.evaluate(request)
        console.print_json(json.dumps(decision_payload(decision), ensure_ascii=False))
        if explain:
            console.print(guard.policy.explain(request))
    finally:
        core.close()


# --------------------------------------------------------------------------
# audit & serving
# --------------------------------------------------------------------------

@audit_app.command("verify")
def audit_verify(config: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Verify the hash chain end to end."""
    core = _core(config)
    try:
        ok, message = core.ledger.verify()
        console.print(f"[{'green' if ok else 'red'}]{message}[/]")
        if not ok:
            raise typer.Exit(code=1)
    finally:
        core.close()


@audit_app.command("tail")
def audit_tail(
    limit: int = typer.Option(20, "--limit", "-n"),
    config: Optional[str] = typer.Option(None, "--config", "-c"),
) -> None:
    """Show the most recent audit events."""
    core = _core(config)
    try:
        table = Table(title=f"Audit ledger (last {limit} of {core.ledger.count()})")
        for column in ("#", "When", "Actor", "Action", "Result", "Targets"):
            table.add_column(column, overflow="fold")
        for event in reversed(core.ledger.recent(limit)):
            table.add_row(
                str(event.sequence),
                event.timestamp.strftime("%m-%d %H:%M:%S"),
                event.actor,
                event.action,
                event.result,
                ", ".join(event.targets[:3]) + ("…" if len(event.targets) > 3 else ""),
            )
        console.print(table)
    finally:
        core.close()


@app.command()
def serve(config: Optional[str] = typer.Option(None, "--config", "-c")) -> None:
    """Run the MCP server over stdio for a local agent."""
    from .mcpserver import build_server

    build_server(GovernanceCore(load_config(config))).run(transport="stdio")


if __name__ == "__main__":  # pragma: no cover
    app()
