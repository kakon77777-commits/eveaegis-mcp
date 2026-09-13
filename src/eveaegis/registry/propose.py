"""Propose A/B/C/D asset classes and project families — proposals, never declarations.

Migration Strategy (2026-09-03) §1 defines the classes; the Recovery Index §19 asks
for every repository to be classed before a Wave 1 plan exists. An agent can do the
first pass from evidence, as long as three things stay true:

* every proposal carries a confidence and a stated rationale;
* a keyword match is never reported as high confidence;
* the result lands in ``registry_proposals``, and only a human moves it to
  ``registry_declarations``.

Hints live in ``config/registry/class_hints.yaml`` so tuning needs no code change.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from ..config import PROJECT_ROOT
from ..core import GovernanceCore
from ..db import loads
from .store import Proposal, RegistryStore

HINTS_PATH = PROJECT_ROOT / "config" / "registry" / "class_hints.yaml"


def load_hints(path: Path | None = None) -> dict[str, Any]:
    p = path or HINTS_PATH
    return yaml.safe_load(p.read_text("utf-8")) or {}


def _lower_set(values: Any) -> set[str]:
    return {str(v).lower() for v in (values or [])}


def propose_for_repository(row: Any, hints: dict[str, Any], readme_hint: str | None) -> list[Proposal]:
    """Return proposals (class, project_family) for one ``repositories`` row."""
    name = row["full_name"].split("/")[-1]
    lname = name.lower()
    text = " ".join(
        s for s in (row["description"] or "", row["homepage"] or "", readme_hint or "") if s
    ).lower()

    core_names = _lower_set(hints.get("core_names"))
    research_names = _lower_set(hints.get("research_names"))
    personal_names = _lower_set(hints.get("personal_names"))
    research_prefixes = _lower_set(hints.get("research_prefixes"))
    domains = _lower_set(hints.get("company_domains"))
    phrases = _lower_set(hints.get("company_phrases"))

    company_signal = next((d for d in domains if d in text), None) or next(
        (p for p in phrases if p in text), None
    )

    proposals: list[Proposal] = []

    # -- class ------------------------------------------------------------
    cls: str
    conf: float
    why: str
    if row["is_archived"]:
        cls, conf, why = "D", 0.85, "archived on GitHub: legacy by the platform's own flag"
    elif row["is_fork"] and lname in personal_names:
        cls, conf, why = "C", 0.6, "fork with a few local commits, listed as personal in hints"
    elif row["is_fork"] and lname not in research_names:
        cls, conf, why = "D", 0.7, "fork; the strategy files forks under Legacy unless it became a real project"
    elif lname in core_names:
        cls, conf, why = "A", 0.6, "listed as company core in class_hints.yaml"
        if company_signal:
            conf, why = 0.75, f"listed as company core; also carries company signal '{company_signal}'"
    elif lname in personal_names:
        cls, conf, why = "C", 0.6, "listed as personal/experimental in class_hints.yaml"
    elif lname in research_names or any(lname.startswith(p) for p in research_prefixes):
        cls, conf, why = "B", 0.55, "matches a known EveMissLab research family; strategy says case-by-case"
    elif row["category"] in ("WEBSITE", "SERVICE", "PRODUCT") and company_signal:
        cls, conf, why = "A", 0.55, f"classified {row['category']} and carries company signal '{company_signal}'"
    elif row["category"] == "RESEARCH":
        cls, conf, why = "B", 0.5, "classified RESEARCH; strategy files research as case-by-case"
    elif company_signal:
        cls, conf, why = "B", 0.4, f"company signal '{company_signal}' but no product/site category; likely research"
    else:
        cls, conf, why = "B", 0.3, "no strong signal; B is the least-wrong default for Neo's own work — confirm"
    proposals.append(Proposal(repository_id=row["id"], field="asset_class", value=cls,
                              confidence=conf, rationale=why))

    # -- project family ---------------------------------------------------
    families: dict[str, str] = {str(k).lower(): str(v) for k, v in (hints.get("families") or {}).items()}
    for prefix in sorted(families, key=len, reverse=True):
        if lname.startswith(prefix):
            proposals.append(Proposal(repository_id=row["id"], field="project_family", value=families[prefix],
                                      confidence=0.7, rationale=f"name prefix '{prefix}'"))
            break

    return proposals


def propose_classes(core: GovernanceCore, *, hints_path: Path | None = None) -> dict[str, int]:
    """Propose class + family for every present repository. Returns counts by class."""
    hints = load_hints(hints_path)
    store = RegistryStore(core)
    rows = core.conn.execute(
        "SELECT * FROM repositories WHERE tenant_id = ? AND missing_since IS NULL ORDER BY full_name",
        (core.tenant_id,),
    ).fetchall()
    all_props: list[Proposal] = []
    counts: dict[str, int] = {}
    for row in rows:
        hint = None
        if not row["description"]:
            snap = core.conn.execute(
                "SELECT payload FROM repository_snapshots WHERE repository_id = ? AND kind = 'readme' "
                "ORDER BY rowid DESC LIMIT 1",
                (row["id"],),
            ).fetchone()
            if snap:
                txt = loads(snap["payload"], "") or ""
                hint = txt[:600]
        props = propose_for_repository(row, hints, hint)
        all_props.extend(props)
        for p in props:
            if p.field == "asset_class":
                counts[p.value or "?"] = counts.get(p.value or "?", 0) + 1
    store.propose(all_props)
    return counts
