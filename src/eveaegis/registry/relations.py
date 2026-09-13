"""Project graph: relations between repositories, from evidence already on disk.

Recovery Index §3/§14/§20 stop treating a repository as an isolated node. This
module recovers the edges the Index names — ``depends_on``, ``derived_from``,
``implements``, ``related``, ``supersedes`` — from what the inventory already
snapshotted: README text, descriptions, dependency manifests, and names. Every
edge carries the evidence it came from, and all of it lands in
``registry_proposals`` (field ``relation``) — a graph an agent *proposes*, that a
human confirms into declarations.

It also scores how *mixed* a repository is: code next to datasets, archives,
handoff folders, research notes. That is the signal behind Neo's "乾淨版 vs 組織版"
— a mixed repository should not be transferred as-is; the organization gets a
clean extraction and the personal copy is marked superseded.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable

from ..core import GovernanceCore
from ..db import loads
from .store import Proposal, RegistryStore

RELATION_KINDS = ("depends_on", "derived_from", "implements", "related", "supersedes")

#: Directory names that mean "not the product": history, scratch, data, hand-offs.
_MIXED_DIRS = {
    "archive", "archives", "old", "legacy", "backup", "backups", "handoff", "handoffs",
    "ingest", "scratch", "tmp", "temp", "drafts", "notes", "research", "papers", "data",
    "datasets", "experiments", "playground", "sandbox", "暫用區",
    "文件歷史區", "研究", "論文", "草稿", "封存",
}
_DATA_EXT = {"sqlite", "db", "zip", "7z", "rar", "tar", "gz", "wav", "mp3", "mp4", "pdf",
             "png", "jpg", "jpeg", "svg", "csv", "parquet", "npy", "pkl", "bin"}
_CODE_EXT = {"py", "ts", "tsx", "js", "mjs", "jsx", "rs", "go", "c", "cc", "cpp", "h",
             "java", "kt", "swift", "rb", "lua", "sh", "ps1", "toml", "yaml", "yml", "json",
             "html", "css", "astro", "vue", "svelte", "lean", "v", "hs", "ml"}

_SUPERSEDE_PATTERNS = (
    r"successor (?:to|of) ([A-Za-z0-9_.\-]+)",
    r"supersedes ([A-Za-z0-9_.\-]+)",
    r"replaces ([A-Za-z0-9_.\-]+)",
    r"replaced by ([A-Za-z0-9_.\-]+)",
    r"superseded by ([A-Za-z0-9_.\-]+)",
    r"moved to ([A-Za-z0-9_.\-]+)",
    r"取代了?\s*([A-Za-z0-9_.\-]+)",
    r"被\s*([A-Za-z0-9_.\-]+)\s*取代",
    r"後繼者?\s*[:：]?\s*([A-Za-z0-9_.\-]+)",
)
_SITE_SUFFIXES = ("-site", "-website", "_site", "-web", "-com")
_IMPL_SUFFIXES = ("-mcp", "-app", "-runtime", "-cli", "-sdk", "-api")


@dataclass
class Edge:
    source: str        # full_name
    target: str        # full_name
    kind: str
    evidence: str
    confidence: float


@dataclass
class MixedSignals:
    files: int = 0
    code_files: int = 0
    data_files: int = 0
    cjk_named: int = 0
    mixed_dirs: list[str] = field(default_factory=list)
    top_dirs: int = 0
    size_mb: float = 0.0
    score: float = 0.0
    reasons: list[str] = field(default_factory=list)

    @property
    def migration_mode(self) -> str:
        """transfer | clean-split — the shape of the move, not whether to move."""
        return "clean-split" if self.score >= 0.5 else "transfer"


# --------------------------------------------------------------------------
# mixed-content scoring
# --------------------------------------------------------------------------

def score_mixed(tree_entries: list[dict[str, Any]], size_kb: int) -> MixedSignals:
    m = MixedSignals(size_mb=round(size_kb / 1024, 1))
    blobs = [e for e in tree_entries if e.get("type") == "blob"]
    m.files = len(blobs)
    if not blobs:
        return m
    tops = Counter(e["path"].split("/")[0] for e in blobs if "/" in e["path"])
    m.top_dirs = len(tops)
    for e in blobs:
        p = e["path"]
        name = p.rsplit("/", 1)[-1]
        ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
        if ext in _CODE_EXT:
            m.code_files += 1
        elif ext in _DATA_EXT:
            m.data_files += 1
        if any(ord(ch) > 0x2E80 for ch in p):
            m.cjk_named += 1
    seen = set()
    for d in tops:
        if d.lower() in _MIXED_DIRS and d not in seen:
            m.mixed_dirs.append(d)
            seen.add(d)

    # "Mixed" means heterogeneous purposes in one repository, not merely "big" or
    # "not code": a coherent corpus is not messy; an engine sharing a repo with
    # a dozen projects' data is.
    score = 0.0
    paths = {e["path"] for e in blobs}
    children = defaultdict(set)
    for pth in paths:
        parts = pth.split("/")
        if len(parts) >= 3:
            children[parts[0]].add(parts[1])
    containers = [d for d in ("projects", "current", "apps", "packages", "repos", "workspaces")
                  if len(children.get(d, ())) >= 3]
    if containers:
        n = max(len(children[d]) for d in containers)
        score += 0.35
        m.reasons.append(f"multi-project container: {', '.join(containers)} holding {n} sub-projects")

    db_files = [pth for pth in paths if pth.rsplit(".", 1)[-1].lower() in ("sqlite", "db", "zip", "7z", "tar", "gz")]
    if db_files:
        score += 0.15
        m.reasons.append(f"{len(db_files)} database/archive files committed")

    web_root = any(pth in paths for pth in ("package.json", "next.config.ts", "next.config.js", "astro.config.mjs", "vite.config.ts", "wrangler.toml", "wrangler.jsonc"))
    research_dirs = [d for d in tops if d.lower() in ("mssp", "research", "ingest", "papers", "notes", "experiments", "lab", "研究", "論文")]
    if web_root and research_dirs:
        score += 0.3
        m.reasons.append("deployable app root next to research/lab directories: " + ", ".join(research_dirs[:4]))

    data_share = m.data_files / m.files
    if data_share >= 0.4:
        score += 0.3; m.reasons.append(f"{data_share:.0%} of files are data/binary")
    elif data_share >= 0.2:
        score += 0.15; m.reasons.append(f"{data_share:.0%} of files are data/binary")
    if m.mixed_dirs:
        score += min(0.15 * len(m.mixed_dirs), 0.35)
        m.reasons.append("history/data directories: " + ", ".join(m.mixed_dirs[:5]))
    cjk_share = m.cjk_named / m.files
    if cjk_share >= 0.2 and not (cjk_share >= 0.5 and m.top_dirs <= 2):
        # a repo that is *entirely* a CJK corpus under one root is coherent, not mixed
        score += 0.15; m.reasons.append(f"{cjk_share:.0%} of paths are CJK-named (notes/papers inside a code repo)")
    if m.size_mb >= 200:
        score += 0.1; m.reasons.append(f"{m.size_mb:.0f} MB")
    m.score = round(min(score, 1.0), 2)
    return m


# --------------------------------------------------------------------------
# relation extraction
# --------------------------------------------------------------------------

def _mentions(text: str, names: Iterable[str]) -> set[str]:
    """Sibling repository names mentioned in text, word-bounded, case-insensitive."""
    found: set[str] = set()
    low = text.lower()
    for n in names:
        if len(n) < 4:
            continue  # 'APR', 'SCL' style names are too short to match safely
        if re.search(r"(?<![A-Za-z0-9_\-])" + re.escape(n.lower()) + r"(?![A-Za-z0-9_\-])", low):
            found.add(n)
    return found


def extract_edges(core: GovernanceCore) -> list[Edge]:
    c = core.conn
    rows = c.execute(
        "SELECT id, full_name, description FROM repositories WHERE tenant_id = ? AND missing_since IS NULL",
        (core.tenant_id,),
    ).fetchall()
    by_short = {r["full_name"].split("/")[-1]: r["full_name"] for r in rows}
    shorts = list(by_short)
    edges: list[Edge] = []

    for r in rows:
        me = r["full_name"]
        short = me.split("/")[-1]
        readme_row = c.execute(
            "SELECT payload FROM repository_snapshots WHERE repository_id = ? AND kind = 'readme' ORDER BY rowid DESC LIMIT 1",
            (r["id"],),
        ).fetchone()
        readme = (loads(readme_row["payload"], "") or "") if readme_row else ""
        desc = r["description"] or ""
        text = desc + "\n" + readme[:20000]

        # explicit GitHub links to siblings — the strongest documentary evidence
        for m_ in re.finditer(r"github\.com/kakon77777-commits/([A-Za-z0-9_.\-]+)", text, re.I):
            tgt = m_.group(1)
            real = next((s for s in shorts if s.lower() == tgt.lower()), None)
            if real and real != short:
                edges.append(Edge(me, by_short[real], "related", f"README links github.com/…/{real}", 0.8))

        # supersession language
        for pat in _SUPERSEDE_PATTERNS:
            for m_ in re.finditer(pat, text, re.I):
                tgt = m_.group(1)
                real = next((s for s in shorts if s.lower() == tgt.lower()), None)
                if not real or real == short:
                    continue
                if "superseded by" in pat or "replaced by" in pat or "moved to" in pat or "被" in pat:
                    edges.append(Edge(by_short[real], me, "supersedes", f"'{m_.group(0)[:60]}'", 0.75))
                else:
                    edges.append(Edge(me, by_short[real], "supersedes", f"'{m_.group(0)[:60]}'", 0.75))

        # "based on", "built on", "driven by" -> derived_from / depends_on
        for m_ in re.finditer(r"(?:based on|built on|built with|driven by|powered by|depends on)\s+\[?([A-Za-z0-9_.\-]+)", text, re.I):
            real = next((s for s in shorts if s.lower() == m_.group(1).lower()), None)
            if real and real != short:
                kind = "derived_from" if m_.group(0).lower().startswith("based") else "depends_on"
                edges.append(Edge(me, by_short[real], kind, f"'{m_.group(0)[:50]}'", 0.6))

        # bare mentions of sibling names in description/README -> related (weak)
        for n in _mentions(desc + "\n" + readme[:6000], shorts):
            if n != short:
                edges.append(Edge(me, by_short[n], "related", f"mentions '{n}'", 0.35))

        # name patterns: X-site -> X (implements/presents), X-mcp -> X (implements)
        for suf in _SITE_SUFFIXES:
            if short.lower().endswith(suf):
                base = short[: -len(suf)]
                real = next((s for s in shorts if s.lower() == base.lower()), None)
                if real:
                    edges.append(Edge(me, by_short[real], "implements", f"name: '{short}' is the site of '{real}'", 0.7))
        for suf in _IMPL_SUFFIXES:
            if short.lower().endswith(suf):
                base = short[: -len(suf)]
                real = next((s for s in shorts if s.lower() == base.lower()), None)
                if real:
                    edges.append(Edge(me, by_short[real], "implements", f"name: '{short}' implements '{real}'", 0.7))

    # dedupe: keep the strongest evidence per (source, target, kind)
    best: dict[tuple[str, str, str], Edge] = {}
    for e in edges:
        k = (e.source, e.target, e.kind)
        if k not in best or e.confidence > best[k].confidence:
            best[k] = e
    return sorted(best.values(), key=lambda e: (e.source, -e.confidence, e.target))


def record_edges(core: GovernanceCore, edges: list[Edge]) -> int:
    ids = {r["full_name"]: r["id"] for r in core.conn.execute("SELECT id, full_name FROM repositories")}
    props = [
        Proposal(
            repository_id=ids[e.source],
            field="relation",
            value=json.dumps({"kind": e.kind, "target": e.target}, ensure_ascii=False),
            confidence=e.confidence,
            rationale=e.evidence,
        )
        for e in edges if e.source in ids
    ]
    return RegistryStore(core).propose(props)


def mixed_signals_for_all(core: GovernanceCore) -> dict[str, MixedSignals]:
    c = core.conn
    out: dict[str, MixedSignals] = {}
    for r in c.execute(
        "SELECT id, full_name, size_kb FROM repositories WHERE tenant_id = ? AND missing_since IS NULL",
        (core.tenant_id,),
    ):
        tree = c.execute(
            "SELECT payload FROM repository_snapshots WHERE repository_id = ? AND kind = 'tree' ORDER BY rowid DESC LIMIT 1",
            (r["id"],),
        ).fetchone()
        entries = (loads(tree["payload"], {}) or {}).get("tree", []) if tree else []
        out[r["full_name"]] = score_mixed(entries, r["size_kb"] or 0)
    return out


def families_from_proposals(core: GovernanceCore) -> dict[str, list[str]]:
    """family -> [full_name], from the latest project_family proposals."""
    store = RegistryStore(core)
    fam = defaultdict(list)
    ids = {r["id"]: r["full_name"] for r in core.conn.execute("SELECT id, full_name FROM repositories WHERE missing_since IS NULL")}
    for rid, p in store.latest_proposals("project_family").items():
        if rid in ids and p.value:
            fam[p.value].append(ids[rid])
    return dict(fam)
