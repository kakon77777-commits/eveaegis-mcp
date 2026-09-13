"""The reorganization report — the portfolio as a graph, for a human to decide on.

Recovery Index §19 steps 3-5 in one document: every repository with its proposed
class, its family, its relations, whether it should move as-is or as a clean
extraction, and the orphans that belong to no family yet. Written in Chinese
because its one reader decides in Chinese; every number in it comes from the
governance database, and every proposal says why.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ..core import GovernanceCore
from .relations import (
    Edge,
    MixedSignals,
    extract_edges,
    families_from_proposals,
    mixed_signals_for_all,
)
from .store import RegistryStore

_CLASS_LABEL = {"A": "A 公司核心", "B": "B 公司研究", "C": "C 個人", "D": "D Legacy"}
_MODE_LABEL = {"transfer": "transfer", "clean-split": "**clean-split**", "stay": "stay", "archive": "archive"}


def _short(full_name: str) -> str:
    return full_name.split("/")[-1]


def _mermaid_id(name: str) -> str:
    return "n_" + "".join(ch if ch.isalnum() else "_" for ch in name)


def build_reorg(core: GovernanceCore) -> dict[str, Any]:
    c = core.conn
    store = RegistryStore(core)
    rows = c.execute(
        """
        SELECT r.*, o.origin_type, o.origin_confidence, o.review_status
        FROM repositories r LEFT JOIN origin_profiles o ON o.repository_id = r.id
        WHERE r.tenant_id = ? AND r.missing_since IS NULL ORDER BY r.full_name
        """,
        (core.tenant_id,),
    ).fetchall()
    p_class = store.latest_proposals("asset_class")
    p_family = store.latest_proposals("project_family")
    decls = store.declarations()
    mixed = mixed_signals_for_all(core)
    edges = extract_edges(core)
    families = families_from_proposals(core)

    repos: dict[str, dict[str, Any]] = {}
    for r in rows:
        d = decls.get(r["id"])
        pc = p_class.get(r["id"])
        pf = p_family.get(r["id"])
        cls = (d.asset_class if d and d.asset_class else None)
        proposed = pc.value if pc else None
        eff = cls or proposed or "?"
        m = mixed.get(r["full_name"]) or MixedSignals()
        if eff == "C":
            mode = "stay"
        elif eff == "D":
            mode = "archive"
        else:
            mode = m.migration_mode
        repos[r["full_name"]] = {
            "name": _short(r["full_name"]),
            "full_name": r["full_name"],
            "class_declared": cls,
            "class_proposed": proposed,
            "class_conf": pc.confidence if pc else 0.0,
            "class_why": pc.rationale if pc else "",
            "family": (d.project_family if d and d.project_family else None) or (pf.value if pf else None),
            "mode": mode,
            "mixed": m,
            "category": r["category"],
            "lifecycle": r["lifecycle"],
            "origin": r["origin_type"] or "",
            "visibility": r["visibility"],
            "is_fork": bool(r["is_fork"]),
            "is_archived": bool(r["is_archived"]),
            "size_mb": round((r["size_kb"] or 0) / 1024, 1),
            "pushed": (r["pushed_at"] or "")[:10],
            "description": (r["description"] or "")[:90],
        }

    in_family = {n for members in families.values() for n in members}
    orphans = [n for n in repos if n not in in_family]
    return {
        "repos": repos,
        "families": families,
        "orphans": orphans,
        "edges": edges,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }


def _family_mermaid(name: str, members: list[str], edges: list[Edge], repos: dict[str, Any]) -> str:
    mem = set(members)
    lines = ["```mermaid", "graph LR"]
    for m in members:
        r = repos[m]
        label = f"{r['name']}<br/>{r['class_declared'] or r['class_proposed'] or '?'} · {r['mode']}"
        lines.append(f"  {_mermaid_id(m)}[\"{label}\"]")
    seen: set[tuple[str, str]] = set()
    for e in edges:
        if e.source in mem and e.confidence >= 0.6:
            key = (e.source, e.target)
            if key in seen:
                continue
            seen.add(key)
            if e.target not in mem:
                lines.append(f"  {_mermaid_id(e.target)}([\"{_short(e.target)}\"])")
            arrow = "-->" if e.kind in ("implements", "supersedes", "depends_on", "derived_from") else "-.-"
            lines.append(f"  {_mermaid_id(e.source)} {arrow}|{e.kind}| {_mermaid_id(e.target)}")
    lines.append("```")
    return "\n".join(lines)


def _repo_line(r: dict[str, Any]) -> str:
    cls = r["class_declared"] or f"{r['class_proposed']}?"
    conf = "" if r["class_declared"] else f" ({r['class_conf']:.2f})"
    flags = []
    if r["is_fork"]:
        flags.append("fork")
    if r["is_archived"]:
        flags.append("archived")
    if r["visibility"] != "public":
        flags.append(r["visibility"])
    tail = f" — {r['description']}" if r["description"] else ""
    return f"| `{r['name']}` | {cls}{conf} | {_MODE_LABEL[r['mode']]} | {r['mixed'].score:.2f} | {r['pushed']} | {r['size_mb']} | {' '.join(flags)} |{tail}"


def render_reorg(data: dict[str, Any]) -> str:
    repos, families, orphans, edges = data["repos"], data["families"], data["orphans"], data["edges"]
    n = len(repos)
    by_mode = defaultdict(int)
    by_class = defaultdict(int)
    for r in repos.values():
        by_mode[r["mode"]] += 1
        by_class[r["class_declared"] or r["class_proposed"] or "?"] += 1
    strong = [e for e in edges if e.confidence >= 0.6]
    splits = sorted((r for r in repos.values() if r["mode"] == "clean-split"), key=lambda r: -r["mixed"].score)
    supers = [e for e in edges if e.kind == "supersedes"]

    out: list[str] = []
    out.append(f"# GitHub 專案重整 — {n} 個倉庫\n")
    out.append(f"**產生：** {data['generated_at']}  ")
    out.append("**來源：** EveAegis 治理資料庫（inventory / origin / classification / registry proposals）  ")
    out.append("**性質：** 全部是**提案**。`class` 後面帶 `?` 和信心值的是機器猜的；沒有 `?` 的是你已宣告的。\n")
    out.append("---\n")
    out.append("## 0. 怎麼讀\n")
    out.append("每個 repo 有四個欄位要你決定：\n")
    out.append("| 欄位 | 意思 | 選項 |\n|---|---|---|")
    out.append("| **class** | 誰擁有它 | A 公司核心 · B 公司研究 · C 個人 · D Legacy |")
    out.append("| **mode** | 怎麼搬 | `transfer` 原樣搬 · `clean-split` org 拿乾淨版、個人版標 superseded · `stay` 留個人 · `archive` 封存 |")
    out.append("| **family** | 屬於哪個專案家族 | 一個家族 = canonical repo + 網站 + MCP + benchmark + archive |")
    out.append("| **canonical** | 家族裡哪一個是正主 | 每個家族至少一個 `true`，其餘 `false`，沒想好就留 `undeclared` |\n")
    out.append("`mixed` 是「混裝分數」（0–1）：≥ 0.5 代表引擎／資料／研究／網站混在同一個 repo，建議 clean-split。理由在第 5 節。\n")
    out.append("---\n")
    out.append("## 1. 總覽\n")
    out.append(f"- 倉庫 **{n}** · 家族 **{len(families)}**（涵蓋 {n - len(orphans)}）· **孤兒 {len(orphans)}**")
    out.append(f"- class 提案：" + " · ".join(f"{_CLASS_LABEL.get(k, k)} {v}" for k, v in sorted(by_class.items())))
    out.append(f"- 遷移模式：" + " · ".join(f"{k} {v}" for k, v in sorted(by_mode.items())))
    out.append(f"- 關係邊：{len(edges)}（強證據 {len(strong)}）· 取代鏈 {len(supers)}\n")
    out.append("---\n")

    # -- families -----------------------------------------------------------
    out.append("## 2. 家族圖\n")
    out.append("實線 = implements／supersedes／depends_on；虛線 = related。圓角節點是家族外的 repo。\n")
    for fam, members in sorted(families.items(), key=lambda kv: -len(kv[1])):
        members = sorted(members, key=lambda m: (repos[m]["mode"] != "clean-split", repos[m]["name"].lower()))
        out.append(f"### 家族 `{fam}`（{len(members)}）\n")
        out.append(_family_mermaid(fam, members, edges, repos))
        out.append("")
        out.append("| repo | class | mode | mixed | 最後推送 | MB | 旗標 | 摘要 |\n|---|---|---|---|---|---|---|---|")
        for m in members:
            out.append(_repo_line(repos[m]))
        out.append("")
    out.append("---\n")

    # -- orphans ------------------------------------------------------------
    out.append(f"## 3. 孤兒 — 沒有家族的 {len(orphans)} 個\n")
    out.append("Index §19 第 5 步要找的東西。三種可能：真的獨立、該加進某個家族、或它自己就是一個新家族的 canonical。\n")
    groups: dict[str, list[str]] = defaultdict(list)
    for o in orphans:
        groups[repos[o]["class_declared"] or repos[o]["class_proposed"] or "?"].append(o)
    for cls in ("A", "B", "C", "D", "?"):
        if cls not in groups:
            continue
        lst = sorted(groups[cls], key=lambda o: (-repos[o]["class_conf"], repos[o]["name"].lower()))
        out.append(f"### {_CLASS_LABEL.get(cls, cls)}（{len(lst)}）\n")
        out.append("| repo | class | mode | mixed | 最後推送 | MB | 旗標 | 摘要 |\n|---|---|---|---|---|---|---|---|")
        for o in lst:
            out.append(_repo_line(repos[o]))
        out.append("")
    low = [o for o in orphans if repos[o]["class_conf"] <= 0.3 and not repos[o]["class_declared"]]
    if low:
        out.append(f"**其中 {len(low)} 個是地板信心（0.30）—— hints 完全不認得，多半是最近一個月的新專案，請優先看：**\n")
        out.append(", ".join(f"`{repos[o]['name']}`" for o in sorted(low, key=lambda o: repos[o]["name"].lower())))
        out.append("")
    out.append("---\n")

    # -- supersession ---------------------------------------------------------
    out.append("## 4. 取代鏈（supersession）\n")
    if supers:
        out.append("從 README／描述文字找到的：\n")
        for e in supers:
            out.append(f"- `{_short(e.source)}` **supersedes** `{_short(e.target)}` — {e.evidence}")
    else:
        out.append("文字裡沒找到明確的取代語句。")
    out.append("\n依名稱形態推測的候選（需要你確認）：\n")
    names = {r["name"].lower(): r for r in repos.values()}
    cands = []
    for r in repos.values():
        low_ = r["name"].lower()
        for suf, what in (("-mvp", "正式版"), ("-prototype", "後繼"), ("_origin", "後繼"), ("-old", "新版"), ("-v1", "v2")):
            if low_.endswith(suf):
                base = low_[: -len(suf)]
                hits = [x for k, x in names.items() if k != low_ and (k == base or k.startswith(base + "-") or k.startswith(base + "_"))]
                for h in hits:
                    cands.append(f"- `{r['name']}` ← 可能被 `{h['name']}` 取代（名稱 `{suf}` 對 {what}）")
    out.extend(sorted(set(cands)) or ["- （無）"])
    out.append("")
    out.append("---\n")

    # -- clean-split ----------------------------------------------------------
    out.append(f"## 5. 乾淨版候選（clean-split）— {len(splits)} 個\n")
    out.append("這些 repo 建議**不要原樣 transfer**：org 建一個乾淨版（只有引擎／產品），個人版保留全部歷史並宣告 `superseded_by` 指向 org 版。這樣 canonical 仍然只有一份。\n")
    for r in splits:
        m = r["mixed"]
        out.append(f"### `{r['name']}` — mixed {m.score:.2f} · {m.size_mb} MB · {m.files} 檔（code {m.code_files} / data {m.data_files}）\n")
        for why in m.reasons:
            out.append(f"- {why}")
        out.append("")
    border = sorted((r for r in repos.values() if 0.3 <= r["mixed"].score < 0.5), key=lambda r: -r["mixed"].score)
    if border:
        out.append("邊界（0.30–0.49，看一眼就好）：" + ", ".join(f"`{r['name']}`({r['mixed'].score:.2f})" for r in border))
        out.append("")
    out.append("---\n")

    # -- decision procedure -----------------------------------------------------
    out.append("## 6. 怎麼做決策 — 每個 repo 問四題\n")
    out.append("1. **它是誰的？** 公司產品／基礎建設／公司網站 → A；EveMissLab 研究但不商用 → B；純個人 → C；死的、被取代的 → D。")
    out.append("2. **它乾淨嗎？** mixed ≥ 0.5 → org 拿乾淨版。決定「乾淨版」裡留什麼的判準：*org 的 repo 裡不該有任何一個檔案是「以後可能用得到」而放的*。")
    out.append("3. **它屬於哪個家族、是不是正主？** 家族裡只有一個 canonical；網站／MCP／benchmark 都是它的衛星。")
    out.append("4. **搬了會壞什麼？** Cloudflare Pages git 連線、Actions secrets、GitHub Pages 網域 —— transfer runbook 的 dry-run 會逐個列出，搬前看。\n")
    out.append("填答案的地方：`repository_registry_2026-09-13.csv` 的 `class` / `target_owner` / `canonical` / `project_family` / `superseded_by` / `notes` 欄。填完 `aegis registry import`。\n")
    out.append("---\n")

    # -- full table -------------------------------------------------------------
    out.append("## 7. 全表（108，按家族 → 名稱）\n")
    out.append("| repo | family | class | mode | mixed | origin | lifecycle | 最後推送 | MB |\n|---|---|---|---|---|---|---|---|---|")
    for r in sorted(repos.values(), key=lambda r: ((r["family"] or "~"), r["name"].lower())):
        cls = r["class_declared"] or f"{r['class_proposed']}?"
        out.append(f"| `{r['name']}` | {r['family'] or ''} | {cls} | {r['mode']} | {r['mixed'].score:.2f} | {r['origin'].replace('ORIGINAL_WITH_DEPENDENCIES', 'ORIG+DEPS')} | {r['lifecycle']} | {r['pushed']} | {r['size_mb']} |")
    out.append("")
    out.append("*EveAegis 產生。class／family／mode／關係全部是提案，宣告之前不是事實。*")
    return "\n".join(out)


def write_reorg_report(core: GovernanceCore, path: Path) -> dict[str, Any]:
    data = build_reorg(core)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_reorg(data), encoding="utf-8")
    # keep the machine view queryable, not just readable
    from .store import Proposal

    props = [
        Proposal(repository_id=rid, field="migration_mode", value=r["mode"],
                 confidence=min(0.9, 0.4 + r["mixed"].score), rationale="; ".join(r["mixed"].reasons) or "no mixed-content signals")
        for rid, r in ((row["id"], data["repos"][row["full_name"]]) for row in core.conn.execute(
            "SELECT id, full_name FROM repositories WHERE tenant_id = ? AND missing_since IS NULL", (core.tenant_id,)))
    ]
    RegistryStore(core).propose(props)
    core.ledger.record("registry_reorg_report", actor="agent:local", tenant=core.tenant_id,
                       detail={"path": str(path), "repositories": len(data["repos"]), "families": len(data["families"]),
                               "orphans": len(data["orphans"]), "edges": len(data["edges"])})
    return data
