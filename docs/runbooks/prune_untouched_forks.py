"""One-off, human-authorized fork deletion. NOT part of EveAegis.

EveAegis v0.1 deliberately does not delete repositories (whitepaper §25). This
script runs the deletion through Neo's own `gh` credential, and uses EveAegis
only to *record* what happened and why. Every repository is re-verified as
untouched (ahead_by == 0) immediately before its deletion, and the run stops on
the first failure rather than continuing blind.

Usage:  python prune_forks.py --dry-run     # verify + print, delete nothing
        python prune_forks.py --execute     # actually delete
"""
from __future__ import annotations
import json, os, subprocess, sys
sys.path.insert(0, r"D:\Ai\work together\eveaegis-mcp\src")
os.environ.setdefault("EVEAEGIS_CONFIG", os.path.join(os.path.dirname(__file__), "..", "..", "config", "config.yaml"))
from eveaegis import GovernanceCore, load_config
from eveaegis.credentials import TokenScope

OWNER = "kakon77777-commits"
PLAN = os.environ.get("PRUNE_PLAN", "forks.json")
execute = "--execute" in sys.argv

def gh(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")

# 0. credential precondition — never proceed on a token that cannot delete
scopes = gh("auth", "status").stderr + gh("auth", "status").stdout
if "delete_repo" not in scopes:
    print("ABORT: gh token lacks the delete_repo scope. Neo must run:\n  gh auth refresh -h github.com -s delete_repo")
    sys.exit(2)

targets = [d for d in json.load(open(PLAN, encoding="utf-8")) if d["ahead"] == 0]
print(f"{'DRY RUN' if not execute else 'EXECUTE'}: {len(targets)} forks, "
      f"{sum(d['size_mb'] for d in targets)/1024:.1f} GB\n")

core = GovernanceCore(load_config())
deleted, kept = [], []
with core.client(TokenScope.READ_METADATA, reason="pre-deletion re-verification") as api:
    for d in targets:
        full = f"{OWNER}/{d['name']}"
        # 1. re-verify RIGHT NOW: still a fork, still ahead_by == 0
        try:
            meta = api.repo(full)
            parent = (meta.get("parent") or {}).get("full_name")
            br = meta.get("default_branch")
            cmp = api.get(f"/repos/{parent}/compare/{parent.split('/')[0]}:{br}...{OWNER}:{br}", repository=parent)
            ahead = cmp.get("ahead_by")
        except Exception as exc:
            print(f"  SKIP  {d['name']:<26} could not re-verify: {str(exc)[:60]}"); kept.append(d["name"]); continue
        if not meta.get("fork") or ahead != 0:
            print(f"  SKIP  {d['name']:<26} no longer eligible (fork={meta.get('fork')} ahead={ahead})"); kept.append(d["name"]); continue

        evidence = {"parent": parent, "ahead_by": ahead, "behind_by": cmp.get("behind_by"),
                    "size_mb": d["size_mb"], "created": d["created"], "github_repository_id": meta.get("id")}
        if not execute:
            print(f"  would delete  {d['name']:<26} ahead=0 behind={evidence['behind_by']:<4} {d['size_mb']:>8} MB  <- {parent}")
            continue

        # 2. record the authorization and the evidence BEFORE the irreversible step
        core.ledger.record("fork_deletion_authorized", actor="human:owner", initiated_by="human:owner",
                           tenant=core.tenant_id, targets=[full], credential_type="gh_cli_delegated_oauth_token",
                           credential_scope="delete_repo", detail={**evidence, "reason": "untouched reference fork; Neo approved all 14 on 2026-09-13"})
        # 3. delete via Neo's own credential, outside EveAegis
        r = gh("repo", "delete", full, "--yes")
        if r.returncode != 0:
            core.ledger.record("fork_deletion_failed", actor="human:owner", tenant=core.tenant_id, targets=[full],
                               result="FAILED", detail={"stderr": r.stderr.strip()[:300]})
            print(f"  FAILED {d['name']:<26} {r.stderr.strip()[:120]}\n  stopping here."); break
        core.ledger.record("fork_deleted", actor="human:owner", initiated_by="human:owner", tenant=core.tenant_id,
                           targets=[full], credential_type="gh_cli_delegated_oauth_token", credential_scope="delete_repo",
                           detail={**evidence, "restorable_until_approx": "90 days via GitHub Settings > Deleted repositories"})
        deleted.append(d["name"]); print(f"  deleted {d['name']:<26} {d['size_mb']:>8} MB")

print(f"\ndeleted {len(deleted)} | skipped {len(kept)} | audit: {core.ledger.verify()}")
core.close()
