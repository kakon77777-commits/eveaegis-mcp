"""Human-authorized repository transfer, personal account -> organization.

NOT part of EveAegis. Transfer is a Level 4 administration action (whitepaper
§11.3) and v0.1 exposes no agent path for it. This runbook runs the transfer
through the operator's own `gh` credential and uses EveAegis only to *record*
what happened and why, then re-syncs so the identity reconciliation heals the
moved repository in place (same surrogate id, governance history intact).

Pre-flight, per repository — the things a transfer is known to break:

* deploy: Cloudflare Pages / Workers connected to the personal account's GitHub
  App need the org connected and the project re-linked; `wrangler` in Actions
  needs its secrets present on the moved repo
* Actions secrets referenced by workflows: listed so they can be verified after
* GitHub Pages: custom domain and source branch are kept by GitHub, but recorded
* open pull requests, webhooks, deploy keys: kept by GitHub, but recorded
* the two remaining forks: a transferred fork keeps its upstream link

Usage:
    python transfer_to_org.py --dry-run  --plan plan.txt      # pre-flight only
    python transfer_to_org.py --execute  --plan plan.txt      # transfer, one by one

`plan.txt`: one `owner/name` per line; lines starting with # are ignored.
Target organization comes from --org (default EveMissLab).
"""
from __future__ import annotations

import argparse, base64, json, os, re, subprocess, sys, time
sys.path.insert(0, r"D:\Ai\work together\eveaegis-mcp\src")
from eveaegis import GovernanceCore, load_config
from eveaegis.credentials import TokenScope
from eveaegis.githubapi import GitHubError, NotFound

ap = argparse.ArgumentParser()
ap.add_argument("--plan", required=True)
ap.add_argument("--org", default="EveMissLab")
g = ap.add_mutually_exclusive_group(required=True)
g.add_argument("--dry-run", action="store_true")
g.add_argument("--execute", action="store_true")
args = ap.parse_args()

targets = [l.strip() for l in open(args.plan, encoding="utf-8") if l.strip() and not l.startswith("#")]
core = GovernanceCore(load_config())


def gh(*a: str) -> subprocess.CompletedProcess:
    return subprocess.run(["gh", *a], capture_output=True, text=True, encoding="utf-8", errors="replace")


def preflight(api, full: str) -> dict:
    """Everything a human should know before this repository moves."""
    meta = api.repo(full)
    br = meta.get("default_branch") or "main"
    tree = {e["path"] for e in api.tree(full, br)} if not meta.get("size") == 0 else set()
    f: dict = {"full_name": full, "private": meta.get("private"), "fork": meta.get("fork"),
               "has_pages": meta.get("has_pages"), "homepage": meta.get("homepage") or "",
               "open_prs": meta.get("open_issues_count", 0), "size_mb": round(meta.get("size", 0) / 1024, 1)}
    # deployment shape
    f["wrangler"] = any(p in tree for p in ("wrangler.toml", "wrangler.jsonc", "wrangler.json"))
    workflows = sorted(p for p in tree if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml")))
    f["workflows"] = workflows
    secrets: set[str] = set()
    for wf in workflows:
        text = api.file_text(full, wf) or ""
        secrets |= set(re.findall(r"secrets\.([A-Za-z0-9_]+)", text))
    f["secrets_referenced"] = sorted(secrets - {"GITHUB_TOKEN"})
    company_domain = any(d in f["homepage"] for d in ("evemisslab.com", "evemisstechnology.com", "evemiss.com",
                                                      "commoninstant.org", "efficientnewlanguage.org",
                                                      "eveglypheditor.com", "agiright.org", "unboundedaxiom.org"))
    # no wrangler + no workflow + a live company domain => most likely Cloudflare's git integration
    f["likely_cloudflare_git_connected"] = bool(company_domain and not f["wrangler"] and not workflows)
    try:
        f["webhooks"] = len(api.get(f"/repos/{full}/hooks", repository=full) or [])
    except GitHubError:
        f["webhooks"] = "n/a"
    try:
        f["deploy_keys"] = len(api.get(f"/repos/{full}/keys", repository=full) or [])
    except GitHubError:
        f["deploy_keys"] = "n/a"
    try:
        f["actions_secrets"] = [s["name"] for s in (api.get(f"/repos/{full}/actions/secrets", repository=full) or {}).get("secrets", [])]
    except GitHubError:
        f["actions_secrets"] = "n/a"
    warnings = []
    if f["likely_cloudflare_git_connected"]:
        warnings.append("Cloudflare git integration: install Cloudflare's GitHub App on the org and re-link the Pages project after the move")
    if f["wrangler"] and f["secrets_referenced"]:
        warnings.append("wrangler deploy via Actions: verify secrets exist on the moved repo before the next push")
    if f["has_pages"]:
        warnings.append("GitHub Pages enabled: check the custom domain/CNAME still resolves after the move")
    if f["fork"]:
        warnings.append("fork: the upstream link is kept, but the transfer moves the fork network membership")
    if isinstance(f["webhooks"], int) and f["webhooks"]:
        warnings.append(f"{f['webhooks']} webhook(s): they move with the repo, but any that point at personal-account URLs need review")
    f["warnings"] = warnings
    return f


print(f"{'DRY RUN' if args.dry_run else 'EXECUTE'}: {len(targets)} repositories -> {args.org}\n")
findings = []
with core.client(TokenScope.READ_CONTENT, reason="transfer pre-flight") as api:
    for full in targets:
        try:
            f = preflight(api, full)
        except (GitHubError, NotFound) as exc:
            print(f"  SKIP  {full}: {str(exc)[:80]}"); continue
        findings.append(f)
        flag = "!" if f["warnings"] else " "
        print(f"{flag} {full.split('/')[-1]:<30} {f['size_mb']:>7} MB  "
              f"{'wrangler ' if f['wrangler'] else ''}{'actions ' if f['workflows'] else ''}{'pages ' if f['has_pages'] else ''}"
              f"{'CF-git? ' if f['likely_cloudflare_git_connected'] else ''}"
              f"secrets={f['secrets_referenced'] or '-'}")
        for w in f["warnings"]:
            print(f"      - {w}")

json.dump(findings, open(os.path.join(os.path.dirname(args.plan), "transfer_preflight.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=1)
if args.dry_run:
    print(f"\npre-flight written for {len(findings)} repositories; nothing moved.")
    core.close(); sys.exit(0)

# ---- execute -----------------------------------------------------------------
moved = 0
for f in findings:
    full = f["full_name"]; name = full.split("/")[-1]
    core.ledger.record("repository_transfer_authorized", actor="human:owner", initiated_by="human:owner",
                       tenant=core.tenant_id, targets=[full], credential_type="gh_cli_delegated_oauth_token",
                       credential_scope="repo", detail={"to": args.org, "preflight": f})
    r = gh("api", "-X", "POST", f"/repos/{full}/transfer", "-f", f"new_owner={args.org}")
    if r.returncode != 0:
        core.ledger.record("repository_transfer_failed", actor="human:owner", tenant=core.tenant_id, targets=[full],
                           result="FAILED", detail={"stderr": r.stderr.strip()[:300]})
        print(f"  FAILED {name}: {r.stderr.strip()[:140]}\n  stopping."); break
    core.ledger.record("repository_transferred", actor="human:owner", initiated_by="human:owner", tenant=core.tenant_id,
                       targets=[full], detail={"to": f"{args.org}/{name}", "note": "GitHub keeps redirects from the old URL"})
    moved += 1; print(f"  moved  {name} -> {args.org}/{name}")
    time.sleep(2)
print(f"\nmoved {moved}/{len(findings)} | audit: {core.ledger.verify()}")
print("next: `aegis sync` (identity reconciliation heals each moved repo under its original surrogate id)")
core.close()
