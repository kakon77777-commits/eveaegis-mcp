"""Isolated, non-executing git access (§21 分析工作區).

§21 is unambiguous: 不得執行不可信倉庫中的程式. Cloning a repository is the moment
that rule is most easily broken, because git itself will happily run repository-
controlled code on the operator's behalf — hooks copied from templates, ``clean``/
``smudge`` filters declared in ``.gitattributes``, ``core.fsmonitor``,
``ext::`` transport helpers, submodule URLs. Every one of those is disabled here,
explicitly, per invocation.

The defences, and what each one stops:

``--mirror``
    Bare clone, no working tree. Nothing is ever checked out, so checkout-time
    filters and ``.gitattributes`` smudge commands never run at all.
``core.hooksPath`` → an empty directory this module owns
    Neutralises any hook the repository ships, including ones a future non-mirror
    code path might trigger.
``protocol.allow=never`` for ``ext``/``file``, ``protocol.version=2``
    ``ext::sh -c …`` remote URLs are remote code execution by design.
``GIT_TERMINAL_PROMPT=0``, ``GIT_ASKPASS``/``SSH_ASKPASS`` disarmed
    An analysis run must never block on an interactive credential prompt.
``--no-recurse-submodules``
    A submodule URL is attacker-controlled input; resolving it fetches from an
    arbitrary host.

Package managers and build tools are not merely "not called" — :func:`assert_safe`
refuses to run at all when ``allow_repository_code_execution`` is set, so a future
caller cannot opt in to ``npm install`` through configuration.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..config import AnalysisConfig

#: Commands the analysis path must never invoke (§21 禁止預設執行). Present as an
#: explicit denylist so the intent survives refactoring, not just as an absence.
FORBIDDEN_COMMANDS: frozenset[str] = frozenset(
    {
        "npm", "yarn", "pnpm", "bun", "npx",
        "pip", "pip3", "poetry", "uv", "pipenv",
        "make", "cmake", "ninja", "gradle", "mvn", "cargo", "go",
        "docker", "podman", "bash", "sh", "powershell", "cmd",
        "node", "python", "ruby", "php",
    }
)

DEFAULT_TIMEOUT_SECONDS = 900
#: Refuse to mirror anything enormous; a governance scan must not fill the disk.
DEFAULT_MAX_CLONE_KB = 512_000


class GitError(RuntimeError):
    def __init__(self, message: str, *, command: list[str] | None = None, stderr: str = "") -> None:
        super().__init__(message)
        self.command = command or []
        self.stderr = stderr


class RepositoryExecutionRefused(GitError):
    """Raised when configuration would permit running repository-controlled code."""


def assert_safe(config: AnalysisConfig) -> None:
    """§21 gate. Called before *every* git operation, not once at startup."""
    if config.allow_repository_code_execution:
        raise RepositoryExecutionRefused(
            "analysis.allow_repository_code_execution is true; the provenance engine "
            "refuses to operate in a configuration that permits executing repository "
            "code (§21). Sandbox execution is out of scope for v0.1 (§25)."
        )


def _hooks_dir(workspace: Path) -> Path:
    """An empty, engine-owned directory used as ``core.hooksPath``."""
    path = workspace / ".empty-hooks"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_env() -> dict[str, str]:
    env = dict(os.environ)
    # Drop rather than blank: git treats an empty GIT_ASKPASS as a program path.
    for inherited in ("GIT_ASKPASS", "SSH_ASKPASS", "GIT_EXTERNAL_DIFF", "GIT_SSH_COMMAND"):
        env.pop(inherited, None)
    env.update(
        {
            "GIT_TERMINAL_PROMPT": "0",     # never block on a credential prompt
            "GIT_LFS_SKIP_SMUDGE": "1",     # LFS smudge shells out; skip it
            "GCM_INTERACTIVE": "never",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_PAGER": "cat",
            "GIT_CONFIG_COUNT": "0",
        }
    )
    return env


def _hardening_flags(workspace: Path) -> list[str]:
    return [
        "-c", f"core.hooksPath={_hooks_dir(workspace).as_posix()}",
        "-c", "core.fsmonitor=false",
        "-c", "protocol.version=2",
        "-c", "protocol.ext.allow=never",
        "-c", "protocol.file.allow=never",
        "-c", "uploadpack.allowFilter=false",
        "-c", "advice.detachedHead=false",
        "-c", "gc.auto=0",
        "-c", "fetch.recurseSubmodules=false",
    ]


def run_git(
    args: list[str],
    *,
    config: AnalysisConfig,
    workspace: Path,
    cwd: Path | None = None,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
    check: bool = True,
) -> str:
    """Run one hardened ``git`` invocation and return stdout.

    ``args`` must start with a git subcommand; anything resembling a build tool is
    rejected before ``subprocess`` is reached.
    """
    assert_safe(config)
    if not args:
        raise GitError("no git subcommand given")
    if args[0].lower() in FORBIDDEN_COMMANDS:
        raise RepositoryExecutionRefused(f"refusing to run '{args[0]}' from the analysis path (§21)")
    if shutil.which("git") is None:
        raise GitError("git executable not found on PATH")

    command = ["git", *_hardening_flags(workspace), *args]
    try:
        completed = subprocess.run(  # noqa: S603 - fixed argv, no shell, hardened env
            command,
            cwd=str(cwd) if cwd else None,
            env=_safe_env(),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitError(f"git timed out after {timeout}s", command=command) from exc

    if check and completed.returncode != 0:
        raise GitError(
            f"git {' '.join(args[:2])} failed with code {completed.returncode}",
            command=command,
            stderr=(completed.stderr or "").strip()[:2000],
        )
    return completed.stdout


# --------------------------------------------------------------------------
# clone
# --------------------------------------------------------------------------

@dataclass(slots=True)
class MirrorClone:
    """A bare mirror of one repository inside its §21 workspace."""

    full_name: str
    path: Path
    workspace: Path
    config: AnalysisConfig

    def git(self, args: list[str], *, check: bool = True, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> str:
        return run_git(
            ["--git-dir", self.path.as_posix(), *args],
            config=self.config,
            workspace=self.workspace,
            timeout=timeout,
            check=check,
        )


def clone_url(full_name: str, *, host: str = "github.com") -> str:
    return f"https://{host}/{full_name}.git"


def mirror_clone(
    full_name: str,
    workspace: Path,
    *,
    config: AnalysisConfig,
    directory: str = "bare.git",
    size_kb: int | None = None,
    max_size_kb: int = DEFAULT_MAX_CLONE_KB,
    refresh: bool = False,
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> MirrorClone:
    """Create (or reuse) ``<workspace>/bare.git`` as a bare mirror.

    Bare and mirrored, so there is no working tree to check out and therefore no
    checkout-time hook or filter to execute. Existing mirrors are reused rather than
    re-cloned; ``refresh=True`` fetches updates in place.
    """
    assert_safe(config)
    if size_kb is not None and size_kb > max_size_kb:
        raise GitError(
            f"{full_name} is {size_kb} KB, above the {max_size_kb} KB mirror ceiling; "
            f"raise max_size_kb explicitly if this repository really must be cloned"
        )

    workspace.mkdir(parents=True, exist_ok=True)
    target = workspace / directory
    if (target / "HEAD").exists():
        clone = MirrorClone(full_name, target, workspace, config)
        if refresh:
            clone.git(["fetch", "--prune", "--no-tags", "origin"], check=False, timeout=timeout)
        return clone
    if target.exists():
        shutil.rmtree(target, ignore_errors=True)

    run_git(
        [
            "clone",
            "--mirror",
            "--no-recurse-submodules",
            "--quiet",
            clone_url(full_name),
            target.as_posix(),
        ],
        config=config,
        workspace=workspace,
        timeout=timeout,
    )
    return MirrorClone(full_name, target, workspace, config)


def add_comparison_remote(
    clone: MirrorClone,
    upstream_full_name: str,
    *,
    remote_name: str = "upstream",
    timeout: int = DEFAULT_TIMEOUT_SECONDS,
) -> bool:
    """Fetch a candidate upstream into the same object store.

    Both histories must live in one repository for ``merge-base`` to mean anything.
    Fetching into the mirror is cheap (shared objects) and, critically, still never
    checks anything out. Returns ``False`` when the upstream could not be fetched —
    a private or deleted candidate is a normal outcome, not an error.
    """
    clone.git(["remote", "remove", remote_name], check=False)
    clone.git(["remote", "add", remote_name, clone_url(upstream_full_name)], check=False)
    output = clone.git(
        ["fetch", "--no-tags", "--quiet", remote_name, f"+refs/heads/*:refs/remotes/{remote_name}/*"],
        check=False,
        timeout=timeout,
    )
    refs = clone.git(["for-each-ref", "--format=%(refname)", f"refs/remotes/{remote_name}"], check=False)
    return bool(refs.strip()) or bool(output.strip())


# --------------------------------------------------------------------------
# history and content readers
# --------------------------------------------------------------------------

def commit_shas(clone: MirrorClone, *, ref: str = "--all", limit: int | None = None) -> set[str]:
    """Commit SHAs reachable from ``ref`` — the C_A / C_B sets of §7.1 S_commit."""
    args = ["rev-list", ref]
    if limit:
        args.append(f"--max-count={limit}")
    output = clone.git(args, check=False)
    return {line.strip() for line in output.splitlines() if line.strip()}


def root_commits(clone: MirrorClone, *, ref: str = "--all") -> set[str]:
    """Parentless commits. A shared root is the strongest ancestry evidence there is."""
    output = clone.git(["rev-list", "--max-parents=0", ref], check=False)
    return {line.strip() for line in output.splitlines() if line.strip()}


def merge_base(clone: MirrorClone, a: str, b: str) -> str | None:
    output = clone.git(["merge-base", a, b], check=False).strip()
    return output.splitlines()[0].strip() if output else None


@dataclass(slots=True)
class BlobEntry:
    sha: str
    size: int
    path: str


def blob_entries(clone: MirrorClone, ref: str = "HEAD") -> list[BlobEntry]:
    """``(sha, size, path)`` for every blob in one tree — the B_A / B_B set of §7.1."""
    output = clone.git(["ls-tree", "-r", "--long", "--full-tree", ref], check=False)
    entries: list[BlobEntry] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        meta, _, path = line.partition("\t")
        parts = meta.split()
        if len(parts) < 4 or parts[1] != "blob":
            continue
        try:
            size = int(parts[3])
        except ValueError:
            size = 0
        entries.append(BlobEntry(parts[2], size, path.strip()))
    return entries


def resolve_ref(clone: MirrorClone, candidates: list[str]) -> str | None:
    for candidate in candidates:
        output = clone.git(["rev-parse", "--verify", "--quiet", candidate], check=False).strip()
        if output:
            return candidate
    return None


def default_head(clone: MirrorClone) -> str | None:
    """Best available tip ref of the mirror, tolerating unusual branch names."""
    return resolve_ref(clone, ["HEAD", "refs/heads/main", "refs/heads/master", "refs/heads/trunk"])


def remotes(clone: MirrorClone) -> dict[str, str]:
    output = clone.git(["remote", "-v"], check=False)
    found: dict[str, str] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            found.setdefault(parts[0], parts[1])
    return found


def commit_count(clone: MirrorClone, ref: str = "--all") -> int:
    output = clone.git(["rev-list", "--count", ref], check=False).strip()
    try:
        return int(output.splitlines()[0]) if output else 0
    except ValueError:
        return 0


def author_histogram(clone: MirrorClone, *, limit: int = 5000) -> dict[str, int]:
    """Commits per author email. Owner changes and import dumps show up here."""
    output = clone.git(["log", "--all", f"--max-count={limit}", "--format=%ae"], check=False)
    histogram: dict[str, int] = {}
    for line in output.splitlines():
        email = line.strip().lower()
        if email:
            histogram[email] = histogram.get(email, 0) + 1
    return histogram


def commit_timestamps(clone: MirrorClone, *, limit: int = 5000) -> list[int]:
    """Unix author times, newest first — the input to mirror sync-pattern detection."""
    output = clone.git(["log", "--all", f"--max-count={limit}", "--format=%at"], check=False)
    stamps: list[int] = []
    for line in output.splitlines():
        try:
            stamps.append(int(line.strip()))
        except ValueError:
            continue
    return stamps


def read_blob(clone: MirrorClone, ref: str, path: str, *, max_bytes: int = 1_048_576) -> str | None:
    """Read one file out of the object store as text. Never touches the filesystem."""
    output = clone.git(["show", f"{ref}:{path}"], check=False)
    if not output:
        return None
    return output[:max_bytes]


def submodule_urls(clone: MirrorClone, ref: str = "HEAD") -> list[str]:
    """URLs declared in ``.gitmodules``. Parsed as text — never resolved or fetched."""
    content = read_blob(clone, ref, ".gitmodules")
    if not content:
        return []
    urls: list[str] = []
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("url"):
            _, _, value = stripped.partition("=")
            if value.strip():
                urls.append(value.strip())
    return urls
