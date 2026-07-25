"""Evidence gathering for the classifier (§5, §24 Phase 3).

This module is deliberately **offline**. Phase 1 (inventory) already persisted the
repository row and whatever snapshots it could fetch; re-hitting the GitHub API
during classification would make the verdict depend on rate limits and on the
moment it ran. Everything here reads ``repositories`` and ``repository_snapshots``
and nothing else.

Every field degrades to ``None`` / empty rather than raising: a half-synced
portfolio must still classify, it just classifies with lower confidence. The
snapshot readers are written against *unknown* payload shapes on purpose — the
inventory module owns the ``kind`` vocabulary and may change it, so we probe
several plausible layouts and give up quietly.
"""

from __future__ import annotations

import base64
import binascii
import re
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ..db import loads

#: Snapshot ``kind`` fragments we know how to read, per logical content type.
_README_KINDS = ("readme",)
_TREE_KINDS = ("tree", "contents", "files", "paths", "listing")
_RELEASE_KINDS = ("release", "tag")
_REPO_KINDS = ("repository", "repo", "metadata")

#: Cap on how much README text is retained. Classification only ever looks at the
#: head of a README; keeping megabytes of prose in ``signals`` would bloat the DB.
README_CHARS = 8000

_WORD_SPLIT = re.compile(r"[^a-z0-9一-鿿]+")
_SEMVER = re.compile(r"\bv?(\d+)\.(\d+)(?:\.(\d+))?\b")


@dataclass(frozen=True)
class RepositorySignals:
    """Everything the classifier is allowed to reason from.

    Frozen because a signal set is an observation, not a working buffer: if a rule
    wants a derived value it computes it, it does not overwrite the evidence.
    """

    repository_id: str
    tenant_id: str
    full_name: str
    owner: str
    name: str

    description: str = ""
    homepage: str | None = None
    topics: tuple[str, ...] = ()
    primary_language: str | None = None
    languages: Mapping[str, int] = field(default_factory=dict)
    license_spdx: str | None = None
    visibility: str = "public"
    default_branch: str = "main"

    is_archived: bool = False
    is_fork: bool = False
    parent_full_name: str | None = None
    source_full_name: str | None = None
    template_full_name: str | None = None

    size_kb: int = 0
    stargazers: int = 0
    open_issues: int = 0

    pushed_at: datetime | None = None
    created_at: datetime | None = None
    days_since_push: int | None = None
    days_since_created: int | None = None

    #: Lowercased repository paths seen in a tree/contents snapshot. Empty means
    #: "no snapshot", which is NOT the same as "repository has no files".
    paths: frozenset[str] = frozenset()
    has_tree_snapshot: bool = False
    readme_text: str = ""
    has_readme_snapshot: bool = False
    release_count: int | None = None
    latest_release_tag: str | None = None
    has_pages: bool | None = None

    # -- derived helpers --------------------------------------------------

    @property
    def has_homepage(self) -> bool:
        return bool(self.homepage and self.homepage.strip())

    @property
    def is_public(self) -> bool:
        return self.visibility == "public"

    def has_file(self, marker: str) -> bool:
        """True when a path matching ``marker`` exists.

        A trailing ``/`` means "directory anywhere in the tree"; otherwise the
        marker is matched as a root-level file first, then as any basename.
        """
        if not self.paths:
            return False
        needle = marker.lower().strip()
        if needle.endswith("/"):
            return any(p == needle.rstrip("/") or p.startswith(needle) or f"/{needle}" in f"/{p}" for p in self.paths)
        if needle in self.paths:
            return True
        suffix = "/" + needle
        return any(p.endswith(suffix) for p in self.paths)

    def text_blob(self) -> str:
        """Lowercased name + description + topics. The README is kept separate so
        rules can weigh curated metadata above prose."""
        parts = [self.name.replace("-", " ").replace("_", " "), self.description, " ".join(self.topics)]
        return " ".join(p for p in parts if p).lower()

    def name_tokens(self) -> frozenset[str]:
        """Normalised tokens of the repository name, for naming-overlap checks."""
        return frozenset(t for t in _WORD_SPLIT.split(self.name.lower()) if len(t) > 2)

    def version_hint(self) -> tuple[int, int, int] | None:
        """Best available version number: release tag first, then description prose."""
        for candidate in (self.latest_release_tag, self.description, self.readme_text[:600]):
            if not candidate:
                continue
            m = _SEMVER.search(candidate)
            if m:
                return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))
        return None

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection stored in ``ClassificationResult.signals``.

        ``paths`` and the README body are summarised rather than copied: the point
        of persisting signals is auditability of the verdict, not a second copy of
        the repository.
        """
        return {
            "full_name": self.full_name,
            "description": self.description[:400],
            "homepage": self.homepage,
            "topics": list(self.topics),
            "primary_language": self.primary_language,
            "languages": dict(list(self.languages.items())[:10]),
            "license_spdx": self.license_spdx,
            "visibility": self.visibility,
            "is_archived": self.is_archived,
            "is_fork": self.is_fork,
            "parent_full_name": self.parent_full_name,
            "template_full_name": self.template_full_name,
            "size_kb": self.size_kb,
            "stargazers": self.stargazers,
            "open_issues": self.open_issues,
            "days_since_push": self.days_since_push,
            "days_since_created": self.days_since_created,
            "path_count": len(self.paths),
            "has_tree_snapshot": self.has_tree_snapshot,
            "has_readme_snapshot": self.has_readme_snapshot,
            "readme_chars": len(self.readme_text),
            "release_count": self.release_count,
            "latest_release_tag": self.latest_release_tag,
            "has_pages": self.has_pages,
        }


# --------------------------------------------------------------------------
# loading
# --------------------------------------------------------------------------

def load_repository_row(
    conn: sqlite3.Connection,
    full_name: str,
    *,
    tenant_id: str | None = None,
) -> sqlite3.Row | None:
    """Fetch one repository row by ``owner/name``, optionally scoped to a tenant."""
    if tenant_id:
        sql = "SELECT * FROM repositories WHERE tenant_id = ? AND full_name = ?"
        params: tuple[Any, ...] = (tenant_id, full_name)
    else:
        sql = "SELECT * FROM repositories WHERE full_name = ?"
        params = (full_name,)
    return conn.execute(sql, params).fetchone()


def collect_signals(
    conn: sqlite3.Connection,
    repository: Mapping[str, Any] | sqlite3.Row,
) -> RepositorySignals:
    """Build a :class:`RepositorySignals` from a ``repositories`` row.

    ``repository`` is a row (or any mapping with the same keys) so callers that
    already hold the row do not pay for a second query.
    """
    row = _as_mapping(repository)
    repository_id = str(row.get("id") or "")
    full_name = str(row.get("full_name") or "")
    owner, _, name = full_name.partition("/")
    if not name:  # tolerate a bare name, e.g. in hand-built fixtures
        owner, name = "", full_name

    pushed_at = _parse_dt(row.get("pushed_at"))
    created_at = _parse_dt(row.get("created_at"))

    readme_text, has_readme = _read_readme(conn, repository_id)
    paths, has_tree = _read_paths(conn, repository_id)
    release_count, latest_tag = _read_releases(conn, repository_id)
    has_pages = _read_has_pages(conn, repository_id, str(row.get("homepage") or ""))

    return RepositorySignals(
        repository_id=repository_id,
        tenant_id=str(row.get("tenant_id") or ""),
        full_name=full_name,
        owner=owner,
        name=name,
        description=str(row.get("description") or ""),
        homepage=(row.get("homepage") or None),
        topics=tuple(str(t).lower() for t in (loads(row.get("topics"), []) or []) if t),
        primary_language=(row.get("primary_language") or None),
        languages=dict(loads(row.get("languages"), {}) or {}),
        license_spdx=(row.get("license_spdx") or None),
        visibility=str(row.get("visibility") or "public"),
        default_branch=str(row.get("default_branch") or "main"),
        is_archived=bool(row.get("is_archived")),
        is_fork=bool(row.get("is_fork")),
        parent_full_name=(row.get("parent_full_name") or None),
        source_full_name=(row.get("source_full_name") or None),
        template_full_name=(row.get("template_full_name") or None),
        size_kb=int(row.get("size_kb") or 0),
        stargazers=int(row.get("stargazers") or 0),
        open_issues=int(row.get("open_issues") or 0),
        pushed_at=pushed_at,
        created_at=created_at,
        days_since_push=_days_since(pushed_at),
        days_since_created=_days_since(created_at),
        paths=paths,
        has_tree_snapshot=has_tree,
        readme_text=readme_text,
        has_readme_snapshot=has_readme,
        release_count=release_count,
        latest_release_tag=latest_tag,
        has_pages=has_pages,
    )


# --------------------------------------------------------------------------
# snapshot readers — every one of these is allowed to find nothing
# --------------------------------------------------------------------------

def _snapshot_payloads(
    conn: sqlite3.Connection,
    repository_id: str,
    kind_fragments: Iterable[str],
) -> list[Any]:
    """Latest-first payloads whose ``kind`` contains any of the given fragments."""
    if not repository_id:
        return []
    try:
        rows = conn.execute(
            "SELECT kind, payload FROM repository_snapshots "
            "WHERE repository_id = ? ORDER BY taken_at DESC",
            (repository_id,),
        ).fetchall()
    except sqlite3.Error:
        return []
    fragments = tuple(f.lower() for f in kind_fragments)
    out: list[Any] = []
    for row in rows:
        kind = str(row["kind"] or "").lower()
        if any(f in kind for f in fragments):
            payload = loads(row["payload"], None)
            out.append(payload if payload is not None else row["payload"])
    return out


def _read_readme(conn: sqlite3.Connection, repository_id: str) -> tuple[str, bool]:
    for payload in _snapshot_payloads(conn, repository_id, _README_KINDS):
        text = _payload_text(payload)
        if text:
            return text[:README_CHARS], True
    return "", False


def _payload_text(payload: Any) -> str:
    """Pull README prose out of whatever shape the inventory phase stored."""
    if isinstance(payload, str):
        return payload
    if isinstance(payload, dict):
        for key in ("text", "content", "body", "readme", "markdown", "raw"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                if str(payload.get("encoding", "")).lower() == "base64" or _looks_base64(value):
                    decoded = _try_b64(value)
                    if decoded:
                        return decoded
                return value
    return ""


def _looks_base64(value: str) -> bool:
    sample = value.strip().replace("\n", "")
    if len(sample) < 40 or len(sample) % 4:
        return False
    return bool(re.fullmatch(r"[A-Za-z0-9+/=]+", sample))


def _try_b64(value: str) -> str:
    try:
        return base64.b64decode(value.encode("ascii"), validate=False).decode("utf-8", "replace")
    except (binascii.Error, UnicodeDecodeError, ValueError):
        return ""


def _read_paths(conn: sqlite3.Connection, repository_id: str) -> tuple[frozenset[str], bool]:
    for payload in _snapshot_payloads(conn, repository_id, _TREE_KINDS):
        paths = _extract_paths(payload)
        if paths:
            return frozenset(paths), True
    return frozenset(), False


def _extract_paths(payload: Any, depth: int = 0) -> set[str]:
    """Recover path strings from a tree payload without assuming its schema."""
    if depth > 4:
        return set()
    out: set[str] = set()
    if isinstance(payload, str):
        candidate = payload.strip().lstrip("./")
        if candidate and "\n" not in candidate and len(candidate) < 400:
            out.add(candidate.lower())
        return out
    if isinstance(payload, list):
        for item in payload:
            out |= _extract_paths(item, depth + 1)
        return out
    if isinstance(payload, dict):
        for key in ("path", "name", "filename"):
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                out.add(value.strip().lstrip("./").lower())
                break
        for key in ("tree", "entries", "files", "items", "paths", "contents"):
            if key in payload:
                out |= _extract_paths(payload[key], depth + 1)
    return out


def _read_releases(conn: sqlite3.Connection, repository_id: str) -> tuple[int | None, str | None]:
    for payload in _snapshot_payloads(conn, repository_id, _RELEASE_KINDS):
        if isinstance(payload, list):
            tag = None
            for item in payload:
                if isinstance(item, dict):
                    tag = item.get("tag_name") or item.get("name") or item.get("tag")
                elif isinstance(item, str):
                    tag = item
                if tag:
                    break
            return len(payload), (str(tag) if tag else None)
        if isinstance(payload, dict):
            tag = payload.get("tag_name") or payload.get("name") or payload.get("tag")
            count = payload.get("count")
            return (int(count) if isinstance(count, int) else 1), (str(tag) if tag else None)
    return None, None


def _read_has_pages(conn: sqlite3.Connection, repository_id: str, homepage: str) -> bool | None:
    for payload in _snapshot_payloads(conn, repository_id, _REPO_KINDS):
        if isinstance(payload, dict) and "has_pages" in payload:
            return bool(payload["has_pages"])
    if homepage:
        # A github.io homepage is Pages by construction; any other homepage still
        # proves the repository is publicly presented, but not that Pages is on.
        return "github.io" in homepage.lower() or None
    return None


# --------------------------------------------------------------------------
# small utilities
# --------------------------------------------------------------------------

def _as_mapping(row: Mapping[str, Any] | sqlite3.Row) -> Mapping[str, Any]:
    if isinstance(row, sqlite3.Row):
        return {k: row[k] for k in row.keys()}
    return row


def _parse_dt(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _days_since(value: datetime | None) -> int | None:
    if value is None:
        return None
    return max(0, int((datetime.now(timezone.utc) - value).total_seconds() // 86400))
