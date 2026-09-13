"""GitHub REST/GraphQL client.

The client never receives a token directly — it holds a
:class:`~eveaegis.credentials.base.CredentialBroker` and mints a scoped, expiring
grant on demand, re-minting when the previous one lapses. Every write helper
asserts that the active scope actually permits the write, so a mis-wired caller
fails in the client rather than at GitHub.

Rate limiting is handled proactively: the client pauses *before* crossing the
remaining-requests floor rather than reacting to a 403.
"""

from __future__ import annotations

import time
from typing import Any, Iterator

import httpx

from ..config import GitHubConfig
from ..credentials import SCOPE_RANK, CredentialBroker, Grant, TokenScope

API_VERSION = "2022-11-28"
USER_AGENT = "EveAegis/0.1 (+https://github.com/kakon77777-commits/eveaegis-mcp)"


#: Keys GitHub uses to wrap a paginated collection alongside ``total_count``. Search
#: uses ``items``; the installation, workflow and check endpoints each use their own.
#: Hardcoding only ``items`` made every other wrapped endpoint paginate to nothing —
#: silently, since an empty page is indistinguishable from an exhausted one.
_COLLECTION_KEYS: tuple[str, ...] = (
    "items",
    "repositories",
    "installations",
    "workflow_runs",
    "artifacts",
    "check_runs",
    "check_suites",
    "jobs",
    "secrets",
    "variables",
)


def _unwrap_collection(payload: dict[str, Any], path: str) -> list[Any]:
    """Pull the list out of a wrapped collection response.

    Falls back to the sole list-valued key when the wrapper is one we have not seen,
    and refuses to guess when several are present — returning the wrong list quietly
    would be worse than failing here.
    """
    for key in _COLLECTION_KEYS:
        value = payload.get(key)
        if isinstance(value, list):
            return value
    lists = [v for v in payload.values() if isinstance(v, list)]
    if len(lists) == 1:
        return lists[0]
    raise GitHubError(
        200,
        f"paginated response has no recognizable collection key (saw {sorted(payload)})",
        path,
    )


def _error_message(resp: httpx.Response) -> str:
    """GitHub error bodies are usually JSON with `message`; never assume it."""
    try:
        payload = resp.json()
        if isinstance(payload, dict) and payload.get("message"):
            return str(payload["message"])
    except ValueError:
        pass
    return (resp.text or "").strip()[:200] or f"HTTP {resp.status_code}"


class GitHubError(RuntimeError):
    def __init__(self, status: int, message: str, path: str) -> None:
        super().__init__(f"GitHub {status} on {path}: {message}")
        self.status = status
        self.message = message
        self.path = path


class NotFound(GitHubError):
    pass


class GitHubClient:
    def __init__(
        self,
        broker: CredentialBroker,
        cfg: GitHubConfig | None = None,
        *,
        scope: TokenScope = TokenScope.READ_METADATA,
        reason: str = "governance read",
        installation_id: int | None = None,
    ) -> None:
        self.broker = broker
        self.cfg = cfg or GitHubConfig()
        self.scope = scope
        self.reason = reason
        #: Which App installation to act as (None = the broker's default). A user
        #: token ignores it; an App token is minted for exactly this account.
        self.installation_id = installation_id
        self._grant: Grant | None = None
        self._client = httpx.Client(
            base_url=self.cfg.api_base,
            timeout=self.cfg.timeout_seconds,
            follow_redirects=True,
        )
        self.rate_limit_remaining: int | None = None
        self.rate_limit_reset: int | None = None
        self.request_count = 0

    # -- lifecycle --------------------------------------------------------

    def close(self) -> None:
        # The broker owns the grant's lifetime (it may be serving other clients);
        # this client only drops its reference. Expiry, not close, ends a grant.
        self._grant = None
        self._client.close()

    def __enter__(self) -> "GitHubClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- auth -------------------------------------------------------------

    def _headers(self, repository: str | None = None) -> dict[str, str]:
        if self._grant is None or self._grant.expired:
            self._grant = self.broker.mint(
                self.scope,
                lifetime_seconds=self.broker.max_lifetime_seconds,
                reason=self.reason,
                installation_id=self.installation_id,
            )
        if repository and not self._grant.covers(repository):
            raise GitHubError(403, f"grant does not cover {repository}", repository)
        return {
            **self._grant.authorization_header(),
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "User-Agent": USER_AGENT,
        }

    def _require_scope(self, needed: TokenScope, what: str) -> None:
        if SCOPE_RANK[self.scope] < SCOPE_RANK[needed]:
            raise GitHubError(
                403,
                f"{what} requires scope '{needed}' but client holds '{self.scope}'",
                what,
            )

    @property
    def credential_description(self) -> dict[str, str]:
        """Non-secret credential facts, for the audit ledger."""
        d = self.broker.describe()
        d["scope"] = str(self.scope)
        return d

    # -- transport --------------------------------------------------------

    def _respect_rate_limit(self) -> None:
        if self.rate_limit_remaining is None or self.rate_limit_reset is None:
            return
        if self.rate_limit_remaining > self.cfg.min_remaining_before_pause:
            return
        wait = max(0, self.rate_limit_reset - int(time.time())) + 1
        if wait > 0:
            time.sleep(min(wait, 90))

    def _track_rate_limit(self, resp: httpx.Response) -> None:
        remaining = resp.headers.get("x-ratelimit-remaining")
        reset = resp.headers.get("x-ratelimit-reset")
        if remaining is not None:
            self.rate_limit_remaining = int(remaining)
        if reset is not None:
            self.rate_limit_reset = int(reset)

    def request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json: Any = None,
        repository: str | None = None,
        raw: bool = False,
    ) -> Any:
        self._respect_rate_limit()
        last_error: Exception | None = None
        for attempt in range(self.cfg.max_retries):
            try:
                resp = self._client.request(
                    method,
                    path,
                    params=params,
                    json=json,
                    headers=self._headers(repository),
                )
            except httpx.HTTPError as exc:  # transport-level
                last_error = exc
                time.sleep(1.5 * (attempt + 1))
                continue

            self._track_rate_limit(resp)
            self.request_count += 1

            if resp.status_code == 404:
                raise NotFound(404, _error_message(resp), path)
            if resp.status_code in (403, 429) and "rate limit" in resp.text.lower():
                reset = int(resp.headers.get("x-ratelimit-reset", time.time() + 60))
                time.sleep(min(max(reset - int(time.time()), 1), 120))
                continue
            if resp.status_code >= 500:
                last_error = GitHubError(resp.status_code, "server error", path)
                time.sleep(1.5 * (attempt + 1))
                continue
            if resp.status_code >= 400:
                raise GitHubError(resp.status_code, _error_message(resp), path)
            if raw:
                return resp
            if not resp.content:
                return None
            try:
                return resp.json()
            except ValueError as exc:
                # A 2xx with a non-JSON body (empty, HTML from a proxy, truncated).
                # Surface it as an API error rather than a decoder traceback.
                raise GitHubError(resp.status_code, f"non-JSON body: {resp.text[:120]!r}", path) from exc

        raise GitHubError(0, f"exhausted retries ({last_error})", path)

    def get(self, path: str, **kwargs: Any) -> Any:
        return self.request("GET", path, **kwargs)

    def paginate(
        self, path: str, *, params: dict[str, Any] | None = None, limit: int | None = None
    ) -> Iterator[dict[str, Any]]:
        """Yield items across pages, following the ``per_page`` config."""
        page_params = dict(params or {})
        page_params.setdefault("per_page", self.cfg.per_page)
        page = 1
        yielded = 0
        while True:
            page_params["page"] = page
            batch = self.get(path, params=page_params)
            if not batch:
                return
            if isinstance(batch, dict):
                batch = _unwrap_collection(batch, path)
            for item in batch:
                yield item
                yielded += 1
                if limit and yielded >= limit:
                    return
            if len(batch) < page_params["per_page"]:
                return
            page += 1

    def graphql(self, query: str, variables: dict[str, Any] | None = None) -> Any:
        data = self.request(
            "POST", "/graphql", json={"query": query, "variables": variables or {}}
        )
        if isinstance(data, dict) and data.get("errors"):
            raise GitHubError(200, str(data["errors"][0].get("message")), "/graphql")
        return data.get("data") if isinstance(data, dict) else data

    # -- read helpers -----------------------------------------------------

    def viewer(self) -> dict[str, Any]:
        return self.get("/user")

    def orgs(self) -> list[dict[str, Any]]:
        return list(self.paginate("/user/orgs"))

    @property
    def identity_mode(self) -> str:
        """``"user"`` or ``"installation"`` — see :class:`CredentialBroker`."""
        return self.broker.identity_mode

    def installation_repos(self) -> Iterator[dict[str, Any]]:
        """Every repository this App installation can reach, across all its accounts.

        The App-token equivalent of ``user_repos`` + ``org_repos`` combined: one
        endpoint already spans the personal account and every organization the
        installation covers, so there is nothing to fan out over.
        """
        return self.paginate("/installation/repositories")

    def user_repos(self, affiliation: str = "owner") -> Iterator[dict[str, Any]]:
        return self.paginate("/user/repos", params={"affiliation": affiliation, "sort": "pushed"})

    def org_repos(self, org: str) -> Iterator[dict[str, Any]]:
        return self.paginate(f"/orgs/{org}/repos", params={"sort": "pushed"})

    def repo(self, full_name: str) -> dict[str, Any]:
        return self.get(f"/repos/{full_name}", repository=full_name)

    def languages(self, full_name: str) -> dict[str, int]:
        return self.get(f"/repos/{full_name}/languages", repository=full_name) or {}

    def readme(self, full_name: str) -> str | None:
        """Decoded README text, or ``None`` when the repo has none."""
        try:
            resp = self.request(
                "GET",
                f"/repos/{full_name}/readme",
                repository=full_name,
                raw=True,
            )
        except NotFound:
            return None
        import base64

        payload = resp.json()
        if payload.get("encoding") != "base64":
            return payload.get("content")
        try:
            return base64.b64decode(payload["content"]).decode("utf-8", errors="replace")
        except (KeyError, ValueError):
            return None

    def file_text(self, full_name: str, path: str) -> str | None:
        try:
            payload = self.get(f"/repos/{full_name}/contents/{path}", repository=full_name)
        except NotFound:
            return None
        if not isinstance(payload, dict) or payload.get("encoding") != "base64":
            return None
        import base64

        return base64.b64decode(payload["content"]).decode("utf-8", errors="replace")

    def tree(self, full_name: str, ref: str, *, recursive: bool = True) -> list[dict[str, Any]]:
        params = {"recursive": "1"} if recursive else None
        payload = self.get(f"/repos/{full_name}/git/trees/{ref}", params=params, repository=full_name)
        return payload.get("tree", []) if isinstance(payload, dict) else []

    def commits(self, full_name: str, *, limit: int = 100) -> list[dict[str, Any]]:
        return list(self.paginate(f"/repos/{full_name}/commits", limit=limit))

    def forks_parent_chain(self, full_name: str, *, max_depth: int = 5) -> list[str]:
        """Walk ``parent`` links upward, so a fork-of-a-fork resolves to its root."""
        chain: list[str] = []
        current = full_name
        for _ in range(max_depth):
            data = self.repo(current)
            parent = (data.get("parent") or {}).get("full_name")
            if not parent or parent in chain:
                break
            chain.append(parent)
            current = parent
        return chain

    def search_repositories(self, query: str, *, limit: int = 10) -> list[dict[str, Any]]:
        return list(self.paginate("/search/repositories", params={"q": query}, limit=limit))

    def rate_limit(self) -> dict[str, Any]:
        return self.get("/rate_limit")

    # -- write helpers (scope-guarded) ------------------------------------

    def update_repo_metadata(self, full_name: str, changes: dict[str, Any]) -> dict[str, Any]:
        self._require_scope(TokenScope.WRITE_METADATA, "repository metadata update")
        return self.request("PATCH", f"/repos/{full_name}", json=changes, repository=full_name)

    def replace_topics(self, full_name: str, topics: list[str]) -> dict[str, Any]:
        self._require_scope(TokenScope.WRITE_METADATA, "topic replacement")
        return self.request(
            "PUT", f"/repos/{full_name}/topics", json={"names": topics}, repository=full_name
        )

    def create_pull_request(
        self, full_name: str, *, title: str, head: str, base: str, body: str, draft: bool = True
    ) -> dict[str, Any]:
        self._require_scope(TokenScope.WRITE_CONTENT_PR, "pull request creation")
        return self.request(
            "POST",
            f"/repos/{full_name}/pulls",
            json={"title": title, "head": head, "base": base, "body": body, "draft": draft},
            repository=full_name,
        )
