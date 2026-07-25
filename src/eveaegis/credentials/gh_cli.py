"""``gh`` CLI credential backend.

The token lives in the OS keyring managed by GitHub CLI. EveAegis shells out to
``gh auth token`` at mint time and keeps the value only inside a :class:`Grant`.

Honest accounting of what this backend is and is not:

* It **does** satisfy the structural half of axiom 1 — agents never touch the
  credential, every use is scoped, expiring and audited.
* It **does not** satisfy the cryptographic half — the underlying token is
  long-lived and account-wide. Only the GitHub App backend gives short-lived,
  per-installation tokens.

Because of that, this backend refuses to issue anything above
:data:`TokenScope.WRITE_METADATA`, and defaults to read-only. Write-heavy phases
must move to :mod:`eveaegis.credentials.github_app`.
"""

from __future__ import annotations

import shutil
import subprocess
from datetime import datetime, timedelta, timezone

from .base import CredentialBroker, CredentialError, Grant, TokenScope


class GhCliBroker(CredentialBroker):
    name = "gh_cli"
    max_scope = TokenScope.WRITE_METADATA

    def __init__(
        self,
        *,
        max_lifetime_seconds: int = 600,
        gh_path: str | None = None,
        hostname: str = "github.com",
    ) -> None:
        super().__init__(max_lifetime_seconds=max_lifetime_seconds)
        self.gh_path = gh_path or shutil.which("gh") or "gh"
        self.hostname = hostname

    def _run(self, args: list[str], timeout: float = 20.0) -> str:
        try:
            proc = subprocess.run(
                [self.gh_path, *args],
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError as exc:
            raise CredentialError(
                "GitHub CLI not found; install it or switch credentials.backend"
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise CredentialError("GitHub CLI timed out") from exc
        if proc.returncode != 0:
            # stderr from `gh` does not contain the token itself, but trim anyway.
            detail = (proc.stderr or "").strip().splitlines()
            raise CredentialError(f"gh {' '.join(args)} failed: {detail[0] if detail else ''}")
        return proc.stdout.strip()

    def _mint(
        self,
        scope: TokenScope,
        lifetime_seconds: int,
        repositories: tuple[str, ...],
        reason: str,
    ) -> Grant:
        token = self._run(["auth", "token", "--hostname", self.hostname])
        if not token:
            raise CredentialError("gh returned an empty token")
        return Grant(
            scope=scope,
            expires_at=datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds),
            backend=self.name,
            credential_type="gh_cli_delegated_oauth_token",
            reason=reason,
            account_login=self.current_login(),
            repositories=repositories,
            _secret=token,
        )

    def current_login(self) -> str | None:
        try:
            return self._run(["api", "user", "--jq", ".login"]) or None
        except CredentialError:
            return None

    def health_check(self) -> tuple[bool, str]:
        if not shutil.which(self.gh_path) and self.gh_path == "gh":
            return False, "gh CLI not on PATH"
        try:
            login = self.current_login()
        except CredentialError as exc:
            return False, str(exc)
        if not login:
            return False, "gh is installed but not authenticated (`gh auth login`)"
        return True, f"authenticated as {login}"

    def describe(self) -> dict[str, str]:
        d = super().describe()
        d["credential_type"] = "gh_cli_delegated_oauth_token"
        d["short_lived"] = "false"
        return d
