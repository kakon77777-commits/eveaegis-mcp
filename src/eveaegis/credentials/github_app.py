"""GitHub App credential backend — the axiom-1-complete path.

Flow: RS256 JWT signed with the App private key → ``POST /app/installations/{id}/
access_tokens`` → installation token that GitHub itself expires within an hour, and
which EveAegis expires much sooner.

This backend is fully implemented but inert until the App exists. Registering it is
a human action (github.com → Settings → Developer settings → GitHub Apps), so the
module fails with an actionable message rather than silently falling back to a
weaker credential.

Requires ``PyJWT[crypto]``; the import is deferred so the rest of EveAegis runs
without it.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

from .base import CredentialBroker, CredentialError, Grant, TokenScope

#: Maps EveAegis scopes onto the GitHub App installation permissions they need.
SCOPE_PERMISSIONS: dict[TokenScope, dict[str, str]] = {
    TokenScope.READ_METADATA: {"metadata": "read"},
    TokenScope.READ_CONTENT: {"metadata": "read", "contents": "read"},
    TokenScope.WRITE_METADATA: {"metadata": "read", "administration": "write"},
    TokenScope.WRITE_CONTENT_PR: {
        "metadata": "read",
        "contents": "write",
        "pull_requests": "write",
    },
    TokenScope.WRITE_CONTENT_DIRECT: {"metadata": "read", "contents": "write"},
    TokenScope.ADMIN: {"metadata": "read", "administration": "write"},
}


class GitHubAppBroker(CredentialBroker):
    name = "github_app"
    max_scope = TokenScope.ADMIN
    identity_mode = "installation"

    def __init__(
        self,
        *,
        app_id: str | None,
        private_key_path: str | None,
        installation_id: int | None,
        api_base: str = "https://api.github.com",
        max_lifetime_seconds: int = 600,
    ) -> None:
        super().__init__(max_lifetime_seconds=max_lifetime_seconds)
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.installation_id = installation_id
        self.api_base = api_base.rstrip("/")

    # -- configuration ----------------------------------------------------

    def _require_config(self) -> tuple[str, Path, int]:
        missing = [
            n
            for n, v in (
                ("credentials.app_id", self.app_id),
                ("credentials.private_key_path", self.private_key_path),
                ("credentials.installation_id", self.installation_id),
            )
            if not v
        ]
        if missing:
            raise CredentialError(
                "GitHub App backend is not configured yet — missing "
                + ", ".join(missing)
                + ". Register a GitHub App, install it on the account, then set these "
                "in config/config.yaml."
            )
        key_path = Path(self.private_key_path)  # type: ignore[arg-type]
        if not key_path.is_file():
            raise CredentialError(f"private key not found at {key_path}")
        return str(self.app_id), key_path, int(self.installation_id)  # type: ignore[arg-type]

    def _app_jwt(self, app_id: str, key_path: Path) -> str:
        try:
            import jwt  # type: ignore
        except ModuleNotFoundError as exc:
            raise CredentialError(
                "GitHub App backend needs PyJWT with crypto extras: pip install 'PyJWT[crypto]'"
            ) from exc
        now = int(time.time())
        payload = {"iat": now - 60, "exp": now + 540, "iss": app_id}
        return jwt.encode(payload, key_path.read_text("utf-8"), algorithm="RS256")

    # -- minting ----------------------------------------------------------

    def _mint(
        self,
        scope: TokenScope,
        lifetime_seconds: int,
        repositories: tuple[str, ...],
        reason: str,
    ) -> Grant:
        app_id, key_path, installation_id = self._require_config()
        body: dict[str, object] = {"permissions": SCOPE_PERMISSIONS[scope]}
        if repositories:
            # Installation tokens take bare repo names, not owner/name.
            body["repositories"] = [r.split("/", 1)[-1] for r in repositories]

        # The token endpoint answers 502 now and then. A transient gateway error is
        # not a reason to abort a sweep, so retry briefly before giving up.
        resp = None
        for attempt in range(5):
            resp = httpx.post(
                f"{self.api_base}/app/installations/{installation_id}/access_tokens",
                headers={
                    "Authorization": f"Bearer {self._app_jwt(app_id, key_path)}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                json=body,
                timeout=20.0,
            )
            if resp.status_code < 500:
                break
            time.sleep(min(3.0 * (2 ** attempt), 30.0))
        assert resp is not None
        if resp.status_code >= 400:
            try:
                detail = str(resp.json().get("message", ""))
            except ValueError:
                detail = (resp.text or "").strip()[:160]
            raise CredentialError(
                f"installation token request failed ({resp.status_code}): {detail}"
            )
        data = resp.json()
        github_expiry = datetime.fromisoformat(data["expires_at"].replace("Z", "+00:00"))
        local_expiry = datetime.now(timezone.utc) + timedelta(seconds=lifetime_seconds)
        return Grant(
            scope=scope,
            expires_at=min(github_expiry, local_expiry),
            backend=self.name,
            credential_type="github_app_installation_token",
            reason=reason,
            repositories=repositories,
            _secret=data["token"],
        )

    def health_check(self) -> tuple[bool, str]:
        try:
            app_id, key_path, _ = self._require_config()
        except CredentialError as exc:
            return False, str(exc)
        try:
            resp = httpx.get(
                f"{self.api_base}/app",
                headers={"Authorization": f"Bearer {self._app_jwt(app_id, key_path)}"},
                timeout=15.0,
            )
        except CredentialError as exc:
            return False, str(exc)
        if resp.status_code != 200:
            return False, f"App authentication failed ({resp.status_code})"
        return True, f"GitHub App '{resp.json().get('slug')}' authenticated"

    def describe(self) -> dict[str, str]:
        d = super().describe()
        d["credential_type"] = "github_app_installation_token"
        d["short_lived"] = "true"
        return d
