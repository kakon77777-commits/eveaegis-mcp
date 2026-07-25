"""Credential brokering — the only place in EveAegis that touches GitHub secrets."""

from __future__ import annotations

from ..config import CredentialConfig
from .base import (
    READ_SCOPES,
    SCOPE_RANK,
    CredentialBroker,
    CredentialError,
    Grant,
    GrantExpired,
    TokenScope,
)
from .gh_cli import GhCliBroker
from .github_app import GitHubAppBroker

__all__ = [
    "CredentialBroker",
    "CredentialError",
    "Grant",
    "GrantExpired",
    "TokenScope",
    "SCOPE_RANK",
    "READ_SCOPES",
    "GhCliBroker",
    "GitHubAppBroker",
    "build_broker",
]

_BACKENDS = {"gh_cli": GhCliBroker, "github_app": GitHubAppBroker}


def build_broker(cfg: CredentialConfig, *, api_base: str = "https://api.github.com") -> CredentialBroker:
    """Instantiate the configured backend. Unknown names fail loudly."""
    backend = cfg.backend
    if backend not in _BACKENDS:
        raise CredentialError(
            f"unknown credential backend '{backend}'; expected one of {sorted(_BACKENDS)}"
        )
    if backend == "gh_cli":
        return GhCliBroker(max_lifetime_seconds=cfg.max_token_lifetime_seconds)
    return GitHubAppBroker(
        app_id=cfg.app_id,
        private_key_path=cfg.private_key_path,
        installation_id=cfg.installation_id,
        api_base=api_base,
        max_lifetime_seconds=cfg.max_token_lifetime_seconds,
    )
