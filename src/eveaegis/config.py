"""Runtime configuration.

Resolution order (first hit wins):

1. explicit path passed to :func:`load_config`
2. ``EVEAEGIS_CONFIG`` environment variable
3. ``<project root>/config/config.yaml``
4. ``<project root>/config/config.example.yaml``

The config file never contains secrets. Credentials are resolved at call time by
:mod:`eveaegis.credentials` (axiom 1) — the only thing stored here is *which broker
backend to ask*.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

PROJECT_ROOT = Path(__file__).resolve().parents[2]


class CredentialConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: str = "gh_cli"
    #: GitHub App backend settings — inert until the App is registered.
    app_id: str | None = None
    private_key_path: str | None = None
    installation_id: int | None = None
    #: Hard ceiling on how long any minted token may live (axiom 5).
    max_token_lifetime_seconds: int = 600


class AnalysisConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    workspace_dir: str = "workspace"
    #: Never execute anything from a cloned repository (§21).
    allow_repository_code_execution: bool = False
    clone_depth: int | None = None
    max_blob_bytes: int = 1_048_576
    minhash_permutations: int = 128
    shingle_size: int = 5
    excluded_dirs: list[str] = Field(
        default_factory=lambda: [
            "node_modules",
            ".venv",
            "venv",
            "vendor",
            "third_party",
            "dist",
            "build",
            "generated",
            "coverage",
            ".cache",
            ".git",
            "__pycache__",
            "target",
            "site-packages",
        ]
    )


class GitHubConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    api_base: str = "https://api.github.com"
    per_page: int = 100
    timeout_seconds: float = 30.0
    max_retries: int = 3
    #: Stop before the secondary-rate-limit wall rather than after it.
    min_remaining_before_pause: int = 50


class GovernanceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tenant_id: str = "evemisslab"
    tenant_name: str = "EveMissLab"
    tenant_type: str = "laboratory"
    policy_dir: str = "config/policies"
    taxonomy_profile: str = "evemisslab-v1"
    #: Read-only mode refuses every write tool regardless of policy (Phase 0 default).
    read_only: bool = True
    require_human_approval: bool = True
    #: GitHub account logins this tenant governs. Once the App is public, anyone can
    #: install it on their own account; an installation on a login not listed here
    #: is ignored and recorded, never swept into the catalog. Empty = only the
    #: App owner's account.
    accounts: list[str] = Field(default_factory=list)


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")

    database_path: str = "workspace/eveaegis.db"
    credentials: CredentialConfig = Field(default_factory=CredentialConfig)
    github: GitHubConfig = Field(default_factory=GitHubConfig)
    analysis: AnalysisConfig = Field(default_factory=AnalysisConfig)
    governance: GovernanceConfig = Field(default_factory=GovernanceConfig)

    #: Absolute path this config was loaded from (``None`` when built from defaults).
    source_path: Path | None = None

    def resolve(self, relative: str) -> Path:
        """Resolve a config-relative path against the project root."""
        p = Path(relative)
        return p if p.is_absolute() else (PROJECT_ROOT / p)

    @property
    def db_path(self) -> Path:
        return self.resolve(self.database_path)

    @property
    def workspace_path(self) -> Path:
        return self.resolve(self.analysis.workspace_dir)

    @property
    def policy_path(self) -> Path:
        return self.resolve(self.governance.policy_dir)


def _candidate_paths(explicit: str | Path | None) -> list[Path]:
    paths: list[Path] = []
    if explicit:
        paths.append(Path(explicit))
    env = os.environ.get("EVEAEGIS_CONFIG")
    if env:
        paths.append(Path(env))
    paths.append(PROJECT_ROOT / "config" / "config.yaml")
    paths.append(PROJECT_ROOT / "config" / "config.example.yaml")
    return paths


def load_config(path: str | Path | None = None) -> Config:
    for candidate in _candidate_paths(path):
        if candidate.is_file():
            raw: dict[str, Any] = yaml.safe_load(candidate.read_text("utf-8")) or {}
            cfg = Config.model_validate(raw)
            cfg.source_path = candidate.resolve()
            return cfg
    return Config()
