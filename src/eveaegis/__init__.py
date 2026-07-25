"""EveAegis — AI-native GitHub portfolio governance control plane.

    Inventory → Origin & Provenance → Classification → Policy
             → Plan → Approval → Execution → Audit

Three boundaries the whole system exists to keep:

    Dependency        ≠ Upstream source
    Agent capability  ≠ Agent authorization
    Machine inference ≠ Public legal claim
"""

from __future__ import annotations

__version__ = "0.1.0"

from .config import Config, load_config
from .core import GovernanceCore

__all__ = ["GovernanceCore", "Config", "load_config", "__version__"]
