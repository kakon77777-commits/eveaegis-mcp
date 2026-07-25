"""§5 / §13.3 classification — signals in, governance labels out.

The classifier never calls GitHub and never writes to a repository. It reads what
inventory persisted, produces a labelled verdict with its rationale, and stops.
Acting on a verdict is the policy engine's business.
"""

from __future__ import annotations

from .classifier import Classifier, TaxonomyProfile
from .signals import RepositorySignals, collect_signals, load_repository_row

__all__ = [
    "Classifier",
    "RepositorySignals",
    "TaxonomyProfile",
    "collect_signals",
    "load_repository_row",
]
