"""Similarity primitives (§7.1 layered similarity, §7.2 decision precedence).

Pure Python on purpose. The whitepaper's similarity layer is the part a reviewer is
most likely to challenge ("why did you say my repo is a fork?"), so it must be
readable and reproducible without pulling in an opaque native dependency. Nothing
here reaches the network, touches the filesystem, or executes repository content.

Two families live here:

``S_commit`` / ``S_blob``
    §7.1 defines both as an *overlap coefficient* — intersection over
    ``min(|A|, |B|)``, not over the union. That is deliberate: a 40-commit fork of a
    40 000-commit upstream shares only a sliver of the union but essentially all of
    its own history, and the whitepaper wants that to read as high similarity.

``S_token``
    MinHash over k-shingles (cheap, symmetric, good for whole-file corpora) and
    Winnowing (positional, good for locating a copied region inside a larger file).
    Both are *weaker* signals than commit ancestry and may never override it (§7.2).
"""

from __future__ import annotations

import hashlib
import random
import re
import unicodedata
from collections.abc import Set as AbstractSet
from typing import Iterable, NamedTuple, Sequence

# 2^61 - 1. A Mersenne prime keeps the universal-hash modulus cheap and collision
# behaviour well understood; the same construction datasketch uses, reimplemented
# so the project keeps zero extra dependencies.
_MERSENNE_PRIME = (1 << 61) - 1
_MAX_HASH = (1 << 32) - 1

#: Fixed seed: two runs of the engine on the same input must produce identical
#: signatures, otherwise stored fingerprints could never be compared across time.
DEFAULT_SEED = 0x45564541  # "EVEA"

DEFAULT_PERMUTATIONS = 128
DEFAULT_SHINGLE_SIZE = 5
DEFAULT_WINNOW_WINDOW = 4

_TOKEN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*|\d+(?:\.\d+)?|[^\sA-Za-z0-9_]")
_WS_RE = re.compile(r"\s+")

_PERMUTATION_CACHE: dict[tuple[int, int], tuple[tuple[int, int], ...]] = {}


# --------------------------------------------------------------------------
# normalization
# --------------------------------------------------------------------------

def normalize_text(text: str) -> str:
    """Whitespace- and case-insensitive normal form used for text-level identity.

    Reformatting a file (tabs to spaces, CRLF to LF, re-indentation) must not make
    it look like a different file, otherwise every upstream that ran a formatter
    would read as "locally rewritten".
    """
    normalized = unicodedata.normalize("NFC", text)
    normalized = normalized.replace("﻿", "").replace("\r\n", "\n").replace("\r", "\n")
    return _WS_RE.sub(" ", normalized).strip().lower()


def normalized_text_hash(text: str) -> str:
    """``sha256:…`` over :func:`normalize_text` — the "identical file" evidence key."""
    return "sha256:" + hashlib.sha256(normalize_text(text).encode("utf-8")).hexdigest()


def normalize_for_fingerprint(text: str) -> str:
    """Aggressive normal form for winnowing: letters and digits only, lowercased.

    Winnowing is a *positional* algorithm; leaving punctuation and whitespace in
    would let a reformatter shift every window and destroy the match.
    """
    lowered = unicodedata.normalize("NFC", text).lower()
    return "".join(ch for ch in lowered if ch.isalnum())


def tokenize(text: str) -> list[str]:
    """Language-agnostic tokenizer: identifiers, numbers, single punctuation marks.

    Deliberately not language-aware. A language-specific lexer would be more precise
    but would silently degrade to nothing on the long tail of file types in a
    55-repository portfolio; a uniform tokenizer degrades *predictably*.
    """
    return _TOKEN_RE.findall(text)


def shingles(items: Sequence[str], size: int = DEFAULT_SHINGLE_SIZE) -> set[str]:
    """Overlapping k-grams joined by ``\\x1f``, which cannot occur in a token."""
    if size <= 0:
        raise ValueError("shingle size must be positive")
    if not items:
        return set()
    if len(items) <= size:
        return {"\x1f".join(items)}
    return {"\x1f".join(items[i : i + size]) for i in range(len(items) - size + 1)}


# --------------------------------------------------------------------------
# MinHash
# --------------------------------------------------------------------------

def _permutations(count: int, seed: int) -> tuple[tuple[int, int], ...]:
    key = (count, seed)
    cached = _PERMUTATION_CACHE.get(key)
    if cached is None:
        rng = random.Random(seed)
        cached = tuple(
            (rng.randint(1, _MERSENNE_PRIME - 1), rng.randint(0, _MERSENNE_PRIME - 1))
            for _ in range(count)
        )
        _PERMUTATION_CACHE[key] = cached
    return cached


def _base_hash(item: str) -> int:
    return int.from_bytes(hashlib.sha1(item.encode("utf-8")).digest()[:8], "big") & _MAX_HASH


def minhash_signature(
    items: Iterable[str],
    *,
    permutations: int = DEFAULT_PERMUTATIONS,
    seed: int = DEFAULT_SEED,
) -> tuple[int, ...]:
    """MinHash signature of a set of strings (shingles, paths, blob SHAs…).

    Returns an empty tuple for empty input rather than a sentinel-filled signature,
    so "nothing to compare" can never be mistaken for "perfectly similar".
    """
    unique = {item for item in items if item}
    if not unique:
        return ()
    perms = _permutations(permutations, seed)
    signature = [_MERSENNE_PRIME] * permutations
    for item in unique:
        base = _base_hash(item)
        for index, (a, b) in enumerate(perms):
            value = (a * base + b) % _MERSENNE_PRIME
            if value < signature[index]:
                signature[index] = value
    return tuple(signature)


def jaccard(a: Iterable[str] | Sequence[int], b: Iterable[str] | Sequence[int]) -> float:
    """Jaccard similarity, exact for sets and estimated for MinHash signatures.

    Polymorphic because callers legitimately hold both forms: an exact set when the
    corpus is small enough to keep in memory, a stored signature when it is not.
    Empty on either side is 0.0 — an unmeasurable pair is never "similar".
    """
    if isinstance(a, (set, frozenset)) and isinstance(b, (set, frozenset)):
        if not a or not b:
            return 0.0
        union = len(a | b)
        return len(a & b) / union if union else 0.0

    sig_a = tuple(a)  # type: ignore[arg-type]
    sig_b = tuple(b)  # type: ignore[arg-type]
    if not sig_a or not sig_b:
        return 0.0
    if len(sig_a) != len(sig_b):
        raise ValueError(
            f"cannot compare MinHash signatures of different lengths "
            f"({len(sig_a)} vs {len(sig_b)})"
        )
    matches = sum(1 for x, y in zip(sig_a, sig_b) if x == y)
    return matches / len(sig_a)


def overlap_coefficient(a: AbstractSet[object], b: AbstractSet[object]) -> float:
    """|A ∩ B| / min(|A|, |B|) — the shape §7.1 uses for S_commit and S_blob."""
    if not a or not b:
        return 0.0
    return len(a & b) / min(len(a), len(b))


def commit_similarity(commits_a: set[str], commits_b: set[str]) -> float:
    """§7.1 S_commit. Inputs are commit SHAs, not messages."""
    return overlap_coefficient(commits_a, commits_b)


def blob_similarity(blobs_a: set[str], blobs_b: set[str]) -> float:
    """§7.1 S_blob. Inputs are blob SHAs — byte-identical content, no heuristics."""
    return overlap_coefficient(blobs_a, blobs_b)


def token_similarity(
    text_a: str,
    text_b: str,
    *,
    permutations: int = DEFAULT_PERMUTATIONS,
    shingle_size: int = DEFAULT_SHINGLE_SIZE,
    seed: int = DEFAULT_SEED,
) -> float:
    """§7.1 S_token via MinHash over token shingles."""
    a = shingles(tokenize(text_a), shingle_size)
    b = shingles(tokenize(text_b), shingle_size)
    if not a or not b:
        return 0.0
    # Small corpora: the exact answer is cheap and strictly better than an estimate.
    if len(a) + len(b) <= 4 * permutations:
        return jaccard(a, b)
    return jaccard(
        minhash_signature(a, permutations=permutations, seed=seed),
        minhash_signature(b, permutations=permutations, seed=seed),
    )


# --------------------------------------------------------------------------
# Winnowing (Schleimer, Wilkerson & Aiken)
# --------------------------------------------------------------------------

class Fingerprint(NamedTuple):
    """One selected k-gram hash and where it started in the normalized text."""

    hash: int
    position: int


def _kgram_hashes(normalized: str, k: int) -> list[int]:
    if len(normalized) < k:
        return []
    return [
        int.from_bytes(hashlib.blake2b(normalized[i : i + k].encode("utf-8"), digest_size=8).digest(), "big")
        for i in range(len(normalized) - k + 1)
    ]


def winnow_fingerprints(
    text: str,
    *,
    k: int = DEFAULT_SHINGLE_SIZE,
    window: int = DEFAULT_WINNOW_WINDOW,
) -> list[Fingerprint]:
    """Select a positional fingerprint set with a guaranteed detection threshold.

    In every window of ``window`` consecutive k-gram hashes the minimum is selected
    (rightmost on ties, per the original paper), which guarantees any shared passage
    of at least ``k + window - 1`` normalized characters produces a shared
    fingerprint, while keeping only ~``2/(window+1)`` of the hashes.
    """
    if k <= 0 or window <= 0:
        raise ValueError("k and window must be positive")
    hashes = _kgram_hashes(normalize_for_fingerprint(text), k)
    if not hashes:
        return []
    if len(hashes) < window:
        lowest = min(hashes)
        return [Fingerprint(lowest, hashes.index(lowest))]

    selected: list[Fingerprint] = []
    previous_position = -1
    for start in range(len(hashes) - window + 1):
        chunk = hashes[start : start + window]
        lowest = min(chunk)
        # Rightmost occurrence: consecutive windows then re-select the same
        # fingerprint instead of emitting a near-duplicate one position over.
        offset = len(chunk) - 1 - chunk[::-1].index(lowest)
        position = start + offset
        if position != previous_position:
            selected.append(Fingerprint(lowest, position))
            previous_position = position
    return selected


def fingerprint_overlap(a: Iterable[Fingerprint], b: Iterable[Fingerprint]) -> float:
    """Overlap coefficient over winnowed hash sets — asymmetric-size friendly."""
    set_a = {fp.hash for fp in a}
    set_b = {fp.hash for fp in b}
    return overlap_coefficient(set_a, set_b)
