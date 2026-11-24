"""Kafka version comparison.

A string compare puts ``3.10.0`` below ``3.6.0``, which is how an audit tool
ends up telling you a current cluster is end-of-life.  Parse to a tuple of ints
and compare that.
"""

from __future__ import annotations

import re

_PART = re.compile(r"\d+")


def parse(version: str | None) -> tuple[int, ...] | None:
    """``"3.5.1.tiered"`` -> ``(3, 5, 1)``; unparseable input -> ``None``.

    Trailing non-numeric qualifiers (MSK ships ``2.8.2.tiered``) are dropped
    rather than guessed at, so they compare equal to the plain release.
    """
    if not isinstance(version, str):
        return None
    parts: list[int] = []
    for chunk in version.strip().split("."):
        match = _PART.fullmatch(chunk.strip())
        if match is None:
            break
        parts.append(int(match.group()))
    return tuple(parts) or None


def _pad(a: tuple[int, ...], b: tuple[int, ...]) -> tuple[tuple[int, ...], tuple[int, ...]]:
    width = max(len(a), len(b))
    return a + (0,) * (width - len(a)), b + (0,) * (width - len(b))


def is_older(version: str | None, minimum: str | None) -> bool | None:
    """True when ``version`` is strictly below ``minimum``.

    ``None`` when either side cannot be parsed -- the caller skips the check
    instead of inventing a verdict.
    """
    left, right = parse(version), parse(minimum)
    if left is None or right is None:
        return None
    left, right = _pad(left, right)
    return left < right


def format_tuple(parts: tuple[int, ...] | None) -> str:
    return ".".join(str(p) for p in parts) if parts else "?"
