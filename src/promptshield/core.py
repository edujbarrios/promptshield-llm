"""Core redaction helpers for promptshield."""

from __future__ import annotations

import re
from collections.abc import Iterable


PatternSpec = tuple[str, str, re.Pattern[str]]

SENSITIVE_QUERY_KEYS = (
    "access_token",
    "api_key",
    "auth",
    "code",
    "key",
    "password",
    "secret",
    "signature",
    "token",
)

DEFAULT_PATTERNS: tuple[PatternSpec, ...] = (
    (
        "email",
        "[EMAIL]",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    ),
    (
        "phone",
        "[PHONE]",
        re.compile(
            r"(?<!\w)(?:\+?\d{1,3}[\s.-]?)?(?:\(?\d{3}\)?[\s.-]?)\d{3}[\s.-]?\d{4}(?!\w)"
        ),
    ),
    (
        "token",
        "[TOKEN]",
        re.compile(r"\bBearer\s+[A-Za-z0-9._~+/=-]{6,}\b", re.IGNORECASE),
    ),
    (
        "api_key",
        "[API_KEY]",
        re.compile(
            r"\b(?:sk-[A-Za-z0-9_-]{12,}|gh[pousr]_[A-Za-z0-9_]{12,}|[A-Za-z0-9_-]{32,})\b"
        ),
    ),
    (
        "token",
        "[TOKEN]",
        re.compile(
            r"\b(?:api[_-]?key|private[_-]?token|token|secret|password)\s*[:=]\s*[\"']?(?!Bearer\b)[^\"'\s&]{6,}",
            re.IGNORECASE,
        ),
    ),
    (
        "sensitive_url",
        "[SENSITIVE_URL]",
        re.compile(
            rf"https?://[^\s<>'\"]+[?&](?:{'|'.join(SENSITIVE_QUERY_KEYS)})=[^\s<>'\"]+",
            re.IGNORECASE,
        ),
    ),
)


def find_sensitive(
    text: str, custom_patterns: dict[str, str] | None = None
) -> list[dict[str, object]]:
    """Return sensitive matches found in text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    matches: list[dict[str, object]] = []
    for kind, _placeholder, pattern in _all_patterns(custom_patterns):
        for match in pattern.finditer(text):
            matches.append(
                {
                    "type": kind,
                    "value": match.group(0),
                    "start": match.start(),
                    "end": match.end(),
                }
            )

    return _without_overlaps(matches)


def shield_prompt(text: str, custom_patterns: dict[str, str] | None = None) -> str:
    """Redact sensitive values from text."""
    if not isinstance(text, str):
        raise TypeError("text must be a string")

    replacements = []
    for kind, placeholder, pattern in _all_patterns(custom_patterns):
        for match in pattern.finditer(text):
            replacements.append(
                {
                    "type": kind,
                    "start": match.start(),
                    "end": match.end(),
                    "placeholder": placeholder,
                }
            )

    redacted = text
    for match in reversed(_without_overlaps(replacements)):
        redacted = (
            redacted[: int(match["start"])]
            + str(match["placeholder"])
            + redacted[int(match["end"]) :]
        )
    return redacted


def _all_patterns(custom_patterns: dict[str, str] | None) -> Iterable[PatternSpec]:
    yield from DEFAULT_PATTERNS

    if not custom_patterns:
        return

    for name, pattern in custom_patterns.items():
        safe_name = name.upper().replace("-", "_").replace(" ", "_")
        yield f"custom_{name}", f"[CUSTOM_{safe_name}]", re.compile(pattern)


def _without_overlaps(matches: list[dict[str, object]]) -> list[dict[str, object]]:
    ordered = sorted(
        matches,
        key=lambda item: (
            int(item["start"]),
            -(int(item["end"]) - int(item["start"])),
        ),
    )

    selected: list[dict[str, object]] = []
    covered_until = -1
    for match in ordered:
        start = int(match["start"])
        end = int(match["end"])
        if start < covered_until:
            continue
        selected.append(match)
        covered_until = end

    return selected
