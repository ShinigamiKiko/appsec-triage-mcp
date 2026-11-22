"""Finding classes whose confirmed or unresolved verdicts require a person's decision."""

from __future__ import annotations

import re
from collections.abc import Iterable

from .models import VerdictLabel

# CWE-79 also covers reflected/DOM XSS: the CWE alone cannot distinguish stored XSS.
DEFAULT_MANUAL_REVIEW_CWES = (
    "CWE-639",  # IDOR / broken object-level authorization
    "CWE-89",   # SQL injection
    "CWE-79",   # XSS, including stored XSS
    "CWE-918",  # SSRF
    "CWE-94",   # Code injection / RCE
    "CWE-95",   # Eval injection / RCE
    "CWE-98",   # PHP file inclusion / RCE
    "CWE-502",  # Deserialization, including RCE chains
    "CWE-77",   # Command injection
    "CWE-78",   # OS command injection
    "CWE-88",   # Argument injection
)


def normalize_cwe(value: object) -> str:
    """Return CWE-89 for either CWE-89 or 89; empty for an absent/malformed value."""
    match = re.fullmatch(r"(?:CWE[-_\s]*)?(\d+)", str(value or "").strip(), re.IGNORECASE)
    return f"CWE-{match.group(1)}" if match else ""


def selected(cwe: object, configured: Iterable[str] | None) -> bool:
    """Whether this finding belongs to a class with mandatory LLM + human review."""
    wanted = {normalize_cwe(item) for item in (configured or ())}
    wanted.discard("")
    return bool(normalize_cwe(cwe)) and normalize_cwe(cwe) in wanted


def enforce(record, configured: Iterable[str] | None):
    """Keep selected confirmed/unknown findings in review; allow proven FP closures."""
    if (record.decided_by == "scope" or not selected(record.cwe, configured)
            or record.verdict.verdict is VerdictLabel.false_positive):
        return record
    marker = f"manual_review_required:{normalize_cwe(record.cwe)}"
    overrides = list(record.overrides)
    if marker not in overrides:
        overrides.append(marker)
    return record.model_copy(update={
        "verdict": record.verdict.model_copy(update={"requires_human_review": True}),
        "overrides": overrides,
    })
