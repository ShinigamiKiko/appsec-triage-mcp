"""Stable finding identity; verdicts are never reused across analysis runs."""

from __future__ import annotations

import hashlib
import re

from .models import Finding

_WS = re.compile(r"\s+")


def fingerprint(finding: Finding) -> str:
    """Stable across line shifts and sensitive to code and dependency-version changes."""
    snippet = _WS.sub(" ", (finding.code_context.snippet or "")).strip()
    material_items = [
        finding.kind,
        finding.rule_id or "",
        finding.cwe or "",
        finding.code_context.file_path.replace("\\", "/"),
        snippet,
    ]
    if dependency := finding.dependency:
        material_items.extend([
            dependency.ecosystem or "",
            dependency.package,
            dependency.installed_version or "",
            *dependency.fixed_versions,
            *dependency.advisory_aliases,
            dependency.reachability or "",
        ])
    material = "␟".join(material_items)
    return hashlib.sha256(material.encode("utf-8")).hexdigest()[:32]
